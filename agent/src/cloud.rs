use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::str::FromStr;
use std::path::Path;
use tokio::time::sleep;
use crate::heuristics::HeuristicsEngine;

static CLOUD_CLIENT: OnceLock<CloudClient> = OnceLock::new();
static LOGS_BUFFER: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
static HEURISTICS_ENGINE: OnceLock<Arc<HeuristicsEngine>> = OnceLock::new();
static GRPC_TX: OnceLock<tokio::sync::mpsc::Sender<AgentMessage>> = OnceLock::new();

pub const DEFAULT_CLOUD_ENDPOINT: &str = "https://backend.kinnector.com";

struct CloudClient {
    pub cloud_endpoint: String,
    pub updates_server: String,
    pub license_key: Option<String>,
    pub auto_analyze: bool,
    pub telemetry_enabled: bool,
}

fn get_client() -> &'static CloudClient {
    CLOUD_CLIENT.get_or_init(|| {
        let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
        let mut cloud_endpoint = DEFAULT_CLOUD_ENDPOINT.to_string();
        let mut updates_server = "https://updates.kinnector.com/rules.db".to_string();
        let mut license_key = None;
        let mut auto_analyze = false;
        let mut telemetry_enabled = true;

        for line in conf.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim();
                let val = line[pos+1..].trim();
                match key {
                    "updates_server" => {
                        if !val.is_empty() { updates_server = val.to_string(); }
                    }
                    "license_key" => {
                        if !val.is_empty() && val != "free" {
                            license_key = Some(val.to_string());
                        }
                    }
                    "auto_analyze" | "auto_analyze_incidents" => {
                        auto_analyze = val.to_lowercase() == "true" || val == "1";
                    }
                    "telemetry_enabled" => {
                        telemetry_enabled = val.to_lowercase() != "false" && val != "0";
                    }
                    _ => {}
                }
            }
        }
        // Enterprise-only undocumented override; not exposed in docs or conf templates
        if let Ok(ep) = std::env::var("VANDAM_CLOUD_ENDPOINT") {
            if !ep.is_empty() { cloud_endpoint = ep; }
        }
        if let Ok(srv) = std::env::var("VANDAM_UPDATES_SERVER") {
            if !srv.is_empty() { updates_server = srv; }
        }
        if let Ok(key) = std::env::var("VANDAM_LICENSE_KEY") {
            if !key.is_empty() && key != "free" { license_key = Some(key); }
        }
        if let Ok(aa) = std::env::var("VANDAM_AUTO_ANALYZE") {
            auto_analyze = aa.to_lowercase() == "true" || aa == "1";
        }
        if let Ok(te) = std::env::var("VANDAM_TELEMETRY_ENABLED") {
            telemetry_enabled = te.to_lowercase() != "false" && te != "0";
        }

        CloudClient { cloud_endpoint, updates_server, license_key, auto_analyze, telemetry_enabled }
    })
}

pub fn update_cloud_config(
    license_key: Option<String>,
    auto_analyze: Option<bool>,
    telemetry_enabled: Option<bool>,
) {
    if let Some(key) = license_key {
        std::env::set_var("VANDAM_LICENSE_KEY", key);
    }
    if let Some(aa) = auto_analyze {
        std::env::set_var("VANDAM_AUTO_ANALYZE", if aa { "true" } else { "false" });
    }
    if let Some(te) = telemetry_enabled {
        std::env::set_var("VANDAM_TELEMETRY_ENABLED", if te { "true" } else { "false" });
    }
}

fn get_logs_buffer() -> &'static Mutex<Vec<String>> {
    LOGS_BUFFER.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn queue_log_entry(entry: &str) {
    if let Ok(mut buf) = get_logs_buffer().lock() {
        buf.push(entry.to_string());
    }
}

pub fn start_cloud_services(heuristics: Arc<HeuristicsEngine>) {
    let _ = HEURISTICS_ENGINE.set(Arc::clone(&heuristics));
    let client = get_client();
    let config = Arc::clone(&heuristics.config);

    // Initial Registration check with Cloud Backend
    let heuristics_reg = Arc::clone(&heuristics);
    tokio::spawn(async move {
        let _ = register_agent_with_cloud(&heuristics_reg).await;
    });

    // 1. Start remote rule updates sync loop (every 6 hours)
    tokio::spawn(async move {
        // Initial sync on boot
        sleep(Duration::from_secs(10)).await;
        loop {
            let _ = sync_rules_now(&config).await;
            sleep(Duration::from_secs(6 * 3600)).await;
        }
    });

    // 2. Start log streaming loop (every 60 seconds)
    start_log_streamer(client);

    // 3. Start cloud-initiated command listener
    start_command_listener(Arc::clone(&heuristics), client);

    // 4. Start forensic offline recovery uploader (every 5 minutes)
    start_forensic_uploader(client);

    // 5. Start heartbeat loop (every 60 seconds)
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;
            let _ = send_heartbeat_ping().await;
        }
    });

    // 6. Start initial inventory sync on boot (after 15 seconds)
    let heuristics_clone = Arc::clone(&heuristics);
    tokio::spawn(async move {
        sleep(Duration::from_secs(15)).await;
        send_inventory_sync(&heuristics_clone).await;
    });

    // 7. Start periodic config sync loop (every 1 hour)
    let heuristics_clone_config = Arc::clone(&heuristics);
    tokio::spawn(async move {
        sleep(Duration::from_secs(30)).await;
        loop {
            let _ = sync_config_from_cloud(&heuristics_clone_config.config).await;
            sleep(Duration::from_secs(3600)).await;
        }
    });
}

pub async fn sync_rules_now(config: &Arc<crate::rules::ConfigManager>) -> bool {
    let client_info = get_client();
    let endpoint = &client_info.cloud_endpoint;
    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();

    println!("[Vandam Cloud gRPC] Initiating remote rule updates sync via gRPC from {}", endpoint);

    let url = if endpoint.contains("/api/v1") {
        if let Some(pos) = endpoint.find("/api/v1") { endpoint[..pos].to_string() } else { endpoint.clone() }
    } else {
        endpoint.clone()
    };

    if let Ok(endpoint_conf) = tonic::transport::Endpoint::from_shared(url) {
        let endpoint_conf = endpoint_conf.connect_timeout(Duration::from_secs(10));
        if let Ok(channel) = endpoint_conf.connect().await {
            let mut grpc_client = VandamServiceClient::new(channel);
            let req = proto::RuleSyncRequest {
                agent_id,
                license_key,
                current_etag: String::new(),
            };

            if let Ok(response) = grpc_client.sync_rules(req).await {
                let resp = response.into_inner();
                if resp.updated && !resp.rules_bundle.is_empty() {
                    match config.reload_from_bytes(&resp.rules_bundle) {
                        Ok(_) => {
                            println!("[Vandam Cloud gRPC] Remote rule sync successful. Rules verified & reloaded in-memory.");
                            // A rule reload may have refreshed GeoIP country ranges —
                            // re-resolve any Country-targeted firewall rules against the
                            // new data.
                            let _ = crate::firewall::reconcile::reconcile_firewall(config);
                            return true;
                        }
                        Err(e) => {
                            eprintln!("[Vandam Cloud gRPC] Cryptographic verification failed for updates: {}. Fallback to existing rules.", e);
                            return false;
                        }
                    }
                }
            }
        }
    }
    false
}

pub async fn send_forensic_payload(alert_id: &str, payload: Vec<u8>) -> bool {
    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();
    let payload_hex = payload.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let forensic_json = serde_json::json!({
        "event": "forensic_payload",
        "alert_id": alert_id,
        "payload_hex": payload_hex
    }).to_string();

    if let Some(tx) = GRPC_TX.get() {
        let _ = tx.send(AgentMessage {
            agent_id,
            license_key,
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            payload_json: forensic_json,
            bpf_capacity_pct: 0,
        }).await;
        
        let local_path = format!("/var/log/kinnector/forensic_{}.json.zst", alert_id);
        let uploaded_path = format!("/var/log/kinnector/uploaded_forensic_{}.json.zst", alert_id);
        let _ = std::fs::rename(local_path, uploaded_path);
        true
    } else {
        false
    }
}

static STARTUP_TIME: OnceLock<std::time::Instant> = OnceLock::new();

fn get_uptime() -> u64 {
    let start = STARTUP_TIME.get_or_init(std::time::Instant::now);
    start.elapsed().as_secs()
}

fn start_log_streamer(_client: &'static CloudClient) {
    let _ = STARTUP_TIME.get_or_init(std::time::Instant::now);

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(60)).await;

            let mut logs = Vec::new();
            if let Ok(buf) = get_logs_buffer().lock() {
                logs = buf.clone();
            }

            if logs.is_empty() {
                continue;
            }

            let is_lsm = unsafe { crate::ffi::is_lsm_active() };
            let in_container = std::path::Path::new("/.dockerenv").exists();
            let is_paid = crate::tls_buffer::is_paid_tier();
            let uptime = get_uptime();

            let payload = serde_json::json!({
                "event": "log_batch",
                "logs": logs,
                "agent_status": {
                    "version": env!("CARGO_PKG_VERSION"),
                    "status": if is_paid { "licensed" } else { "active" },
                    "tier": if is_paid { "paid" } else { "free" },
                    "lsm_active": is_lsm,
                    "in_container": in_container,
                    "uptime_secs": uptime,
                }
            }).to_string();

            if let Some(tx) = GRPC_TX.get() {
                let agent_id = get_or_create_agent_id();
                let license_key = get_or_create_license_key();
                let res = tx.send(AgentMessage {
                    agent_id,
                    license_key,
                    timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
                    payload_json: payload,
                    bpf_capacity_pct: 0,
                }).await;

                if res.is_ok() {
                    if let Ok(mut buf) = get_logs_buffer().lock() {
                        let sent_len = logs.len();
                        if buf.len() >= sent_len {
                            buf.drain(0..sent_len);
                        } else {
                            buf.clear();
                        }
                    }
                }
            }
        }
    });
}

fn start_forensic_uploader(client: &'static CloudClient) {
    

    tokio::spawn(async move {
        loop {
            // Check for unsent forensic payloads every 5 minutes
            sleep(Duration::from_secs(300)).await;

            let log_dir = Path::new("/var/log/kinnector");
            let Ok(entries) = std::fs::read_dir(log_dir) else { continue; };

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                        if filename.starts_with("forensic_") && filename.ends_with(".json.zst") {
                            let alert_id = filename
                                .trim_start_matches("forensic_")
                                .trim_end_matches(".json.zst");

                            if let Ok(bytes) = std::fs::read(&path) {
                                println!("[Vandam Cloud] Offline recovery: Retrying forensic upload for alert {}", alert_id);
                                let _ = send_forensic_payload(alert_id, bytes).await;
                            }
                        }
                    }
                }
            }
        }
    });
}

pub mod proto {
    tonic::include_proto!("vandam");
}

use proto::vandam_service_client::VandamServiceClient;
use proto::AgentMessage;

struct MyStream(tokio::sync::mpsc::Receiver<AgentMessage>);

impl futures_core::Stream for MyStream {
    type Item = AgentMessage;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

fn start_command_listener(heuristics: Arc<HeuristicsEngine>, client: &'static CloudClient) {
    let endpoint = client.cloud_endpoint.clone();

    tokio::spawn(async move {
        loop {
            let url = if endpoint.contains("/api/v1") {
                if let Some(pos) = endpoint.find("/api/v1") {
                    endpoint[..pos].to_string()
                } else {
                    endpoint.clone()
                }
            } else {
                endpoint.clone()
            };

            tracing::info!("[Vandam Cloud] Attempting gRPC connection to console: {}", url);
            match tonic::transport::Endpoint::from_shared(url) {
                Ok(endpoint_conf) => {
                    let endpoint_conf = endpoint_conf
                        .keep_alive_while_idle(true)
                        .connect_timeout(Duration::from_secs(10));
                    
                    match endpoint_conf.connect().await {
                        Ok(channel) => {
                            tracing::info!("[Vandam Cloud] gRPC connected to console.");
                            let mut grpc_client = VandamServiceClient::new(channel);

                            let (tx, rx) = tokio::sync::mpsc::channel(100);
                            let _ = GRPC_TX.set(tx.clone());
                            
                            let agent_id = uuid::Uuid::new_v4().to_string();
                            let license_key = client.license_key.clone().unwrap_or_default();
                            let reg_payload = serde_json::json!({
                                "event": "register",
                                "agent_version": env!("CARGO_PKG_VERSION"),
                            }).to_string();

                            let _ = tx.send(AgentMessage {
                                agent_id: agent_id.clone(),
                                license_key: license_key.clone(),
                                timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
                                payload_json: reg_payload,
                                bpf_capacity_pct: 0,
                            }).await;

                            let outbound_stream = MyStream(rx);
                            
                            match grpc_client.command_stream(outbound_stream).await {
                                Ok(response) => {
                                    let mut inbound_stream = response.into_inner();
                                    
                                    while let Ok(Some(msg)) = inbound_stream.message().await {
                                        if let Ok(cmd_json) = serde_json::from_str::<serde_json::Value>(&msg.command_json) {
                                            process_cloud_command(cmd_json, Arc::clone(&heuristics)).await;
                                        }
                                    }
                                    tracing::warn!("[Vandam Cloud] gRPC stream closed by remote console.");
                                }
                                Err(e) => {
                                    tracing::error!("[Vandam Cloud] Failed to establish gRPC stream: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("[Vandam Cloud] gRPC connection failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("[Vandam Cloud] Invalid gRPC URL: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}

/// Adds (or no-ops if already present) a `FirewallProvenance::Cloud, locked:
/// true` block rule for `ip` and runs a reconcile pass. Idempotent by IP so
/// a repeated/retried `block_ip` command doesn't pile up duplicate rules.
fn add_cloud_ip_rule(ip: &str, config: &Arc<crate::rules::ConfigManager>) {
    let mut rules = crate::firewall::read_firewall_rules();
    let already_blocked = rules.iter().any(|r| {
        r.provenance == crate::firewall::FirewallProvenance::Cloud
            && matches!(&r.target, crate::firewall::FirewallTarget::IpCidr(cidr) if cidr == ip)
    });
    if already_blocked {
        return;
    }
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();
    rules.push(crate::firewall::FirewallRule {
        id: uuid::Uuid::new_v4().to_string(),
        target: crate::firewall::FirewallTarget::IpCidr(ip.to_string()),
        direction: "inbound".to_string(),
        action: "DROP".to_string(),
        port: None,
        scope: "global".to_string(),
        site: None,
        reason: Some("Blocked by cloud fleet command".to_string()),
        provenance: crate::firewall::FirewallProvenance::Cloud,
        locked: true,
        created_at: now.clone(),
        updated_at: now,
    });
    crate::firewall::write_firewall_rules(&rules);
    let report = crate::firewall::reconcile::reconcile_firewall(config);
    if !report.errors.is_empty() {
        eprintln!("[Vandam Cloud] firewall reconcile errors after block_ip: {:?}", report.errors);
    }
}

/// Removes every `Cloud`-provenance rule targeting `ip` (there should be at
/// most one, given `add_cloud_ip_rule`'s idempotency) and reconciles.
fn remove_cloud_ip_rule(ip: &str, config: &Arc<crate::rules::ConfigManager>) {
    let mut rules = crate::firewall::read_firewall_rules();
    let initial_len = rules.len();
    rules.retain(|r| {
        !(r.provenance == crate::firewall::FirewallProvenance::Cloud
            && matches!(&r.target, crate::firewall::FirewallTarget::IpCidr(cidr) if cidr == ip))
    });
    if rules.len() == initial_len {
        return;
    }
    crate::firewall::write_firewall_rules(&rules);
    let report = crate::firewall::reconcile::reconcile_firewall(config);
    if !report.errors.is_empty() {
        eprintln!("[Vandam Cloud] firewall reconcile errors after unblock_ip: {:?}", report.errors);
    }
}

async fn process_cloud_command(cmd: serde_json::Value, heuristics: Arc<HeuristicsEngine>) {
    let Some(action) = cmd.get("action").and_then(|a| a.as_str()) else { return; };
    println!("[Vandam Cloud] Received remote control command: {}", action);
    match action {
        "maintenance_enable" => {
            let duration = cmd.get("duration_minutes").and_then(|d| d.as_u64()).unwrap_or(0);
            let reason = cmd.get("reason").and_then(|r| r.as_str()).unwrap_or("Remote cloud command");
            crate::maintenance::enable_maintenance_mode(duration, reason);
        }
        "maintenance_disable" => {
            crate::maintenance::disable_maintenance_mode();
        }
        "reload_rules" => {
            if let Some(engine) = HEURISTICS_ENGINE.get() {
                if engine.config.reload().is_ok() {
                    let _ = crate::firewall::reconcile::reconcile_firewall(&engine.config);
                }
            }
        }
        "disable_monitoring" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Vandam Cloud] Remote command: Disabling monitoring for PID {}", pid);
                crate::allowlist::get_disabled_monitoring_pids().insert(pid as u32);
            } else if let Some(path) = cmd.get("web_root").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Disabling FIM/monitoring for web root {}", path);
                crate::allowlist::get_disabled_web_roots().insert(path.to_string());
            }
        }
        "enable_monitoring" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Vandam Cloud] Remote command: Re-enabling monitoring for PID {}", pid);
                crate::allowlist::get_disabled_monitoring_pids().remove(&(pid as u32));
            } else if let Some(path) = cmd.get("web_root").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Re-enabling FIM/monitoring for web root {}", path);
                crate::allowlist::get_disabled_web_roots().remove(path);
            }
        }
        "disable_tls" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Vandam Cloud] Remote command: Disabling TLS telemetry decryption/storage for PID {}", pid);
                crate::allowlist::get_disabled_tls_pids().insert(pid as u32);
            }
        }
        "enable_tls" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Vandam Cloud] Remote command: Re-enabling TLS telemetry decryption/storage for PID {}", pid);
                crate::allowlist::get_disabled_tls_pids().remove(&(pid as u32));
            }
        }
        "kill_process" => {
            if let Some(pid) = cmd.get("pid").and_then(|p| p.as_u64()) {
                println!("[Vandam Cloud] Remote command: Killing process ID {}", pid);
                unsafe { libc::kill(pid as i32, libc::SIGKILL); }
            }
        }
        "restore_file" => {
            if let (Some(qp), Some(op)) = (
                cmd.get("quarantine_path").and_then(|p| p.as_str()),
                cmd.get("original_path").and_then(|p| p.as_str()),
            ) {
                println!("[Vandam Cloud] Remote command: Restoring quarantined file {} to {}", qp, op);
                let _ = crate::quarantine::restore_file(qp, op);
            }
        }
        "quarantine_file" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Quarantining file path {}", path);
                let alert_id = uuid::Uuid::new_v4().to_string();
                let _ = crate::quarantine::quarantine_file(
                    path,
                    &alert_id,
                    "Remote-initiated quarantine command from fleet manager",
                    "Threat.Server.FileQuarantined"
                );
            }
        }
        "block_ip" => {
            // Routed through the firewall rule store + reconcile pass
            // (rather than shelling to iptables directly, as this used to)
            // so a cloud-issued block shows up in GET /api/v1/firewall and
            // is enforced consistently across whichever backend(s) are
            // active — previously this was a disconnected code path that
            // never touched firewall_rules.json. Tagged Cloud/locked so the
            // local API refuses to un-block it; only a matching "unblock_ip"
            // command (or the cloud sync in vandam) can remove it.
            if let Some(ip) = cmd.get("ip").and_then(|i| i.as_str()) {
                if std::net::IpAddr::from_str(ip).is_ok() {
                    println!("[Vandam Cloud] Remote command: Blocking IP {} (firewall rule store)", ip);
                    add_cloud_ip_rule(ip, &heuristics.config);
                } else {
                    eprintln!("[Vandam Cloud] Remote command: ignoring block_ip with invalid IP '{}'", ip);
                }
            }
        }
        "unblock_ip" => {
            if let Some(ip) = cmd.get("ip").and_then(|i| i.as_str()) {
                println!("[Vandam Cloud] Remote command: Unblocking IP {} (firewall rule store)", ip);
                remove_cloud_ip_rule(ip, &heuristics.config);
            }
        }
        "trigger_scan" => {
            println!("[Vandam Cloud] Remote command: Triggering OSV vulnerability scan");
            let roots = heuristics.web_roots.clone();
            tokio::spawn(async move {
                for root in roots {
                    let _ = crate::scanner::run_scan(&root).await;
                }
            });
        }
        "sync_rules" | "rules_sync" => {
            println!("[Vandam Cloud] Remote command: Triggering immediate remote rules sync");
            let config_clone = Arc::clone(&heuristics.config);
            tokio::spawn(async move {
                let _ = sync_rules_now(&config_clone).await;
            });
        }
        "push_rules" => {
            if let Some(rules_hex) = cmd.get("rules_hex").and_then(|r| r.as_str()) {
                println!("[Vandam Cloud] Remote command: Received rules push payload over stream.");
                if let Some(bytes) = hex_to_bytes(rules_hex) {
                    match heuristics.config.reload_from_bytes(&bytes) {
                        Ok(_) => {
                            println!("[Vandam Cloud] Rules updated and activated successfully from stream payload.");
                            let _ = crate::firewall::reconcile::reconcile_firewall(&heuristics.config);
                        }
                        Err(e) => {
                            eprintln!("[Vandam Cloud] Failed to load rules pushed over stream: {}", e);
                        }
                    }
                }
            }
        }
        "fim_add" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Adding FIM watch path {}", path);
                let _ = crate::fim::add_fim_watch_path(std::path::PathBuf::from(path));
            }
        }
        "fim_remove" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Removing FIM watch path {}", path);
                let _ = crate::fim::remove_fim_watch_path(std::path::PathBuf::from(path));
            }
        }
        "allowlist_add" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Registering path in allowlist: {}", path);
                crate::allowlist::register_path_recursive(path);
            }
        }
        "allowlist_remove" => {
            if let Some(path) = cmd.get("path").and_then(|p| p.as_str()) {
                println!("[Vandam Cloud] Remote command: Deregistering path from allowlist: {}", path);
                crate::allowlist::deregister_path_recursive(path);
            }
        }
        "sync_inventory" | "inventory_sync" => {
            println!("[Vandam Cloud] Remote command: Triggering immediate inventory sync");
            let heuristics_clone = Arc::clone(&heuristics);
            tokio::spawn(async move {
                send_inventory_sync(&heuristics_clone).await;
            });
        }
        _ => {
            eprintln!("[Vandam Cloud] Unknown remote command action: {}", action);
        }
    }
}

pub async fn send_inventory_sync(heuristics: &HeuristicsEngine) {
    let client = get_client();
    let endpoint = &client.cloud_endpoint;

    let mut containers = Vec::new();
    let mounts = crate::discovery::get_active_container_mounts();
    for entry in mounts.iter() {
        containers.push(serde_json::json!({
            "container_id": entry.key(),
            "mounts": entry.value().iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>()
        }));
    }

    let mut proxies = Vec::new();
    for p in crate::discovery::auto_discover_proxies() {
        proxies.push(serde_json::json!({
            "name": p.name,
            "config_dirs": p.config_dirs.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
            "access_logs": p.access_logs.iter().map(|f| f.to_string_lossy()).collect::<Vec<_>>(),
        }));
    }

    let listening_services = crate::discovery::get_listening_services();

    let mut packages = Vec::new();
    for root in &heuristics.web_roots {
        packages.extend(crate::scanner::get_installed_packages(root));
    }

    let payload = serde_json::json!({
        "event": "host_inventory",
        "web_roots": heuristics.web_roots,
        "proxies": proxies,
        "listening_services": listening_services,
        "containers": containers,
        "packages": packages,
        "tls_forensics": crate::tls_buffer::get_tls_forensics_status(),
    }).to_string();

    if let Some(tx) = GRPC_TX.get() {
        let agent_id = get_or_create_agent_id();
        let license_key = get_or_create_license_key();
        let _ = tx.send(AgentMessage {
            agent_id,
            license_key,
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            payload_json: payload,
            bpf_capacity_pct: 0,
        }).await;
        println!("[Vandam Cloud gRPC] Host inventory successfully synced to fleet manager.");
    }
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 { return None; }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}

fn resolve_incident_file(payload: &crate::notifications::AlertPayload) -> Option<std::path::PathBuf> {
    // 0. Check the real-time telemetry-recorded loaded scripts list for the PID or parent PID
    let pid = payload.process.pid;
    if pid > 0 {
        if let Some(engine) = HEURISTICS_ENGINE.get() {
            if let Some(scripts) = engine.get_loaded_scripts_for_pid(pid) {
                for script in scripts {
                    let p = std::path::PathBuf::from(script);
                    if p.exists() && p.is_file() {
                        return Some(p);
                    }
                }
            }
            let ppid = payload.process.parent_pid;
            if ppid > 0 {
                if let Some(scripts) = engine.get_loaded_scripts_for_pid(ppid) {
                    for script in scripts {
                        let p = std::path::PathBuf::from(script);
                        if p.exists() && p.is_file() {
                            return Some(p);
                        }
                    }
                }
            }
        }
    }

    // 1. If it's a binary execution threat, the executed binary itself is the target
    let exec_path = std::path::PathBuf::from(&payload.process.exec_path);
    
    // Check if the exec_path itself exists and is a file
    if exec_path.exists() && exec_path.is_file() {
        let name_lower = exec_path.to_string_lossy().to_lowercase();
        // If it's not a standard system interpreter/shell, it could be a compiled payload (ELF) or binary itself
        let is_system_interpreter = name_lower.contains("/php") || name_lower.contains("/python") ||
            name_lower.contains("/node") || name_lower.contains("/ruby") ||
            name_lower.contains("/java") || name_lower.contains("/bash") ||
            name_lower.contains("/sh") || name_lower.contains("/dash");
        
        if !is_system_interpreter {
            return Some(exec_path);
        }
    }

    // 2. If the exec_path is a system interpreter, we parse the command line to find the script/jar file
    let cmdline = &payload.process.cmdline;
    let parts: Vec<&str> = cmdline.split_whitespace().collect();
    for part in parts.iter().skip(1) {
        if part.starts_with('-') {
            continue;
        }
        let p = std::path::PathBuf::from(part);
        if p.exists() && p.is_file() {
            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
            if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" {
                return Some(p);
            }
        }
    }

    // 3. Scan active file descriptors in /proc/<pid>/fd/ and memory maps in /proc/<pid>/maps (dynamic load check)
    let pid = payload.process.pid;
    if pid > 0 {
        if let Ok(entries) = std::fs::read_dir(format!("/proc/{}/fd", pid)) {
            for entry in entries.flatten() {
                if let Ok(link) = std::fs::read_link(entry.path()) {
                    if link.is_file() {
                        let ext = link.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
                        if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" {
                            return Some(link);
                        }
                    }
                }
            }
        }
        if let Ok(maps_str) = std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
            for line in maps_str.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(last_part) = parts.last() {
                    if last_part.starts_with('/') {
                        let p = std::path::PathBuf::from(*last_part);
                        if p.is_file() {
                            let ext = p.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
                            if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" {
                                return Some(p);
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Fallback: Parse the alert's remediation status/description for any absolute paths
    let status = &payload.remediation.status;
    let words: Vec<&str> = status.split_whitespace().collect();
    for word in words {
        let cleaned = word.trim_matches(|c| c == ',' || c == '.' || c == '\'' || c == '"' || c == '(' || c == ')');
        if cleaned.starts_with('/') {
            let p = std::path::PathBuf::from(cleaned);
            if p.exists() && p.is_file() {
                let ext = p.extension().and_then(|s| s.to_str()).unwrap_or_default().to_lowercase();
                if ext == "php" || ext == "js" || ext == "py" || ext == "rb" || ext == "jar" || ext == "class" || ext == "elf" {
                    return Some(p);
                }
                if cleaned.contains("quarantine") || cleaned.contains("uploads") || cleaned.contains("/tmp") {
                    return Some(p);
                }
            }
        }
    }

    None
}

pub fn send_alert_immediate(payload: &crate::notifications::AlertPayload) {
    let client = get_client();
    if !client.telemetry_enabled { return; }

    let payload = payload.clone();
    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();

    tokio::spawn(async move {
        if let Some(tx) = GRPC_TX.get() {
            let json_payload = serde_json::to_string(&payload).unwrap_or_default();
            let _ = tx.send(AgentMessage {
                agent_id,
                license_key,
                timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
                payload_json: json_payload,
                bpf_capacity_pct: 0,
            }).await;
        }
    });
}

pub async fn send_heartbeat_ping() -> bool {
    let client = get_client();
    let _endpoint = &client.cloud_endpoint;

    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();
    let heartbeat_payload = serde_json::json!({
        "event": "heartbeat",
        "agent_id": agent_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "maintenance_mode": crate::maintenance::get_maintenance_status(),
        "systemd_watchdog_active": true
    }).to_string();

    if let Some(tx) = GRPC_TX.get() {
        let _ = tx.send(AgentMessage {
            agent_id,
            license_key,
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            payload_json: heartbeat_payload,
            bpf_capacity_pct: 0,
        }).await;
        true
    } else {
        false
    }
}

pub async fn sync_config_from_cloud(config: &Arc<crate::rules::ConfigManager>) -> bool {
    let client_info = get_client();
    let endpoint = &client_info.cloud_endpoint;
    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();

    let url = if endpoint.contains("/api/v1") {
        if let Some(pos) = endpoint.find("/api/v1") { endpoint[..pos].to_string() } else { endpoint.clone() }
    } else {
        endpoint.clone()
    };

    if let Ok(endpoint_conf) = tonic::transport::Endpoint::from_shared(url) {
        let endpoint_conf = endpoint_conf.connect_timeout(Duration::from_secs(10));
        if let Ok(channel) = endpoint_conf.connect().await {
            let mut grpc_client = VandamServiceClient::new(channel);
            let req = proto::ConfigSyncRequest {
                agent_id,
                license_key,
                current_config_hash: String::new(),
            };

            if let Ok(response) = grpc_client.sync_config(req).await {
                let resp = response.into_inner();
                if resp.updated && !resp.config_json.is_empty() {
                    let override_path = std::path::Path::new("/etc/kinnector/override.json");
                    if std::fs::write(override_path, &resp.config_json).is_ok() {
                        if config.reload().is_ok() {
                            let _ = crate::firewall::reconcile::reconcile_firewall(config);
                        }
                        println!("[Vandam Cloud gRPC] Config sync successful. Applied overrides to /etc/kinnector/override.json");
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Transport for firewall rule bidirectional sync — owned by OSS because
/// the gRPC channel/endpoint plumbing (`get_client()`, connection setup)
/// is OSS-private, matching how `send_forensic_payload` gives `vandam`'s
/// `investigate.rs` a building block instead of duplicating gRPC setup
/// there. The *decision* to call this (gated by subscription tier) belongs
/// to Pro — see `vandam/src/firewall_sync.rs`'s `CloudFirewallSync`
/// impl, which is the only caller.
///
/// Returns `Ok(Some(cloud_rules_json))` when the cloud has an updated rule
/// set to apply, `Ok(None)` when the cloud reports nothing new, `Err` on
/// any transport/RPC failure.
pub async fn sync_firewall_rules_with_cloud(local_rules_json: String) -> Result<Option<String>, String> {
    let client_info = get_client();
    let endpoint = &client_info.cloud_endpoint;
    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();

    let url = if endpoint.contains("/api/v1") {
        if let Some(pos) = endpoint.find("/api/v1") { endpoint[..pos].to_string() } else { endpoint.clone() }
    } else {
        endpoint.clone()
    };

    let endpoint_conf = tonic::transport::Endpoint::from_shared(url)
        .map_err(|e| format!("invalid cloud endpoint: {}", e))?
        .connect_timeout(Duration::from_secs(10));
    let channel = endpoint_conf.connect().await.map_err(|e| format!("failed to connect: {}", e))?;

    let mut grpc_client = VandamServiceClient::new(channel);
    let req = proto::FirewallSyncRequest {
        agent_id,
        license_key,
        local_rules_json,
    };

    let response = grpc_client
        .sync_firewall_rules(req)
        .await
        .map_err(|e| format!("SyncFirewallRules RPC failed: {}", e))?;
    let resp = response.into_inner();
    if resp.updated && !resp.cloud_rules_json.is_empty() {
        Ok(Some(resp.cloud_rules_json))
    } else {
        Ok(None)
    }
}

pub async fn push_config_to_cloud() -> bool {
    let client_info = get_client();
    let _endpoint = &client_info.cloud_endpoint;
    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();
    let conf_content = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();

    let push_payload = serde_json::json!({
        "event": "config_push",
        "config_content": conf_content,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }).to_string();

    if let Some(tx) = GRPC_TX.get() {
        let _ = tx.send(AgentMessage {
            agent_id,
            license_key,
            timestamp_ns: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            payload_json: push_payload,
            bpf_capacity_pct: 0,
        }).await;
        true
    } else {
        false
    }
}

pub fn get_or_create_agent_id() -> String {
    let path = Path::new("/var/lib/kinnector/agent_id");
    if let Ok(id) = std::fs::read_to_string(path) {
        let trimmed = id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let new_id = uuid::Uuid::new_v4().to_string();
    let _ = std::fs::create_dir_all("/var/lib/kinnector");
    let _ = std::fs::write(path, &new_id);
    new_id
}

pub fn get_or_create_license_key() -> String {
    let client = get_client();
    if let Some(key) = &client.license_key {
        if !key.is_empty() && key != "free" {
            return key.clone();
        }
    }

    let path = Path::new("/var/lib/kinnector/license_key");
    if let Ok(key) = std::fs::read_to_string(path) {
        let trimmed = key.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let agent_id = get_or_create_agent_id();
    let default_key = format!("community-free-{}", &agent_id[..8.min(agent_id.len())]);
    let _ = std::fs::create_dir_all("/var/lib/kinnector");
    let _ = std::fs::write(path, &default_key);
    default_key
}

pub fn get_distro_info() -> String {
    if let Ok(os_release) = std::fs::read_to_string("/etc/os-release") {
        for line in os_release.lines() {
            if line.starts_with("PRETTY_NAME=") {
                return line.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string();
            }
        }
    }
    "Linux (Unknown Distro)".to_string()
}

pub fn get_kernel_version() -> String {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|k| k.trim().to_string())
        .unwrap_or_else(|_| "Linux 6.x".to_string())
}

pub fn get_lsm_capabilities() -> String {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|l| l.trim().to_string())
        .unwrap_or_else(|_| "capability,bpf".to_string())
}

pub fn get_grub_cmdline() -> String {
    std::fs::read_to_string("/proc/cmdline")
        .map(|c| c.trim().to_string())
        .unwrap_or_default()
}

pub async fn register_agent_with_cloud(heuristics: &Arc<HeuristicsEngine>) -> String {
    let client = get_client();
    let endpoint = &client.cloud_endpoint;

    let agent_id = get_or_create_agent_id();
    let license_key = get_or_create_license_key();
    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_else(|_| "localhost".to_string());

    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let ram_total_gb = if pages > 0 && page_size > 0 {
        ((pages as u64 * page_size as u64) / (1024 * 1024 * 1024)) as u32
    } else {
        0
    };

    // 1. Try gRPC Native Registration RPC
    let url = if endpoint.contains("/api/v1") {
        if let Some(pos) = endpoint.find("/api/v1") { endpoint[..pos].to_string() } else { endpoint.clone() }
    } else {
        endpoint.clone()
    };

    if let Ok(endpoint_conf) = tonic::transport::Endpoint::from_shared(url) {
        let endpoint_conf = endpoint_conf.connect_timeout(Duration::from_secs(5));
        if let Ok(channel) = endpoint_conf.connect().await {
            let mut grpc_client = VandamServiceClient::new(channel);
            let req = proto::RegisterRequest {
                agent_id: agent_id.clone(),
                license_key: license_key.clone(),
                vandam_version: env!("CARGO_PKG_VERSION").to_string(),
                core_version: "1.0.0".to_string(),
                hostname: hostname.clone(),
                distro: get_distro_info(),
                kernel_version: get_kernel_version(),
                lsm_supported: get_lsm_capabilities(),
                grub_cmdline: get_grub_cmdline(),
                ram_total_gb,
            };

            if let Ok(response) = grpc_client.register_agent(req).await {
                let resp = response.into_inner();
                let verdict_str = match resp.verdict() {
                    proto::register_response::Verdict::Allow => "ALLOW",
                    proto::register_response::Verdict::Deny => "DENY",
                    proto::register_response::Verdict::UpdateRequired => "UPDATE_REQUIRED",
                };
                println!("[Vandam Cloud gRPC] Agent Registration Verdict: {}", verdict_str);
                if resp.update_required || verdict_str == "UPDATE_REQUIRED" {
                    println!("[Vandam Cloud gRPC] Update required by Backend. Triggering rule sync...");
                    let _ = sync_rules_now(&heuristics.config).await;
                }
                return verdict_str.to_string();
            }
        }
    }

    "ALLOW".to_string()
}
