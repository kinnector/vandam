use tokio::net::UnixListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use vandam::heuristics::HeuristicsEngine;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct RaspEvent {
    #[serde(rename = "type")]
    event_type: String,
    pid: u32,
    function: String,
    path: String,
    in_request: i32,
    http: Value,
    trace: Value,
    is_install_context: Option<i32>,
    #[serde(default)]
    network_links: Option<Vec<vandam::notifications::NetworkLinkMetadata>>,
    #[serde(default)]
    process_tree: Option<Vec<vandam::notifications::ProcessTreeEntry>>,
    #[serde(default)]
    loaded_scripts: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct PostMortemTrace {
    incident_id: String,
    trace: Value,
}

#[derive(Serialize)]
struct RaspVerdict {
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    incident_id: Option<String>,
}

const BLOCKING_EVENT_TYPES: &[&str] = &["exec_call", "file_read", "file_write", "chmod"];

pub async fn start_rasp_listener(heuristics: Arc<HeuristicsEngine>) {
    let socket_path = "/run/vandam/rasp_telemetry.sock";
    let _ = std::fs::remove_file(socket_path);
    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("[vandam RASP] Failed to bind to {}: {}", socket_path, e);
            return;
        }
    };
    let _ = std::fs::set_permissions(socket_path, std::os::unix::fs::PermissionsExt::from_mode(0o777));
    vandam::heuristics::set_rasp_active(true);
    tracing::info!("[vandam RASP] Active! Listening on {}", socket_path);

    loop {
        match listener.accept().await {
            Ok((mut socket, _addr)) => {
                let engine = Arc::clone(&heuristics);
                let peer_pid = socket.peer_cred().ok().and_then(|cred| cred.pid());
                tokio::spawn(async move {
                    let (read_half, mut write_half) = socket.split();
                    let mut reader = BufReader::new(read_half);
                    let mut line = String::new();

                    while let Ok(bytes_read) = reader.read_line(&mut line).await {
                        if bytes_read == 0 { break; }

                        if let Ok(json_val) = serde_json::from_str::<Value>(&line) {
                            if json_val.get("incident_id").is_some() {
                                if let Ok(pm) = serde_json::from_value::<PostMortemTrace>(json_val) {
                                    tracing::warn!("[vandam RASP] Post-Mortem Trace for Incident {}: {}", pm.incident_id, pm.trace);
                                }
                            } else if let Ok(mut event) = serde_json::from_value::<RaspEvent>(json_val) {
                                event.network_links = Some(vandam::link_tracker::get_process_network_links(event.pid));
                                event.process_tree = Some(engine.build_origin_tree(event.pid));
                                event.loaded_scripts = engine.get_loaded_scripts_for_pid(event.pid);

                                let is_blocking = BLOCKING_EVENT_TYPES.contains(&event.event_type.as_str());
                                // Already sent by every RASP client (see vandam-php's vandam_rasp.c) on
                                // every event — just wasn't being read into an alert before.
                                let site = event.http.get("http_host")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.to_string());

                                if is_blocking {
                                    let is_malicious = evaluate_oss_rules(&event, &engine);
                                    let verdict = if is_malicious { "deny" } else { "allow" };
                                    let incident_id = if is_malicious { Some(uuid::Uuid::new_v4().to_string()) } else { None };
                                    if is_malicious {
                                        tracing::warn!("[vandam RASP] BLOCKED: PID {} called {} with '{}'", event.pid, event.function, event.path);
                                        dispatch_rasp_blocked_alert(&engine, event.pid, &event.function, &event.path, event.trace.clone(), site);
                                    }
                                    let response = serde_json::to_string(&RaspVerdict { verdict: verdict.to_string(), incident_id }).unwrap() + "\n";
                                    let _ = write_half.write_all(response.as_bytes()).await;
                                } else {
                                    // F&F: forward to Pro LLM pipeline
                                    tracing::debug!("[vandam RASP] F&F event: {} -> {}", event.event_type, event.function);
                                    dispatch_in_memory_execution_alert(&engine, event.pid, &event.function, &event.path, event.trace.clone(), site);
                                }
                            } else {
                                tracing::error!("[vandam RASP] Failed to parse event: {}", line);
                            }
                        } else {
                            tracing::error!("[vandam RASP] Invalid JSON: {}", line);
                        }
                        line.clear();
                    }

                    // Connection severed check
                    if let Some(pid) = peer_pid {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                            tracing::warn!("[vandam RASP] Process {} still alive but RASP connection severed!", pid);
                            let mut exe = String::new();
                            let mut cmd = String::new();
                            let mut ppid = 0u32;
                            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                                let parts: Vec<&str> = stat.split_whitespace().collect();
                                if parts.len() >= 4 { ppid = parts[3].parse().unwrap_or(0); }
                            }
                            if let Ok(l) = std::fs::read_link(format!("/proc/{}/exe", pid)) { exe = l.to_string_lossy().to_string(); }
                            if let Ok(c) = std::fs::read_to_string(format!("/proc/{}/cmdline", pid)) { cmd = c.replace('\0', " ").trim().to_string(); }
                            engine.emit_threat_with_id(
                                uuid::Uuid::new_v4().to_string(),
                                pid as u32, &exe, &cmd, "", ppid,
                                "Warning.RASP.EngineDisabled",
                                &format!("RASP connection for process {} severed while process is still alive.", pid)
                            );
                        }
                    }
                });
            }
            Err(e) => { tracing::error!("[vandam RASP] Accept error: {}", e); }
        }
    }
}

/// Resolves a pid to (exe, cmdline, parent_exe, parent_pid) via the OSS
/// engine's process map, falling back to a raw /proc read — same lookup
/// vandam's own alert-reporting helpers use internally.
fn resolve_process_identity(engine: &HeuristicsEngine, pid: u32, fallback_cmdline: &str) -> (String, String, String, u32) {
    if let Some(proc) = engine.process_map.get(&pid) {
        let (p_exe, p_pid) = if let Some(parent) = engine.process_map.get(&proc.ppid) {
            (parent.exe.clone(), parent.pid)
        } else {
            (String::new(), proc.ppid)
        };
        (proc.exe.clone(), proc.cmdline.clone(), p_exe, p_pid)
    } else {
        let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| "php".to_string());
        (exe, fallback_cmdline.to_string(), String::new(), 0)
    }
}

/// Builds and dispatches an AlertPayload for an in-memory (fire-and-forget)
/// RASP event. Site-tagging (from the RASP client's self-reported host) and
/// the paid-tier gate on that attribution are Pro-only concerns — see
/// CLAUDE.md's "OSS / Pro separation" — so this whole payload is assembled
/// here rather than in vandam's OSS-owned heuristics.rs.
fn dispatch_in_memory_execution_alert(engine: &Arc<HeuristicsEngine>, pid: u32, function: &str, code: &str, trace: Value, site: Option<String>) {
    let (exe, cmdline, parent_exe, parent_pid) = resolve_process_identity(engine, pid, "in-memory eval");

    let snippet = if code.len() > 120 { &code[..120] } else { code };
    let desc = format!("In-memory dynamic code execution detected via RASP ({}): '{}'", function, snippet);
    let web_root = engine.web_roots.first().map(|s| s.as_str()).unwrap_or("/var/www/html");
    let rich_ctx = vandam::discovery::build_rich_rasp_context(pid, function, "", web_root, trace);

    let alert_id = uuid::Uuid::new_v4().to_string();
    vandam::tls_buffer::flush_on_alert(pid, &alert_id);

    let payload = vandam::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Threat.Server.InMemoryCode".to_string(),
        severity: "CRITICAL".to_string(),
        confidence: 0.90,
        container: engine.resolve_container_info(pid),
        process: vandam::notifications::ProcessInfo {
            pid,
            exec_path: exe.clone(),
            cmdline,
            parent_exec_path: parent_exe,
            parent_pid,
            verified_package: Some(vandam::allowlist::verify_system_package_binary(&exe)),
            envs: Vec::new(),
            args: Vec::new(),
                    signature_name: None,
            service: None,
},
        remediation: vandam::notifications::RemediationInfo {
            action: "LOG_ALERT".to_string(),
            status: desc,
            requires_cloud_decision: false,
                    quarantine: None,
},
        rasp_context: Some(rich_ctx),
        origin_tree: engine.build_origin_tree(pid),
        network_links: vandam::link_tracker::get_process_network_links(pid),
        container_meta: engine.build_container_meta(pid),
        // PHP/RASP site attribution is a base Pro-binary capability, not
        // gated behind an active subscription — you already get it just by
        // running Pro, licensed or not. Only the surrounding forensic detail
        // (rasp_context above) requires a paid tier — see get_alerts() in
        // vandam/src/api.rs. site_source is ClientReported since this came
        // straight from the RASP client's http_host, no inference involved.
        site_source: site.as_ref().map(|_| vandam::notifications::SiteSource::ClientReported),
        site,
            event_detail: None,
};
    vandam::notifications::dispatch_alert(payload);
}

/// Builds and dispatches an AlertPayload for a blocking RASP event. See
/// `dispatch_in_memory_execution_alert` — same reasoning for why this lives
/// in vandam rather than vandam.
fn dispatch_rasp_blocked_alert(engine: &Arc<HeuristicsEngine>, pid: u32, function: &str, path: &str, trace: Value, site: Option<String>) {
    let (exe, cmdline, parent_exe, parent_pid) = resolve_process_identity(engine, pid, "rasp blocked call");

    let desc = format!("Synchronous execution of {}('{}') BLOCKED by RASP engine", function, path);
    let web_root = engine.web_roots.first().map(|s| s.as_str()).unwrap_or("/var/www/html");
    let rich_ctx = vandam::discovery::build_rich_rasp_context(pid, function, "", web_root, trace);

    let alert_id = uuid::Uuid::new_v4().to_string();
    vandam::tls_buffer::flush_on_alert(pid, &alert_id);

    let payload = vandam::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Threat.Server.RaspBlocked".to_string(),
        severity: "CRITICAL".to_string(),
        confidence: 1.0,
        container: engine.resolve_container_info(pid),
        process: vandam::notifications::ProcessInfo {
            pid,
            exec_path: exe.clone(),
            cmdline,
            parent_exec_path: parent_exe,
            parent_pid,
            verified_package: Some(vandam::allowlist::verify_system_package_binary(&exe)),
            envs: Vec::new(),
            args: Vec::new(),
                    signature_name: None,
            service: None,
},
        remediation: vandam::notifications::RemediationInfo {
            action: "BLOCKED_BY_RASP".to_string(),
            status: desc,
            requires_cloud_decision: false,
                    quarantine: None,
},
        rasp_context: Some(rich_ctx),
        origin_tree: engine.build_origin_tree(pid),
        network_links: vandam::link_tracker::get_process_network_links(pid),
        container_meta: engine.build_container_meta(pid),
        // PHP/RASP site attribution is a base Pro-binary capability, not
        // gated behind an active subscription — you already get it just by
        // running Pro, licensed or not. Only the surrounding forensic detail
        // (rasp_context above) requires a paid tier — see get_alerts() in
        // vandam/src/api.rs. site_source is ClientReported since this came
        // straight from the RASP client's http_host, no inference involved.
        site_source: site.as_ref().map(|_| vandam::notifications::SiteSource::ClientReported),
        site,
            event_detail: None,
};
    vandam::notifications::dispatch_alert(payload);
}

fn evaluate_oss_rules(event: &RaspEvent, heuristics: &Arc<HeuristicsEngine>) -> bool {
    let path = event.path.clone();
    let mut is_server_context = false;

    if let Some(proc) = heuristics.process_map.get(&event.pid) {
        is_server_context = proc.is_listening_server;
        if proc.is_database && event.event_type == "exec_call" { return true; }
    }

    if event.event_type == "exec_call" && is_server_context {
        let path_lower = path.to_lowercase();
        if heuristics.system_shells.contains(&path)
            || heuristics.system_shells.contains(&path_lower)
            || heuristics.system_shells.iter().any(|s| path.ends_with(s.as_str()))
        {
            return true;
        }
        if heuristics.config.is_protected_binary(&path) { return true; }
        let is_system_path = path.starts_with("/bin/") || path.starts_with("/sbin/")
            || path.starts_with("/usr/bin/") || path.starts_with("/usr/sbin/")
            || path.starts_with("/usr/local/bin/") || path.starts_with("/usr/libexec/")
            || path.starts_with("/lib/") || path.starts_with("/lib64/")
            || path.starts_with("/usr/lib/") || path.starts_with("/usr/lib64/");
        if !is_system_path && !vandam::allowlist::is_inode_allowed_for_process(&path, &heuristics.web_roots) {
            return true;
        }
    }

    if (event.event_type == "file_read" || event.event_type == "file_write") && is_server_context {
        if !path.starts_with("/proc/") && !path.starts_with("/dev/") && !path.starts_with("/sys/") {
            if !vandam::allowlist::is_system_tmp_path(&path) {
                if !vandam::allowlist::is_inode_allowed_for_process(&path, &heuristics.web_roots) {
                    return true;
                }
            }
        }
    }

    false
}
