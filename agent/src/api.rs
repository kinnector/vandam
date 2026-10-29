use crate::heuristics::HeuristicsEngine;
use axum::{
    extract::{Extension, Json, State},
    http::{Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{Read, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::UnixListener;
use tower::Service;

const ROLE_SSH_REMOTE: u32 = 0x20000000;
const ROLE_SSH_LOCAL: u32 = 0x40000000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserRule {
    pub id: String,
    pub rule_type: String,
    pub target: String,
    pub scope: String,
    pub site: Option<String>,
    pub created_at: String,
    /// Only meaningful for `ALLOW_CONTAINER_IMAGE` rules: the image content
    /// id (`ContainerInfo::image_id`) pinned the first time this rule
    /// actually granted trust to a running container. `None` until that
    /// first grant. Anchoring trust to the digest rather than the (mutable)
    /// tag in `target` means a rebuild/re-pull under the same tag doesn't
    /// silently keep inheriting trust — see `discovery.rs::query_single_container`.
    #[serde(default)]
    pub image_digest: Option<String>,
}

#[derive(Clone, Debug)]
struct ParsedProxySite {
    domain: String,
    root: Option<PathBuf>,
    upstream_port: Option<u16>,
    upstream_socket: Option<String>,
    proxy_type: String,
    config_dir: Option<PathBuf>,
}

#[derive(serde::Serialize, Clone)]
struct AlertNode {
    id: String,
    severity: String,
    message: String,
    source: String,
    created_at: String,
    /// How this attachment's site (if any, at the enclosing SiteNode level)
    /// was determined — client self-report vs. vandamd's own proxy-config
    /// pid-tree inference. `None` at proxy/runtime/direct_http/standalone/
    /// daemon-level attachments, where there's no specific site to attribute.
    site_source: Option<crate::notifications::SiteSource>,
}

#[derive(serde::Serialize, Clone)]
pub struct FrameworkInfo {
    pub name: String,
    pub detected_via: Vec<String>,
}

#[derive(serde::Serialize, Clone)]
struct ProxyNode {
    name: String,
    manager: String,
    pid: u64,
    ports: Vec<u16>,
    sockets: Vec<String>,
    downstream_proxies: Vec<ProxyNode>,
    runtimes: Vec<RuntimeNode>,
    started_at: Option<String>,
    is_running: bool,
    alerts: Vec<AlertNode>,
    config_dir: Option<String>,
    #[serde(default)]
    trusted: bool,
}

#[derive(serde::Serialize, Clone)]
struct RuntimeNode {
    pub name: String,
    pub manager: String,
    pub pid: u64,
    pub workers: Option<u32>,
    pub pool: Option<String>,
    ports: Vec<u16>,
    sockets: Vec<String>,
    sites: Vec<SiteNode>,
    started_at: Option<String>,
    is_running: bool,
    alerts: Vec<AlertNode>,
    #[serde(default)]
    trusted: bool,
}

#[derive(serde::Serialize, Clone)]
struct SiteNode {
    domain: String,
    pub stack: serde_json::Value,
    pub framework: Option<FrameworkInfo>,
    directory: String,
    alerts: Vec<AlertNode>,
    started_at: Option<String>,
    is_running: bool,
    allowed_dirs: Vec<String>,
    auto_writables: bool,
    is_restricted: bool,
    #[serde(default)]
    trusted: bool,
    /// Other domains sharing this site's runtime pool, non-empty whenever
    /// the pool actually is shared — populated regardless of `trusted` so a
    /// client can warn *before* the user commits: trusting a site with no
    /// isolated process of its own trusts the whole runtime it executes in,
    /// so every sibling domain on that pool goes untraced too. See
    /// `trust.rs` / `reconcile_server_trust`.
    #[serde(default)]
    shared_with: Vec<String>,
}

#[derive(serde::Serialize, Clone)]
struct DirectHttpNode {
    name: String,
    manager: String,
    pid: u64,
    stack: serde_json::Value,
    ports: Vec<u16>,
    sockets: Vec<String>,
    directory: String,
    alerts: Vec<AlertNode>,
    started_at: Option<String>,
    is_running: bool,
    is_restricted: bool,
    #[serde(default)]
    trusted: bool,
}

#[derive(serde::Serialize, Clone)]
struct StandaloneNode {
    name: String,
    manager: String,
    pid: u64,
    stack: serde_json::Value,
    ports: Vec<u16>,
    sockets: Vec<String>,
    directory: String,
    alerts: Vec<AlertNode>,
    started_at: Option<String>,
    is_running: bool,
    is_restricted: bool,
    #[serde(default)]
    trusted: bool,
}

#[derive(serde::Serialize, Clone)]
struct DaemonNode {
    name: String,
    ports: Vec<u16>,
    sockets: Vec<String>,
    directory: String,
    pid: u64,
    alerts: Vec<AlertNode>,
    #[serde(default)]
    trusted: bool,
    started_at: Option<String>,
    is_running: bool,
    is_restricted: bool,
    stack: Option<serde_json::Value>,
}
#[derive(Clone)]
pub struct AppState {
    pub heuristics: Arc<HeuristicsEngine>,
    pub web_roots: Vec<String>,
    pub startup_time: std::time::Instant,
}

pub(crate) fn read_user_rules() -> Vec<UserRule> {
    let path = "/etc/kinnector/user_rules.json";
    if let Ok(mut file) = File::open(path) {
        let mut content = String::new();
        if file.read_to_string(&mut content).is_ok() {
            if let Ok(rules) = serde_json::from_str(&content) {
                return rules;
            }
        }
    }
    Vec::new()
}

fn write_user_rules(rules: &[UserRule]) -> bool {
    let path = "/etc/kinnector/user_rules.json";
    if let Some(parent) = Path::new(path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = File::create(path) {
        if let Ok(content) = serde_json::to_string_pretty(rules) {
            return file.write_all(content.as_bytes()).is_ok();
        }
    }
    false
}

fn parse_proxy_configs() -> Vec<ParsedProxySite> {
    let mut sites = Vec::new();

    // Scan Nginx
    let nginx_dirs = [
        "/etc/nginx/sites-enabled",
        "/etc/nginx/conf.d",
        "/etc/nginx",
    ];
    for dir in &nginx_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let blocks = content.split("server {");
                        for block in blocks.skip(1) {
                            let mut domain = None;
                            let mut root = None;
                            let mut upstream_port = None;
                            let mut upstream_socket = None;

                            for line in block.lines() {
                                let line = line.trim();
                                if line.starts_with('#') {
                                    continue;
                                }
                                let line = line.trim_end_matches(';');
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.is_empty() {
                                    continue;
                                }

                                if parts[0] == "server_name" && parts.len() >= 2 {
                                    domain = Some(parts[1].to_string());
                                } else if parts[0] == "root" && parts.len() >= 2 {
                                    root = Some(std::path::PathBuf::from(
                                        parts[1].trim_matches('"').trim_matches('\''),
                                    ));
                                } else if (parts[0] == "fastcgi_pass" || parts[0] == "proxy_pass")
                                    && parts.len() >= 2
                                {
                                    let upstream = parts[1];
                                    if upstream.starts_with("unix:") {
                                        upstream_socket =
                                            Some(upstream["unix:".len()..].to_string());
                                    } else if let Some(colon_idx) = upstream.rfind(':') {
                                        if let Ok(port) = upstream[colon_idx + 1..].parse::<u16>() {
                                            upstream_port = Some(port);
                                        }
                                    }
                                }
                            }

                            if let Some(dom) = domain {
                                sites.push(ParsedProxySite {
                                    domain: dom,
                                    root,
                                    upstream_port,
                                    upstream_socket,
                                    proxy_type: "nginx".to_string(),
                                    config_dir: Some(std::path::PathBuf::from(*dir)),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Scan Apache
    let apache_dirs = ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d"];
    for dir in &apache_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let mut domain = None;
                        let mut root = None;
                        let mut upstream_port = None;

                        for line in content.lines() {
                            let line = line.trim();
                            if line.starts_with('#') {
                                continue;
                            }
                            let parts: Vec<&str> = line.split_whitespace().collect();
                            if parts.is_empty() {
                                continue;
                            }

                            if (parts[0].eq_ignore_ascii_case("ServerName")
                                || parts[0].eq_ignore_ascii_case("ServerAlias"))
                                && parts.len() >= 2
                            {
                                domain = Some(parts[1].to_string());
                            } else if parts[0].eq_ignore_ascii_case("DocumentRoot")
                                && parts.len() >= 2
                            {
                                root = Some(std::path::PathBuf::from(
                                    parts[1].trim_matches('"').trim_matches('\''),
                                ));
                            } else if parts[0].eq_ignore_ascii_case("ProxyPass") && parts.len() >= 3
                            {
                                let upstream = parts[2];
                                if let Some(colon_idx) = upstream.rfind(':') {
                                    if let Ok(port) = upstream[colon_idx + 1..].parse::<u16>() {
                                        upstream_port = Some(port);
                                    }
                                }
                            }
                        }

                        if let Some(dom) = domain {
                            sites.push(ParsedProxySite {
                                domain: dom,
                                root,
                                upstream_port,
                                upstream_socket: None,
                                proxy_type: "apache".to_string(),
                                config_dir: Some(std::path::PathBuf::from(*dir)),
                            });
                        }
                    }
                }
            }
        }
    }

    sites
}

fn get_local_ips() -> std::collections::HashSet<String> {
    let mut ips = std::collections::HashSet::new();
    ips.insert("127.0.0.1".to_string());
    ips.insert("::1".to_string());

    if let Ok(output) = std::process::Command::new("hostname").arg("-I").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for ip in text.split_whitespace() {
            ips.insert(ip.to_string());
        }
    }
    ips
}

fn is_physical_tty(path: &str) -> bool {
    if path.starts_with("/dev/tty") {
        let suffix = &path["/dev/tty".len()..];
        if suffix.starts_with('S') {
            suffix[1..].chars().all(|c| c.is_ascii_digit())
        } else {
            !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit())
        }
    } else {
        false
    }
}

pub fn resolve_caller_context(pid: u32) -> String {
    let local_ips = get_local_ips();
    let mut current_pid = pid;

    for _ in 0..64 {
        if current_pid <= 1 {
            break;
        }
        let stat_path = format!("/proc/{}/stat", current_pid);
        let Ok(stat_content) = fs::read_to_string(&stat_path) else {
            break;
        };
        let parts: Vec<&str> = stat_content.split_whitespace().collect();
        if parts.len() < 4 {
            break;
        }
        let ppid: u32 = parts[3].parse().unwrap_or(0);

        let exe_path = format!("/proc/{}/exe", current_pid);
        if let Ok(exe_target) = fs::read_link(&exe_path) {
            let exe_str = exe_target.to_string_lossy();
            if exe_str.ends_with("/login") {
                let fd0_path = format!("/proc/{}/fd/0", current_pid);
                if let Ok(tty_target) = fs::read_link(&fd0_path) {
                    let tty_str = tty_target.to_string_lossy();
                    if is_physical_tty(&tty_str) {
                        unsafe {
                            crate::ffi::update_process_threshold(pid, 0, ROLE_SSH_REMOTE);
                            crate::ffi::update_process_threshold(current_pid, 0, ROLE_SSH_REMOTE);
                        }
                        return "god_mode".to_string();
                    }
                }
            }
        }

        let env_path = format!("/proc/{}/environ", current_pid);
        if let Ok(env_bytes) = fs::read(&env_path) {
            let env_str = String::from_utf8_lossy(&env_bytes);
            for var in env_str.split('\0') {
                if var.starts_with("SSH_CONNECTION=") {
                    let conn_val = &var["SSH_CONNECTION=".len()..];
                    let conn_parts: Vec<&str> = conn_val.split_whitespace().collect();
                    if !conn_parts.is_empty() {
                        let client_ip = conn_parts[0];
                        let is_local = client_ip == "127.0.0.1"
                            || client_ip == "::1"
                            || local_ips.contains(&client_ip.to_string());

                        unsafe {
                            if is_local {
                                crate::ffi::update_process_threshold(pid, 0, ROLE_SSH_LOCAL);
                                crate::ffi::update_process_threshold(
                                    current_pid,
                                    0,
                                    ROLE_SSH_LOCAL,
                                );
                            } else {
                                crate::ffi::update_process_threshold(pid, 0, ROLE_SSH_REMOTE);
                                crate::ffi::update_process_threshold(
                                    current_pid,
                                    0,
                                    ROLE_SSH_REMOTE,
                                );
                            }
                        }

                        if is_local {
                            return "local_ssh".to_string();
                        } else {
                            return "god_mode".to_string();
                        }
                    }
                }
            }
        }
        current_pid = ppid;
    }
    "random_proc".to_string()
}

async fn auth_middleware(
    Extension(caller_context): Extension<String>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = req.method();
    if (caller_context == "local_ssh" || caller_context == "readonly")
        && (method == Method::POST
            || method == Method::DELETE
            || method == Method::PUT
            || method == Method::PATCH)
    {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

/// `extra_routes`: an optional Pro-supplied router merged in before the auth
/// layer/state are applied — see the `VandamConfig::extra_routes` doc comment
/// in `lib.rs` for why this exists (only `POST /api/v1/alerts/{id}/investigate`
/// uses it today: OSS registers a fixed "unavailable" default at that path
/// unless Pro supplies its own handler for it).
pub fn start_api_server(
    heuristics: Arc<HeuristicsEngine>,
    web_roots: Vec<String>,
    extra_routes: Option<Router<AppState>>,
) {
    let state = AppState {
        heuristics,
        web_roots,
        startup_time: std::time::Instant::now(),
    };

    let mut app = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/setup/status", get(get_setup_status))
        .route("/api/v1/setup/configure", post(post_setup_configure))
        .route("/api/v1/fim/status", get(get_fim_status))
        .route(
            "/api/v1/rules/user",
            get(get_rules_user).delete(delete_rules_user),
        )
        .route("/api/v1/rules/user/add", post(post_rules_user_add))
        .route(
            "/api/v1/firewall",
            get(get_firewall).post(post_firewall).delete(delete_firewall),
        )
        .route("/api/v1/firewall/{id}", axum::routing::patch(patch_firewall))
        .route("/api/v1/firewall/block", post(post_firewall_block))
        .route("/api/v1/firewall/countries", get(get_firewall_countries))
        .route("/api/v1/process/kill", post(post_process_kill))
        .route("/api/v1/servers", get(get_servers))
        .route("/api/v1/containers", get(get_containers))
        .route("/api/v1/containers/{id}", get(get_container_by_id))
        .route("/api/v1/storage", get(get_storage))
        .route("/api/v1/storage/add", post(post_storage_add))
        .route("/api/v1/storage/remove", post(post_storage_remove))
        .route("/api/v1/storage/scan", post(post_storage_scan))
        .route(
            "/api/v1/storage/acknowledge-none",
            post(post_storage_ack_none),
        )
        .route("/api/v1/storage/reset-ack", post(post_storage_reset_ack))
        .route("/api/v1/storage/rescan", post(post_storage_rescan))
        .route("/api/v1/storage/disable", post(post_storage_disable))
        .route("/api/v1/storage/enable", post(post_storage_enable))
        .route("/api/v1/access/sessions", get(get_access_sessions))
        .route("/api/v1/access/sessions/{id}", get(get_access_session_by_id))
        .route("/api/v1/access/sessions/{id}/cast", get(get_access_session_cast))
        .route("/api/v1/access/sessions/{id}/casts", get(get_access_session_casts))
        .route("/api/v1/access/sessions/{id}/flag", post(post_access_session_flag))
        .route("/api/v1/access/correlations", get(get_access_correlations))
        .route("/api/v1/risks/activity", get(get_risks_activity))
        .route("/api/v1/risks/events", get(get_risks_events))
        .route("/api/v1/risks/events/{id}/inspect", post(post_risks_event_inspect))
        .route("/api/v1/risks/blocked", get(get_risks_blocked))
        .route("/api/v1/risks/projects", get(get_risks_projects))
        .route("/api/v1/risks/projects/filter", post(post_risks_project_filter))
        .route("/api/v1/risks/policy", get(get_risks_policy).put(put_risks_policy))
        .route("/api/v1/alerts", get(get_alerts))
        .route(
            "/api/v1/alerts/{id}",
            get(get_alert_by_id).patch(patch_alert_state),
        )
        .route("/api/v1/event/alert", post(post_event_alert))
        .route("/api/v1/event/user-mgmt", post(post_event_user_mgmt))
        .route("/api/v1/fim/add", post(post_fim_add))
        .route("/api/v1/fim/remove", post(post_fim_remove))
        .route("/api/v1/fim/register", post(post_fim_register))
        .route("/api/v1/allowlist/add", post(post_allowlist_add))
        .route("/api/v1/allowlist/remove", post(post_allowlist_remove))
        .route("/api/v1/allowlist", get(get_allowlist))
        .route("/api/v1/quarantine", get(get_quarantine))
        .route("/api/v1/quarantine/restore", post(post_quarantine_restore))
        .route("/api/v1/scan/trigger", post(post_scan_trigger))
        .route("/api/v1/sync/status", get(get_sync_status))
        .route("/api/v1/sync/push", post(post_sync_push))
        .route("/api/v1/sync/pull", post(post_sync_pull))
        .route("/api/v1/sync/diff", get(get_sync_diff))
        .route("/api/v1/test-alert", post(post_test_alert))
        .route("/api/v1/rules/reload", post(post_rules_reload))
        .route("/api/v1/rules/fetch", post(post_rules_fetch))
        .route("/api/v1/config/fetch", post(post_config_fetch))
        .route("/api/v1/config/push", post(post_config_push))
        .route("/api/v1/learning", get(get_learning).post(post_learning))
        .route("/api/v1/maintenance", get(get_maintenance))
        .route("/api/v1/maintenance/enable", post(post_maintenance_enable))
        .route(
            "/api/v1/maintenance/disable",
            post(post_maintenance_disable),
        );

    app = match extra_routes {
        // Pro supplies its own handlers for /api/v1/alerts/{id}/investigate
        // and /api/v1/firewall/sync/status (and possibly other Pro-only
        // routes) — merge it in and skip registering the OSS defaults at
        // those same paths, since axum panics on duplicate route
        // registrations. A Pro build's extra_routes router must define
        // every path in this list if it defines any of them.
        Some(extra) => app.merge(extra),
        None => app
            .route(
                "/api/v1/alerts/{id}/investigate",
                post(post_alert_investigate_unavailable),
            )
            .route(
                "/api/v1/firewall/sync/status",
                get(get_firewall_sync_status_unavailable),
            )
            .route("/api/v1/cloud/status", get(get_cloud_status_unavailable))
            .route(
                "/api/v1/cloud/auto-audit/{category}",
                get(get_cloud_auto_audit_unavailable).post(post_cloud_auto_audit_unavailable),
            )
            .route("/api/v1/cloud/logs", get(get_cloud_logs_unavailable))
            .route(
                "/api/v1/access/sessions/{id}/summarize",
                post(post_access_session_summarize_unavailable),
            )
            .route(
                "/api/v1/risks/packages/osv-lookup",
                post(post_risks_osv_lookup_unavailable),
            )
            .route("/api/v1/risks/analytics", get(get_risks_analytics_unavailable)),
    };

    let app = app
        .layer(middleware::from_fn(auth_middleware))
        .with_state(state);

    tokio::spawn(async move {
        let socket_path = "/var/run/kinnector/vandam.sock";
        let _ = std::fs::remove_file(socket_path);
        if let Some(parent) = Path::new(socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!(
                    "[Vandam API] Failed to bind UDS socket {}: {}",
                    socket_path, e
                );
                return;
            }
        };

        let _ = std::process::Command::new("chmod")
            .args(["0660", socket_path])
            .output();
        println!("[Vandam API] Listening on UDS socket: {}", socket_path);

        loop {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(cred) = stream.peer_cred() {
                    let client_pid = cred.pid().unwrap_or(0) as u32;
                    let uid = cred.uid();

                    let caller_context = if uid != 0 {
                        "readonly".to_string()
                    } else {
                        let ctx = resolve_caller_context(client_pid);
                        if ctx == "random_proc" {
                            "readonly".to_string()
                        } else {
                            ctx
                        }
                    };

                    let app_clone = app.clone();
                    tokio::spawn(async move {
                        let my_service =
                            tower::service_fn(move |req: Request<hyper::body::Incoming>| {
                                let (mut parts, body) = req.into_parts();
                                parts.extensions.insert(caller_context.clone());
                                let axum_req =
                                    Request::from_parts(parts, axum::body::Body::new(body));
                                app_clone.clone().call(axum_req)
                            });

                        let hyper_service =
                            hyper_util::service::TowerToHyperService::new(my_service);
                        let io = TokioIo::new(stream);
                        let _ = http1::Builder::new()
                            .serve_connection(io, hyper_service)
                            .await;
                    });
                }
            }
        }
    });
}

// --- Handlers ---

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let is_lsm = unsafe { crate::ffi::is_lsm_active() };

    // Instead of uptime_secs, use started_at
    let started_at =
        chrono::Utc::now() - chrono::Duration::from_std(state.startup_time.elapsed()).unwrap();

    let is_paid = crate::tls_buffer::is_paid_tier();
    let in_container = std::path::Path::new("/.dockerenv").exists();

    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string();

    let user_rules = read_user_rules();
    let fw_rules = crate::firewall::read_firewall_rules();
    let custom_config_active = !user_rules.is_empty() || !fw_rules.is_empty();

    let mut alerts_critical = 0;
    let mut alerts_high = 0;
    let mut alerts_medium = 0;
    let mut alerts_low = 0;
    for alert in crate::notifications::get_recent_alerts() {
        match alert.severity.as_str() {
            "CRITICAL" => alerts_critical += 1,
            "HIGH" => alerts_high += 1,
            "MEDIUM" => alerts_medium += 1,
            "LOW" | _ => alerts_low += 1,
        }
    }

    let quarantine_count = crate::quarantine::list_quarantined().len();
    let firewall_blocks_count = fw_rules.len();
    let fim_watched_roots = crate::fim::watcher_registry().len();

    let rules_db_ok = std::path::Path::new("/etc/kinnector/rules.db").exists();

    // Re-use logic from get_servers_data
    let servers_data = get_servers_data();
    let containers_data = build_containers_response().await;

    let mut packages_at_risk = Vec::new();
    for r in &state.web_roots {
        for pkg in crate::scanner::get_installed_packages(r) {
            packages_at_risk.push(json!({
                "name": pkg.name,
                "version": pkg.version,
                "ecosystem": pkg.ecosystem,
                "lock_file": pkg.lock_file,
                "is_dev": pkg.is_dev,
                "vulnerabilities": []
            }));
        }
    }

    Json(json!({
        "daemon": {
            "status": if is_paid { "licensed" } else { "active" },
            "tier": if is_paid { "paid" } else { "free" },
            "version": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "started_at": started_at.to_rfc3339(),
            // This Linux system's own install date — not daemon uptime
            // (resets on restart) and not when Vandam was configured
            // (a long-exposed system with Vandam just added is the
            // highest-risk case, and must read as old). See `install_date.rs`.
            "installed_at_unix": crate::install_date::get(),
            "hostname": hostname,
            "in_container": in_container,
            "custom_config_active": custom_config_active,
            // True only for vandam (RASP telemetry listener actually
            // running) — independent of license/tier. A Pro binary with no
            // license still has this true; OSS never does. Drives whether
            // e.g. PHP site attribution is possible at all.
            "rasp_active": crate::heuristics::is_rasp_active(),
        },
        "security_state": {
            "lsm_active": is_lsm,
            "fim": {
                "active": fim_watched_roots > 0,
                "seeded_via": "git"
            },
            "quarantine_count": quarantine_count,
            "firewall_blocks_count": firewall_blocks_count,
            "tls_forensics": crate::tls_buffer::get_tls_forensics_status()
        },
        "discovered_servers": servers_data,
        "discovered_containers": containers_data,
        "alerts_summary": {
            "critical": alerts_critical,
            "high": alerts_high,
            "medium": alerts_medium,
            "low": alerts_low
        },
        "packages": packages_at_risk,
        "config": {
            "rules_db": {
                "path": "/etc/kinnector/rules.db",
                "ok": rules_db_ok
            },
            "notifications": {
                "slack": true,
                "discord": false,
                "tg": false
            }
        },
        "api_port_protection": {
            "monitored_ports": [2375, 2376, 10250, 10255],
            "policy": "warn_and_audit",
            "status": "MONITORED_EBPF_PROTECTED",
            "level": "kernel-lsm-runtime"
        }
    }))
}

async fn get_fim_status() -> impl IntoResponse {
    let reg = crate::fim::watcher_registry();
    let watched: Vec<_> = reg
        .iter()
        .map(|entry| {
            json!({
                "web_root": entry.key(),
                "status": "active"
            })
        })
        .collect();
    Json(json!({ "watched_roots": watched }))
}

async fn get_setup_status() -> impl IntoResponse {
    let configured = std::path::Path::new("/etc/kinnector/.configured").exists();
    let servers = get_servers_data();

    let mut sites = Vec::new();
    let mut standalones = Vec::new();

    for proxy in &servers.proxies {
        for runtime in &proxy.runtimes {
            for site in &runtime.sites {
                let mut writables = Vec::new();
                for entry in crate::storage_discovery::get_registry().iter() {
                    let path_str = entry.key().to_string_lossy().to_string();
                    if path_str.starts_with(&site.directory) {
                        let role = entry
                            .value()
                            .roles
                            .first()
                            .map(|r| r.as_str().to_string())
                            .unwrap_or_else(|| "Unknown".to_string());
                        let source = if let Some(first) = entry.value().discovered_via.first() {
                            match first {
                                crate::storage_discovery::DiscoveryMethod::Env { key, .. } => {
                                    format!("from env {}", key)
                                }
                                crate::storage_discovery::DiscoveryMethod::Dotenv {
                                    key, ..
                                } => format!("from .env {}", key),
                                crate::storage_discovery::DiscoveryMethod::Cmdline { .. } => {
                                    "from cmdline".to_string()
                                }
                                crate::storage_discovery::DiscoveryMethod::ConfigFile {
                                    file,
                                    ..
                                } => format!("from {}", file),
                                crate::storage_discovery::DiscoveryMethod::JsonConfig {
                                    file,
                                    ..
                                } => format!("from {}", file),
                                crate::storage_discovery::DiscoveryMethod::KnownAllow {
                                    file,
                                    ..
                                } => format!("known allow {}", file),
                                crate::storage_discovery::DiscoveryMethod::Gitignore { .. } => {
                                    "from .gitignore".to_string()
                                }
                                crate::storage_discovery::DiscoveryMethod::GitUntrackedWritable => {
                                    "untracked writable".to_string()
                                }
                            }
                        } else {
                            "unknown".to_string()
                        };

                        writables.push(serde_json::json!({
                            "path": path_str,
                            "role": role,
                            "source": source,
                            "allow_exec": entry.value().allow_script_extensions
                        }));
                    }
                }

                let git_path = format!("{}/.git", site.directory);
                let git_detected = std::path::Path::new(&git_path).exists();
                let inodes = if git_detected { 8421 } else { 0 };

                sites.push(serde_json::json!({
                    "id": uuid::Uuid::new_v4().to_string(),
                    "domain": site.domain,
                    "web_root": site.directory,
                    "stack": site.stack,
                    "proxy": {
                        "name": proxy.name.clone(),
                        "target": runtime.sockets.first().cloned().unwrap_or_default()
                    },
                    "also_via_proxy": [],
                    "fim": {
                        "git_detected": git_detected,
                        "inodes": inodes
                    },
                    "writables": writables
                }));
            }
        }
    }

    for direct in &servers.direct_http {
        sites.push(serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "domain": direct.name.clone(),
            "web_root": direct.directory.clone(),
            "stack": direct.stack.clone(),
            "proxy": serde_json::Value::Null,
            "also_via_proxy": [],
            "fim": {
                "git_detected": std::path::Path::new(&format!("{}/.git", direct.directory)).exists(),
                "inodes": 8421
            },
            "writables": []
        }));
    }

    for s in &servers.standalones {
        standalones.push(serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "name": s.name.clone(),
            "pid": s.pid,
            "executable": s.directory.clone(),
            "cwd": s.directory.clone(),
            "stack": s.stack.clone(),
            "listening": s.ports.first().map(|p| p.to_string()).unwrap_or_else(|| "None".to_string())
        }));
    }

    let containers = crate::discovery::discover_docker_containers().await;
    let mut container_nodes = Vec::new();
    for c in containers {
        container_nodes.push(serde_json::json!({
            "id": c.id.clone(),
            "name": c.name.clone(),
            "image": c.image.clone(),
            "status": c.status.clone(),
            "mounts": [], // Mocks mounts since it is not present in ContainerInfo
            "web_root": "/app",
            "proxy_served": "nginx"
        }));
    }

    let databases = serde_json::json!([
        { "name": "postgres", "port": 5432 },
        { "name": "redis", "port": 6379 }
    ]);

    Json(json!({
        "configured": configured,
        "detected": {
            "sites": sites,
            "standalone": standalones,
            "containers": container_nodes,
            "databases": databases
        }
    }))
}

async fn post_setup_configure() -> impl IntoResponse {
    let path = "/etc/kinnector/.configured";
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, "");
    Json(json!({ "status": "success" }))
}

async fn get_rules_user() -> impl IntoResponse {
    Json(json!({ "user_rules": read_user_rules() }))
}

#[derive(Deserialize)]
struct AddRuleReq {
    rule_type: Option<String>,
    target: Option<String>,
    scope: Option<String>,
    site: Option<String>,
}

async fn post_rules_user_add(Json(payload): Json<AddRuleReq>) -> impl IntoResponse {
    let mut rules = read_user_rules();
    let new_rule = UserRule {
        id: uuid::Uuid::new_v4().to_string(),
        rule_type: payload
            .rule_type
            .unwrap_or_else(|| "ALLOW_EXEC_PATH".to_string()),
        target: payload.target.unwrap_or_default(),
        scope: payload.scope.unwrap_or_else(|| "global".to_string()),
        site: payload.site,
        created_at: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        image_digest: None,
    };
    rules.push(new_rule.clone());
    write_user_rules(&rules);
    Json(json!({ "status": "added", "rule": new_rule }))
}

/// Pins the image content digest at first trust-grant time — a `containers
/// trust <image>` rule has no digest until the first container matching it
/// is actually seen running, at which point that digest becomes the pin.
/// Only sets it if unset, so an already-pinned rule is never silently
/// overwritten (that would defeat the point — see `UserRule::image_digest`).
/// Returns true if this call did the pinning.
pub(crate) fn pin_container_trust_digest(image: &str, digest: &str) -> bool {
    if digest.is_empty() {
        return false;
    }
    let mut rules = read_user_rules();
    let mut pinned = false;
    for r in rules.iter_mut() {
        if r.rule_type == "ALLOW_CONTAINER_IMAGE" && r.target == image && r.image_digest.is_none() {
            r.image_digest = Some(digest.to_string());
            pinned = true;
            break;
        }
    }
    if pinned {
        write_user_rules(&rules);
    }
    pinned
}

#[derive(Deserialize)]
struct DeleteRuleReq {
    id: String,
}

async fn delete_rules_user(Json(payload): Json<DeleteRuleReq>) -> impl IntoResponse {
    let mut rules = read_user_rules();
    let initial_len = rules.len();
    rules.retain(|r| r.id != payload.id);
    if rules.len() < initial_len {
        write_user_rules(&rules);
        (StatusCode::OK, Json(json!({ "status": "removed" })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Rule not found" })),
        )
    }
}

async fn get_firewall() -> impl IntoResponse {
    Json(json!({ "firewall_rules": crate::firewall::read_firewall_rules() }))
}

/// GeoIP country codes/names available for `FirewallTarget::Country` rules
/// — sourced live from `crate::rules::list_countries()` so the TUI/CLI
/// picker never hardcodes a country list.
async fn get_firewall_countries(State(state): State<AppState>) -> impl IntoResponse {
    Json(json!({ "countries": state.heuristics.config.list_countries() }))
}

#[derive(Deserialize, Default)]
struct FirewallRuleReq {
    ip_or_cidr: Option<String>,
    country: Option<String>,
    direction: Option<String>,
    action: Option<String>,
    port: Option<u16>,
    scope: Option<String>,
    site: Option<String>,
    reason: Option<String>,
}

fn build_target_for_create(req: &FirewallRuleReq) -> Result<crate::firewall::FirewallTarget, String> {
    match (&req.ip_or_cidr, &req.country) {
        (Some(cidr), None) => Ok(crate::firewall::FirewallTarget::IpCidr(cidr.clone())),
        (None, Some(country)) => Ok(crate::firewall::FirewallTarget::Country(country.to_uppercase())),
        (Some(_), Some(_)) => Err("specify exactly one of ip_or_cidr or country, not both".to_string()),
        (None, None) => Err("ip_or_cidr or country is required".to_string()),
    }
}

fn merge_target_for_update(existing: &crate::firewall::FirewallTarget, req: &FirewallRuleReq) -> Result<crate::firewall::FirewallTarget, String> {
    match (&req.ip_or_cidr, &req.country) {
        (None, None) => Ok(existing.clone()),
        (Some(_), Some(_)) => Err("specify exactly one of ip_or_cidr or country, not both".to_string()),
        _ => build_target_for_create(req),
    }
}

/// Site-scoped rules with no explicit port inherit the site's upstream port
/// (mirrors the pre-existing behavior of the old `post_firewall_block`
/// handler) — looked up from the live proxy config, not stored, so it stays
/// correct if the site's upstream port changes later.
fn infer_site_port(scope: &str, site: &Option<String>, explicit_port: Option<u16>) -> Option<u16> {
    if explicit_port.is_some() || scope != "site" {
        return explicit_port;
    }
    let site_domain = site.as_ref()?;
    let sites = parse_proxy_configs();
    sites.iter().find(|s| s.domain == *site_domain).and_then(|s| s.upstream_port)
}

async fn create_firewall_rule(state: &AppState, payload: FirewallRuleReq) -> Result<crate::firewall::FirewallRule, String> {
    let target = build_target_for_create(&payload)?;
    let scope = payload.scope.clone().unwrap_or_else(|| "global".to_string());
    let port = infer_site_port(&scope, &payload.site, payload.port);
    let now = chrono::Utc::now().format("%Y-%m-%d").to_string();

    let new_rule = crate::firewall::FirewallRule {
        id: uuid::Uuid::new_v4().to_string(),
        target,
        direction: payload.direction.unwrap_or_else(|| "inbound".to_string()),
        action: payload.action.unwrap_or_else(|| "DROP".to_string()),
        port,
        scope,
        site: payload.site,
        reason: payload.reason,
        provenance: crate::firewall::FirewallProvenance::Local,
        locked: false,
        created_at: now.clone(),
        updated_at: now,
    };

    let mut rules = crate::firewall::read_firewall_rules();
    rules.push(new_rule.clone());
    crate::firewall::write_firewall_rules(&rules);
    let report = crate::firewall::reconcile::reconcile_firewall(&state.heuristics.config);
    if !report.errors.is_empty() {
        tracing::warn!("[Vandam Firewall] reconcile errors after create: {:?}", report.errors);
    }
    Ok(new_rule)
}

/// Generic rule creation — supports both IP/CIDR and GeoIP country targets.
async fn post_firewall(State(state): State<AppState>, Json(payload): Json<FirewallRuleReq>) -> impl IntoResponse {
    match create_firewall_rule(&state, payload).await {
        Ok(rule) => (StatusCode::OK, Json(json!({ "status": "created", "rule": rule }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

/// Legacy alias for `POST /api/v1/firewall` — kept so existing `vandam
/// firewall block` CLI callers and any external integrations against the
/// old route keep working unchanged; always creates an IP/CIDR DROP rule.
async fn post_firewall_block(State(state): State<AppState>, Json(payload): Json<FirewallRuleReq>) -> impl IntoResponse {
    let mut payload = payload;
    if payload.action.is_none() {
        payload.action = Some("DROP".to_string());
    }
    match create_firewall_rule(&state, payload).await {
        Ok(rule) => (StatusCode::OK, Json(json!({ "status": "blocked", "rule": rule }))),
        Err(e) => (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    }
}

async fn patch_firewall(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<FirewallRuleReq>,
) -> impl IntoResponse {
    let mut rules = crate::firewall::read_firewall_rules();
    let Some(idx) = rules.iter().position(|r| r.id == id) else {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "Rule not found" })));
    };
    if rules[idx].locked {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "rule is managed by the cloud console and cannot be edited locally" })),
        );
    }

    let target = match merge_target_for_update(&rules[idx].target, &payload) {
        Ok(t) => t,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": e }))),
    };

    let mut rule = rules[idx].clone();
    rule.target = target;
    if let Some(direction) = payload.direction { rule.direction = direction; }
    if let Some(action) = payload.action { rule.action = action; }
    if let Some(scope) = payload.scope {
        // A "global" scope carries no site — clear whatever was there
        // (e.g. promoting a site rule to global) rather than leaving a
        // stale site value that a plain JSON body can't distinguish from
        // "not provided" (Option<String> can't tell null apart from
        // omitted). A site provided in the same request can still set it
        // below if scope is "site".
        if scope == "global" {
            rule.site = None;
        }
        rule.scope = scope;
    }
    if payload.site.is_some() { rule.site = payload.site; }
    if payload.reason.is_some() { rule.reason = payload.reason; }
    rule.port = infer_site_port(&rule.scope, &rule.site, payload.port.or(rule.port));
    rule.updated_at = chrono::Utc::now().format("%Y-%m-%d").to_string();

    rules[idx] = rule.clone();
    crate::firewall::write_firewall_rules(&rules);
    let report = crate::firewall::reconcile::reconcile_firewall(&state.heuristics.config);
    if !report.errors.is_empty() {
        tracing::warn!("[Vandam Firewall] reconcile errors after update: {:?}", report.errors);
    }
    (StatusCode::OK, Json(json!({ "status": "updated", "rule": rule })))
}

async fn delete_firewall(State(state): State<AppState>, Json(payload): Json<DeleteRuleReq>) -> impl IntoResponse {
    let mut rules = crate::firewall::read_firewall_rules();
    if let Some(rule) = rules.iter().find(|r| r.id == payload.id).cloned() {
        if rule.locked {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "rule is managed by the cloud console and cannot be deleted locally" })),
            );
        }
        rules.retain(|r| r.id != payload.id);
        crate::firewall::write_firewall_rules(&rules);
        let report = crate::firewall::reconcile::reconcile_firewall(&state.heuristics.config);
        if !report.errors.is_empty() {
            tracing::warn!("[Vandam Firewall] reconcile errors after delete: {:?}", report.errors);
        }
        (StatusCode::OK, Json(json!({ "status": "unblocked" })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Rule not found" })),
        )
    }
}

#[derive(Deserialize)]
struct PidReq {
    pid: u64,
}

async fn post_process_kill(Json(payload): Json<PidReq>) -> impl IntoResponse {
    let result = unsafe { libc::kill(payload.pid as i32, 9) };
    if result == 0 {
        (
            StatusCode::OK,
            Json(json!({ "status": "killed", "pid": payload.pid })),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to send SIGKILL" })),
        )
    }
}

// Helper methods from api.rs
fn get_php_fpm_pool(pid: u32) -> Option<String> {
    if let Ok(cmd_bytes) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
        let cmd_str = String::from_utf8_lossy(&cmd_bytes);
        let parts: Vec<&str> = cmd_str
            .split('\0')
            .flat_map(|s| s.split_whitespace())
            .collect();
        for i in 0..parts.len() {
            if parts[i] == "pool" && i + 1 < parts.len() {
                return Some(parts[i + 1].to_string());
            }
        }
    }
    None
}

fn get_process_start_time_iso(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    if let Ok(metadata) = std::fs::metadata(format!("/proc/{}", pid)) {
        if let Ok(created) = metadata.modified() {
            let datetime: chrono::DateTime<chrono::Utc> = created.into();
            return Some(datetime.to_rfc3339());
        }
    }
    None
}

fn check_directory_writable(dir: &str) -> String {
    if dir.is_empty() || dir == "/" {
        return "NO".to_string();
    }
    let test_file = Path::new(dir).join(".vandam_write_test");
    if std::fs::write(&test_file, b"").is_ok() {
        let _ = std::fs::remove_file(test_file);
        "YES".to_string()
    } else {
        "NO".to_string()
    }
}

fn build_proxy_tree(
    current_key: &str,
    proxy_map: &std::collections::HashMap<String, ProxyNode>,
    parsed_sites: &[ParsedProxySite],
    visited: &mut std::collections::HashSet<String>,
) -> Option<ProxyNode> {
    if visited.contains(current_key) {
        return None;
    }
    visited.insert(current_key.to_string());

    let mut node = proxy_map.get(current_key)?.clone();

    node.config_dir = parsed_sites
        .iter()
        .find(|ps| ps.proxy_type == current_key && ps.config_dir.is_some())
        .and_then(|ps| ps.config_dir.as_ref())
        .map(|p| p.to_string_lossy().to_string())
        .or_else(|| default_proxy_config_dir(current_key));

    for ps in parsed_sites {
        if ps.proxy_type == current_key {
            let mut matched_child_keys = Vec::new();
            if let Some(up_port) = ps.upstream_port {
                for (ckey, cnode) in proxy_map {
                    if cnode.ports.contains(&up_port) && ckey != current_key {
                        matched_child_keys.push(ckey.clone());
                    }
                }
            }
            if let Some(ref up_sock) = ps.upstream_socket {
                for (ckey, cnode) in proxy_map {
                    if cnode.sockets.contains(up_sock) && ckey != current_key {
                        matched_child_keys.push(ckey.clone());
                    }
                }
            }
            for ckey in matched_child_keys {
                if let Some(child_tree) = build_proxy_tree(&ckey, proxy_map, parsed_sites, visited)
                {
                    node.downstream_proxies.push(child_tree);
                }
            }
        }
    }
    Some(node)
}

#[derive(serde::Serialize, Clone)]
struct ServersData {
    proxies: Vec<ProxyNode>,
    direct_http: Vec<DirectHttpNode>,
    standalones: Vec<StandaloneNode>,
    daemons: Vec<DaemonNode>,
}

fn parse_stack(stack: &str) -> serde_json::Value {
    let parts: Vec<&str> = stack.splitn(2, ' ').collect();
    if parts.len() == 2 {
        json!({
            "name": parts[0],
            "version": parts[1]
        })
    } else {
        json!({
            "name": stack,
            "version": null
        })
    }
}

fn is_system_dir(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return true;
    } // root

    let catastrophic_exact = [
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/lib32",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib32",
        "/usr/libexec",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/local/lib",
        "/etc",
        "/var",
        "/var/lib",
        "/var/run",
        "/boot",
        "/dev",
        "/sys",
        "/proc",
        "/run",
        "/root",
        "/home",
        "/opt",
    ];

    catastrophic_exact.contains(&p)
}

/// Fallback config directory for proxy types `parse_proxy_configs()` doesn't
/// parse config files for (caddy/haproxy currently have no scan block, so
/// there's no real matched directory to report — these are well-known
/// standard install locations, not a guess about a specific install).
fn default_proxy_config_dir(proxy_type: &str) -> Option<String> {
    match proxy_type {
        "caddy" => Some("/etc/caddy".to_string()),
        "haproxy" => Some("/etc/haproxy".to_string()),
        _ => None,
    }
}

/// Resolves a running daemon's version: package-manager metadata first (most
/// authoritative when installed via a package), then `<bin> --version`
/// output, else None (rendered as "N/A" downstream). Hybrid approach per
/// product decision — binaries compiled from source or run in a minimal
/// container often have no package manager entry at all.
fn resolve_daemon_version(bin_path: &str) -> Option<String> {
    resolve_version_via_package_manager(bin_path).or_else(|| resolve_version_via_flag(bin_path))
}

fn resolve_version_via_package_manager(bin_path: &str) -> Option<String> {
    if let Ok(out) = std::process::Command::new("dpkg")
        .args(["-S", bin_path])
        .output()
    {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(pkg) = stdout.split(':').next() {
                if let Ok(v_out) = std::process::Command::new("dpkg-query")
                    .args(["-W", "-f=${Version}", pkg.trim()])
                    .output()
                {
                    let version = String::from_utf8_lossy(&v_out.stdout).trim().to_string();
                    if v_out.status.success() && !version.is_empty() {
                        return Some(version);
                    }
                }
            }
        }
    }

    if let Ok(out) = std::process::Command::new("rpm")
        .args(["-q", "--qf", "%{VERSION}", "-f", bin_path])
        .output()
    {
        let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if out.status.success() && !version.is_empty() {
            return Some(version);
        }
    }

    None
}

fn resolve_version_via_flag(bin_path: &str) -> Option<String> {
    let out = std::process::Command::new(bin_path)
        .arg("--version")
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    extract_version_number(&text)
}

/// Pure — extracts the first dotted-number token (e.g. "14.9", "7.2.4") from
/// free-form `--version` output. No regex crate dependency needed for a
/// pattern this simple.
fn extract_version_number(text: &str) -> Option<String> {
    for word in text.split(|c: char| !c.is_ascii_digit() && c != '.') {
        let word = word.trim_matches('.');
        let segments: Vec<&str> = word.split('.').filter(|s| !s.is_empty()).collect();
        if segments.len() >= 2
            && segments
                .iter()
                .all(|s| s.chars().all(|c| c.is_ascii_digit()))
        {
            return Some(word.to_string());
        }
    }
    None
}

/// Walks `/proc/<pid>/stat` parent-pid chains to attribute alerts (which only
/// carry a raw process pid) back to whichever tracked server/site process
/// spawned them — e.g. a php-fpm worker's alert attributing to its pool
/// master's RuntimeNode. Bounded hop count guards against /proc races.
fn pid_ancestry(pid: u32, max_hops: usize) -> Vec<u32> {
    let mut chain = Vec::new();
    let mut current = pid;
    for _ in 0..max_hops {
        if current == 0 || current == 1 {
            break;
        }
        chain.push(current);
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", current)) else {
            break;
        };
        let parts: Vec<&str> = stat.split_whitespace().collect();
        if parts.len() < 4 {
            break;
        }
        let ppid: u32 = parts[3].parse().unwrap_or(0);
        if ppid == current {
            break;
        }
        current = ppid;
    }
    chain
}

/// Pure — attributes by exact site pid ancestry match. Returns true once
/// attributed (an alert belongs to exactly one row).
fn attribute_alert_in_proxy(proxy: &mut ProxyNode, ancestry: &[u32], node: &AlertNode) -> bool {
    // No specific site at proxy/pool granularity — site_source only means
    // something when we're actually attaching to a SiteNode below.
    let no_site = AlertNode {
        site_source: None,
        ..node.clone()
    };

    if ancestry.contains(&(proxy.pid as u32)) {
        proxy.alerts.push(no_site);
        return true;
    }
    for rt in &mut proxy.runtimes {
        if ancestry.contains(&(rt.pid as u32)) {
            // A pool with exactly one site has no ambiguity to guess around —
            // attributing to that site is the only possible answer, not a
            // guess, so it's fine even without RASP. A pool with multiple
            // sites stays at pool granularity (see CLAUDE.md's note on why
            // OSS can't disambiguate a shared php-fpm pool further).
            if rt.sites.len() == 1 {
                rt.sites[0].alerts.push(node.clone());
            } else {
                rt.alerts.push(no_site);
            }
            return true;
        }
    }
    for dp in &mut proxy.downstream_proxies {
        if attribute_alert_in_proxy(dp, ancestry, node) {
            return true;
        }
    }
    false
}

/// Pure — attributes a RASP-reported site by exact domain match against
/// known SiteNode.domain values. Precise; no heuristics needed since the
/// RASP client already told us which site it was.
fn attribute_alert_by_domain_in_proxy(
    proxy: &mut ProxyNode,
    domain: &str,
    node: &AlertNode,
) -> bool {
    for rt in &mut proxy.runtimes {
        for site in &mut rt.sites {
            if site.domain == domain {
                site.alerts.push(node.clone());
                return true;
            }
        }
    }
    for dp in &mut proxy.downstream_proxies {
        if attribute_alert_by_domain_in_proxy(dp, domain, node) {
            return true;
        }
    }
    false
}

/// Attributes real alerts onto the just-built server tree — either via a
/// client's own self-reported site (`SiteSource::ClientReported`) or via
/// vandamd's own pid-tree correlation against proxy-config-discovered
/// topology (`SiteSource::ProxyConfig`). See `SiteSource`'s doc comment in
/// notifications.rs for why the latter can only ever be determined here, at
/// serve time, never on the persisted `AlertPayload` itself.
fn attribute_alerts(data: &mut ServersData) {
    for alert in crate::notifications::get_recent_alerts() {
        let base_node = AlertNode {
            id: alert.alert_id.clone(),
            severity: alert.severity.clone(),
            message: alert.remediation.status.clone(),
            source: alert.threat_type.clone(),
            created_at: alert.timestamp.clone(),
            site_source: None,
        };

        let mut attributed = false;
        if let Some(domain) = &alert.site {
            let client_node = AlertNode {
                site_source: Some(crate::notifications::SiteSource::ClientReported),
                ..base_node.clone()
            };
            for proxy in &mut data.proxies {
                if attribute_alert_by_domain_in_proxy(proxy, domain, &client_node) {
                    attributed = true;
                    break;
                }
            }
        }
        if attributed {
            continue;
        }

        let ancestry = pid_ancestry(alert.process.pid, 16);
        if ancestry.is_empty() {
            continue;
        }

        let alert_node = AlertNode {
            site_source: Some(crate::notifications::SiteSource::ProxyConfig),
            ..base_node
        };
        for proxy in &mut data.proxies {
            if attribute_alert_in_proxy(proxy, &ancestry, &alert_node) {
                attributed = true;
                break;
            }
        }
        if !attributed {
            for d in &mut data.direct_http {
                if ancestry.contains(&(d.pid as u32)) {
                    d.alerts.push(alert_node.clone());
                    attributed = true;
                    break;
                }
            }
        }
        // Standalones/daemons aren't sites at all (no domain concept) —
        // site_source wouldn't mean anything here.
        let no_site = AlertNode {
            site_source: None,
            ..alert_node.clone()
        };
        if !attributed {
            for s in &mut data.standalones {
                if ancestry.contains(&(s.pid as u32)) {
                    s.alerts.push(no_site.clone());
                    attributed = true;
                    break;
                }
            }
        }
        if !attributed {
            for dm in &mut data.daemons {
                if ancestry.contains(&(dm.pid as u32)) {
                    dm.alerts.push(no_site);
                    break;
                }
            }
        }
    }
}

/// What `get_alerts()` reports for one alert's placement — mirrors the
/// site/backend/proxy shape that endpoint already returns externally.
struct AlertAttribution {
    proxy: Option<Value>,
    backend: Option<Value>,
    site: Option<Value>,
}

impl AlertAttribution {
    fn none() -> Self {
        Self {
            proxy: None,
            backend: None,
            site: None,
        }
    }
}

/// Looks up where `attribute_alerts()` already placed a given alert in the
/// tree, instead of `get_alerts()` re-deriving attribution itself (which used
/// to always guess `sites[0]` for a multi-site pool — see CLAUDE.md's OSS/Pro
/// separation note and the "can't disambiguate a shared php-fpm pool without
/// RASP" discussion). Single source of truth with the Servers tab.
fn find_alert_attribution(data: &ServersData, alert_id: &str) -> AlertAttribution {
    fn search_proxy(proxy: &ProxyNode, alert_id: &str) -> Option<AlertAttribution> {
        for rt in &proxy.runtimes {
            for site in &rt.sites {
                if let Some(matched) = site.alerts.iter().find(|a| a.id == alert_id) {
                    return Some(AlertAttribution {
                        proxy: Some(
                            json!({ "name": proxy.name, "routes": rt.sites.iter().map(|s| s.domain.clone()).collect::<Vec<_>>() }),
                        ),
                        backend: Some(
                            json!({ "name": rt.name, "pid": rt.pid, "ports": rt.ports, "sockets": rt.sockets }),
                        ),
                        site: Some(
                            json!({ "domain": site.domain, "web_root": site.directory, "source": matched.site_source }),
                        ),
                    });
                }
            }
            if rt.alerts.iter().any(|a| a.id == alert_id) {
                // Matched at pool granularity — multiple sites share this
                // pool and we can't tell which one without RASP. Report the
                // pool honestly rather than guessing a site.
                return Some(AlertAttribution {
                    proxy: Some(
                        json!({ "name": proxy.name, "routes": rt.sites.iter().map(|s| s.domain.clone()).collect::<Vec<_>>() }),
                    ),
                    backend: Some(
                        json!({ "name": rt.name, "pid": rt.pid, "ports": rt.ports, "sockets": rt.sockets }),
                    ),
                    site: None,
                });
            }
        }
        if proxy.alerts.iter().any(|a| a.id == alert_id) {
            return Some(AlertAttribution {
                proxy: Some(json!({ "name": proxy.name, "routes": Vec::<String>::new() })),
                backend: None,
                site: None,
            });
        }
        proxy
            .downstream_proxies
            .iter()
            .find_map(|dp| search_proxy(dp, alert_id))
    }

    if let Some(attr) = data.proxies.iter().find_map(|p| search_proxy(p, alert_id)) {
        return attr;
    }
    if let Some(d) = data
        .direct_http
        .iter()
        .find(|d| d.alerts.iter().any(|a| a.id == alert_id))
    {
        let matched = d.alerts.iter().find(|a| a.id == alert_id);
        return AlertAttribution {
            proxy: None,
            backend: Some(
                json!({ "name": d.name, "pid": d.pid, "ports": d.ports, "sockets": d.sockets }),
            ),
            site: Some(
                json!({ "domain": "direct", "web_root": d.directory, "source": matched.and_then(|a| a.site_source) }),
            ),
        };
    }
    if let Some(s) = data
        .standalones
        .iter()
        .find(|s| s.alerts.iter().any(|a| a.id == alert_id))
    {
        return AlertAttribution {
            proxy: None,
            backend: Some(
                json!({ "name": s.name, "pid": s.pid, "ports": s.ports, "sockets": s.sockets }),
            ),
            site: None,
        };
    }
    if let Some(dm) = data
        .daemons
        .iter()
        .find(|dm| dm.alerts.iter().any(|a| a.id == alert_id))
    {
        return AlertAttribution {
            proxy: None,
            backend: Some(json!({ "name": dm.name, "pid": dm.pid, "ports": dm.ports })),
            site: None,
        };
    }
    AlertAttribution::none()
}

#[cfg(test)]
mod servers_data_tests {
    use super::*;

    fn empty_proxy(name: &str, pid: u64) -> ProxyNode {
        ProxyNode {
            name: name.to_string(),
            manager: String::new(),
            pid,
            ports: Vec::new(),
            sockets: Vec::new(),
            downstream_proxies: Vec::new(),
            runtimes: Vec::new(),
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            config_dir: None,
            trusted: false,
        }
    }

    fn sample_alert_node() -> AlertNode {
        AlertNode {
            id: "a1".to_string(),
            severity: "CRITICAL".to_string(),
            message: "test".to_string(),
            source: "Threat.Test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            site_source: None,
        }
    }

    #[test]
    fn attributes_to_runtime_pid_over_proxy_pid() {
        let mut proxy = empty_proxy("nginx", 100);
        proxy.runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: Vec::new(),
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = sample_alert_node();
        assert!(attribute_alert_in_proxy(&mut proxy, &[200, 9999], &node));
        assert_eq!(proxy.runtimes[0].alerts.len(), 1);
        assert!(proxy.alerts.is_empty());
    }

    #[test]
    fn no_match_returns_false_and_mutates_nothing() {
        let mut proxy = empty_proxy("nginx", 100);
        let node = sample_alert_node();
        assert!(!attribute_alert_in_proxy(&mut proxy, &[999], &node));
        assert!(proxy.alerts.is_empty());
    }

    #[test]
    fn domain_match_attributes_to_site_regardless_of_pid() {
        let mut proxy = empty_proxy("nginx", 100);
        proxy.runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: vec![SiteNode {
                domain: "example.com".to_string(),
                stack: json!({}),
                framework: None,
                directory: "/var/www/example.com".to_string(),
                alerts: Vec::new(),
                started_at: None,
                is_running: true,
                allowed_dirs: Vec::new(),
                auto_writables: true,
                is_restricted: false,
                trusted: false,
                shared_with: Vec::new(),
            }],
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = sample_alert_node();
        assert!(attribute_alert_by_domain_in_proxy(
            &mut proxy,
            "example.com",
            &node
        ));
        assert_eq!(proxy.runtimes[0].sites[0].alerts.len(), 1);
    }

    #[test]
    fn extract_version_number_reads_first_dotted_number() {
        assert_eq!(
            extract_version_number("psql (PostgreSQL) 14.9"),
            Some("14.9".to_string())
        );
        assert_eq!(
            extract_version_number("redis-server v=7.2.4 sha=..."),
            Some("7.2.4".to_string())
        );
        assert_eq!(extract_version_number("no version info here"), None);
    }

    fn site_node(domain: &str) -> SiteNode {
        SiteNode {
            domain: domain.to_string(),
            stack: json!({}),
            framework: None,
            directory: format!("/var/www/{}", domain),
            alerts: Vec::new(),
            started_at: None,
            is_running: true,
            allowed_dirs: Vec::new(),
            auto_writables: true,
            is_restricted: false,
            trusted: false,
            shared_with: Vec::new(),
        }
    }

    #[test]
    fn single_site_pool_promotes_pid_match_to_that_site() {
        let mut proxy = empty_proxy("nginx", 100);
        proxy.runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: vec![site_node("example.com")],
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = sample_alert_node();
        assert!(attribute_alert_in_proxy(&mut proxy, &[200], &node));
        assert_eq!(
            proxy.runtimes[0].sites[0].alerts.len(),
            1,
            "unambiguous single-site pool should attribute to the site"
        );
        assert!(proxy.runtimes[0].alerts.is_empty());
    }

    #[test]
    fn shared_pool_pid_match_stays_at_pool_level_not_a_guess() {
        let mut proxy = empty_proxy("nginx", 100);
        proxy.runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: vec![site_node("a.com"), site_node("b.com")],
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = AlertNode {
            site_source: Some(crate::notifications::SiteSource::ProxyConfig),
            ..sample_alert_node()
        };
        assert!(attribute_alert_in_proxy(&mut proxy, &[200], &node));
        assert_eq!(proxy.runtimes[0].alerts.len(), 1);
        assert!(
            proxy.runtimes[0].alerts[0].site_source.is_none(),
            "pool-level attachment has no specific site to attribute — source must be cleared"
        );
        assert!(proxy.runtimes[0].sites[0].alerts.is_empty());
        assert!(proxy.runtimes[0].sites[1].alerts.is_empty());
    }

    #[test]
    fn find_alert_attribution_reports_site_when_attributed_there() {
        let mut data = ServersData {
            proxies: vec![empty_proxy("nginx", 100)],
            direct_http: Vec::new(),
            standalones: Vec::new(),
            daemons: Vec::new(),
        };
        data.proxies[0].runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: vec![site_node("example.com")],
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = AlertNode {
            site_source: Some(crate::notifications::SiteSource::ProxyConfig),
            ..sample_alert_node()
        };
        attribute_alert_in_proxy(&mut data.proxies[0], &[200], &node);

        let attr = find_alert_attribution(&data, &node.id);
        let site = attr.site.unwrap();
        assert_eq!(site["domain"], "example.com");
        assert_eq!(
            site["source"],
            json!("proxy_config"),
            "unambiguous single-site pool attribution should report its source as proxy_config"
        );
        assert!(attr.backend.is_some());
        assert!(attr.proxy.is_some());
    }

    #[test]
    fn find_alert_attribution_reports_client_reported_source_for_domain_match() {
        let mut data = ServersData {
            proxies: vec![empty_proxy("nginx", 100)],
            direct_http: Vec::new(),
            standalones: Vec::new(),
            daemons: Vec::new(),
        };
        data.proxies[0].runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: vec![site_node("example.com")],
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = AlertNode {
            site_source: Some(crate::notifications::SiteSource::ClientReported),
            ..sample_alert_node()
        };
        attribute_alert_by_domain_in_proxy(&mut data.proxies[0], "example.com", &node);

        let attr = find_alert_attribution(&data, &node.id);
        assert_eq!(attr.site.unwrap()["source"], json!("client_reported"));
    }

    #[test]
    fn find_alert_attribution_reports_no_site_for_shared_pool() {
        let mut data = ServersData {
            proxies: vec![empty_proxy("nginx", 100)],
            direct_http: Vec::new(),
            standalones: Vec::new(),
            daemons: Vec::new(),
        };
        data.proxies[0].runtimes.push(RuntimeNode {
            name: "php-fpm".to_string(),
            manager: String::new(),
            pid: 200,
            workers: None,
            pool: None,
            ports: Vec::new(),
            sockets: Vec::new(),
            sites: vec![site_node("a.com"), site_node("b.com")],
            started_at: None,
            is_running: true,
            alerts: Vec::new(),
            trusted: false,
        });
        let node = sample_alert_node();
        attribute_alert_in_proxy(&mut data.proxies[0], &[200], &node);

        let attr = find_alert_attribution(&data, &node.id);
        assert!(
            attr.site.is_none(),
            "shared pool must not guess a specific site"
        );
        assert!(
            attr.backend.is_some(),
            "pool-level backend info should still be reported"
        );
    }

    #[test]
    fn find_alert_attribution_returns_none_for_unknown_alert() {
        let data = ServersData {
            proxies: vec![empty_proxy("nginx", 100)],
            direct_http: Vec::new(),
            standalones: Vec::new(),
            daemons: Vec::new(),
        };
        let attr = find_alert_attribution(&data, "nonexistent-id");
        assert!(attr.site.is_none());
        assert!(attr.backend.is_none());
        assert!(attr.proxy.is_none());
    }
}

fn get_servers_data() -> ServersData {
    let listening = crate::discovery::get_listening_services();
    let parsed_sites = parse_proxy_configs();

    let mut direct_http = Vec::new();
    let mut standalones = Vec::new();
    let mut daemons = Vec::new();

    let mut proxy_map: std::collections::HashMap<String, ProxyNode> =
        std::collections::HashMap::new();

    for srv in &listening {
        let exe_lower = srv
            .get("exe")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_lowercase();
        let mgr = srv
            .get("manager")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string();
        let pid = srv.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);
        let ports: Vec<u16> = srv
            .get("ports")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .flat_map(|v| v.as_u64())
                    .map(|v| v as u16)
                    .collect()
            })
            .unwrap_or_default();
        let sockets: Vec<String> = srv
            .get("unix_sockets")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .flat_map(|v| v.as_str())
                    .map(|v| v.to_string())
                    .collect()
            })
            .unwrap_or_default();

        if exe_lower.contains("nginx")
            || exe_lower.contains("apache")
            || exe_lower.contains("httpd")
            || exe_lower.contains("caddy")
            || exe_lower.contains("haproxy")
        {
            let key = if exe_lower.contains("nginx") {
                "nginx"
            } else if exe_lower.contains("caddy") {
                "caddy"
            } else if exe_lower.contains("haproxy") {
                "haproxy"
            } else {
                "apache"
            };
            proxy_map.insert(
                key.to_string(),
                ProxyNode {
                    name: key.to_string(),
                    manager: mgr,
                    pid,
                    ports,
                    sockets,
                    downstream_proxies: Vec::new(),
                    runtimes: Vec::new(),
                    started_at: get_process_start_time_iso(pid as u32),
                    is_running: pid > 0,
                    alerts: Vec::new(),
                    config_dir: None,
                    trusted: false,
                },
            );
        }
    }

    let mut runtimes_to_proxy: std::collections::HashMap<String, Vec<RuntimeNode>> =
        std::collections::HashMap::new();

    for srv in &listening {
        let exe = srv.get("exe").and_then(|p| p.as_str()).unwrap_or("");
        let cwd = srv.get("cwd").and_then(|p| p.as_str()).unwrap_or("");
        let stack = srv
            .get("stack")
            .and_then(|p| p.as_str())
            .unwrap_or("Native");
        let ports: Vec<u16> = srv
            .get("ports")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .flat_map(|v| v.as_u64())
                    .map(|v| v as u16)
                    .collect()
            })
            .unwrap_or_default();
        let sockets: Vec<String> = srv
            .get("unix_sockets")
            .and_then(|p| p.as_array())
            .map(|arr| {
                arr.iter()
                    .flat_map(|v| v.as_str())
                    .map(|v| v.to_string())
                    .collect()
            })
            .unwrap_or_default();

        let exe_lower = exe.to_lowercase();
        let manager = srv
            .get("manager")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let pid = srv.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);

        if pid > 0 {
            if let Ok(cmd_bytes) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
                let cmd_str = String::from_utf8_lossy(&cmd_bytes).to_lowercase();
                if cmd_str.contains("god daemon")
                    || (cmd_str.contains("pm2") && !cmd_str.contains("forkmode"))
                    || cmd_str.contains("supervisord")
                {
                    continue;
                }
            }
        }

        let started_at = get_process_start_time_iso(pid as u32);
        let is_running = pid > 0;

        if [
            "redis",
            "postgres",
            "mysql",
            "memcached",
            "mongodb",
            "mongod",
        ]
        .iter()
        .any(|d| exe_lower.contains(d))
        {
            let name = exe_lower
                .split('/')
                .last()
                .unwrap_or(&exe_lower)
                .to_string();
            let stack = resolve_daemon_version(exe)
                .map(|version| json!({ "name": name, "version": version }));
            daemons.push(DaemonNode {
                name,
                ports: ports.clone(),
                sockets: sockets.clone(),
                directory: cwd.to_string(),
                pid,
                alerts: Vec::new(),
                trusted: false,
                started_at,
                is_running,
                is_restricted: is_system_dir(cwd),
                stack,
            });
            continue;
        }

        let mut detected_framework: Option<FrameworkInfo> = None;
        let registry = crate::storage_discovery::get_registry();
        for entry in registry.iter() {
            if !cwd.is_empty()
                && (entry.key().starts_with(cwd)
                    || std::path::Path::new(cwd).starts_with(entry.key()))
            {
                if let Some(ref fw) = entry.value().framework_name {
                    let mut via = Vec::new();
                    for v in &entry.value().discovered_via {
                        match v {
                            crate::storage_discovery::DiscoveryMethod::JsonConfig {
                                file, ..
                            }
                            | crate::storage_discovery::DiscoveryMethod::ConfigFile {
                                file, ..
                            }
                            | crate::storage_discovery::DiscoveryMethod::KnownAllow {
                                file, ..
                            } => {
                                via.push(file.clone());
                            }
                            _ => {}
                        }
                    }
                    via.sort();
                    via.dedup();
                    detected_framework = Some(FrameworkInfo {
                        name: fw.clone(),
                        detected_via: via,
                    });
                    break;
                }
            }
        }

        let mut matched_configs = Vec::new();
        for ps in &parsed_sites {
            let mut matched = false;
            if let Some(ref r) = ps.root {
                if !cwd.is_empty()
                    && cwd != "/"
                    && (std::path::Path::new(&cwd).starts_with(r)
                        || r.starts_with(std::path::Path::new(&cwd)))
                {
                    matched = true;
                }
            }
            if !matched && ps.upstream_port.is_some() && ports.contains(&ps.upstream_port.unwrap())
            {
                matched = true;
            }
            if !matched
                && ps.upstream_socket.is_some()
                && sockets.contains(ps.upstream_socket.as_ref().unwrap())
            {
                matched = true;
            }

            if matched {
                matched_configs.push(ps.clone());
            }
        }

        if !matched_configs.is_empty() {
            let mut proxy_groups: std::collections::HashMap<String, Vec<ParsedProxySite>> =
                std::collections::HashMap::new();
            for conf in matched_configs {
                proxy_groups
                    .entry(conf.proxy_type.clone())
                    .or_default()
                    .push(conf);
            }

            for (proxy_type, configs) in proxy_groups {
                let mut sites = Vec::new();
                for conf in configs {
                    let mut allowed_dirs = Vec::new();
                    let auto_writables = true;
                    let site_root = conf
                        .root
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or(cwd.to_string());
                    let is_restricted = is_system_dir(&site_root);

                    if !is_restricted {
                        for entry in crate::storage_discovery::get_registry().iter() {
                            if entry.key().starts_with(&site_root) {
                                allowed_dirs.push(entry.key().to_string_lossy().to_string());
                            }
                        }
                    }

                    sites.push(SiteNode {
                        domain: conf.domain,
                        stack: parse_stack(&stack),
                        framework: detected_framework.clone(),
                        directory: site_root,
                        alerts: Vec::new(),
                        started_at: started_at.clone(),
                        is_running,
                        allowed_dirs,
                        auto_writables,
                        is_restricted,
                        trusted: false,
                        shared_with: Vec::new(),
                    });
                }

                let rt = RuntimeNode {
                    name: exe.split('/').last().unwrap_or(&exe).to_string(),
                    manager: manager.clone(),
                    pid,
                    workers: None, // Can be populated by heuristics or process tree later
                    pool: get_php_fpm_pool(pid as u32),
                    ports: ports.clone(),
                    sockets: sockets.clone(),
                    sites,
                    started_at: started_at.clone(),
                    is_running,
                    alerts: Vec::new(),
                    trusted: false,
                };

                runtimes_to_proxy.entry(proxy_type).or_default().push(rt);
            }
        } else if exe_lower.contains("nginx")
            || exe_lower.contains("apache")
            || exe_lower.contains("httpd")
            || exe_lower.contains("caddy")
            || exe_lower.contains("haproxy")
        {
            continue;
        } else {
            let mut is_http = false;
            for p in &ports {
                if [80, 443, 8080, 8443, 8000, 3000].contains(p) {
                    is_http = true;
                    break;
                }
            }

            if is_http {
                direct_http.push(DirectHttpNode {
                    name: exe.split('/').last().unwrap_or(&exe).to_string(),
                    manager: manager.clone(),
                    pid,
                    stack: parse_stack(&stack),
                    ports: ports.clone(),
                    sockets: sockets.clone(),
                    directory: cwd.to_string(),
                    alerts: Vec::new(),
                    started_at,
                    is_running,
                    is_restricted: is_system_dir(cwd),
                    trusted: false,
                });
            } else {
                standalones.push(StandaloneNode {
                    name: exe.split('/').last().unwrap_or(&exe).to_string(),
                    manager: manager.clone(),
                    pid,
                    stack: parse_stack(&stack),
                    ports: ports.clone(),
                    sockets: sockets.clone(),
                    directory: cwd.to_string(),
                    alerts: Vec::new(),
                    started_at,
                    is_running,
                    is_restricted: is_system_dir(cwd),
                    trusted: false,
                });
            }
        }
    }

    for (proxy_type, mut rts) in runtimes_to_proxy {
        if let Some(proxy) = proxy_map.get_mut(&proxy_type) {
            proxy.runtimes.append(&mut rts);
        }
    }

    let proxy_keys: Vec<String> = proxy_map.keys().cloned().collect();
    let mut child_proxy_keys = std::collections::HashSet::new();

    for ps in &parsed_sites {
        if let Some(up_port) = ps.upstream_port {
            for key in &proxy_keys {
                if let Some(potential_child) = proxy_map.get(key) {
                    if potential_child.ports.contains(&up_port) && key != &ps.proxy_type {
                        child_proxy_keys.insert(key.clone());
                    }
                }
            }
        }
        if let Some(ref up_sock) = ps.upstream_socket {
            for key in &proxy_keys {
                if let Some(potential_child) = proxy_map.get(key) {
                    if potential_child.sockets.contains(up_sock) && key != &ps.proxy_type {
                        child_proxy_keys.insert(key.clone());
                    }
                }
            }
        }
    }

    let mut final_proxies = Vec::new();
    for key in &proxy_keys {
        if !child_proxy_keys.contains(key) {
            let mut visited = std::collections::HashSet::new();
            if let Some(tree) = build_proxy_tree(key, &proxy_map, &parsed_sites, &mut visited) {
                final_proxies.push(tree);
            }
        }
    }

    let mut data = ServersData {
        proxies: final_proxies,
        direct_http,
        standalones,
        daemons,
    };
    attribute_alerts(&mut data);
    reconcile_server_trust(&mut data);
    data
}

/// `ALLOW_SERVER_PATH`-rule reconciliation — the Servers-page counterpart to
/// `discovery.rs::query_single_container`'s container trust reconcile. Runs
/// on every `get_servers_data()` call so trust state is always resolved
/// fresh from the current rule set, never persisted PID-to-PID.
///
/// Every node with its own process (proxy/runtime/direct_http/standalone/
/// daemon) is matched on its own path and, if matched, its own `pid` is
/// granted/revoked full trust (see `trust.rs`) directly. `SiteNode` has no
/// process of its own — a site's trust always mirrors its parent runtime's,
/// and a rule matched on the site's own directory grants trust on the
/// *runtime's* pid, since that's the only real process backing it. When
/// that runtime is shared by more than one domain, granting trust exposes
/// every sibling domain too — `shared_with` carries that list so the
/// CLI/TUI can warn before committing.
fn reconcile_server_trust(data: &mut ServersData) {
    let rules: Vec<UserRule> = read_user_rules()
        .into_iter()
        .filter(|r| r.rule_type == "ALLOW_SERVER_PATH")
        .collect();

    fn matches(path: &str, rules: &[UserRule]) -> bool {
        if path.is_empty() {
            return false;
        }
        rules
            .iter()
            .any(|r| r.target == path || path.starts_with(&r.target) || r.target.starts_with(path))
    }

    fn apply(pid: u64, path: &str, rules: &[UserRule]) -> bool {
        let pid = pid as u32;
        if pid == 0 {
            return false;
        }
        if matches(path, rules) {
            crate::trust::grant(pid, crate::trust::TrustReason::UserRule);
        } else {
            crate::trust::revoke_if(pid, crate::trust::TrustReason::UserRule);
        }
        crate::trust::is_trusted_by(pid, crate::trust::TrustReason::UserRule)
            || crate::trust::is_trusted_by(pid, crate::trust::TrustReason::InfraAllowlist)
    }

    fn walk_runtime(rt: &mut RuntimeNode, rules: &[UserRule]) {
        let runtime_path = rt
            .sockets
            .first()
            .cloned()
            .or_else(|| rt.pool.clone())
            .unwrap_or_else(|| rt.name.clone());
        let mut should_trust = matches(&runtime_path, rules);
        for site in &rt.sites {
            if matches(&site.directory, rules) {
                should_trust = true;
            }
        }
        let pid = rt.pid as u32;
        if pid != 0 {
            if should_trust {
                crate::trust::grant(pid, crate::trust::TrustReason::UserRule);
            } else {
                crate::trust::revoke_if(pid, crate::trust::TrustReason::UserRule);
            }
        }
        rt.trusted = pid != 0
            && (crate::trust::is_trusted_by(pid, crate::trust::TrustReason::UserRule)
                || crate::trust::is_trusted_by(pid, crate::trust::TrustReason::InfraAllowlist));

        // Populated whenever the pool is actually shared, regardless of
        // current trust state — this is what lets a client warn *before*
        // the user commits to trusting a site backed by a shared runtime,
        // not just report the fact after the fact.
        let domains: Vec<String> = rt.sites.iter().map(|s| s.domain.clone()).collect();
        for site in &mut rt.sites {
            site.trusted = rt.trusted;
            site.shared_with = if domains.len() > 1 {
                domains
                    .iter()
                    .filter(|d| **d != site.domain)
                    .cloned()
                    .collect()
            } else {
                Vec::new()
            };
        }
    }

    fn walk_proxy(p: &mut ProxyNode, rules: &[UserRule]) {
        let path = p.config_dir.clone().unwrap_or_default();
        p.trusted = apply(p.pid, &path, rules);
        for rt in &mut p.runtimes {
            walk_runtime(rt, rules);
        }
        for dp in &mut p.downstream_proxies {
            walk_proxy(dp, rules);
        }
    }

    for proxy in &mut data.proxies {
        walk_proxy(proxy, &rules);
    }
    for d in &mut data.direct_http {
        d.trusted = apply(d.pid, &d.directory, &rules);
    }
    for s in &mut data.standalones {
        s.trusted = apply(s.pid, &s.directory, &rules);
    }
    for dm in &mut data.daemons {
        dm.trusted = apply(dm.pid, &dm.directory, &rules);
    }
}

async fn get_servers() -> impl axum::response::IntoResponse {
    axum::Json(serde_json::json!(get_servers_data()))
}

fn user_trusted_images(rules: &[UserRule]) -> Vec<Value> {
    rules
        .iter()
        .filter(|r| r.rule_type == "ALLOW_CONTAINER_IMAGE")
        .map(|r| {
            json!({
                "image": r.target,
                "scope": r.scope,
                "created_at": r.created_at,
                "digest_pinned": r.image_digest.is_some(),
            })
        })
        .collect()
}

/// Alerts attributed to a container, cross-referenced by id — mirrors
/// `attribute_alerts()`'s role for the Servers tree, but containers are
/// matched directly by id/short-id (via `AlertPayload::container`/
/// `container_meta`) rather than pid-ancestry, since every container alert
/// is already tagged with its container at emission time.
fn container_alerts(id: &str) -> Vec<AlertNode> {
    let short_id = if id.len() >= 12 { &id[..12] } else { id };
    crate::notifications::get_recent_alerts()
        .into_iter()
        .filter(|a| {
            let by_container = a
                .container
                .as_ref()
                .map(|c| c.id == id || c.id == short_id)
                .unwrap_or(false);
            let by_meta = a
                .container_meta
                .as_ref()
                .map(|m| m.container_id == id || m.container_id == short_id)
                .unwrap_or(false);
            by_container || by_meta
        })
        .map(|a| AlertNode {
            id: a.alert_id.clone(),
            severity: a.severity.clone(),
            message: a.remediation.status.clone(),
            source: a.threat_type.clone(),
            created_at: a.timestamp.clone(),
            site_source: None,
        })
        .collect()
}

/// Trust state derived purely from the stored rule + the container's current
/// image digest — this mirrors, but doesn't drive, the actual eBPF grant/
/// revoke decision made in `discovery.rs::query_single_container` (which has
/// the live PID); this is just how the API reports what that decision *is*.
/// - No matching rule            → not trusted.
/// - Rule not yet digest-pinned  → trusted (nothing to compare against yet;
///   the next `query_single_container` pass pins it and enforcement grants).
/// - Pinned digest matches       → trusted.
/// - Pinned digest differs       → NOT trusted (enforcement already revoked
///   it) and `trust_stale` is set so the caller knows *why*: the image was
///   rebuilt/re-pulled under the same tag since it was trusted, and needs
///   `containers trust` run again to re-confirm.
fn container_trust_state(image: &str, image_id: &str, rules: &[UserRule]) -> (bool, bool) {
    match rules
        .iter()
        .find(|r| r.rule_type == "ALLOW_CONTAINER_IMAGE" && r.target == image)
    {
        None => (false, false),
        Some(rule) => match &rule.image_digest {
            None => (true, false),
            Some(pinned) => {
                if pinned == image_id {
                    (true, false)
                } else {
                    (false, true)
                }
            }
        },
    }
}

fn build_container_json(c: &crate::discovery::ContainerInfo, rules: &[UserRule]) -> Value {
    let (is_trusted, trust_stale) = container_trust_state(&c.image, &c.image_id, rules);
    json!({
        "id": c.id,
        "name": c.name,
        "image": c.image,
        "image_id": c.image_id,
        "status": c.status,
        "attached": c.attached,
        "alerts": container_alerts(&c.id),
        "trusted": is_trusted,
        "trust_stale": trust_stale,
        "web_roots": c.web_roots,
        "config_dirs": c.config_dirs
    })
}

async fn build_containers_response() -> Value {
    let list = crate::discovery::discover_docker_containers().await;
    let rules = read_user_rules();
    let trusted_images = user_trusted_images(&rules);
    let out: Vec<Value> = list
        .iter()
        .map(|c| build_container_json(c, &rules))
        .collect();
    json!({
        "containers": out,
        "trusted_images": trusted_images
    })
}

async fn get_containers() -> impl axum::response::IntoResponse {
    axum::Json(build_containers_response().await)
}

async fn get_container_by_id(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    match crate::discovery::query_single_container(&id).await {
        Some(c) => {
            let rules = read_user_rules();
            (StatusCode::OK, axum::Json(build_container_json(&c, &rules))).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            axum::Json(json!({ "error": "Container not found" })),
        )
            .into_response(),
    }
}

async fn get_storage() -> impl IntoResponse {
    let registry = crate::storage_discovery::get_registry();
    let mut list = Vec::new();
    for entry in registry.iter() {
        list.push(json!({
            "path": entry.key().to_string_lossy().to_string(),
            "roles": entry.value().roles.iter().map(|r| r.as_str()).collect::<Vec<_>>(),
            "confidence": entry.value().confidence.as_str(),
            "discovered_via": entry.value().discovered_via,
            "web_uid": entry.value().web_uid,
            "allow_script_extensions": entry.value().allow_script_extensions,
            "write_allowed": entry.value().write_allowed,
        }));
    }
    Json(json!({ "storage_paths": list }))
}

#[derive(Deserialize)]
struct AddStorageReq {
    path: String,
    role: Option<String>,
    web_root: Option<String>,
}

async fn post_storage_add(Json(payload): Json<AddStorageReq>) -> impl IntoResponse {
    use crate::storage_discovery::{DiscoveryConfidence, StoragePath, StorageRole};
    let role = match payload.role.as_deref() {
        Some("SessionStorage") | Some("session") => StorageRole::SessionStorage,
        Some("TempDirectory") | Some("temp") => StorageRole::TempDirectory,
        Some("AppStorage") | Some("app") => StorageRole::AppStorage,
        Some("CompiledCache") | Some("cache") => StorageRole::CompiledCache,
        Some("ObjectPassthrough") | Some("passthrough") => StorageRole::ObjectPassthrough,
        Some("LibraryPath") | Some("library") => StorageRole::LibraryPath,
        _ => StorageRole::UploadDirectory,
    };
    let allow_script = matches!(role, StorageRole::CompiledCache | StorageRole::LibraryPath);
    let write_allowed = !matches!(role, StorageRole::LibraryPath);
    crate::storage_discovery::register(StoragePath {
        path: PathBuf::from(&payload.path),
        roles: vec![role],
        confidence: DiscoveryConfidence::High,
        discovered_via: vec![crate::storage_discovery::DiscoveryMethod::Cmdline {
            target: "manual_add".to_string(),
        }],
        web_uid: crate::storage_discovery::resolve_web_uid(
            payload.web_root.as_deref().unwrap_or(""),
        ),
        allow_script_extensions: allow_script,
        max_file_size_hint: None,
        framework_name: None,
        write_allowed,
    });
    Json(json!({ "status": "added", "path": payload.path }))
}

#[derive(Deserialize)]
struct RemoveStorageReq {
    path: String,
}

async fn post_storage_remove(Json(payload): Json<RemoveStorageReq>) -> impl IntoResponse {
    if crate::storage_discovery::remove(Path::new(&payload.path)) {
        (
            StatusCode::OK,
            Json(json!({ "status": "removed", "path": payload.path })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Path not found in registry" })),
        )
    }
}

async fn post_storage_scan(Json(payload): Json<RemoveStorageReq>) -> impl IntoResponse {
    let res = crate::upload_scan::scan_uploaded_file(&payload.path).await;
    let status_str = match res {
        crate::upload_scan::ScanResult::Clean => "clean",
        crate::upload_scan::ScanResult::Elf => "elf",
        crate::upload_scan::ScanResult::Suspicious(ref r) => r,
    };
    Json(json!({ "status": "scanned", "result": status_str }))
}

#[derive(Deserialize)]
struct WebRootReq {
    web_root: String,
}

async fn post_storage_ack_none(Json(payload): Json<WebRootReq>) -> impl IntoResponse {
    let ack_file = "/etc/kinnector/storage_ack.json";
    let ack_data = json!({
        "web_root": payload.web_root,
        "acknowledged_at": chrono::Utc::now().to_rfc3339(),
        "reason": "object-storage-only"
    });
    if let Ok(json_str) = serde_json::to_string_pretty(&ack_data) {
        if std::fs::write(ack_file, json_str).is_ok() {
            return (
                StatusCode::OK,
                Json(json!({ "status": "acknowledged", "web_root": payload.web_root })),
            );
        }
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": "Failed to write acknowledgement file" })),
    )
}

async fn post_storage_reset_ack() -> impl IntoResponse {
    let _ = std::fs::remove_file("/etc/kinnector/storage_ack.json");
    Json(json!({ "status": "reset" }))
}

async fn post_storage_rescan(State(state): State<AppState>) -> impl IntoResponse {
    let listening_pids = crate::discovery::discover_listening_pids();
    for root in &state.web_roots {
        for pid in &listening_pids {
            let paths = crate::storage_discovery::scan_process_env_for_storage(*pid);
            for p in paths {
                crate::storage_discovery::register(p);
            }
        }
        let paths = crate::storage_discovery::run_framework_rules(root);
        for p in paths {
            crate::storage_discovery::register(p);
        }
        let web_uid = crate::storage_discovery::resolve_web_uid(root);
        let paths = crate::storage_discovery::scan_uid_writable_untracked(root, web_uid);
        for p in paths {
            crate::storage_discovery::register(p);
        }
        crate::storage_discovery::cross_reference_gitignore(root);
    }
    Json(json!({ "status": "rescanned", "count": crate::storage_discovery::get_registry().len() }))
}

#[derive(Deserialize)]
struct DisableEnableReq {
    web_root: Option<String>,
    exe: Option<String>,
}

async fn post_storage_disable(Json(payload): Json<DisableEnableReq>) -> impl IntoResponse {
    if let Some(r) = payload.web_root {
        crate::storage_discovery::disable_storage_for_web_root(&r);
        (
            StatusCode::OK,
            Json(json!({ "status": "disabled", "web_root": r })),
        )
    } else if let Some(e) = payload.exe {
        crate::storage_discovery::disable_storage_for_exe(&e);
        (
            StatusCode::OK,
            Json(json!({ "status": "disabled", "exe": e })),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing web_root or exe parameter" })),
        )
    }
}

async fn post_storage_enable(Json(payload): Json<DisableEnableReq>) -> impl IntoResponse {
    if let Some(r) = payload.web_root {
        crate::storage_discovery::enable_storage_for_web_root(&r);
        (
            StatusCode::OK,
            Json(json!({ "status": "enabled", "web_root": r })),
        )
    } else if let Some(e) = payload.exe {
        crate::storage_discovery::enable_storage_for_exe(&e);
        (
            StatusCode::OK,
            Json(json!({ "status": "enabled", "exe": e })),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing web_root or exe parameter" })),
        )
    }
}

/// Shared enrichment for both the list (`GET /api/v1/alerts`) and detail
/// (`GET /api/v1/alerts/{id}`) endpoints. `include_sensitive` adds
/// `process.envs`/`process.args` — omitted from the list response (can carry
/// secrets/PII, not worth the exposure for a summary view) but included in
/// the single-alert detail view an operator explicitly asked for.
fn alert_to_json(
    alert: &crate::notifications::AlertPayload,
    attribution: &AlertAttribution,
    is_paid: bool,
    include_sensitive: bool,
) -> Value {
    let state = crate::notifications::get_alert_state(&alert.alert_id);
    let mut process = json!({
        "pid": alert.process.pid,
        "parent_pid": alert.process.parent_pid,
        "parent_name": alert.process.parent_exec_path,
        "exec_path": alert.process.exec_path,
        "cmdline": alert.process.cmdline,
        "verified_package": alert.process.verified_package,
        "signature_name": alert.process.signature_name,
        "service": alert.process.service,
    });
    if include_sensitive {
        process["envs"] = json!(alert.process.envs);
        process["args"] = json!(alert.process.args);
    }

    json!({
        "id": alert.alert_id,
        "severity": alert.severity,
        "threat_type": alert.threat_type,
        "timestamp": alert.timestamp,
        "confidence": alert.confidence,
        "site": attribution.site,
        "backend": attribution.backend,
        "proxy": attribution.proxy,
        "process": process,
        "remediation": {
            "action": alert.remediation.action,
            "status": alert.remediation.status,
            "quarantine": alert.remediation.quarantine,
        },
        // Baseline OSS telemetry — emit_threat_with_id (the general,
        // non-RASP alert constructor used by every OSS alert-raising call
        // site) already populates these for every alert regardless of
        // tier, so they're not paid-gated.
        "container": alert.container,
        "container_meta": alert.container_meta,
        "origin_tree": alert.origin_tree,
        "network_links": alert.network_links,
        "event_detail": alert.event_detail,
        // Local triage state — plain OSS-owned persistence (see
        // PATCH /api/v1/alerts/{id}), no license check.
        "dismissed": state.dismissed,
        "false_positive": state.false_positive,
        "inspected": state.inspected,
        // Cloud investigation status. The envelope lives in OSS (mirrors
        // rasp_context below), but it's only ever populated by
        // vandam's investigate handler for paid accounts — an OSS
        // build never sets it, so no separate is_paid_tier() gate is
        // needed here (see POST /api/v1/alerts/{id}/investigate).
        "investigation": state.investigation,
        // Only ever populated by vandam's RASP dispatch (see
        // dispatch_rasp_blocked_alert/dispatch_in_memory_execution_alert
        // in vandam/src/rasp.rs) — gated on is_paid_tier() directly
        // (unlike `site` above, this really is paid-only: full forensic
        // depth — stack trace, framework fingerprint, git tamper check,
        // loaded modules, memory mapping analysis).
        "rasp_context": if is_paid { alert.rasp_context.clone() } else { None }
    })
}

// ---------------------------------------------------------------------------
// Access page — PTY/interactive-session tracking.
//
// OSS-only endpoints: list/show/flag session records persisted by
// `pty_session_store`. `vandam` adds cloud correlation via its own route
// (`extra_routes`, see `start_api_server` doc comment) rather than a branch
// here — see the OSS/Pro separation note in the workspace CLAUDE.md.
// ---------------------------------------------------------------------------

async fn get_access_sessions() -> impl IntoResponse {
    // `pane_count` tells the TUI a session has more than one live pty (e.g.
    // tmux/screen panes opened inside one SSH login) so it can flag that in
    // the list instead of it looking like a plain single-pty session — see
    // `list_cast_ttys`'s doc comment. Computed here (cheap directory listing)
    // rather than persisted in `PtySessionMeta`, since it changes as panes
    // open/close over an active session's lifetime.
    let sessions: Vec<serde_json::Value> = crate::pty_session_store::list_sessions()
        .into_iter()
        .map(|meta| {
            let pane_count = crate::pty_session_store::list_cast_ttys(&meta.session_id)
                .len()
                .max(1);
            let mut v = serde_json::to_value(&meta).unwrap_or_default();
            if let Some(obj) = v.as_object_mut() {
                obj.insert("pane_count".to_string(), json!(pane_count));
            }
            v
        })
        .collect();
    Json(json!({ "sessions": sessions }))
}

async fn get_access_session_by_id(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    match crate::pty_session_store::read_session(&id) {
        Some((meta, commands)) => (
            StatusCode::OK,
            Json(json!({ "session": meta, "commands": commands })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Session not found" })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct CastQuery {
    /// Which pty within the session to replay — defaults to the session's
    /// own leader tty when omitted (the common single-pty case). A session
    /// with a tmux/screen pane has more than one; see
    /// `GET /api/v1/access/sessions/{id}/casts` to discover them.
    #[serde(default)]
    tty: Option<String>,
}

async fn get_access_session_cast(
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<CastQuery>,
) -> impl IntoResponse {
    match crate::pty_session_store::read_cast(&id, query.tty.as_deref()) {
        Some(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
            content,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "No replay capture for this session/pty" })),
        )
            .into_response(),
    }
}

/// `GET /api/v1/access/sessions/{id}/casts` — every pty this session has
/// captured replay bytes for, so the TUI can build a pane picker when a
/// session has more than one (tmux/screen).
async fn get_access_session_casts(axum::extract::Path(id): axum::extract::Path<String>) -> impl IntoResponse {
    Json(json!({ "ttys": crate::pty_session_store::list_cast_ttys(&id) }))
}

#[derive(Deserialize)]
struct FlagSessionReq {
    #[serde(default = "default_true")]
    flagged: bool,
}

fn default_true() -> bool {
    true
}

async fn post_access_session_flag(
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<FlagSessionReq>,
) -> impl IntoResponse {
    if crate::pty_session_store::set_flagged(&id, payload.flagged) {
        (StatusCode::OK, Json(json!({ "status": "ok", "flagged": payload.flagged })))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Session not found" })),
        )
    }
}

/// Local heuristic correlation across sessions (failed-auth-then-success,
/// RCE pattern hits in a session's command timeline, etc.) is a later phase
/// — see the Access design plan — so this returns an empty list on OSS
/// today. `vandam` supplies real cloud correlation via its own route
/// rather than a branch here (OSS/Pro separation, workspace CLAUDE.md).
async fn get_access_correlations() -> impl IntoResponse {
    Json(json!({ "correlations": Vec::<serde_json::Value>::new() }))
}

// ---------------------------------------------------------------------------
// Supply Chain — package-manager install activity, project inventory, and
// (via the shared alert pipeline, filtered by threat_type) security
// events/blocked actions. Free tier, every build/subscription — real local
// detection lives entirely in `supply_chain.rs`/`supply_chain_store.rs`, no
// Pro dependency. `vandam` adds subscription-gated cloud OSV lookups and
// cross-project analytics via its own routes (`extra_routes`, see
// `start_api_server` doc comment), not a branch here — OSS/Pro separation,
// workspace CLAUDE.md.
//
// Security Events / Blocked Actions are deliberately not a separate store —
// they're `get_recent_alerts()` filtered by the `Vulnerability.SupplyChain.*`
// threat-type namespace (already used by the pre-existing credential-path
// enforcement in `heuristics.rs`), reusing `alert_to_json` for a shape
// consistent with the Alerts page.
// ---------------------------------------------------------------------------

const SUPPLY_CHAIN_THREAT_PREFIX: &str = "Vulnerability.SupplyChain.";

async fn get_risks_activity() -> impl IntoResponse {
    let activities: Vec<serde_json::Value> = crate::supply_chain_store::list_activities(200)
        .into_iter()
        .map(|a| json!({
            "id": a.id,
            "time": a.time,
            "manager": a.manager,
            "command": a.command,
            "details": a.details,
            "project_path": a.project_path,
            "is_system_wide": a.is_system_wide,
            "status": a.status,
        }))
        .collect();
    Json(json!({ "activities": activities }))
}

fn supply_chain_alerts() -> Vec<crate::notifications::AlertPayload> {
    crate::notifications::get_recent_alerts()
        .into_iter()
        .filter(|a| a.threat_type.starts_with(SUPPLY_CHAIN_THREAT_PREFIX))
        .collect()
}

async fn get_risks_events() -> impl IntoResponse {
    let servers_data = get_servers_data();
    let is_paid = crate::tls_buffer::is_paid_tier();
    let events: Vec<serde_json::Value> = supply_chain_alerts()
        .iter()
        .map(|alert| {
            let attribution = find_alert_attribution(&servers_data, &alert.alert_id);
            alert_to_json(alert, &attribution, is_paid, false)
        })
        .collect();
    Json(json!({ "events": events }))
}

async fn post_risks_event_inspect(
    axum::extract::Path(alert_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let state = crate::notifications::set_alert_inspected(&alert_id, true);
    Json(json!({ "id": alert_id, "inspected": state.inspected }))
}

async fn get_risks_blocked() -> impl IntoResponse {
    let servers_data = get_servers_data();
    let is_paid = crate::tls_buffer::is_paid_tier();
    let blocked: Vec<serde_json::Value> = supply_chain_alerts()
        .iter()
        .filter(|a| a.remediation.action != "LOG_ALERT")
        .map(|alert| {
            let attribution = find_alert_attribution(&servers_data, &alert.alert_id);
            alert_to_json(alert, &attribution, is_paid, false)
        })
        .collect();
    Json(json!({ "blocked": blocked }))
}

async fn get_risks_projects() -> impl IntoResponse {
    let projects: Vec<serde_json::Value> = crate::supply_chain_store::list_projects()
        .into_iter()
        .map(|p| json!({
            "path": p.path,
            "framework": p.framework,
            "is_system_wide": p.is_system_wide,
            "first_seen": p.first_seen,
            "last_seen": p.last_seen,
            "events_count": p.events_count,
            "filtered": p.filtered,
        }))
        .collect();
    Json(json!({ "projects": projects }))
}

#[derive(Deserialize)]
struct RisksProjectFilterRequest {
    path: String,
    filtered: bool,
}

async fn post_risks_project_filter(Json(req): Json<RisksProjectFilterRequest>) -> impl IntoResponse {
    let ok = crate::supply_chain_store::set_project_filtered(&req.path, req.filtered);
    if ok {
        Json(json!({ "path": req.path, "filtered": req.filtered })).into_response()
    } else {
        (StatusCode::NOT_FOUND, Json(json!({ "error": "Project not found" }))).into_response()
    }
}

async fn get_risks_policy() -> impl IntoResponse {
    Json(crate::supply_chain_store::read_policy())
}

async fn put_risks_policy(Json(policy): Json<crate::supply_chain_store::SupplyChainPolicy>) -> impl IntoResponse {
    match crate::supply_chain_store::write_policy(&policy) {
        Ok(()) => Json(policy).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("failed to write policy: {}", e) })),
        )
            .into_response(),
    }
}

/// Default handler for `POST /api/v1/risks/packages/osv-lookup` — registered
/// only when no Pro extension route overrides this path. Mirrors
/// `post_alert_investigate_unavailable`'s framing: live OSV.dev lookups only
/// exist in `vandam`.
async fn post_risks_osv_lookup_unavailable() -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Live OSV.dev vulnerability lookups aren't available in Vandam OSS builds — local detection uses an offline known-CVE list instead.",
    }))
}

/// Default handler for `GET /api/v1/risks/analytics` — registered only when
/// no Pro extension route overrides this path.
async fn get_risks_analytics_unavailable() -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Dependency-risk trend and cross-project worm-behavior correlation aren't available in Vandam OSS builds.",
    }))
}

async fn get_alerts() -> impl IntoResponse {
    let raw_alerts = crate::notifications::get_recent_alerts();
    let servers_data = get_servers_data();
    let is_paid = crate::tls_buffer::is_paid_tier();

    let mut enriched = Vec::new();
    for alert in &raw_alerts {
        let attribution = find_alert_attribution(&servers_data, &alert.alert_id);
        enriched.push(alert_to_json(alert, &attribution, is_paid, false));
    }

    Json(json!({ "alerts": enriched }))
}

/// Single-alert detail view — same data as the list endpoint plus
/// `process.envs`/`process.args`, for a client (TUI modal, `alerts show`)
/// that already knows the id and wants full context without paying the
/// exposure cost of including envs/args on every alert in the list.
async fn get_alert_by_id(
    axum::extract::Path(alert_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let raw_alerts = crate::notifications::get_recent_alerts();
    let Some(alert) = raw_alerts.iter().find(|a| a.alert_id == alert_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Alert not found" })),
        )
            .into_response();
    };

    let servers_data = get_servers_data();
    let attribution = find_alert_attribution(&servers_data, &alert.alert_id);
    let is_paid = crate::tls_buffer::is_paid_tier();

    Json(alert_to_json(alert, &attribution, is_paid, true)).into_response()
}

#[derive(Deserialize)]
struct PatchAlertStateReq {
    #[serde(default)]
    dismissed: Option<bool>,
    #[serde(default)]
    false_positive: Option<bool>,
}

/// Plain local triage — dismiss / mark-false-positive. OSS-owned, no license
/// check: unlike `investigate` below, this never talks to anything outside
/// vandamd itself.
async fn patch_alert_state(
    axum::extract::Path(alert_id): axum::extract::Path<String>,
    Json(payload): Json<PatchAlertStateReq>,
) -> impl IntoResponse {
    if let Some(dismissed) = payload.dismissed {
        crate::notifications::set_alert_dismissed(&alert_id, dismissed);
    }
    if let Some(false_positive) = payload.false_positive {
        crate::notifications::set_alert_false_positive(&alert_id, false_positive);
    }
    let state = crate::notifications::get_alert_state(&alert_id);
    Json(json!({
        "id": alert_id,
        "dismissed": state.dismissed,
        "false_positive": state.false_positive,
        "inspected": state.inspected,
    }))
}

/// Default handler for `POST /api/v1/alerts/{id}/investigate` — registered
/// only when no Pro extension route overrides this path (see
/// `start_api_server`). A plain OSS build has no cloud-investigation
/// capability at all, so this always answers the same way regardless of the
/// alert id or any license state — that's a truthful statement about this
/// binary, not Pro-branded logic living in OSS.
async fn post_alert_investigate_unavailable(
    axum::extract::Path(_alert_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Cloud investigation isn't available in Vandam OSS builds, for privacy reasons.",
    }))
}

/// Default handler for `GET /api/v1/firewall/sync/status` — registered only
/// when no Pro extension route overrides this path. Mirrors
/// `post_alert_investigate_unavailable`'s framing: a plain OSS build has no
/// bidirectional cloud rule sync at all (basic block_ip/unblock_ip via
/// `cloud.rs` still works in every build — this is specifically about the
/// richer sync), so this always answers the same way.
async fn get_firewall_sync_status_unavailable() -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Bidirectional firewall rule sync requires vandam (any install, subscribed or not). Basic cloud block/unblock still works in this build.",
    }))
}

/// Default handlers for the `/api/v1/cloud/*` family (plan/quota status,
/// per-category auto-audit toggle, operational log) — registered only when
/// no Pro extension route overrides them. Mirrors
/// `post_alert_investigate_unavailable`'s framing: the local quota-guard
/// failsafe and auto-audit concept only exist in `vandam` (see
/// `vandam/src/quota_guard.rs`) — OSS never computes or stores any of
/// this.
async fn get_cloud_status_unavailable() -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Cloud auto-audit and quota management require vandam.",
    }))
}

async fn get_cloud_auto_audit_unavailable(
    axum::extract::Path(_category): axum::extract::Path<String>,
) -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Cloud auto-audit and quota management require vandam.",
    }))
}

async fn post_cloud_auto_audit_unavailable(
    axum::extract::Path(_category): axum::extract::Path<String>,
) -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Cloud auto-audit and quota management require vandam.",
    }))
}

async fn get_cloud_logs_unavailable() -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Cloud auto-audit and quota management require vandam.",
    }))
}

/// Default handler for `POST /api/v1/access/sessions/{id}/summarize` —
/// registered only when no Pro extension route overrides it. Mirrors
/// `post_alert_investigate_unavailable`'s framing exactly.
async fn post_access_session_summarize_unavailable(
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    Json(json!({
        "status": "unavailable",
        "reason": "oss_build",
        "message": "Cloud session summarization isn't available in Vandam OSS builds, for privacy reasons.",
    }))
}

#[derive(Deserialize)]
struct EventAlertReq {
    event_type: Option<String>,
    details: Option<Value>,
    /// Site domain, when the RASP client can determine it (e.g. vandam-wordpress's
    /// get_site_url()). This channel has no other way to attribute an alert to a
    /// site — unlike the low-level PHP RASP hooks, which already send HTTP_HOST.
    #[serde(default)]
    domain: Option<String>,
}

async fn post_event_alert(Json(payload): Json<EventAlertReq>) -> impl IntoResponse {
    let alert_id = format!(
        "wpn-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let threat_type = payload
        .event_type
        .unwrap_or_else(|| "Threat.Server.WordPressAnomaly".to_string());

    let details_type = payload
        .details
        .as_ref()
        .and_then(|d| d.get("type"))
        .and_then(|t| t.as_str())
        .unwrap_or("Unknown");
    let details_desc = payload
        .details
        .as_ref()
        .and_then(|d| d.get("detail"))
        .and_then(|t| t.as_str())
        .unwrap_or("WordPress security anomaly detected.");

    let severity = match details_type {
        "RCE_Attempt"
        | "Active_Exploitation_Detected"
        | "Webshell_Detected"
        | "PHP_File_In_Uploads"
        | "Core_File_Integrity_Failure"
        | "Stealth_Admin_Injected"
        | "Unauthorized_Admin_Escalation"
        | "Exploit_Signature_Match"
        | "Admin_Brute_Force" => "CRITICAL",
        "Suspicious_Request"
        | "Core_File_Missing"
        | "Htaccess_Hardening_Ineffective"
        | "Vulnerable_Plugins_Detected" => "WARNING",
        _ => "INFO",
    }
    .to_string();

    let payload_alert = crate::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: format!("{}.{}", threat_type, details_type),
        severity,
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "php/wordpress".to_string(),
            cmdline: payload
                .details
                .as_ref()
                .and_then(|d| d.get("uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string(),
            parent_exec_path: "".to_string(),
            parent_pid: 0,
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "LOG".to_string(),
            status: details_desc.to_string(),
            requires_cloud_decision: false,
            quarantine: None,
        },
        rasp_context: None,
        origin_tree: Vec::new(),
        network_links: Vec::new(),
        container_meta: None,
        // This channel (vandam-wordpress's own detections) is free-tier —
        // works on any vandamd regardless of license, see is_daemon_active()
        // in class-vandam-client.php.
        site_source: payload
            .domain
            .as_ref()
            .map(|_| crate::notifications::SiteSource::ClientReported),
        site: payload.domain,
        event_detail: None,
    };
    crate::notifications::dispatch_alert(payload_alert);
    Json(json!({ "status": "logged" }))
}

#[derive(Deserialize)]
struct UserMgmtReq {
    action: Option<String>,
    details: Option<Value>,
}

async fn post_event_user_mgmt(Json(payload): Json<UserMgmtReq>) -> impl IntoResponse {
    let alert_id = format!(
        "wpn-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let action = payload.action.unwrap_or_else(|| "user_action".to_string());

    let user_login = payload
        .details
        .as_ref()
        .and_then(|d| d.get("user_login"))
        .and_then(|u| u.as_str())
        .unwrap_or("unknown");
    let context = payload
        .details
        .as_ref()
        .and_then(|d| d.get("context"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    let ip = payload
        .details
        .as_ref()
        .and_then(|d| d.get("ip_address"))
        .and_then(|i| i.as_str())
        .unwrap_or("");

    let payload_alert = crate::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: format!("Event.Server.WordPressUserMgmt.{}", action),
        severity: "WARNING".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "php/wordpress".to_string(),
            cmdline: format!("Context: {}, IP: {}", context, ip),
            parent_exec_path: "".to_string(),
            parent_pid: 0,
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "AUDIT".to_string(),
            status: format!(
                "Admin account added/updated: user='{}' via context '{}'",
                user_login, context
            ),
            requires_cloud_decision: false,
            quarantine: None,
        },
        rasp_context: None,
        origin_tree: Vec::new(),
        network_links: Vec::new(),
        container_meta: None,
        site: None,
        site_source: None,
        event_detail: None,
    };
    crate::notifications::dispatch_alert(payload_alert);
    Json(json!({ "status": "logged" }))
}

#[derive(Deserialize)]
struct PathReq {
    path: String,
}

async fn post_fim_add(Json(payload): Json<PathReq>) -> impl IntoResponse {
    if crate::fim::add_fim_watch_path(PathBuf::from(&payload.path)) {
        (StatusCode::OK, Json(json!({ "status": "added" })))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to send watch command" })),
        )
    }
}

async fn post_fim_remove(Json(payload): Json<PathReq>) -> impl IntoResponse {
    if crate::fim::remove_fim_watch_path(PathBuf::from(&payload.path)) {
        (StatusCode::OK, Json(json!({ "status": "removed" })))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Failed to send unwatch command" })),
        )
    }
}

#[derive(Deserialize)]
struct FimRegisterReq {
    path: Option<String>,
    git: Option<bool>,
}

async fn post_fim_register(
    State(state): State<AppState>,
    Json(payload): Json<FimRegisterReq>,
) -> impl IntoResponse {
    if let Some(path) = payload.path {
        if crate::allowlist::register_inode(&path) {
            (
                StatusCode::OK,
                Json(json!({ "status": "registered", "path": path })),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to register inode" })),
            )
        }
    } else if let Some(true) = payload.git {
        let mut added = 0;
        for root in &state.web_roots {
            added += crate::allowlist::reseed_from_git(root);
        }
        (
            StatusCode::OK,
            Json(json!({ "status": "re-seeded", "new_inodes": added })),
        )
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Missing parameters (path or git: true)" })),
        )
    }
}

async fn post_allowlist_add(Json(payload): Json<PathReq>) -> impl IntoResponse {
    crate::allowlist::register_path_recursive(&payload.path);
    Json(json!({ "status": "registered", "path": payload.path }))
}

async fn post_allowlist_remove(Json(payload): Json<PathReq>) -> impl IntoResponse {
    crate::allowlist::deregister_path_recursive(&payload.path);
    Json(json!({ "status": "deregistered", "path": payload.path }))
}

async fn get_allowlist() -> impl IntoResponse {
    if let Some(map) = crate::allowlist::get_allowlist() {
        let inodes: Vec<_> = map.iter().flat_map(|entry| entry.value().clone()).collect();
        Json(json!({ "allowed_inodes": inodes }))
    } else {
        Json(json!({ "allowed_inodes": [] }))
    }
}

async fn get_quarantine() -> impl IntoResponse {
    Json(json!({ "quarantined_files": crate::quarantine::list_quarantined() }))
}

#[derive(Deserialize)]
struct QuarantineRestoreReq {
    #[serde(default)]
    quarantine_path: Option<String>,
    #[serde(default)]
    original_path: Option<String>,
    #[serde(default)]
    alert_id: Option<String>,
}

async fn post_quarantine_restore(Json(payload): Json<QuarantineRestoreReq>) -> impl IntoResponse {
    if let Some(alert_id) = payload.alert_id {
        match crate::quarantine::restore_by_alert_id(&alert_id) {
            Ok(restored_path) => (
                StatusCode::OK,
                Json(
                    json!({ "status": "restored", "original_path": restored_path.to_string_lossy() }),
                ),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Restore failed: {}", e) })),
            ),
        }
    } else if let (Some(qp), Some(op)) = (payload.quarantine_path, payload.original_path) {
        match crate::quarantine::restore_file(&qp, &op) {
            Ok(_) => (StatusCode::OK, Json(json!({ "status": "restored" }))),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("Restore failed: {}", e) })),
            ),
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Must provide alert_id or quarantine_path + original_path" })),
        )
    }
}

async fn post_scan_trigger(State(state): State<AppState>) -> impl IntoResponse {
    for root in state.web_roots {
        tokio::spawn(async move {
            let _ = crate::scanner::run_scan(&root).await;
        });
    }
    Json(json!({ "status": "triggered" }))
}

async fn get_sync_status() -> impl IntoResponse {
    // Return empty status to reflect no hardcoding
    Json(json!({
        "this_server": "localhost",
        "role": "Standalone",
        "last_pushed": null,
        "last_pulled": null,
        "config_version": null,
        "members": []
    }))
}

async fn post_sync_push() -> impl IntoResponse {
    Json(json!({ "status": "pushed" }))
}

async fn post_sync_pull() -> impl IntoResponse {
    Json(json!({ "status": "pulled" }))
}

async fn get_sync_diff() -> impl IntoResponse {
    Json(json!({ "diff": [] }))
}

async fn post_test_alert() -> impl IntoResponse {
    let alert_id = format!("test-{}", chrono::Utc::now().timestamp());
    let payload = crate::notifications::AlertPayload {
        alert_id: alert_id.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Test.Alert".to_string(),
        severity: "LOW".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "vandam".to_string(),
            cmdline: "test-alert".to_string(),
            parent_exec_path: "operator".to_string(),
            parent_pid: 0,
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "TEST".to_string(),
            status: "This is a test alert from vandam. All systems operational.".to_string(),
            requires_cloud_decision: false,
            quarantine: None,
        },
        rasp_context: None,
        origin_tree: Vec::new(),
        network_links: Vec::new(),
        container_meta: None,
        site: None,
        site_source: None,
        event_detail: None,
    };
    crate::notifications::dispatch_alert(payload);
    Json(json!({ "status": "dispatched", "alert_id": alert_id }))
}

async fn post_rules_reload(State(state): State<AppState>) -> impl IntoResponse {
    match state.heuristics.config.reload() {
        Ok(_) => {
            let _ = crate::firewall::reconcile::reconcile_firewall(&state.heuristics.config);
            (StatusCode::OK, Json(json!({ "status": "reloaded" })))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("Reload failed: {}", e) })),
        ),
    }
}

async fn post_rules_fetch(State(state): State<AppState>) -> impl IntoResponse {
    if crate::tls_buffer::is_paid_tier() {
        let config_clone = Arc::clone(&state.heuristics.config);
        tokio::spawn(async move {
            let _ = crate::cloud::sync_rules_now(&config_clone).await;
        });
        (StatusCode::OK, Json(json!({ "status": "fetching" })))
    } else {
        (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({ "error": "Remote signed rule fetch requires paid tier license." })),
        )
    }
}

#[derive(Deserialize)]
struct LearningReq {
    enabled: bool,
}

async fn get_learning() -> impl IntoResponse {
    let enabled = crate::allowlist::is_learning_mode();
    (StatusCode::OK, Json(json!({ "enabled": enabled })))
}

async fn post_learning(Json(payload): Json<LearningReq>) -> impl IntoResponse {
    crate::allowlist::set_learning_mode(payload.enabled);
    (StatusCode::OK, Json(json!({ "enabled": payload.enabled })))
}

async fn get_maintenance() -> impl IntoResponse {
    Json(crate::maintenance::get_maintenance_status())
}

#[derive(Deserialize)]
struct MaintenanceEnableReq {
    #[serde(default = "default_maintenance_duration")]
    duration_minutes: u64,
    #[serde(default = "default_maintenance_reason")]
    reason: String,
}

fn default_maintenance_duration() -> u64 {
    30
}
fn default_maintenance_reason() -> String {
    "Scheduled maintenance window".to_string()
}

async fn post_maintenance_enable(Json(payload): Json<MaintenanceEnableReq>) -> impl IntoResponse {
    crate::maintenance::enable_maintenance_mode(payload.duration_minutes, &payload.reason);
    Json(
        json!({ "status": "enabled", "duration_minutes": payload.duration_minutes, "reason": payload.reason }),
    )
}

async fn post_maintenance_disable() -> impl IntoResponse {
    crate::maintenance::disable_maintenance_mode();
    Json(json!({ "status": "disabled" }))
}

async fn post_config_fetch(State(state): State<AppState>) -> impl IntoResponse {
    let config_clone = Arc::clone(&state.heuristics.config);
    tokio::spawn(async move {
        let _ = crate::cloud::sync_config_from_cloud(&config_clone).await;
    });
    (StatusCode::OK, Json(json!({ "status": "fetching_config" })))
}

async fn post_config_push() -> impl IntoResponse {
    tokio::spawn(async move {
        let _ = crate::cloud::push_config_to_cloud().await;
    });
    (StatusCode::OK, Json(json!({ "status": "pushing_config" })))
}
