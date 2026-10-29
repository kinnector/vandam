use serde::Deserialize;

/// One row of `servers list`: a proxy/daemon group header, a site, or a writable directory under it.
#[derive(Clone, Debug)]
pub struct ServerTarget {
    pub id: usize,
    pub tree_label: String,
    pub name: String,
    pub ports: String,
    pub stack: String,
    pub status: String,
    pub path: String,
    pub is_group: bool,
    pub trusted: bool,
    /// Other domains sharing this row's runtime pool — see `SiteNode::shared_with`.
    pub shared_with: Vec<String>,
}

/// Real (non-mock) server/site topology, mirroring vandamd's ServersData
/// (`vandam/src/api.rs`). Counterpart to `daemon_status.rs` — the shape is
/// shared between `/api/v1/servers` (dedicated Servers-tab fetch) and
/// `/api/v1/status`'s embedded `discovered_servers` (Status tab row 2),
/// since vandamd's `get_status()` literally calls `get_servers_data()`.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct ServersData {
    #[serde(default)]
    pub proxies: Vec<ProxyNode>,
    #[serde(default)]
    pub direct_http: Vec<DirectHttpNode>,
    #[serde(default)]
    pub standalones: Vec<StandaloneNode>,
    #[serde(default)]
    pub daemons: Vec<DaemonNode>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct AlertNode {
    #[serde(default)]
    pub severity: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct ProxyNode {
    pub name: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub downstream_proxies: Vec<ProxyNode>,
    #[serde(default)]
    pub runtimes: Vec<RuntimeNode>,
    pub is_running: bool,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    #[serde(default)]
    pub config_dir: Option<String>,
    #[serde(default)]
    pub trusted: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RuntimeNode {
    pub name: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub sockets: Vec<String>,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub sites: Vec<SiteNode>,
    pub is_running: bool,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    #[serde(default)]
    pub trusted: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct SiteNode {
    pub domain: String,
    #[serde(default)]
    pub stack: serde_json::Value,
    #[serde(default)]
    pub framework: Option<FrameworkInfo>,
    pub directory: String,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    pub is_running: bool,
    #[serde(default)]
    pub allowed_dirs: Vec<String>,
    pub is_restricted: bool,
    #[serde(default)]
    pub trusted: bool,
    /// Other domains sharing this site's runtime pool — non-empty whenever
    /// the pool actually is shared, regardless of `trusted`, so the TUI/CLI
    /// can warn *before* the user commits: trusting a site with no isolated
    /// process of its own trusts the whole shared runtime, and every
    /// sibling domain goes untraced too.
    #[serde(default)]
    pub shared_with: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct FrameworkInfo {
    pub name: String,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DirectHttpNode {
    pub name: String,
    #[serde(default)]
    pub stack: serde_json::Value,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub directory: String,
    pub is_running: bool,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    pub is_restricted: bool,
    #[serde(default)]
    pub trusted: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct StandaloneNode {
    pub name: String,
    #[serde(default)]
    pub stack: serde_json::Value,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub directory: String,
    pub is_running: bool,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    pub is_restricted: bool,
    #[serde(default)]
    pub trusted: bool,
}

#[derive(Deserialize, Clone, Debug)]
pub struct DaemonNode {
    pub name: String,
    #[serde(default)]
    pub ports: Vec<u16>,
    pub directory: String,
    pub is_running: bool,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    pub is_restricted: bool,
    #[serde(default)]
    pub stack: Option<serde_json::Value>,
    #[serde(default)]
    pub trusted: bool,
}

pub fn fetch(socket_path: &str) -> Result<ServersData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/servers", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/servers response: {}", e))
}

#[derive(Deserialize, Clone, Debug)]
struct UserRule {
    id: String,
    rule_type: String,
    target: String,
}

fn find_trust_rule(socket_path: &str, path: &str) -> Result<Option<UserRule>, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/rules/user", None)?;
    let rules: Vec<UserRule> = value
        .get("user_rules")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Ok(rules.into_iter().find(|r| r.rule_type == "ALLOW_SERVER_PATH" && r.target == path))
}

/// Trusts a server/site/proxy/daemon path — vandamd resolves which
/// currently-running process(es) that path matches and grants them full
/// trust (see `vandam/src/trust.rs`: file, exec, network, escape-protection
/// — everything). Anchored on path, not pid, so it's re-resolved fresh on
/// every `/api/v1/servers` fetch rather than pinned to a process that may
/// restart. Shared by the CLI's `servers trust` and the TUI's `[t]` key.
pub fn trust(socket_path: &str, path: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "rule_type": "ALLOW_SERVER_PATH",
        "target": path,
        "scope": "site",
    });
    crate::query_daemon(socket_path, "POST", "/api/v1/rules/user/add", Some(&body)).map(|_| ())
}

/// Untrusts a path: finds the matching `ALLOW_SERVER_PATH` rule and deletes
/// it by id (same two-step flow as `containers_data::untrust`, since
/// `DELETE /api/v1/rules/user` only takes a rule id).
pub fn untrust(socket_path: &str, path: &str) -> Result<(), String> {
    let rule = find_trust_rule(socket_path, path)?
        .ok_or_else(|| format!("Path '{}' is not currently trusted.", path))?;
    let body = serde_json::json!({ "id": rule.id });
    crate::query_daemon(socket_path, "DELETE", "/api/v1/rules/user", Some(&body)).map(|_| ())
}

/// Parses the `discovered_servers` sub-object already embedded in
/// `/api/v1/status`'s response — used by the Status tab's row 2 so it
/// doesn't need a second daemon round trip.
pub fn from_status_json(value: &serde_json::Value) -> ServersData {
    value.get("discovered_servers")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// True if any discovered runtime looks like a PHP-FPM pool. Used to show an
/// honest "site-to-alert attribution isn't possible in the OSS build" notice
/// — per-request site context (the HTTP Host header) only exists inside a
/// RASP-style hook in the request lifecycle; below that layer (where OSS's
/// kernel/eBPF telemetry operates) there's no way to recover it, full stop.
pub fn has_php_fpm_runtime(data: &ServersData) -> bool {
    fn proxy_has_php(proxy: &ProxyNode) -> bool {
        proxy.runtimes.iter().any(|rt| rt.name.to_lowercase().contains("php"))
            || proxy.downstream_proxies.iter().any(proxy_has_php)
    }
    data.proxies.iter().any(proxy_has_php)
}

fn stack_label(stack: &serde_json::Value) -> String {
    let name = stack.get("name").and_then(|v| v.as_str()).unwrap_or("");
    if name.is_empty() {
        return String::new();
    }
    match stack.get("version").and_then(|v| v.as_str()) {
        Some(version) if !version.is_empty() => format!("{} {}", name, version),
        _ => name.to_string(),
    }
}

fn row_status(is_running: bool, has_alerts: bool, is_restricted: bool, is_writable_row: bool) -> &'static str {
    if !is_running {
        "INACTIVE"
    } else if has_alerts {
        "WARNING"
    } else if is_restricted {
        "SHIELDED"
    } else if is_writable_row {
        "ACTIVE"
    } else {
        "SECURE"
    }
}

struct TargetBuilder {
    targets: Vec<ServerTarget>,
}

impl TargetBuilder {
    fn push(&mut self, tree_label: String, name: String, ports: String, stack: String, status: &str, path: String, is_group: bool) {
        let id = self.targets.len();
        self.targets.push(ServerTarget { id, tree_label, name, ports, stack, status: status.to_string(), path, is_group, trusted: false, shared_with: Vec::new() });
    }

    /// Sets trust state on the row just pushed — kept as a separate step
    /// rather than extra `push` params since most rows (group headers,
    /// synthetic writable-dir rows) have no real trust data of their own.
    fn set_trust(&mut self, trusted: bool, shared_with: Vec<String>) {
        if let Some(last) = self.targets.last_mut() {
            last.trusted = trusted;
            last.shared_with = shared_with;
        }
    }

    fn prefix(depth: usize, is_last: bool) -> String {
        if depth == 0 {
            String::new()
        } else {
            let mut s = String::new();
            for _ in 0..depth.saturating_sub(1) {
                s.push_str("    ");
            }
            s.push_str(if is_last { "└── " } else { "├── " });
            s
        }
    }

    fn push_writable_dirs(&mut self, dirs: &[String], depth: usize, is_restricted: bool) {
        let count = dirs.len();
        for (i, dir) in dirs.iter().enumerate() {
            let is_last = i + 1 == count;
            let label = format!("{}{} (writable)", Self::prefix(depth, is_last), dir);
            let exec_text = if is_restricted { "Exec: BLOCKED".to_string() } else { "Exec: DEFAULT POLICY".to_string() };
            self.push(label, format!("{} (Writable Dir)", dir), "-".to_string(), exec_text, "SHIELDED", dir.clone(), false);
        }
    }

    fn push_site(&mut self, site: &SiteNode, ports: &str, depth: usize, is_last: bool) {
        let framework = site.framework.as_ref().map(|f| f.name.as_str()).unwrap_or("");
        let stack = stack_label(&site.stack);
        let stack_text = if framework.is_empty() { stack } else if stack.is_empty() { framework.to_string() } else { format!("{} / {}", stack, framework) };
        let has_alerts = !site.alerts.is_empty();
        let status = row_status(site.is_running, has_alerts, site.is_restricted, false);
        let label = format!("{}{}", Self::prefix(depth, is_last && site.allowed_dirs.is_empty()), site.domain);
        self.push(label, format!("{} (Site)", site.domain), ports.to_string(), stack_text, status, site.directory.clone(), false);
        self.set_trust(site.trusted, site.shared_with.clone());
        self.push_writable_dirs(&site.allowed_dirs, depth + 1, site.is_restricted);
    }

    fn push_runtime(&mut self, rt: &RuntimeNode, depth: usize, is_last: bool) {
        let ports = if !rt.ports.is_empty() {
            rt.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")
        } else if let Some(s) = rt.sockets.first() {
            format!("unix:{}", s)
        } else {
            "-".to_string()
        };
        let has_alerts = !rt.alerts.is_empty();
        let status = row_status(rt.is_running, has_alerts, false, false);
        let label = format!("{}{}", Self::prefix(depth, is_last && rt.sites.is_empty()), rt.name);
        // Same fallback chain vandamd's reconcile pass uses to anchor trust
        // for a runtime with no config path of its own (see api.rs's
        // reconcile_server_trust) — trusting via this row must send the same
        // string the server will actually match against.
        let anchor_path = rt.sockets.first().cloned().or_else(|| rt.pool.clone()).unwrap_or_else(|| rt.name.clone());
        self.push(label, rt.name.clone(), ports.clone(), format!("{} sites", rt.sites.len()), status, anchor_path, false);
        self.set_trust(rt.trusted, Vec::new());

        let count = rt.sites.len();
        for (i, site) in rt.sites.iter().enumerate() {
            self.push_site(site, &ports, depth + 1, i + 1 == count);
        }
    }

    fn push_proxy(&mut self, proxy: &ProxyNode, depth: usize) {
        let site_count: usize = proxy.runtimes.iter().map(|rt| rt.sites.len()).sum();
        let stack = match &proxy.config_dir {
            Some(dir) => format!("{} ({} sites)", dir, site_count),
            None => format!("{} sites", site_count),
        };
        let has_alerts = !proxy.alerts.is_empty();
        let status = row_status(proxy.is_running, has_alerts, false, false);
        let label = format!("{}▼ {} (Reverse Proxy)", Self::prefix(depth, false), proxy.name);
        let path = proxy.config_dir.clone().unwrap_or_default();
        self.push(label, format!("{} (Reverse Proxy)", proxy.name), proxy.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "), stack, status, path, true);
        self.set_trust(proxy.trusted, Vec::new());

        let count = proxy.runtimes.len();
        for (i, rt) in proxy.runtimes.iter().enumerate() {
            self.push_runtime(rt, depth + 1, i + 1 == count);
        }
        for dp in &proxy.downstream_proxies {
            self.push_proxy(dp, depth + 1);
        }
    }
}

/// Pure, unit-testable: flattens vandamd's real server tree into the same
/// `ServerTarget` row shape the Servers tab table already renders.
pub fn build_server_targets(data: &ServersData) -> Vec<ServerTarget> {
    let mut b = TargetBuilder { targets: Vec::new() };

    for proxy in &data.proxies {
        b.push_proxy(proxy, 0);
    }

    if !data.direct_http.is_empty() {
        b.push("▼ Direct HTTP Services".to_string(), "Direct HTTP Services".to_string(), "-".to_string(), format!("{} services", data.direct_http.len()), "ACTIVE", String::new(), true);
        let count = data.direct_http.len();
        for (i, d) in data.direct_http.iter().enumerate() {
            let is_last = i + 1 == count;
            let stack = stack_label(&d.stack);
            let status = row_status(d.is_running, !d.alerts.is_empty(), d.is_restricted, false);
            let label = format!("{}{}", TargetBuilder::prefix(1, is_last), d.name);
            b.push(label, d.name.clone(), d.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "), stack, status, d.directory.clone(), false);
            b.set_trust(d.trusted, Vec::new());
        }
    }

    if !data.standalones.is_empty() {
        b.push("▼ Standalone Applications".to_string(), "Standalone Applications".to_string(), "-".to_string(), format!("{} apps", data.standalones.len()), "ACTIVE", String::new(), true);
        let count = data.standalones.len();
        for (i, s) in data.standalones.iter().enumerate() {
            let is_last = i + 1 == count;
            let stack = stack_label(&s.stack);
            let status = row_status(s.is_running, !s.alerts.is_empty(), s.is_restricted, false);
            let label = format!("{}{}", TargetBuilder::prefix(1, is_last), s.name);
            b.push(label, s.name.clone(), s.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "), stack, status, s.directory.clone(), false);
            b.set_trust(s.trusted, Vec::new());
        }
    }

    if !data.daemons.is_empty() {
        b.push("▼ System Daemons".to_string(), "System Daemons".to_string(), "-".to_string(), format!("{} daemons", data.daemons.len()), "ACTIVE", String::new(), true);
        let count = data.daemons.len();
        for (i, d) in data.daemons.iter().enumerate() {
            let is_last = i + 1 == count;
            let stack = d.stack.as_ref().map(stack_label).filter(|s| !s.is_empty()).unwrap_or_else(|| "N/A".to_string());
            let status = row_status(d.is_running, !d.alerts.is_empty(), d.is_restricted, false);
            let label = format!("{}{}", TargetBuilder::prefix(1, is_last), d.name);
            b.push(label, d.name.clone(), d.ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "), stack, status, d.directory.clone(), false);
            b.set_trust(d.trusted, Vec::new());
        }
    }

    b.targets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(domain: &str, allowed_dirs: Vec<&str>, is_restricted: bool) -> SiteNode {
        SiteNode {
            domain: domain.to_string(),
            stack: serde_json::json!({ "name": "PHP-FPM", "version": null }),
            framework: Some(FrameworkInfo { name: "Laravel".to_string() }),
            directory: format!("/var/www/{}", domain),
            alerts: Vec::new(),
            is_running: true,
            allowed_dirs: allowed_dirs.into_iter().map(|s| s.to_string()).collect(),
            is_restricted,
            trusted: false,
            shared_with: Vec::new(),
        }
    }

    fn sample_data() -> ServersData {
        ServersData {
            proxies: vec![ProxyNode {
                name: "nginx".to_string(),
                ports: vec![80, 443],
                downstream_proxies: Vec::new(),
                runtimes: vec![RuntimeNode {
                    name: "php-fpm".to_string(),
                    ports: Vec::new(),
                    sockets: vec!["fpm.sock".to_string()],
                    pool: None,
                    sites: vec![
                        site("example.com", vec!["/var/www/example.com/uploads"], true),
                        site("blog.example.com", vec![], false),
                    ],
                    is_running: true,
                    alerts: Vec::new(),
                    trusted: false,
                }],
                is_running: true,
                alerts: Vec::new(),
                config_dir: Some("/etc/nginx".to_string()),
                trusted: false,
            }],
            direct_http: Vec::new(),
            standalones: Vec::new(),
            daemons: vec![DaemonNode {
                name: "redis-server".to_string(),
                ports: vec![6379],
                directory: "/var/lib/redis".to_string(),
                is_running: true,
                alerts: Vec::new(),
                is_restricted: true,
                trusted: false,
                stack: Some(serde_json::json!({ "name": "redis-server", "version": "7.2.4" })),
            }],
        }
    }

    #[test]
    fn builds_group_header_for_proxy_and_daemons() {
        let targets = build_server_targets(&sample_data());
        assert!(targets[0].is_group);
        assert_eq!(targets[0].name, "nginx (Reverse Proxy)");
        assert!(targets.iter().any(|t| t.is_group && t.name == "System Daemons"));
    }

    #[test]
    fn writable_dir_becomes_child_row_of_its_site() {
        let targets = build_server_targets(&sample_data());
        let idx = targets.iter().position(|t| t.name == "example.com (Site)").unwrap();
        assert_eq!(targets[idx + 1].name, "/var/www/example.com/uploads (Writable Dir)");
        assert_eq!(targets[idx + 1].status, "SHIELDED");
    }

    #[test]
    fn site_without_writable_dirs_has_no_child_row() {
        let targets = build_server_targets(&sample_data());
        let idx = targets.iter().position(|t| t.name == "blog.example.com (Site)").unwrap();
        assert!(targets.get(idx + 1).map_or(true, |t| !t.name.contains("Writable Dir")));
    }

    #[test]
    fn has_php_fpm_runtime_detects_php_fpm_pool() {
        assert!(has_php_fpm_runtime(&sample_data()));
    }

    #[test]
    fn has_php_fpm_runtime_false_when_no_php_present() {
        let mut data = sample_data();
        data.proxies[0].runtimes[0].name = "node".to_string();
        assert!(!has_php_fpm_runtime(&data));
    }

    #[test]
    fn daemon_version_is_resolved_into_stack_text() {
        let targets = build_server_targets(&sample_data());
        let redis = targets.iter().find(|t| t.name == "redis-server").unwrap();
        assert_eq!(redis.stack, "redis-server 7.2.4");
    }

    #[test]
    fn status_derives_from_running_restricted_and_alerts() {
        let mut data = sample_data();
        data.proxies[0].runtimes[0].sites[0].alerts.push(AlertNode { severity: "CRITICAL".to_string() });
        let targets = build_server_targets(&data);
        let example = targets.iter().find(|t| t.name == "example.com (Site)").unwrap();
        assert_eq!(example.status, "WARNING");
    }

    #[test]
    fn not_running_reports_inactive_regardless_of_alerts() {
        let mut data = sample_data();
        data.proxies[0].runtimes[0].sites[0].is_running = false;
        let targets = build_server_targets(&data);
        let example = targets.iter().find(|t| t.name == "example.com (Site)").unwrap();
        assert_eq!(example.status, "INACTIVE");
    }

    #[test]
    fn from_status_json_extracts_discovered_servers_field() {
        let value = serde_json::json!({
            "discovered_servers": { "proxies": [], "direct_http": [], "standalones": [], "daemons": [] },
            "other_field": "ignored"
        });
        let data = from_status_json(&value);
        assert!(data.proxies.is_empty());
    }

    #[test]
    fn from_status_json_defaults_when_field_absent() {
        let data = from_status_json(&serde_json::json!({}));
        assert!(data.proxies.is_empty());
        assert!(data.daemons.is_empty());
    }
}
