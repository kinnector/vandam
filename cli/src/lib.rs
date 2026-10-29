use clap::{Parser, Subcommand};
use colored::Colorize;
use serde_json::{json, Value};
use std::path::PathBuf;

pub mod commands;
pub mod output;
pub mod client;

/// Direct signup/upgrade flow — for CTAs the operator reaches by explicitly
/// invoking a paid feature (they already know they want Pro, they just need
/// the link). Not for ambient/passive CTAs — see `learn_more_url` for those.
pub const PRO_URL: &str = "https://kinnector.dev/pro";

/// Content page explaining a specific problem before pitching a subscription
/// — for ambient CTAs (banners/lock-screens the operator sees just by
/// navigating a tab or running a routine command, not because they asked for
/// a paid feature). No such page exists yet on kinnector.dev; this is a
/// placeholder for whoever builds the marketing site to fill in — the point
/// of centralizing it here is that it only needs updating in one place once
/// real pages exist. `topic` becomes a URL path segment so different ambient
/// CTAs can eventually point at different specific pages (e.g. explaining
/// *why* an unaudited re-baseline is risky) instead of one generic pitch.
pub fn learn_more_url(topic: &str) -> String {
    format!("https://kinnector.dev/learn/{}", topic)
}

#[derive(Parser, Debug)]
#[command(name = "vandam")]
#[command(about = "vandam operator CLI", version)]
pub struct Cli {
    #[arg(long, default_value = "human", help = "Output format (human, json)")]
    pub output: String,

    #[arg(long, help = "Path to daemon Unix socket")]
    pub daemon_socket: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Show daemon health, LSM/eBPF mode, and config version
    Status,

    /// View or follow the alert audit log
    Alerts {
        #[command(subcommand)]
        action: AlertsAction,
    },

    /// Manage storage paths — per-path write/execute policy
    Storages {
        #[command(subcommand)]
        action: StoragesAction,
    },

    /// Manage custom allow/deny rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Show site-resolved server list and detail
    Servers {
        #[command(subcommand)]
        action: ServersAction,
    },

    /// Manage container trust and security
    Containers {
        #[command(subcommand)]
        action: ContainersAction,
    },

    /// Manage site-specific or global firewall blocks
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// File integrity monitoring — tracks watched files/directories for
    /// unexpected changes and lets you re-baseline after a legitimate one
    FileIntegrity {
        #[command(subcommand)]
        action: FileIntegrityAction,
    },

    /// Process management operations
    Process {
        #[command(subcommand)]
        action: ProcessAction,
    },

    /// Scan operations
    Scan {
        #[command(subcommand)]
        action: ScanAction,
    },

    /// Fleet config sync operations (Pro only)
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },

    /// Fire a test alert to all configured notification endpoints
    TestAlert,

    /// Print version
    Version,

    /// Apply setup non-interactively
    Setup {
        #[command(subcommand)]
        action: commands::setup::SetupAction,
    },

    /// View or toggle dynamic learning mode
    Learning {
        #[command(subcommand)]
        action: Option<LearningAction>,
    },

    /// Interactive session / correlation views
    Access {
        #[command(subcommand)]
        action: commands::access::AccessAction,
    },

    /// Cloud auto-audit config, quota/usage status, and the local-failsafe log
    Cloud {
        #[command(subcommand)]
        action: commands::cloud::CloudAction,
    },

    /// Deep forensic audit scans (config safety, binary/package integrity,
    /// live process/socket/PTY context, cloud correlation — distinct from
    /// `alerts`)
    Audit {
        #[command(subcommand)]
        action: commands::audit::AuditAction,
    },

    /// Supply-chain / package-manager risk views (free tier, real local
    /// detection; live OSV lookups/analytics are vandam subscriber-only)
    Risks {
        #[command(subcommand)]
        action: commands::risks::RisksAction,
    },

    /// Files moved aside after being flagged malicious — view or restore them
    Quarantine {
        #[command(subcommand)]
        action: QuarantineAction,
    },

    /// Trusted-file inode allowlist (paths exempt from tamper alerting —
    /// distinct from `file-integrity register`, which manages the file
    /// integrity baseline itself)
    Allowlist {
        #[command(subcommand)]
        action: AllowlistAction,
    },

    /// Temporarily suspend active enforcement (audit-only for the window) —
    /// e.g. during a planned deploy so legitimate changes don't get blocked
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceAction,
    },

    /// This agent's own config sync with the cloud (distinct from `sync`,
    /// which is fleet peer-to-peer config sync between agents)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum QuarantineAction {
    /// List quarantined files
    List,
    /// Restore a quarantined file — either by the alert that caused the
    /// quarantine, or by an explicit quarantine/original path pair
    Restore {
        #[arg(long)]
        alert_id: Option<String>,
        #[arg(long, requires = "original_path", conflicts_with = "alert_id")]
        quarantine_path: Option<String>,
        #[arg(long, requires = "quarantine_path", conflicts_with = "alert_id")]
        original_path: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AllowlistAction {
    List,
    /// Trust a path recursively (never flagged for tamper/exec anomalies)
    Add { path: String },
    Remove { path: String },
}

#[derive(Subcommand, Debug)]
pub enum MaintenanceAction {
    Status,
    Enable {
        #[arg(long, default_value_t = 30)]
        duration_minutes: u64,
        #[arg(long, default_value = "Scheduled maintenance window")]
        reason: String,
    },
    Disable,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Fetch latest config from the cloud (async — dispatches and returns
    /// immediately, vandamd applies it via its existing hot-reload path)
    Fetch,
    /// Push local config to the cloud
    Push,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LearningAction {
    /// Enable learning mode
    Enable,
    /// Disable learning mode
    Disable,
}

#[derive(Subcommand, Debug)]
pub enum AlertsAction {
    /// List alerts
    List {
        #[arg(long)]
        severity: Option<String>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        since: Option<String>,
    },
    /// Stream alerts in real time
    Follow {
        #[arg(long)]
        severity: Option<String>,
    },
    /// Request a cloud investigation for an alert (Pro subscribers only —
    /// vandamd answers differently by build/license, see `alerts_data::investigate`)
    Investigate {
        alert_id: String,
    },
    /// Dismiss an alert (local triage, persisted by vandamd, no license required)
    Dismiss {
        alert_id: String,
    },
    /// Mark an alert as a false positive (local triage, persisted by vandamd, no license required)
    FalsePositive {
        alert_id: String,
    },
    /// Allow exception for a detected alert
    Allow {
        alert_id: String,
        #[arg(long)]
        r#type: String,
        #[arg(long, default_value = "site")]
        scope: String,
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum StoragesAction {
    /// List registered storage paths
    List {
        #[arg(long)]
        site: Option<String>,
    },
    /// Register a path
    Add {
        path: String,
        #[arg(long)]
        role: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        global: bool,
    },
    /// Deregister a path
    Remove {
        path: String,
    },
    /// Attach a storage path to a site
    Attach {
        path: String,
        #[arg(long)]
        site: String,
    },
    /// Detach a storage path from a site
    Detach {
        path: String,
        #[arg(long)]
        site: String,
    },
    /// Trigger manual rescan of discovery pillars
    Discover,
    /// Run a manual malware scan on a file
    Scan {
        path: String,
    },
    /// Re-enable storage protection previously disabled for a web root or
    /// exe (see `disable`) — exactly one of --web-root/--exe required.
    Enable {
        #[arg(long, conflicts_with = "exe")]
        web_root: Option<String>,
        #[arg(long, conflicts_with = "web_root")]
        exe: Option<String>,
    },
    /// Suppress storage-write enforcement for a web root or exe (e.g. a
    /// known noisy legitimate writer) — exactly one required.
    Disable {
        #[arg(long, conflicts_with = "exe")]
        web_root: Option<String>,
        #[arg(long, conflicts_with = "web_root")]
        exe: Option<String>,
    },
    /// Clear the "no writable storage found, acknowledged" flag so the
    /// site is re-evaluated on the next discovery pass.
    ResetAck,
    /// Acknowledge that a site legitimately has no local writable storage
    /// (e.g. object-storage-only) so it stops being flagged.
    AcknowledgeNone {
        web_root: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum RulesAction {
    /// List rules
    List {
        #[arg(long)]
        site: Option<String>,
    },
    /// Add custom exception rule
    Add {
        #[arg(long)]
        r#type: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "site")]
        scope: String,
    },
    /// Remove user rule
    Remove {
        rule_id: String,
    },
    /// Hot-reload rules.db
    Reload,
    /// Pull remote signed rules (Pro only)
    Fetch,
}

#[derive(Subcommand, Debug)]
pub enum ServersAction {
    /// List all sites and servers
    List,
    /// Show detailed info for a site
    Show {
        site_domain: String,
    },
    /// Show ASCII process tree for a site
    ProcessTree {
        site_domain: String,
    },
    /// Trust a server/site path — turns OFF all local enforcement (file,
    /// exec, network, escape-protection) for the process(es) behind it and
    /// everything they spawn. If the path resolves to a shared runtime pool,
    /// every other domain on that pool is affected too.
    Trust {
        path: String,
    },
    /// Untrust a previously-trusted path — restores full enforcement.
    Untrust {
        path: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ContainersAction {
    /// List containers and image trust status
    List,
    /// Show detailed status of a container
    Show {
        id: String,
    },
    /// Trust a container image hash
    Trust {
        image: String,
        #[arg(long, default_value = "site")]
        scope: String,
    },
    /// Untrust a container image hash
    Untrust {
        image: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum FirewallAction {
    /// List all firewall rules
    List {
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        global: bool,
    },
    /// Add a block rule (legacy alias for `add`/`create` — kept for
    /// existing scripts; always creates an IP/CIDR DROP rule)
    Block {
        ip_or_cidr: String,
        #[arg(long)]
        site: Option<String>,
        #[arg(long, default_value = "inbound")]
        direction: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove a block rule by IP/CIDR (legacy alias — kept for existing
    /// scripts; prefer `remove` by rule id for country-targeted rules)
    Unblock {
        ip_or_cidr: String,
        #[arg(long)]
        site: Option<String>,
    },
    /// Create a rule targeting either an IP/CIDR or a GeoIP country code
    /// (exactly one of `--ip` / `--country` is required)
    Add {
        #[arg(long, conflicts_with = "country")]
        ip: Option<String>,
        #[arg(long, conflicts_with = "ip")]
        country: Option<String>,
        #[arg(long, default_value = "inbound")]
        direction: String,
        #[arg(long, default_value = "DROP")]
        action: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Edit an existing rule in place (mirrors the TUI's `[e]` edit dialog).
    /// Only supplied fields change — omitted fields keep their current
    /// value (see `vandam::api::patch_firewall`'s merge semantics). Fails
    /// with a 409 if the rule is cloud-managed (`locked`).
    Update {
        rule_id: String,
        #[arg(long, conflicts_with = "country")]
        ip: Option<String>,
        #[arg(long, conflicts_with = "ip")]
        country: Option<String>,
        #[arg(long)]
        direction: Option<String>,
        #[arg(long)]
        action: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Also switches scope to "site" — use `promote` to move a rule
        /// back to global scope, this flag can't unset a site.
        #[arg(long)]
        site: Option<String>,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove a rule by id
    Remove {
        rule_id: String,
    },
    /// Promote a site-specific rule to global
    Promote {
        rule_id: String,
    },
    /// List GeoIP country codes available for `add --country`
    Countries,
    /// Cloud rule sync status (vandam builds only — works regardless of
    /// subscription status; OSS builds report why it's unavailable)
    Sync,
}

#[derive(Subcommand, Debug)]
pub enum FileIntegrityAction {
    /// Show watched roots status
    Status {
        #[arg(long)]
        site: Option<String>,
    },
    /// Watch a directory
    Watch {
        path: String,
    },
    /// Stop watching a directory
    Unwatch {
        path: String,
    },
    /// Re-baseline the trusted-inode allowlist file integrity checks run
    /// against — after confirming a flagged change was legitimate
    /// (`--path`), or after a deploy to re-seed the whole baseline from git
    /// across every web root (`--git`). Exactly one required. Without this,
    /// the only way to clear a legitimate change is a full daemon restart,
    /// which re-baselines everything blindly (including anything an
    /// attacker planted).
    Register {
        #[arg(long, conflicts_with = "git")]
        path: Option<String>,
        #[arg(long, conflicts_with = "path")]
        git: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum ProcessAction {
    /// SIGKILL a process PID
    Kill {
        pid: u32,
    },
}

#[derive(Subcommand, Debug)]
pub enum ScanAction {
    /// List CVE dependencies vulnerabilities
    Dependencies {
        #[arg(long)]
        site: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SyncAction {
    /// Get fleet sync status
    Status,
    /// Push configuration to fleet
    Push {
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Pull configuration from leader
    Pull {
        #[arg(long)]
        from: Option<String>,
    },
    /// Diff local config against fleet member
    Diff {
        #[arg(long)]
        against: Option<String>,
    },
}

const AUDIT_LOG: &str = "/var/log/kinnector/audit.log";

/// Renders a firewall rule's `target` field (vandamd's tagged-enum shape,
/// `{"type":"IpCidr","value":"..."}` or `{"type":"Country","value":"US"}`)
/// as a single display string for CLI tables — mirrors
/// `vandam/src/tui/firewall_data.rs`'s `target_display`, duplicated here
/// rather than shared since the CLI works with raw `serde_json::Value`
/// (via `query_daemon`) instead of the typed `FirewallRuleData`.
fn rule_target_display(rule: &serde_json::Value) -> String {
    let Some(target) = rule.get("target") else { return String::new(); };
    let value = target.get("value").and_then(|v| v.as_str()).unwrap_or("");
    match target.get("type").and_then(|t| t.as_str()) {
        Some("Country") => format!("🌍 {}", value),
        _ => value.to_string(),
    }
}

/// Raw (non-JSON-parsed) body of a vandamd response — for endpoints that
/// don't return a single JSON value, e.g. `GET /api/v1/access/sessions/{id}/cast`
/// (newline-delimited asciicast frames). `query_daemon` below is the
/// JSON-parsing convenience wrapper every other caller uses.
pub fn query_daemon_raw(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<String, String> {
    use std::io::{Read, Write as IoWrite};
    use std::os::unix::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| format!("Failed to connect to daemon socket: {}. Is vandamd running?", e))?;

    let body_str = body.map(|b| b.to_string()).unwrap_or_default();
    let req = if body_str.is_empty() {
        format!("{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", method, path)
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, body_str.len(), body_str
        )
    };

    stream.write_all(req.as_bytes())
        .map_err(|e| format!("Failed to write to daemon socket: {}", e))?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)
        .map_err(|e| format!("Failed to read from daemon socket: {}", e))?;

    let res_str = String::from_utf8_lossy(&response);
    let body_part = res_str.split("\r\n\r\n").nth(1)
        .ok_or_else(|| "Malformed HTTP response from daemon".to_string())?;
    Ok(body_part.to_string())
}

pub fn query_daemon(
    socket_path: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let body_part = query_daemon_raw(socket_path, method, path, body)?;
    serde_json::from_str(&body_part)
        .map_err(|e| format!("Failed to parse JSON response: {}. Body: {}", e, body_part))
}

/// Cloud Analytics upsell copy for non-paid users (OSS or Pro-without-subscription
/// — both see the same thing). Shown on `alerts list` regardless of `--output`
/// format so a human reading the terminal and an LLM agent parsing `--output json`
/// both get the same marketing message, not just the human-formatted branch.
/// Two variants (has_alerts) mirror the same has-incidents/quiet split already
/// used by the TUI's Status tab CTA block (`src/tui/dashboard/status.rs`).
fn cloud_upsell_json(has_alerts: bool) -> Value {
    let (headline, body) = if has_alerts {
        (
            "Local detection stopped this — here's the forensic depth Cloud adds",
            "If you're running the Pro build, RASP already blocked this and told you which site it happened on — that's included free, no subscription needed. A Cloud subscription adds the full forensic reconstruction behind it: the exact stack trace at the moment of exploitation, automatic framework fingerprinting (e.g. \"Laravel 10, detected via composer.json\"), git-based tamper detection that tells you whether the exploited file was part of your deployed code or planted outside version control, inspection of every dynamically loaded module to catch malicious extensions, and memory-mapping analysis that catches in-memory-only malware — the kind that never writes a file to disk and slips past traditional file scanning entirely. On top of that, Cloud correlates this event against every other server in your fleet in real time and against a live global threat-intelligence feed, so coordinated campaigns that only show up as a pattern across multiple servers don't go unnoticed. Same binary, same server — nothing to migrate, five minutes to activate.",
        )
    } else {
        (
            "No incidents right now — Cloud Analytics still adds a layer local rules can't",
            "A quiet log doesn't mean nothing was attempted. Sophisticated attackers routinely probe first and strike later, or use techniques deliberately designed to blend into normal traffic and slip past static, local-only rules. A Cloud subscription continuously cross-references every server in your fleet against a live global threat-intelligence feed and AI-driven behavioral heuristics, catching coordinated or previously-unseen attacks before they'd ever register locally — plus one fleet-wide dashboard instead of checking each server by hand. And if something ever does get blocked, you get the full forensic reconstruction on top of it: exact stack trace, framework fingerprint, git-based tamper detection, loaded-module inspection, and memory analysis that catches fileless malware — all layered on top of the PHP site attribution the Pro build already gives you for free.",
        )
    };
    json!({
        "eligible": true,
        "headline": headline,
        "body": body,
        "learn_more_url": learn_more_url("alerts"),
    })
}

fn print_cloud_upsell(upsell: &Value) {
    let headline = upsell.get("headline").and_then(|v| v.as_str()).unwrap_or("");
    let body = upsell.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let url = upsell.get("learn_more_url").and_then(|v| v.as_str()).unwrap_or("");
    println!();
    println!("{}", format!("☁ {}", headline).yellow().bold());
    println!("{}", textwrap_simple(body, 100).bright_black());
    println!("{}", url.cyan().underline());
}

/// Minimal word-wrap so the upsell paragraph doesn't run off a narrow terminal —
/// no external dependency needed for something this small.
fn textwrap_simple(text: &str, width: usize) -> String {
    let mut out = String::new();
    let mut line_len = 0;
    for word in text.split_whitespace() {
        if line_len > 0 && line_len + 1 + word.len() > width {
            out.push('\n');
            line_len = 0;
        } else if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word.len();
    }
    out
}

pub fn run(cli: Cli) {
    let socket = cli.daemon_socket.unwrap_or_else(|| "/var/run/kinnector/vandam.sock".to_string());
    let output = match output::CliOutput::from_flag(&cli.output) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(output::EXIT_USAGE);
        }
    };

    match cli.command {
        Commands::Status => {
            match query_daemon(&socket, "GET", "/api/v1/status", None) {
                Ok(status) => {
                    let pid = std::fs::read_to_string("/var/run/kinnector/vandamd.pid")
                        .ok()
                        .map(|s| s.trim().to_string());
                    let data = json!({
                        "running": true,
                        "pid": pid,
                        "version": status.get("version").cloned().unwrap_or(json!("0.1.0")),
                        "lsm_active": status.get("lsm_active").cloned().unwrap_or(json!(false)),
                        "uptime_secs": status.get("uptime_secs").cloned().unwrap_or(json!(0)),
                        "custom_config_active": status.get("custom_config_active").cloned().unwrap_or(json!(false)),
                        "web_roots": status.get("web_roots").cloned().unwrap_or(json!([])),
                    });
                    output.emit_ok(&data, |s| {
                        println!("{}", "=== vandam Status ===".bold().cyan());
                        println!("  Daemon PID   : {}", s["pid"].as_str().unwrap_or("?").green());
                        println!("  Status       : {}", "RUNNING".green().bold());
                        println!("  Version      : {}", s["version"].as_str().unwrap_or("0.1.0").green());
                        println!("  LSM Mode     : {}", if s["lsm_active"].as_bool().unwrap_or(false) { "LSM-active".green() } else { "Tracepoint-fallback".yellow() });
                        println!("  Uptime (s)   : {}", s["uptime_secs"].as_u64().unwrap_or(0).to_string().cyan());

                        let custom_config = s["custom_config_active"].as_bool().unwrap_or(false);
                        if custom_config {
                            println!("  Custom Rules : {}", "ACTIVE (⚠ Custom allowed settings detected — protection may be reduced)".yellow());
                        } else {
                            println!("  Custom Rules : {}", "None (Full protection active)".green());
                        }

                        if let Some(roots) = s["web_roots"].as_array() {
                            let root_paths: Vec<&str> = roots.iter().flat_map(|r| r.as_str()).collect();
                            println!("  Web Roots    : {:?}", root_paths);
                        }
                    });
                }
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            }
        }

        Commands::Alerts { action } => match action {
            AlertsAction::List { severity, site, since } => {
                // Accept either a full RFC3339 timestamp or a bare date (YYYY-MM-DD),
                // interpreted as that date's start-of-day UTC — a raw date is what
                // operators will type in practice, an exact instant is what alerts
                // are stamped with.
                let since_dt: Option<chrono::DateTime<chrono::Utc>> = since.as_deref().and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&chrono::Utc)).ok()
                        .or_else(|| {
                            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
                                .and_then(|d| d.and_hms_opt(0, 0, 0))
                                .map(|dt| chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(dt, chrono::Utc))
                        })
                });
                if since.is_some() && since_dt.is_none() {
                    output.emit_err(output::CliError::usage(format!(
                        "--since {:?} is not a valid RFC3339 timestamp or YYYY-MM-DD date", since.as_deref().unwrap_or("")
                    )));
                }
                match query_daemon(&socket, "GET", "/api/v1/alerts", None) {
                    Ok(res) => {
                        let alerts = res.get("alerts").and_then(|a| a.as_array()).cloned().unwrap_or_default();
                        let filtered: Vec<Value> = alerts.into_iter().filter(|item| {
                            if let Some(ref sev) = severity {
                                if item.get("severity").and_then(|s| s.as_str()).unwrap_or("") != sev.to_uppercase() {
                                    return false;
                                }
                            }
                            if let Some(ref s) = site {
                                // site.domain (real attribution, see attribute_alerts() in
                                // vandam/src/api.rs) — not exec_path, which was never a site
                                // identifier and matched nothing meaningful. An alert with no
                                // site attribution (unattributed pool-level, or gated for a
                                // non-paid tier) never matches an explicit --site filter.
                                if item.get("site").and_then(|si| si.get("domain")).and_then(|s| s.as_str()).unwrap_or("") != s {
                                    return false;
                                }
                            }
                            if let Some(cutoff) = since_dt {
                                let item_ts = item.get("timestamp").and_then(|s| s.as_str())
                                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                    .map(|dt| dt.with_timezone(&chrono::Utc));
                                match item_ts {
                                    Some(ts) if ts >= cutoff => {}
                                    _ => return false,
                                }
                            }
                            true
                        }).collect();

                        // Cheap local-socket call — only used to decide whether to show the
                        // cloud-upsell block below. Paid tier (OSS build with a license, or
                        // Pro with an active subscription) never sees it.
                        let is_paid = query_daemon(&socket, "GET", "/api/v1/status", None)
                            .ok()
                            .and_then(|s| s.get("daemon").and_then(|d| d.get("tier")).and_then(|t| t.as_str()).map(|t| t == "paid"))
                            .unwrap_or(false);

                        let upsell = if is_paid { None } else { Some(cloud_upsell_json(!filtered.is_empty())) };
                        let response = json!({ "alerts": filtered, "cloud_upsell": upsell });

                        output.emit_ok(&response, |response| {
                            let filtered = response["alerts"].as_array().cloned().unwrap_or_default();
                            println!("{}", "=== Alerts List ===".bold().cyan());
                            if filtered.is_empty() {
                                println!("  No matching alerts.");
                            } else {
                                for item in &filtered {
                                    let ts = item.get("timestamp").and_then(|s| s.as_str()).unwrap_or("");
                                    let severity = item.get("severity").and_then(|s| s.as_str()).unwrap_or("");
                                    let threat = item.get("threat_type").and_then(|s| s.as_str()).unwrap_or("?");
                                    let action = item.get("remediation").and_then(|r| r.get("action")).and_then(|s| s.as_str()).unwrap_or("");

                                    let sev_colored = match severity {
                                        "CRITICAL" => severity.red().bold(),
                                        "HIGH" => severity.yellow().bold(),
                                        _ => severity.white(),
                                    };
                                    println!("[{}] {} {} -> {}", ts.bright_black(), sev_colored, threat.bold().white(), action.green());

                                    let mut detail_parts: Vec<String> = Vec::new();
                                    if let Some(domain) = item.get("site").and_then(|si| si.get("domain")).and_then(|s| s.as_str()) {
                                        detail_parts.push(format!("site: {}", domain));
                                    }
                                    if let Some(name) = item.get("backend").and_then(|b| b.get("name")).and_then(|s| s.as_str()) {
                                        detail_parts.push(format!("backend: {}", name));
                                    }
                                    if let Some(conf) = item.get("confidence").and_then(|c| c.as_f64()) {
                                        detail_parts.push(format!("confidence: {:.2}", conf));
                                    }
                                    if let Some(cname) = item.get("container").and_then(|c| c.get("name")).and_then(|s| s.as_str()) {
                                        let mut c_desc = cname.to_string();
                                        if let Some(status) = item.get("container").and_then(|c| c.get("status")).and_then(|s| s.as_str()) {
                                            c_desc.push_str(&format!(" [{}]", status));
                                        }
                                        detail_parts.push(format!("container: {}", c_desc));
                                    }
                                    if let Some(sig) = item.get("process").and_then(|p| p.get("signature_name")).and_then(|s| s.as_str()) {
                                        detail_parts.push(format!("signature: {}", sig));
                                    }
                                    if let Some(svc) = item.get("process").and_then(|p| p.get("service")).and_then(|s| s.as_str()) {
                                        detail_parts.push(format!("service: {}", svc));
                                    }
                                    if !detail_parts.is_empty() {
                                        println!("         {}", detail_parts.join("  ·  ").bright_black());
                                    }
                                    if let Some(q) = item.get("remediation").and_then(|r| r.get("quarantine")).filter(|v| !v.is_null()) {
                                        let orig = q.get("original_path").and_then(|s| s.as_str()).unwrap_or("");
                                        let dest = q.get("quarantine_path").and_then(|s| s.as_str()).unwrap_or("");
                                        println!("         {}", format!("quarantined: {} -> {}", orig, dest).bright_black());
                                    }
                                    if let Some(ed) = item.get("event_detail").filter(|v| !v.is_null()) {
                                        if let Some(ed_type) = ed.get("type").and_then(|s| s.as_str()) {
                                            println!("         {}", format!("event: {} {}", ed_type, ed).bright_black());
                                        }
                                    }
                                    if !item.get("rasp_context").map_or(true, |v| v.is_null()) {
                                        println!("         {}", "full forensic context available: stack trace, framework fingerprint, git tamper check, loaded modules, memory analysis — see --output json".cyan());
                                    }
                                }
                            }
                            if let Some(upsell) = response.get("cloud_upsell").filter(|v| !v.is_null()) {
                                print_cloud_upsell(upsell);
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            AlertsAction::Follow { severity } => {
                if !output.is_json() {
                    println!("{}", "[vandam] Streaming alerts (Ctrl-C to stop)...".bold());
                }
                use std::io::{BufRead, BufReader, Seek, SeekFrom};
                let file = match std::fs::File::open(AUDIT_LOG) {
                    Ok(f) => f,
                    Err(_) => output.emit_err(output::CliError::daemon(format!("Audit log not found: {}", AUDIT_LOG))),
                };
                let mut reader = BufReader::new(file);
                let _ = reader.seek(SeekFrom::End(0));
                let sev = severity.as_deref().map(|s| s.to_uppercase());
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    let mut line = String::new();
                    while let Ok(n) = reader.read_line(&mut line) {
                        if n == 0 { break; }
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line.trim()) {
                            let severity = val.get("severity").and_then(|s| s.as_str()).unwrap_or("");
                            if let Some(ref filter) = sev {
                                if severity != filter { continue; }
                            }
                            if output.is_json() {
                                println!("{}", val);
                            } else {
                                let threat = val.get("threat_type").and_then(|s| s.as_str()).unwrap_or("?");
                                let ts = val.get("timestamp").and_then(|s| s.as_str()).unwrap_or("");
                                let pid = val.get("process").and_then(|p| p.get("pid")).and_then(|p| p.as_u64()).unwrap_or(0);
                                let exe = val.get("process").and_then(|p| p.get("exec_path")).and_then(|s| s.as_str()).unwrap_or("");
                                let action = val.get("remediation").and_then(|r| r.get("action")).and_then(|s| s.as_str()).unwrap_or("");

                                let sev_colored = match severity {
                                    "CRITICAL" => severity.red().bold(),
                                    "HIGH" => severity.yellow().bold(),
                                    _ => severity.white(),
                                };
                                println!("[{}] {} {} pid={} exe={} action={}",
                                    ts.bright_black(), sev_colored, threat.bold().white(),
                                    pid.to_string().cyan(), exe.cyan(), action.green());
                            }
                        }
                        line.clear();
                    }
                }
            }
            AlertsAction::Investigate { alert_id } => {
                // No check_pro_command() gate here: unlike Sync/RulesAction::Fetch,
                // this must work (and answer correctly) on every build — the
                // daemon itself differs by build/license (OSS: "unavailable",
                // Pro no-sub: "upgrade_required", Pro paid: "pending"), so
                // gating stays server-side only (see vandam/src/api.rs and
                // vandam/src/investigate.rs).
                match crate::client::alerts::investigate(&socket, &alert_id) {
                    Ok(res) => {
                        output.emit_ok(&res, |r| {
                            let msg = r.message.clone().unwrap_or_else(|| r.status.clone());
                            println!("[vandam] Investigate {}: {}", alert_id.yellow(), msg);
                            if let Some(id) = &r.investigation_id {
                                println!("  investigation id: {}", id.cyan());
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            AlertsAction::Dismiss { alert_id } => {
                match crate::client::alerts::set_dismissed(&socket, &alert_id, true) {
                    Ok(()) => {
                        let data = json!({ "alert_id": alert_id, "dismissed": true });
                        output.emit_ok(&data, |_| {
                            println!("[vandam] Alert {} dismissed.", alert_id.yellow());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            AlertsAction::FalsePositive { alert_id } => {
                match crate::client::alerts::set_false_positive(&socket, &alert_id, true) {
                    Ok(()) => {
                        let data = json!({ "alert_id": alert_id, "false_positive": true });
                        output.emit_ok(&data, |_| {
                            println!("[vandam] Alert {} marked as false positive.", alert_id.yellow());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            AlertsAction::Allow { alert_id, r#type, scope, path } => {
                let body = json!({
                    "rule_type": r#type,
                    "target": path.unwrap_or_else(|| "alert-exception".to_string()),
                    "scope": scope,
                });
                match query_daemon(&socket, "POST", "/api/v1/rules/user/add", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "alert_id": alert_id, "status": "exception_registered" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Creating exception rule for alert: {}", d["alert_id"].as_str().unwrap_or("").yellow());
                            println!("{}", "Security exception rule registered successfully.".green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Storages { action } => match action {
            StoragesAction::List { site } => {
                match query_daemon(&socket, "GET", "/api/v1/storage", None) {
                    Ok(res) => {
                        let paths = res.get("storage_paths").and_then(|p| p.as_array()).cloned().unwrap_or_default();
                        let filtered: Vec<Value> = paths.into_iter().filter(|item| {
                            if let Some(ref s) = site {
                                if !item.get("path").and_then(|x| x.as_str()).unwrap_or("").contains(s) {
                                    return false;
                                }
                            }
                            true
                        }).collect();

                        output.emit_ok(&filtered, |filtered| {
                            println!("{}", "=== Registered Storage Paths ===".bold().cyan());
                            if filtered.is_empty() {
                                println!("  No storage paths registered.");
                            } else {
                                println!("{:<45} {:<20} {:<12} {:<10} {:<10}", "Path", "Roles", "Confidence", "Scripts", "Write");
                                println!("{}", "-".repeat(102));
                                for p in filtered {
                                    let path = p.get("path").and_then(|x| x.as_str()).unwrap_or("");
                                    let roles = p.get("roles").and_then(|x| x.as_array())
                                        .map(|arr| arr.iter().flat_map(|val| val.as_str()).collect::<Vec<_>>().join(", "))
                                        .unwrap_or_default();
                                    let confidence = p.get("confidence").and_then(|x| x.as_str()).unwrap_or("");
                                    let allow_script = p.get("allow_script_extensions").and_then(|x| x.as_bool()).unwrap_or(false);
                                    let write_allowed = p.get("write_allowed").and_then(|x| x.as_bool()).unwrap_or(true);

                                    println!("{:<45} {:<20} {:<12} {:<10} {:<10}", path.yellow(), roles.green(), confidence.cyan(), if allow_script { "Allowed".green() } else { "Blocked".red() }, if write_allowed { "Allowed".green() } else { "Blocked".red() });
                                }
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::Add { path, role, site, global: _ } => {
                let body = json!({
                    "path": path,
                    "role": role,
                    "web_root": site.unwrap_or_default(),
                });
                match query_daemon(&socket, "POST", "/api/v1/storage/add", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "path": path, "status": "added" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Adding storage path: {}", d["path"].as_str().unwrap_or("").yellow());
                            println!("{}", "Successfully registered path.".green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::Remove { path } => {
                let body = json!({ "path": path });
                match query_daemon(&socket, "POST", "/api/v1/storage/remove", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "path": path, "status": "removed" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Removing storage path: {}", d["path"].as_str().unwrap_or("").yellow());
                            println!("{}", "Successfully removed path.".green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::Attach { path: _, site: _ } => {
                output.emit_not_implemented(
                    "storages attach",
                    "no dedicated attach/detach endpoint exists in vandamd yet",
                );
            }
            StoragesAction::Detach { path: _, site: _ } => {
                output.emit_not_implemented(
                    "storages detach",
                    "no dedicated attach/detach endpoint exists in vandamd yet",
                );
            }
            StoragesAction::Discover => {
                match query_daemon(&socket, "POST", "/api/v1/storage/rescan", None) {
                    Ok(res) => {
                        let count = res.get("count").and_then(|c| c.as_u64()).unwrap_or(0);
                        let data = json!({ "count": count });
                        output.emit_ok(&data, |d| {
                            println!("{}", "[vandam] Running rescan of all discovery pillars...".bold());
                            println!("{}", format!("Discovery completed. Found {} paths.", d["count"]).green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::Scan { path } => {
                let body = json!({ "path": path });
                match query_daemon(&socket, "POST", "/api/v1/storage/scan", Some(&body)) {
                    Ok(res) => {
                        let result = res.get("result").and_then(|r| r.as_str()).unwrap_or("unknown").to_string();
                        let data = json!({ "path": path, "result": result });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Malware scanning file: {}", d["path"].as_str().unwrap_or("").yellow());
                            println!("Result: {}", d["result"].as_str().unwrap_or("").bold().green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::Enable { web_root, exe } => {
                let body = json!({ "web_root": web_root, "exe": exe });
                match query_daemon(&socket, "POST", "/api/v1/storage/enable", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => output.emit_ok(&res, |_| println!("{}", "Storage protection enabled.".green())),
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::Disable { web_root, exe } => {
                let body = json!({ "web_root": web_root, "exe": exe });
                match query_daemon(&socket, "POST", "/api/v1/storage/disable", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => output.emit_ok(&res, |_| println!("{}", "Storage protection disabled.".yellow())),
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::ResetAck => {
                match query_daemon(&socket, "POST", "/api/v1/storage/reset-ack", None) {
                    Ok(res) => output.emit_ok(&res, |_| println!("{}", "Storage acknowledgement reset.".green())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            StoragesAction::AcknowledgeNone { web_root } => {
                let body = json!({ "web_root": web_root });
                match query_daemon(&socket, "POST", "/api/v1/storage/acknowledge-none", Some(&body)) {
                    Ok(res) => output.emit_ok(&res, |_| println!("Acknowledged {} has no local writable storage.", web_root)),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Rules { action } => match action {
            RulesAction::List { site } => {
                match query_daemon(&socket, "GET", "/api/v1/rules/user", None) {
                    Ok(res) => {
                        let rules = res.get("user_rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                        let filtered: Vec<Value> = rules.into_iter().filter(|r| {
                            if let Some(ref s) = site {
                                if r.get("site").and_then(|x| x.as_str()) != Some(s.as_str()) {
                                    return false;
                                }
                            }
                            true
                        }).collect();

                        output.emit_ok(&filtered, |filtered| {
                            println!("{}", "=== User Overrides & Exceptions ===".bold().cyan());
                            if filtered.is_empty() {
                                println!("  No custom overrides registered.");
                            } else {
                                println!("{:<38} {:<20} {:<30} {:<10}", "ID", "Rule Type", "Target", "Scope");
                                println!("{}", "-".repeat(98));
                                for r in filtered {
                                    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                    let r_type = r.get("rule_type").and_then(|v| v.as_str()).unwrap_or("");
                                    let target = r.get("target").and_then(|v| v.as_str()).unwrap_or("");
                                    let scope = r.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                                    println!("{:<38} {:<20} {:<30} {:<10}", id.yellow(), r_type.green(), target.cyan(), scope.white());
                                }
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            RulesAction::Add { r#type, target, scope } => {
                let body = json!({
                    "rule_type": r#type,
                    "target": target,
                    "scope": scope,
                });
                match query_daemon(&socket, "POST", "/api/v1/rules/user/add", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "status": "added" });
                        output.emit_ok(&data, |_| {
                            println!("[vandam] Adding override rule...");
                            println!("{}", "Rule registered successfully.".green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            RulesAction::Remove { rule_id } => {
                let body = json!({ "id": rule_id });
                match query_daemon(&socket, "DELETE", "/api/v1/rules/user", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "rule_id": rule_id, "status": "removed" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Removing rule ID: {}", d["rule_id"].as_str().unwrap_or("").yellow());
                            println!("{}", "Rule deleted successfully.".green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            RulesAction::Reload => {
                match query_daemon(&socket, "POST", "/api/v1/rules/reload", None) {
                    Ok(_) => {
                        let data = json!({ "status": "reloaded" });
                        output.emit_ok(&data, |_| println!("{}", "Rules database reloaded successfully.".green()));
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            RulesAction::Fetch => {
                match query_daemon(&socket, "POST", "/api/v1/rules/fetch", None) {
                    Ok(_) => {
                        let data = json!({ "status": "fetch_triggered" });
                        output.emit_ok(&data, |_| println!("{}", "Remote rules fetch triggered successfully.".green()));
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Servers { action } => match action {
            ServersAction::List => {
                match query_daemon(&socket, "GET", "/api/v1/servers", None) {
                    Ok(res) => {
                        // Real /api/v1/servers shape is proxies/direct_http/standalones/daemons
                        // (nested proxy->runtime->site trees), not the flattened sites/standalone/via
                        // shape this handler used to assume — that shape never existed in vandamd's
                        // response. Reuses the TUI's own parser so CLI and TUI can't drift apart on
                        // what the real payload means.
                        let data: crate::client::servers::ServersData = serde_json::from_value(res.clone())
                            .unwrap_or_default();
                        output.emit_ok(&res, |_| {
                            println!("{}", "=== Discovered Protected Sites & Servers ===".bold().cyan());
                            let targets = crate::client::servers::build_server_targets(&data);
                            if targets.is_empty() {
                                println!("No servers discovered on this host.");
                                return;
                            }
                            println!("{:<50} {:<18} {:<28} {:<10} {:<20}", "SERVICE HIERARCHY & STORAGE PATHS", "TARGET / PORTS", "STACK & POLICY", "STATUS", "ENFORCEMENT");
                            println!("{}", "-".repeat(126));
                            for t in &targets {
                                // Inverted on purpose — see Containers' row rendering for the
                                // full rationale: trusted = unmonitored = the risky state.
                                let enforcement = if t.trusted {
                                    "⚠ UNMONITORED".red().to_string()
                                } else if t.is_group {
                                    "-".normal().to_string()
                                } else {
                                    "✓ MONITORED".green().to_string()
                                };
                                println!("{:<50} {:<18} {:<28} {:<10} {:<20}", t.tree_label, t.ports, t.stack, t.status, enforcement);
                                if t.trusted && !t.shared_with.is_empty() {
                                    println!("  {} shares this trusted runtime with: {}", "⚠".yellow(), t.shared_with.join(", ").yellow());
                                }
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            ServersAction::Show { site_domain: _ } => {
                output.emit_not_implemented("servers show", "no per-site detail endpoint exists in vandamd yet");
            }
            ServersAction::ProcessTree { site_domain: _ } => {
                output.emit_not_implemented("servers process-tree", "no per-site process-tree endpoint exists in vandamd yet");
            }
            ServersAction::Trust { path } => {
                match crate::client::servers::trust(&socket, &path) {
                    Ok(()) => {
                        let data = json!({ "path": path, "status": "trust_rule_added" });
                        output.emit_ok(&data, |d| {
                            println!("{} {}", "[vandam] Trusting server path (turns off ALL local enforcement):".yellow(), d["path"].as_str().unwrap_or("").bold());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            ServersAction::Untrust { path } => {
                match crate::client::servers::untrust(&socket, &path) {
                    Ok(()) => {
                        let data = json!({ "path": path, "status": "trust_rule_removed" });
                        output.emit_ok(&data, |d| {
                            println!("{} {}", "[vandam] Untrusted server path (enforcement restored):".green(), d["path"].as_str().unwrap_or("").bold());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Containers { action } => match action {
            ContainersAction::List => {
                match query_daemon(&socket, "GET", "/api/v1/containers", None) {
                    Ok(res) => {
                        // Real shape is {"containers": [...], "trusted_images": [...]}
                        // (an object), not a bare array. Reuses the TUI's own parser
                        // so CLI and TUI can't drift apart on what the real payload
                        // means — same approach as ServersAction::List above.
                        let data: crate::client::containers::ContainersData = serde_json::from_value(res.clone())
                            .unwrap_or_default();
                        output.emit_ok(&res, |_| {
                            println!("{}", "=== Monitored Docker Containers ===".bold().cyan());
                            let targets = crate::client::containers::build_container_targets(&data);
                            if targets.is_empty() {
                                println!("  No containers found.");
                            } else {
                                println!("{:<14} {:<18} {:<24} {:<10} {:<16} {:<20}", "ID", "Name", "Image", "Status", "Vandam Attached", "Enforcement");
                                println!("{}", "-".repeat(104));
                                for t in &targets {
                                    let attached_str = if t.attached { "[● Attached]".green() } else { "[○ Unattached]".yellow() };
                                    // Inverted on purpose: trusted = enforcement OFF = the risky
                                    // state, so it's flagged, not shown as a good "YES".
                                    let enforcement_str = if t.trusted {
                                        "UNMONITORED (trusted)".red()
                                    } else if t.trust_stale {
                                        "STALE (re-trust)".yellow()
                                    } else {
                                        "MONITORED".green()
                                    };
                                    println!("{:<14} {:<18} {:<24} {:<10} {:<25} {:<20}", t.short_id.yellow(), t.name.green(), t.image.cyan(), t.status, attached_str, enforcement_str);
                                }
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            ContainersAction::Show { id } => {
                match query_daemon(&socket, "GET", &format!("/api/v1/containers/{}", id), None) {
                    Ok(res) => {
                        output.emit_ok(&res, |d| {
                            println!("{}", "=== Container Detail ===".bold().cyan());
                            println!("  ID:      {}", d.get("id").and_then(|v| v.as_str()).unwrap_or(""));
                            println!("  Name:    {}", d.get("name").and_then(|v| v.as_str()).unwrap_or(""));
                            println!("  Image:   {}", d.get("image").and_then(|v| v.as_str()).unwrap_or(""));
                            println!("  Image ID:{}", d.get("image_id").and_then(|v| v.as_str()).unwrap_or(""));
                            println!("  Status:  {}", d.get("status").and_then(|v| v.as_str()).unwrap_or(""));
                            let trusted = d.get("trusted").and_then(|v| v.as_bool()).unwrap_or(false);
                            let trust_stale = d.get("trust_stale").and_then(|v| v.as_bool()).unwrap_or(false);
                            // Inverted on purpose — trusted means ALL local
                            // enforcement is OFF for this container, which is the
                            // state worth flagging, not a reassuring "true".
                            if trust_stale {
                                println!("  Enforcement: {}", "STALE — image rebuilt/re-pulled since trusted, run 'containers trust' again to re-confirm".yellow());
                            } else if trusted {
                                println!("  Enforcement: {}", "OFF — this container is TRUSTED and unmonitored, it can do anything".red().bold());
                            } else {
                                println!("  Enforcement: {}", "ON — fully monitored".green());
                            }
                            let alert_count = d.get("alerts").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                            println!("  Alerts:  {}", alert_count);
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            ContainersAction::Trust { image, scope } => {
                match crate::client::containers::trust(&socket, &image, &scope) {
                    Ok(()) => {
                        let data = json!({ "image": image, "status": "trust_rule_added" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Adding container image to trusted database: {}", d["image"].as_str().unwrap_or("").yellow());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            ContainersAction::Untrust { image } => {
                match crate::client::containers::untrust(&socket, &image) {
                    Ok(()) => {
                        let data = json!({ "image": image, "status": "trust_rule_removed" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Removed container image from trusted database: {}", d["image"].as_str().unwrap_or("").yellow());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Setup { action } => match action {
            commands::setup::SetupAction::Configure(args) => {
                commands::setup::handle(&output, &socket, args);
            }
        },

        Commands::Learning { action } => match action {
            None => {
                match query_daemon(&socket, "GET", "/api/v1/learning", None) {
                    Ok(res) => {
                        let enabled = res.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
                        let data = json!({ "enabled": enabled });
                        output.emit_ok(&data, |d| {
                            println!("{}", "=== Learning Mode Status ===".bold().cyan());
                            if d["enabled"].as_bool().unwrap_or(false) {
                                println!("  Learning Mode: {}", "ENABLED (Auto-registering file reads)".green().bold());
                            } else {
                                println!("  Learning Mode: {}", "DISABLED (Enforcing security allowlist)".yellow());
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            Some(LearningAction::Enable) => {
                match query_daemon(&socket, "POST", "/api/v1/learning", Some(&json!({ "enabled": true }))) {
                    Ok(_) => {
                        let data = json!({ "enabled": true });
                        output.emit_ok(&data, |_| println!("{}", "Learning mode enabled successfully.".green()));
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            Some(LearningAction::Disable) => {
                match query_daemon(&socket, "POST", "/api/v1/learning", Some(&json!({ "enabled": false }))) {
                    Ok(_) => {
                        let data = json!({ "enabled": false });
                        output.emit_ok(&data, |_| println!("{}", "Learning mode disabled successfully. Vandam will now enforce allowlists.".green()));
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        },

        Commands::Firewall { action } => match action {
            FirewallAction::List { site, global } => {
                match query_daemon(&socket, "GET", "/api/v1/firewall", None) {
                    Ok(res) => {
                        let rules = res.get("firewall_rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                        let filtered: Vec<Value> = rules.into_iter().filter(|r| {
                            if global && r.get("scope").and_then(|s| s.as_str()) != Some("global") {
                                return false;
                            }
                            if let Some(ref s) = site {
                                if r.get("site").and_then(|x| x.as_str()) != Some(s.as_str()) {
                                    return false;
                                }
                            }
                            true
                        }).collect();

                        output.emit_ok(&filtered, |filtered| {
                            println!("{}", "=== Firewall Rules ===".bold().cyan());
                            if filtered.is_empty() {
                                println!("  No firewall rules applied.");
                            } else {
                                println!("{:<38} {:<20} {:<10} {:<10} {:<8} {:<15}", "ID", "TARGET", "ACTION", "SCOPE", "LOCKED", "REASON");
                                println!("{}", "-".repeat(105));
                                for r in filtered {
                                    let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("");
                                    let target = rule_target_display(r);
                                    let act = r.get("action").and_then(|v| v.as_str()).unwrap_or("");
                                    let scope = r.get("scope").and_then(|v| v.as_str()).unwrap_or("");
                                    let reason = r.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                                    let locked = if r.get("locked").and_then(|v| v.as_bool()).unwrap_or(false) { "cloud" } else { "" };
                                    println!("{:<38} {:<20} {:<10} {:<10} {:<8} {:<15}", id.yellow(), target.cyan(), act.green(), scope.white(), locked.bright_black(), reason.bright_black());
                                }
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Block { ip_or_cidr, site, direction, reason } => {
                let body = json!({
                    "ip_or_cidr": ip_or_cidr,
                    "direction": direction,
                    "action": "DROP",
                    "scope": if site.is_some() { "site" } else { "global" },
                    "site": site,
                    "reason": reason,
                });
                match query_daemon(&socket, "POST", "/api/v1/firewall/block", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        let data = json!({ "ip_or_cidr": ip_or_cidr, "status": "blocked" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Adding block rule for IP: {}", d["ip_or_cidr"].as_str().unwrap_or("").yellow());
                            println!("{}", "Firewall DROP rule applied.".green());
                        });
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Unblock { ip_or_cidr, site } => {
                match query_daemon(&socket, "GET", "/api/v1/firewall", None) {
                    Ok(res) => {
                        let rules = res.get("firewall_rules").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                        let mut found_id = None;
                        for r in &rules {
                            let rule_site = r.get("site").and_then(|v| v.as_str());
                            if rule_target_display(r) == ip_or_cidr && rule_site == site.as_deref() {
                                found_id = r.get("id").and_then(|v| v.as_str()).map(|s| s.to_string());
                                break;
                            }
                        }

                        if let Some(id) = found_id {
                            let body = json!({ "id": id });
                            match query_daemon(&socket, "DELETE", "/api/v1/firewall", Some(&body)) {
                                Ok(res) if res.get("error").is_none() => {
                                    let data = json!({ "ip_or_cidr": ip_or_cidr, "status": "unblocked" });
                                    output.emit_ok(&data, |d| {
                                        println!("[vandam] Removing block rule for IP: {}", d["ip_or_cidr"].as_str().unwrap_or("").yellow());
                                        println!("{}", "Firewall rule successfully deleted.".green());
                                    });
                                }
                                Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                                Err(e) => output.emit_err(output::CliError::daemon(format!("Failed to delete: {}", e))),
                            }
                        } else {
                            output.emit_err(output::CliError::daemon("Block rule not found in firewall registry.".to_string()));
                        }
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Add { ip, country, direction, action, port, site, reason } => {
                let body = json!({
                    "ip_or_cidr": ip,
                    "country": country,
                    "direction": direction,
                    "action": action,
                    "port": port,
                    "scope": if site.is_some() { "site" } else { "global" },
                    "site": site,
                    "reason": reason,
                });
                match query_daemon(&socket, "POST", "/api/v1/firewall", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        output.emit_ok(&res, |r| {
                            let rule = r.get("rule").cloned().unwrap_or_default();
                            println!("{}", "Firewall rule created.".green());
                            println!("  id:     {}", rule.get("id").and_then(|v| v.as_str()).unwrap_or("").yellow());
                            println!("  target: {}", rule_target_display(&rule).cyan());
                        });
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Update { rule_id, ip, country, direction, action, port, site, reason } => {
                let scope = if site.is_some() { Some("site".to_string()) } else { None };
                let body = json!({
                    "ip_or_cidr": ip,
                    "country": country,
                    "direction": direction,
                    "action": action,
                    "port": port,
                    "scope": scope,
                    "site": site,
                    "reason": reason,
                });
                match query_daemon(&socket, "PATCH", &format!("/api/v1/firewall/{}", rule_id), Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        output.emit_ok(&res, |r| {
                            let rule = r.get("rule").cloned().unwrap_or_default();
                            println!("{}", "Firewall rule updated.".green());
                            println!("  id:     {}", rule.get("id").and_then(|v| v.as_str()).unwrap_or("").yellow());
                            println!("  target: {}", rule_target_display(&rule).cyan());
                        });
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Remove { rule_id } => {
                let body = json!({ "id": rule_id });
                match query_daemon(&socket, "DELETE", "/api/v1/firewall", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        let data = json!({ "rule_id": rule_id, "status": "removed" });
                        output.emit_ok(&data, |_| println!("{}", "Firewall rule removed.".green()));
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Promote { rule_id } => {
                let body = json!({ "scope": "global" });
                match query_daemon(&socket, "PATCH", &format!("/api/v1/firewall/{}", rule_id), Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        let data = json!({ "rule_id": rule_id, "status": "promoted" });
                        output.emit_ok(&data, |_| println!("{}", "Rule promoted to global scope.".green()));
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Countries => {
                match query_daemon(&socket, "GET", "/api/v1/firewall/countries", None) {
                    Ok(res) => {
                        let countries = res.get("countries").cloned().unwrap_or(Value::Array(Vec::new()));
                        output.emit_ok(&countries, |c| {
                            println!("{}", "=== GeoIP Countries Available ===".bold().cyan());
                            if let Some(arr) = c.as_array() {
                                if arr.is_empty() {
                                    println!("  No GeoIP data loaded — see protect-community/scripts/update_geoip.sh.");
                                }
                                for entry in arr {
                                    if let Some(pair) = entry.as_array() {
                                        if pair.len() == 2 {
                                            let code = pair[0].as_str().unwrap_or("");
                                            let name = pair[1].as_str().unwrap_or("");
                                            println!("  {:<6} {}", code.yellow(), name);
                                        }
                                    }
                                }
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FirewallAction::Sync => {
                match query_daemon(&socket, "GET", "/api/v1/firewall/sync/status", None) {
                    Ok(res) => {
                        output.emit_ok(&res, |r| {
                            let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
                            let message = r.get("message").and_then(|v| v.as_str()).unwrap_or("");
                            let colored_status = if status == "active" { status.green() } else { status.yellow() };
                            println!("{} {}", "Cloud sync:".bold().cyan(), colored_status);
                            if !message.is_empty() {
                                println!("  {}", message);
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::FileIntegrity { action } => match action {
            FileIntegrityAction::Status { site } => {
                match query_daemon(&socket, "GET", "/api/v1/fim/status", None) {
                    Ok(res) => {
                        let roots = res.get("watched_roots").and_then(|r| r.as_array()).cloned().unwrap_or_default();
                        let filtered: Vec<Value> = roots.into_iter().filter(|r| {
                            if let Some(ref s) = site {
                                if !r.get("web_root").and_then(|v| v.as_str()).unwrap_or("").contains(s) {
                                    return false;
                                }
                            }
                            true
                        }).collect();

                        output.emit_ok(&filtered, |filtered| {
                            println!("{}", "=== File Integrity Monitoring Watchers ===".bold().cyan());
                            for r in filtered {
                                let root_path = r.get("web_root").and_then(|v| v.as_str()).unwrap_or("");
                                let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("");
                                println!("  {} -> {}", root_path.yellow(), status.green().bold());
                            }
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FileIntegrityAction::Watch { path } => {
                let body = json!({ "path": path });
                match query_daemon(&socket, "POST", "/api/v1/fim/add", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "path": path, "status": "watching" });
                        output.emit_ok(&data, |d| println!("[vandam] Adding watch path to file integrity monitoring: {}", d["path"].as_str().unwrap_or("").yellow()));
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FileIntegrityAction::Unwatch { path } => {
                let body = json!({ "path": path });
                match query_daemon(&socket, "POST", "/api/v1/fim/remove", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "path": path, "status": "unwatched" });
                        output.emit_ok(&data, |d| println!("[vandam] Removing watch path from file integrity monitoring: {}", d["path"].as_str().unwrap_or("").yellow()));
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            FileIntegrityAction::Register { path, git } => {
                // Informational only — doesn't block the register, same
                // "warn, don't gate" approach as every other advisory in
                // this codebase. Shown when this Linux install clears an
                // "old" threshold (~6 months, `vandam::install_date` —
                // the OS's own filesystem age, not Vandam's configure date
                // or daemon uptime, both of which read a long-exposed
                // system that just got Vandam installed as "brand new" —
                // exactly backwards, since that's the highest-risk case
                // for trusting a fresh baseline) *and* no audit has ever
                // been run. Two extra calls (status + audit runs) are fine
                // here — this is a one-shot command, not a redraw loop.
                const SIX_MONTHS_SECS: i64 = 60 * 60 * 24 * 30 * 6;
                let installed_at_unix = match crate::client::status::fetch(&socket) {
                    crate::client::status::DaemonStatus::Connected(health) => health.installed_at_unix,
                    crate::client::status::DaemonStatus::Unreachable(_) => None,
                };
                let is_old_install = installed_at_unix
                    .map(|installed_at| chrono::Utc::now().timestamp() - installed_at >= SIX_MONTHS_SECS)
                    .unwrap_or(false);
                let has_been_audited = crate::client::audit::fetch_runs(&socket)
                    .map(|data| !data.runs.is_empty())
                    .unwrap_or(false);
                if is_old_install && !has_been_audited {
                    eprintln!(
                        "{}",
                        format!(
                            "⚠ This Linux installation is 6+ months old and has never had a full audit. Local detection catches known patterns, but sophisticated attacks are specifically designed to evade local-only heuristics — recommend a full audit (vandam) before trusting a new baseline. Learn more: {}",
                            learn_more_url("file-integrity")
                        ).yellow()
                    );
                }
                let body = json!({ "path": path, "git": if git { Some(true) } else { None } });
                match query_daemon(&socket, "POST", "/api/v1/fim/register", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        output.emit_ok(&res, |r| {
                            match r.get("status").and_then(|v| v.as_str()).unwrap_or("?") {
                                "registered" => println!(
                                    "{}",
                                    format!("Re-baselined {}", r.get("path").and_then(|v| v.as_str()).unwrap_or("")).green()
                                ),
                                "re-seeded" => println!(
                                    "{}",
                                    format!(
                                        "Re-seeded file integrity baseline from git: {} new inode(s) registered.",
                                        r.get("new_inodes").and_then(|v| v.as_u64()).unwrap_or(0)
                                    ).green()
                                ),
                                other => println!("Unexpected response: {}", other),
                            }
                        });
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Process { action } => match action {
            ProcessAction::Kill { pid } => {
                let body = json!({ "pid": pid });
                match query_daemon(&socket, "POST", "/api/v1/process/kill", Some(&body)) {
                    Ok(_) => {
                        let data = json!({ "pid": pid, "status": "terminated" });
                        output.emit_ok(&data, |d| {
                            println!("[vandam] Sending SIGKILL to PID {}", d["pid"].to_string().red());
                            println!("{}", "Process terminated.".green());
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Scan { action } => match action {
            ScanAction::Dependencies { site } => {
                match query_daemon(&socket, "POST", "/api/v1/scan/trigger", None) {
                    Ok(_) => {
                        let data = json!({ "site": site, "status": "triggered" });
                        output.emit_ok(&data, |d| {
                            println!("{}", "=== Dependency OSV Vulnerability Scan ===".bold().cyan());
                            println!("Site scoped: {:?}", d["site"]);
                        });
                    }
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        }

        Commands::Sync { action } => {
            match action {
                SyncAction::Status => {
                    match query_daemon(&socket, "GET", "/api/v1/sync/status", None) {
                        Ok(res) => {
                            output.emit_ok(&res, |res| {
                                println!("{}", "=== Sync Fleet Status ===".bold().cyan());
                                println!("Local Node: {}", res.get("this_server").and_then(|v| v.as_str()).unwrap_or(""));
                                println!("Role      : {}", res.get("role").and_then(|v| v.as_str()).unwrap_or(""));
                                if let Some(members) = res.get("members").and_then(|m| m.as_array()) {
                                    println!("\nFleet members:");
                                    for m in members {
                                        let host = m.get("host").and_then(|v| v.as_str()).unwrap_or("");
                                        let status = m.get("status").and_then(|v| v.as_str()).unwrap_or("");
                                        let rev = m.get("rev").and_then(|v| v.as_str()).unwrap_or("unknown");
                                        println!("  {} -> {} ({})", host.yellow(), status.green(), rev.cyan());
                                    }
                                }
                            });
                        }
                        Err(e) => output.emit_err(output::CliError::daemon(e)),
                    }
                }
                SyncAction::Push { to: _, all: _ } => {
                    output.emit_not_implemented(
                        "sync push",
                        "vandamd's /api/v1/sync/push endpoint currently performs no work",
                    );
                }
                SyncAction::Pull { from: _ } => {
                    output.emit_not_implemented(
                        "sync pull",
                        "vandamd's /api/v1/sync/pull endpoint currently performs no work",
                    );
                }
                SyncAction::Diff { against: _ } => {
                    match query_daemon(&socket, "GET", "/api/v1/sync/diff", None) {
                        Ok(res) => {
                            let diff = res.get("diff").and_then(|d| d.as_array()).cloned().unwrap_or_default();
                            output.emit_ok(&diff, |diff| {
                                println!("{}", "=== Sync Diff ===".bold().cyan());
                                for line in diff {
                                    if let Some(l) = line.as_str() {
                                        if l.starts_with('+') {
                                            println!("{}", l.green());
                                        } else if l.starts_with('-') {
                                            println!("{}", l.red());
                                        } else {
                                            println!("{}", l);
                                        }
                                    }
                                }
                            });
                        }
                        Err(e) => output.emit_err(output::CliError::daemon(e)),
                    }
                }
            }
        }

        Commands::TestAlert => {
            match query_daemon(&socket, "POST", "/api/v1/test-alert", None) {
                Ok(res) => {
                    output.emit_ok(&res, |res| {
                        println!("{}", "[vandam] Triggering test alert...".bold());
                        println!("{}", format!("Dispatched alert_id={}", res.get("alert_id").and_then(|v| v.as_str()).unwrap_or("")).green());
                    });
                }
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            }
        }

        Commands::Version => {
            let data = json!({ "version": env!("CARGO_PKG_VERSION"), "schema_version": 1 });
            output.emit_ok(&data, |d| {
                println!("vandam v{} (vandam)", d["version"].as_str().unwrap_or(""));
            });
        }

        Commands::Access { action } => commands::access::handle(&output, action, &socket),
        Commands::Cloud { action } => commands::cloud::handle(&output, action, &socket),
        Commands::Audit { action } => commands::audit::handle(&output, action, &socket),
        Commands::Risks { action } => commands::risks::handle(&output, action, &socket),
        Commands::Quarantine { action } => match action {
            QuarantineAction::List => match query_daemon(&socket, "GET", "/api/v1/quarantine", None) {
                Ok(res) => {
                    let files = res.get("quarantined_files").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    output.emit_ok(&files, |files| {
                        if files.is_empty() {
                            println!("No quarantined files.");
                            return;
                        }
                        for f in files {
                            println!(
                                "{:<40} <- {}",
                                f.get("original_path").and_then(|v| v.as_str()).unwrap_or(""),
                                f.get("reason").and_then(|v| v.as_str()).unwrap_or(""),
                            );
                        }
                    });
                }
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            },
            QuarantineAction::Restore { alert_id, quarantine_path, original_path } => {
                let body = json!({
                    "alert_id": alert_id,
                    "quarantine_path": quarantine_path,
                    "original_path": original_path,
                });
                match query_daemon(&socket, "POST", "/api/v1/quarantine/restore", Some(&body)) {
                    Ok(res) if res.get("error").is_none() => {
                        output.emit_ok(&res, |r| {
                            println!(
                                "{}",
                                format!("Restored: {}", r.get("original_path").and_then(|v| v.as_str()).unwrap_or("")).green()
                            );
                        });
                    }
                    Ok(res) => output.emit_err(output::CliError::daemon(res.get("error").and_then(|e| e.as_str()).unwrap_or("request rejected").to_string())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        },

        Commands::Allowlist { action } => match action {
            AllowlistAction::List => match query_daemon(&socket, "GET", "/api/v1/allowlist", None) {
                Ok(res) => {
                    let inodes = res.get("allowed_inodes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                    output.emit_ok(&inodes, |inodes| {
                        if inodes.is_empty() {
                            println!("No allowlisted inodes.");
                            return;
                        }
                        for i in inodes {
                            println!("{}", i);
                        }
                    });
                }
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            },
            AllowlistAction::Add { path } => {
                let body = json!({ "path": path });
                match query_daemon(&socket, "POST", "/api/v1/allowlist/add", Some(&body)) {
                    Ok(res) => output.emit_ok(&res, |_| println!("{}", format!("Allowlisted {}", path).green())),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            AllowlistAction::Remove { path } => {
                let body = json!({ "path": path });
                match query_daemon(&socket, "POST", "/api/v1/allowlist/remove", Some(&body)) {
                    Ok(res) => output.emit_ok(&res, |_| println!("Removed {} from allowlist.", path)),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
        },

        Commands::Maintenance { action } => match action {
            MaintenanceAction::Status => match query_daemon(&socket, "GET", "/api/v1/maintenance", None) {
                Ok(res) => output.emit_ok(&res, |r| {
                    let active = r.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                    if active {
                        println!("{}", "Maintenance mode: ACTIVE".yellow().bold());
                        println!("  reason: {}", r.get("reason").and_then(|v| v.as_str()).unwrap_or(""));
                        println!("  expires (unix): {}", r.get("expires_at_unix").and_then(|v| v.as_i64()).unwrap_or(0));
                    } else {
                        println!("{}", "Maintenance mode: inactive".green());
                    }
                }),
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            },
            MaintenanceAction::Enable { duration_minutes, reason } => {
                let body = json!({ "duration_minutes": duration_minutes, "reason": reason });
                match query_daemon(&socket, "POST", "/api/v1/maintenance/enable", Some(&body)) {
                    Ok(res) => output.emit_ok(&res, |_| {
                        println!(
                            "{}",
                            format!("Maintenance mode enabled for {} minute(s): {}", duration_minutes, reason).yellow().bold()
                        );
                    }),
                    Err(e) => output.emit_err(output::CliError::daemon(e)),
                }
            }
            MaintenanceAction::Disable => match query_daemon(&socket, "POST", "/api/v1/maintenance/disable", None) {
                Ok(res) => output.emit_ok(&res, |_| println!("{}", "Maintenance mode disabled — full enforcement resumed.".green())),
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            },
        },

        Commands::Config { action } => match action {
            ConfigAction::Fetch => match query_daemon(&socket, "POST", "/api/v1/config/fetch", None) {
                Ok(res) => output.emit_ok(&res, |_| println!("Config fetch from cloud dispatched.")),
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            },
            ConfigAction::Push => match query_daemon(&socket, "POST", "/api/v1/config/push", None) {
                Ok(res) => output.emit_ok(&res, |_| println!("Config push to cloud dispatched.")),
                Err(e) => output.emit_err(output::CliError::daemon(e)),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_upsell_json_has_both_variants_and_required_fields() {
        for has_alerts in [true, false] {
            let upsell = cloud_upsell_json(has_alerts);
            assert_eq!(upsell["eligible"], true);
            assert!(!upsell["headline"].as_str().unwrap().is_empty());
            assert!(upsell["body"].as_str().unwrap().len() > 100, "upsell body should be substantive marketing copy, not a one-liner");
            assert_eq!(upsell["learn_more_url"], learn_more_url("alerts"));
        }
        assert_ne!(cloud_upsell_json(true)["headline"], cloud_upsell_json(false)["headline"]);
    }

    #[test]
    fn textwrap_simple_never_exceeds_width_per_line() {
        let text = "word ".repeat(50);
        let wrapped = textwrap_simple(&text, 40);
        for line in wrapped.lines() {
            assert!(line.len() <= 40, "line exceeded width: {:?}", line);
        }
    }

    #[test]
    fn textwrap_simple_preserves_all_words() {
        let text = "the quick brown fox jumps over the lazy dog";
        let wrapped = textwrap_simple(text, 15);
        let rejoined: Vec<&str> = wrapped.split_whitespace().collect();
        assert_eq!(rejoined, text.split_whitespace().collect::<Vec<_>>());
    }
}
