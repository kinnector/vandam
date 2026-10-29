use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::net::UnixListener;
use tokio::sync::broadcast;

static DISPATCH_DEDUP: OnceLock<Arc<DashMap<String, i64>>> = OnceLock::new();
const DEDUP_WINDOW_SECS: i64 = 300; // 5 minutes

static ALERT_LRU_CACHE: OnceLock<DashMap<(u32, String, u64), i64>> = OnceLock::new();
static ALERT_CHANNEL: OnceLock<broadcast::Sender<String>> = OnceLock::new();

static RECENT_ALERTS: OnceLock<Mutex<VecDeque<AlertPayload>>> = OnceLock::new();
const MAX_RECENT_ALERTS: usize = 100;

/// Local triage/investigation state for an alert, keyed by `alert_id`.
/// Separate from `AlertPayload` (which is append-only, one entry per
/// dispatched alert) because this is mutable state a client sets *after* the
/// alert already exists — dismiss/false-positive are plain OSS-owned local
/// state, `investigation` is only ever populated by vandam (see
/// `InvestigationInfo`).
static ALERT_STATE: OnceLock<DashMap<String, AlertState>> = OnceLock::new();

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AlertState {
    #[serde(default)]
    pub dismissed: bool,
    #[serde(default)]
    pub false_positive: bool,
    #[serde(default)]
    pub investigation: Option<InvestigationInfo>,
    /// Local "acknowledged" flag — first used by the Supply Chain tab's
    /// Security Events subtab (`GET /api/v1/risks/events`), generic enough
    /// for any alert-backed list view. Plain OSS-owned local state, no
    /// license check, same shape as `dismissed`/`false_positive`.
    #[serde(default)]
    pub inspected: bool,
}

/// Status of a paid-tier cloud investigation request. The envelope lives here
/// in OSS (mirrors `rasp_context`'s struct also living in OSS despite only
/// being populated by Pro) so `get_alerts()` can serialize it uniformly —
/// only `vandam`'s investigate handler ever calls `set_investigation_state`,
/// so an OSS build never populates this and callers see `None`.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InvestigationInfo {
    pub status: InvestigationStatus,
    pub requested_at: String,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub report_url: Option<String>,
}

fn alert_state_store() -> &'static DashMap<String, AlertState> {
    ALERT_STATE.get_or_init(DashMap::new)
}

/// Read an alert's local triage state. Never fails — an alert with no
/// recorded state (the common case) returns the all-`false`/`None` default.
pub fn get_alert_state(alert_id: &str) -> AlertState {
    alert_state_store()
        .get(alert_id)
        .map(|s| s.value().clone())
        .unwrap_or_default()
}

pub fn set_alert_dismissed(alert_id: &str, dismissed: bool) -> AlertState {
    let mut entry = alert_state_store().entry(alert_id.to_string()).or_default();
    entry.dismissed = dismissed;
    entry.clone()
}

pub fn set_alert_false_positive(alert_id: &str, false_positive: bool) -> AlertState {
    let mut entry = alert_state_store().entry(alert_id.to_string()).or_default();
    entry.false_positive = false_positive;
    entry.clone()
}

pub fn set_alert_inspected(alert_id: &str, inspected: bool) -> AlertState {
    let mut entry = alert_state_store().entry(alert_id.to_string()).or_default();
    entry.inspected = inspected;
    entry.clone()
}

/// Set by `vandam`'s investigate handler only — see `InvestigationInfo`.
pub fn set_investigation_state(alert_id: &str, investigation: InvestigationInfo) -> AlertState {
    let mut entry = alert_state_store().entry(alert_id.to_string()).or_default();
    entry.investigation = Some(investigation);
    entry.clone()
}

pub fn add_alert_to_queue(payload: AlertPayload) {
    let queue =
        RECENT_ALERTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_RECENT_ALERTS)));
    if let Ok(mut q) = queue.lock() {
        if q.len() >= MAX_RECENT_ALERTS {
            q.pop_front();
        }
        q.push_back(payload);
    }
}

pub fn get_recent_alerts() -> Vec<AlertPayload> {
    let queue =
        RECENT_ALERTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_RECENT_ALERTS)));
    if let Ok(q) = queue.lock() {
        q.iter().cloned().collect()
    } else {
        Vec::new()
    }
}

/// B-09 fix: Emit a one-time warning if notifications.json is absent so operators
/// are not silently left wondering why webhooks aren't firing.
static NOTIF_CONFIG_WARNED: OnceLock<()> = OnceLock::new();

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SlackConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DiscordConfig {
    pub enabled: bool,
    pub webhook_url: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericWebhookConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub headers: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotificationSettings {
    pub slack: Option<SlackConfig>,
    pub discord: Option<DiscordConfig>,
    pub telegram: Option<TelegramConfig>,
    #[serde(rename = "generic_webhook")]
    pub generic_webhook: Option<GenericWebhookConfig>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NotificationConfig {
    pub notifications: NotificationSettings,
}

fn default_confidence() -> f32 {
    0.90
}

/// How a `site` attribution was determined. Mirrors `storage_discovery`'s
/// `DiscoveryMethod` provenance-tracking pattern, applied to sites instead of
/// storage paths — more inference methods (`.env`, server config, ...) can be
/// added here as they're implemented; `ProxyConfig` is the only one today.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SiteSource {
    /// vandamd's own inference — pid-tree correlation against topology
    /// discovered by parsing reverse-proxy configs (nginx/apache
    /// `server_name` directives). Only ever determined at serve time (see
    /// `attribute_alerts()`/`find_alert_attribution()` in api.rs) — a
    /// persisted `AlertPayload` has no server-topology context available at
    /// creation time, so this variant never appears on `AlertPayload.site_source`.
    ProxyConfig,
    /// A client told us directly — vandam-php's `http_host` (RASP) or
    /// vandam-wordpress's `get_site_url()`. No inference involved.
    ClientReported,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlertPayload {
    pub alert_id: String,
    pub timestamp: String,
    pub threat_type: String,
    pub severity: String,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    pub container: Option<ContainerInfo>,
    pub process: ProcessInfo,
    pub remediation: RemediationInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rasp_context: Option<crate::discovery::RaspRichContext>,
    #[serde(default)]
    pub origin_tree: Vec<ProcessTreeEntry>,
    #[serde(default)]
    pub network_links: Vec<NetworkLinkMetadata>,
    #[serde(default)]
    pub container_meta: Option<ContainerMeta>,
    /// Site/domain this alert is attributed to, when known. Filled from a
    /// client's self-report (e.g. vandam-wordpress sending its own domain,
    /// or vandam's RASP listener reporting its own request context) at
    /// creation time. vandamd's own pid-tree correlation happens later, at
    /// serve time, and is never recorded here — see `SiteSource::ProxyConfig`.
    #[serde(default)]
    pub site: Option<String>,
    /// How `site` was determined — `None` iff `site` is `None`. Always
    /// `ClientReported` here in practice: see `SiteSource::ProxyConfig`'s
    /// doc comment for why that variant can't appear on a persisted payload.
    #[serde(default)]
    pub site_source: Option<SiteSource>,
    /// Structured detail for the triggering eBPF event, when the alert came
    /// from `heuristics.rs`'s `EventType` handling rather than a generic
    /// threat/quarantine path. See `AlertEventDetail`.
    #[serde(default)]
    pub event_detail: Option<AlertEventDetail>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessTreeEntry {
    pub pid: u32,
    pub ppid: u32,
    pub exec_path: String,
    pub cmdline: String,
    #[serde(default)]
    pub verified_package: Option<String>,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub ports: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NetworkLinkMetadata {
    pub dst_ip: String,
    pub dst_port: u16,
    pub target_type: String,
    pub target_service: String,
    pub last_connect_time: String,
    #[serde(default)]
    pub dst_process_tree: Vec<ProcessTreeEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerMeta {
    pub container_id: String,
    pub container_name: String,
    pub container_image: String,
    pub orchestrator: String,
    pub namespace: Option<String>,
    pub pod_uid: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    #[serde(default)]
    pub image_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub attached: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exec_path: String,
    pub cmdline: String,
    pub parent_exec_path: String,
    pub parent_pid: u32,
    #[serde(default)]
    pub verified_package: Option<String>,
    #[serde(default)]
    pub envs: Vec<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// Detected software signature for this process (e.g. from
    /// `linux_web_signatures.json`/`linux_database_signatures.json` via
    /// `kinnector-config`), when known.
    #[serde(default)]
    pub signature_name: Option<String>,
    /// systemd unit name running this process, when known.
    #[serde(default)]
    pub service: Option<String>,
}

/// Structured detail for quarantine remediation actions. Mirrors the values
/// already interpolated into `RemediationInfo.status` text by
/// `quarantine::emit_quarantine_alert` — kept here as structured fields too so
/// clients (e.g. `POST /api/v1/quarantine/restore`) don't have to parse them
/// back out of a free-text string.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuarantineInfo {
    pub original_path: String,
    pub quarantine_path: String,
    pub inode: u64,
    pub success: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemediationInfo {
    pub action: String,
    pub status: String,
    #[serde(default)]
    pub requires_cloud_decision: bool,
    #[serde(default)]
    pub quarantine: Option<QuarantineInfo>,
}

/// Structured detail for the eBPF event that triggered an alert. Carries the
/// fields that `heuristics.rs`'s `EventType` match arms already compute but
/// previously only interpolated into `RemediationInfo.status` free text.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertEventDetail {
    NetworkAccept {
        source_ip: String,
        source_port: u16,
        local_port: u16,
    },
    DnsQuery {
        domain: String,
        server_ip: String,
        server_port: u16,
    },
    FileDelete {
        path: String,
        is_critical_dir: bool,
    },
    Signal {
        target_pid: u32,
        signal: i32,
    },
}

pub async fn load_notification_config() -> Option<NotificationConfig> {
    let path = Path::new("/etc/kinnector/notifications.json");
    if !path.exists() {
        return None;
    }
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(config) = serde_json::from_str::<NotificationConfig>(&content) {
            return Some(config);
        }
    }
    None
}

fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub fn start_alert_socket_server() {
    tokio::spawn(async {
        let socket_path = "/run/vandam/alerts.sock";
        let _ = std::fs::remove_file(socket_path);
        let _ = std::fs::create_dir_all("/run/vandam");

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => {
                let _ =
                    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666));
                l
            }
            Err(e) => {
                tracing::error!(
                    "[Vandam Alert Socket] Failed to bind Unix socket {}: {}",
                    socket_path,
                    e
                );
                return;
            }
        };

        tracing::info!("[Vandam Alert Socket] Listening on {}", socket_path);
        let tx = ALERT_CHANNEL.get_or_init(|| {
            let (t, _) = broadcast::channel(100);
            t
        });

        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut rx = tx.subscribe();
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt;
                    while let Ok(msg) = rx.recv().await {
                        if stream.write_all(msg.as_bytes()).await.is_err() {
                            break;
                        }
                        if stream.write_all(b"\n").await.is_err() {
                            break;
                        }
                    }
                });
            }
        }
    });
}

pub fn broadcast_alert_to_socket(payload_json: &str) {
    let tx = ALERT_CHANNEL.get_or_init(|| {
        let (t, _) = broadcast::channel(100);
        t
    });
    let _ = tx.send(payload_json.to_string());
}

static CORRELATION_TRACKER: OnceLock<Arc<DashMap<u32, (i64, Vec<String>)>>> = OnceLock::new();
const CORRELATION_WINDOW_SECS: i64 = 30;

pub fn calculate_confidence_and_correlate(payload: &mut AlertPayload) {
    let mut base_conf: f32 = match payload.severity.as_str() {
        "CRITICAL" => 0.90,
        "HIGH" => 0.75,
        "MEDIUM" => 0.60,
        "LOW" => 0.40,
        _ => 0.50,
    };

    let pid = payload.process.pid;
    let now = chrono::Utc::now().timestamp();

    if pid > 0 {
        let tracker = CORRELATION_TRACKER.get_or_init(|| Arc::new(DashMap::new()));
        let mut is_multi_threat = false;

        if let Some(mut entry) = tracker.get_mut(&pid) {
            let (start_time, ref mut threats) = *entry;
            if now - start_time <= CORRELATION_WINDOW_SECS {
                if !threats.contains(&payload.threat_type) {
                    threats.push(payload.threat_type.clone());
                }
                if threats.len() >= 2 {
                    is_multi_threat = true;
                }
            } else {
                *entry = (now, vec![payload.threat_type.clone()]);
            }
        } else {
            tracker.insert(pid, (now, vec![payload.threat_type.clone()]));
        }

        if is_multi_threat {
            base_conf = (base_conf + 0.15).min(1.0);
            if payload.threat_type.starts_with("Threat.Server.")
                && payload.threat_type != "Threat.Server.ActiveExploit"
            {
                payload.threat_type = "Threat.Server.ActiveExploit".to_string();
                payload.severity = "CRITICAL".to_string();
            }
        }
    }

    payload.confidence = base_conf;
}

pub fn dispatch_alert(mut payload: AlertPayload) {
    calculate_confidence_and_correlate(&mut payload);

    // 1. Userspace LRU Alert Deduplication: check (pid, violation_type, command_hash)
    let cmd_hash = calculate_hash(&payload.process.cmdline);
    let lru_key = (payload.process.pid, payload.threat_type.clone(), cmd_hash);
    let lru_cache = ALERT_LRU_CACHE.get_or_init(|| DashMap::new());
    let now_ms = chrono::Utc::now().timestamp_millis();
    if let Some(last_time) = lru_cache.get(&lru_key) {
        if now_ms - *last_time < 1000 {
            tracing::info!("[Vandam Alert Deduplication] Suppressing high-frequency duplicate alert for PID {}", payload.process.pid);
            return;
        }
    }
    lru_cache.insert(lru_key, now_ms);

    add_alert_to_queue(payload.clone());
    if let Ok(s) = serde_json::to_string(&payload) {
        let _ = crate::audit::write_to_audit_log(&s);
        crate::cloud::queue_log_entry(&s);
        broadcast_alert_to_socket(&s);
    }
    crate::cloud::send_alert_immediate(&payload);

    tokio::spawn(async move {
        // Dedup: skip if same (threat_type, pid) fired within 5 min
        let mut dedup_key = format!("{}:{}", payload.threat_type, payload.process.pid);
        if payload.threat_type.starts_with("Event.Server.SSHAuth") {
            use std::str::FromStr;
            let ip = payload
                .remediation
                .status
                .split_whitespace()
                .find(|word| {
                    let cleaned = word.trim_matches(|c| {
                        c == ',' || c == '.' || c == ':' || c == '\'' || c == '"'
                    });
                    std::net::IpAddr::from_str(cleaned).is_ok()
                })
                .map(|word| {
                    word.trim_matches(|c| c == ',' || c == '.' || c == ':' || c == '\'' || c == '"')
                })
                .unwrap_or("");
            dedup_key = format!("{}:{}:{}", payload.threat_type, payload.process.pid, ip);
        }
        let now = chrono::Utc::now().timestamp();
        let dedup = DISPATCH_DEDUP.get_or_init(|| Arc::new(DashMap::new()));
        if let Some(last) = dedup.get(&dedup_key) {
            if now - *last < DEDUP_WINDOW_SECS {
                return;
            }
        }
        dedup.insert(dedup_key, now);

        let config = match load_notification_config().await {
            Some(c) => c,
            None => {
                // B-09 fix: warn once instead of silently returning
                NOTIF_CONFIG_WARNED.get_or_init(|| {
                    eprintln!(
                        "[Vandam Notifications] WARNING: /etc/kinnector/notifications.json not found. \
                         Webhook dispatch is disabled. Create the file to enable Slack/Discord/Telegram alerts."
                    );
                });
                return;
            }
        };
        let client = reqwest::Client::new();

        // 1. Slack dispatch
        if let Some(slack) = config.notifications.slack {
            if slack.enabled && !slack.webhook_url.is_empty() {
                let slack_body = serde_json::json!({
                    "text": format!(
                        "🚨 *[Kinnector EDR Alert]*\n*Threat*: `{}`\n*Severity*: `{}`\n*PID*: `{}`\n*Executable*: `{}`\n*Cmdline*: `{}`\n*Action*: `{}` ({})",
                        payload.threat_type, payload.severity, payload.process.pid, payload.process.exec_path, payload.process.cmdline, payload.remediation.action, payload.remediation.status
                    )
                });
                let _ = client
                    .post(&slack.webhook_url)
                    .json(&slack_body)
                    .send()
                    .await;
            }
        }

        // 2. Discord dispatch
        if let Some(discord) = config.notifications.discord {
            if discord.enabled && !discord.webhook_url.is_empty() {
                let discord_body = serde_json::json!({
                    "content": format!(
                        "💥 **[Kinnector EDR Alert]**\n**Threat**: `{}`\n**Severity**: `{}`\n**Executable**: `{}`\n**Action**: `{}`",
                        payload.threat_type, payload.severity, payload.process.exec_path, payload.remediation.action
                    )
                });
                let _ = client
                    .post(&discord.webhook_url)
                    .json(&discord_body)
                    .send()
                    .await;
            }
        }

        // 3. Telegram dispatch
        if let Some(telegram) = config.notifications.telegram {
            if telegram.enabled && !telegram.bot_token.is_empty() && !telegram.chat_id.is_empty() {
                let tg_url = format!(
                    "https://api.telegram.org/bot{}/sendMessage",
                    telegram.bot_token
                );
                let tg_body = serde_json::json!({
                    "chat_id": telegram.chat_id,
                    "text": format!(
                        "⚠️ [Kinnector Alert]\nThreat: {}\nSeverity: {}\nPath: {}\nAction: {}",
                        payload.threat_type, payload.severity, payload.process.exec_path, payload.remediation.action
                    )
                });
                let _ = client.post(&tg_url).json(&tg_body).send().await;
            }
        }

        // 4. Generic Webhook dispatch
        if let Some(generic) = config.notifications.generic_webhook {
            if generic.enabled && !generic.endpoint.is_empty() {
                let mut req = client.post(&generic.endpoint).json(&payload);
                if let Some(headers) = generic.headers {
                    for (k, v) in headers {
                        req = req.header(k, v);
                    }
                }
                let _ = req.send().await;
            }
        }
    });
}
