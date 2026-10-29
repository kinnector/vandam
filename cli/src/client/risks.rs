use serde::{Deserialize, Serialize};


/// Real (non-mock) install-activity record, mirroring vandamd's
/// `GET /api/v1/risks/activity` response (`SupplyChainActivity` in
/// `vandam/src/supply_chain_store.rs`). Counterpart to `access_data.rs`'s
/// `Session` — same fetch/build shape.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ActivityRecord {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub time: String,
    #[serde(default)]
    pub manager: String,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub details: String,
    #[serde(default)]
    pub project_path: String,
    #[serde(default)]
    pub is_system_wide: bool,
    #[serde(default)]
    pub status: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct ActivityData {
    #[serde(default)]
    pub activities: Vec<ActivityRecord>,
}

/// One alert as returned by `GET /api/v1/risks/events` / `/blocked` — same
/// shape `alert_to_json` produces for the Alerts page, filtered server-side
/// to the `Vulnerability.SupplyChain.*` threat-type namespace. Only the
/// fields this tab renders are modeled here (not the full Alerts shape).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct RiskEvent {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub threat_type: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub process: RiskEventProcess,
    #[serde(default)]
    pub remediation: RiskEventRemediation,
    #[serde(default)]
    pub inspected: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct RiskEventProcess {
    #[serde(default)]
    pub exec_path: String,
    #[serde(default)]
    pub cmdline: String,
    #[serde(default)]
    pub parent_name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct RiskEventRemediation {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct RiskEventsData {
    #[serde(default)]
    pub events: Vec<RiskEvent>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct RiskBlockedData {
    #[serde(default)]
    pub blocked: Vec<RiskEvent>,
}

/// Mirrors vandamd's `ProjectRecord` (`vandam/src/supply_chain_store.rs`).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct ProjectRecord {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub framework: String,
    #[serde(default)]
    pub is_system_wide: bool,
    #[serde(default)]
    pub events_count: usize,
    #[serde(default)]
    pub filtered: bool,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct ProjectsData {
    #[serde(default)]
    pub projects: Vec<ProjectRecord>,
}

/// Mirrors `vandam::supply_chain_store::SupplyChainPolicy` — the free-tier
/// local prevention-rules dialog's backing data.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct SupplyChainPolicy {
    #[serde(default)]
    pub block_postinstall_scripts: bool,
    #[serde(default)]
    pub registry_allowlist: Vec<String>,
    #[serde(default)]
    pub auto_quarantine_severity: Option<String>,
    #[serde(default)]
    pub excluded_project_paths: Vec<String>,
}

pub fn fetch_activity(socket_path: &str) -> Result<ActivityData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/risks/activity", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/risks/activity response: {}", e))
}

pub fn fetch_events(socket_path: &str) -> Result<RiskEventsData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/risks/events", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/risks/events response: {}", e))
}

pub fn inspect_event(socket_path: &str, id: &str) -> Result<(), String> {
    let path = format!("/api/v1/risks/events/{}/inspect", id);
    crate::query_daemon(socket_path, "POST", &path, None).map(|_| ())
}

pub fn fetch_blocked(socket_path: &str) -> Result<RiskBlockedData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/risks/blocked", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/risks/blocked response: {}", e))
}

pub fn fetch_projects(socket_path: &str) -> Result<ProjectsData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/risks/projects", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/risks/projects response: {}", e))
}

pub fn filter_project(socket_path: &str, path: &str, filtered: bool) -> Result<(), String> {
    let body = serde_json::json!({ "path": path, "filtered": filtered });
    crate::query_daemon(socket_path, "POST", "/api/v1/risks/projects/filter", Some(&body)).map(|_| ())
}

pub fn fetch_policy(socket_path: &str) -> Result<SupplyChainPolicy, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/risks/policy", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/risks/policy response: {}", e))
}

pub fn put_policy(socket_path: &str, policy: &SupplyChainPolicy) -> Result<(), String> {
    crate::query_daemon(socket_path, "PUT", "/api/v1/risks/policy", Some(&serde_json::to_value(policy).unwrap_or_default())).map(|_| ())
}
