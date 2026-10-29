use serde::{Deserialize, Serialize};

/// Real (non-mock) alert list, mirroring vandamd's `/api/v1/alerts` response
/// (`alert_to_json` in `vandam/src/api.rs`). Counterpart to `containers_data.rs`
/// / `servers_data.rs` — same `fetch`/mutate/`build_*_targets` shape, shared
/// between the TUI's Alerts tab and the CLI's `alerts` subcommands.
#[derive(Deserialize, Default, Clone, Debug)]
pub struct AlertsData {
    #[serde(default)]
    pub alerts: Vec<Alert>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct SiteInfo {
    #[serde(default)]
    pub domain: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct BackendInfo {
    #[serde(default)]
    pub name: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct ProcessInfo {
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub exec_path: String,
    #[serde(default)]
    pub cmdline: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct RemediationInfo {
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct ContainerInfo {
    #[serde(default)]
    pub name: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct InvestigationInfo {
    #[serde(default)]
    pub status: String,
}

/// Paid-tier-gated forensic context — always `None` on an OSS build or an
/// unlicensed daemon (see `is_paid_tier()` gating in `vandam/src/api.rs`).
#[derive(Deserialize, Default, Clone, Debug)]
pub struct RaspContext {
    #[serde(default)]
    pub function_name: String,
    #[serde(default)]
    pub source_file: String,
    #[serde(default)]
    pub affected_lib: String,
    #[serde(default)]
    pub rasp_stack: String,
    #[serde(default)]
    pub rasp_integrity: String,
    #[serde(default)]
    pub is_interpreted: bool,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct Alert {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub threat_type: String,
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub site: Option<SiteInfo>,
    #[serde(default)]
    pub backend: Option<BackendInfo>,
    #[serde(default)]
    pub process: ProcessInfo,
    #[serde(default)]
    pub remediation: RemediationInfo,
    #[serde(default)]
    pub container: Option<ContainerInfo>,
    #[serde(default)]
    pub dismissed: bool,
    #[serde(default)]
    pub false_positive: bool,
    #[serde(default)]
    pub investigation: Option<InvestigationInfo>,
    #[serde(default)]
    pub rasp_context: Option<RaspContext>,
}

pub fn fetch(socket_path: &str) -> Result<AlertsData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/alerts", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/alerts response: {}", e))
}

/// Dismiss / mark-false-positive — plain OSS-owned local triage, no license
/// check (see `PATCH /api/v1/alerts/{id}` in `vandam/src/api.rs`). Shared by
/// the CLI's `alerts dismiss`/`alerts false-positive` and the TUI's `[d]`/`[f]`
/// keys so they can't drift on the request shape vandamd expects.
pub fn set_dismissed(socket_path: &str, alert_id: &str, dismissed: bool) -> Result<(), String> {
    let body = serde_json::json!({ "dismissed": dismissed });
    let path = format!("/api/v1/alerts/{}", alert_id);
    crate::query_daemon(socket_path, "PATCH", &path, Some(&body)).map(|_| ())
}

pub fn set_false_positive(socket_path: &str, alert_id: &str, false_positive: bool) -> Result<(), String> {
    let body = serde_json::json!({ "false_positive": false_positive });
    let path = format!("/api/v1/alerts/{}", alert_id);
    crate::query_daemon(socket_path, "PATCH", &path, Some(&body)).map(|_| ())
}

/// Result of `POST /api/v1/alerts/{id}/investigate`. `status` differs by
/// build/license — `"unavailable"` (OSS build), `"upgrade_required"` (Pro, no
/// subscription), or `"pending"` (Pro, paid — cloud investigation dispatched).
/// The daemon is authoritative; this is a thin carrier for whatever it said,
/// not a client-side tier decision (see `vandam/src/api.rs`'s default handler
/// and `vandam/src/investigate.rs`'s real one).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct InvestigateResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub investigation_id: Option<String>,
}

pub fn investigate(socket_path: &str, alert_id: &str) -> Result<InvestigateResult, String> {
    let path = format!("/api/v1/alerts/{}/investigate", alert_id);
    let value = crate::query_daemon(socket_path, "POST", &path, None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse investigate response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_response_shape_parses_into_alerts_data() {
        let value = serde_json::json!({
            "alerts": [
                { "id": "a1", "severity": "HIGH", "threat_type": "Threat.Test", "timestamp": "2026-01-01T00:00:00Z",
                  "process": { "pid": 1, "exec_path": "/bin/sh", "cmdline": "sh" },
                  "remediation": { "action": "LOG_ALERT", "status": "test" } }
            ]
        });
        let data: AlertsData = serde_json::from_value(value).unwrap();
        assert_eq!(data.alerts.len(), 1);
        assert_eq!(data.alerts[0].id, "a1");
    }
}
