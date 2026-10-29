use serde::{Deserialize, Serialize};

/// Real (non-mock) cloud/quota status, mirroring vandamd's
/// `/api/v1/cloud/*` responses (`vandam/src/quota_guard.rs`,
/// `vandam/src/cloud_api.rs`). Counterpart to `access_data.rs` — same
/// fetch/mutate shape, shared between the TUI's Cloud tab and the CLI's
/// `cloud` subcommands. On an OSS build or a Pro build with no Pro
/// extension routes, every endpoint here returns `{"status":"unavailable",
/// "reason":"oss_build"}` instead of this shape — callers should treat a
/// parse failure/empty `categories` as "not available," not an error.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct CategoryState {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub manually_disabled: bool,
    #[serde(default)]
    pub tripped: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub tripped_at: Option<String>,
    #[serde(default)]
    pub cooldown_until: Option<i64>,
    #[serde(default)]
    pub window_used: usize,
    #[serde(default)]
    pub window_limit: usize,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct CloudStatus {
    #[serde(default)]
    pub plan: String,
    #[serde(default)]
    pub categories: Vec<CategoryState>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct LogEntry {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub detail: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct CloudLogsData {
    #[serde(default)]
    pub logs: Vec<LogEntry>,
}

pub fn fetch_status(socket_path: &str) -> Result<CloudStatus, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/cloud/status", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/cloud/status response: {}", e))
}

pub fn fetch_logs(socket_path: &str) -> Result<CloudLogsData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/cloud/logs", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/cloud/logs response: {}", e))
}

pub fn set_auto_audit(socket_path: &str, category: &str, enabled: bool) -> Result<(), String> {
    let body = serde_json::json!({ "enabled": enabled });
    let path = format!("/api/v1/cloud/auto-audit/{}", category);
    crate::query_daemon(socket_path, "POST", &path, Some(&body)).map(|_| ())
}

/// Human-readable category order for the 4-row toggle list — fixed rather
/// than whatever order the daemon happens to return, so the TUI/CLI don't
/// jitter between refreshes.
pub const CATEGORY_ORDER: [&str; 4] = ["alerts", "sessions", "audits", "supply_chain"];

pub fn category_label(category: &str) -> &'static str {
    match category {
        "alerts" => "Alerts",
        "sessions" => "Sessions",
        "audits" => "Audits",
        "supply_chain" => "Supply Chain",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_status_response_shape_parses() {
        let value = serde_json::json!({
            "plan": "max",
            "categories": [
                { "category": "alerts", "manually_disabled": false, "tripped": false, "reason": null,
                  "tripped_at": null, "cooldown_until": null, "window_used": 3, "window_limit": 200 }
            ]
        });
        let status: CloudStatus = serde_json::from_value(value).unwrap();
        assert_eq!(status.plan, "max");
        assert_eq!(status.categories.len(), 1);
        assert_eq!(status.categories[0].window_limit, 200);
    }

    #[test]
    fn unavailable_response_does_not_panic_and_yields_empty_categories() {
        let value = serde_json::json!({ "status": "unavailable", "reason": "oss_build" });
        let status: CloudStatus = serde_json::from_value(value).unwrap();
        assert!(status.categories.is_empty());
        assert!(status.plan.is_empty());
    }
}
