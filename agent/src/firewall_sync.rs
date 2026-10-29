use axum::{response::IntoResponse, routing::get, Json, Router};
use serde_json::json;
use vandam::api::AppState;
use vandam::firewall::cloud_sync::CloudFirewallSync;
use vandam::firewall::FirewallRule;

/// Pro's implementation of bidirectional firewall rule sync — the
/// `CloudFirewallSync` counterpart to `investigate.rs`'s route override,
/// but threaded through `VandamConfig::firewall_cloud_sync` instead of
/// `extra_routes` since it's called periodically from `run_vandam`'s
/// background loop, not from an HTTP handler.
///
/// Unlike `investigate.rs` (paywalled via `is_paid_tier()`), firewall sync
/// works in every vandam build regardless of subscription status —
/// this is a deliberate product decision, not an oversight: fleet-wide
/// firewall control needs to work for `sub` and `nosub` installs alike.
/// `is_paid_tier()` still gates other Pro-only capabilities (investigate,
/// RASP) unaffected by this file.
pub struct ProFirewallSync;

#[async_trait::async_trait]
impl CloudFirewallSync for ProFirewallSync {
    async fn push_local_rules(&self, rules: &[FirewallRule]) -> Result<(), String> {
        let json = serde_json::to_string(rules).map_err(|e| e.to_string())?;
        vandam::cloud::sync_firewall_rules_with_cloud(json).await.map(|_| ())
    }

    async fn pull_cloud_rules(&self) -> Result<Vec<FirewallRule>, String> {
        match vandam::cloud::sync_firewall_rules_with_cloud(String::new()).await? {
            Some(cloud_rules_json) => serde_json::from_str(&cloud_rules_json)
                .map_err(|e| format!("failed to parse cloud rules: {}", e)),
            None => Ok(Vec::new()),
        }
    }
}

/// Pro's implementation of `GET /api/v1/firewall/sync/status`, merged into
/// vandamd's shared UDS router via `VandamConfig::extra_routes` — overrides
/// the OSS default ("unavailable, oss_build") registered at the same path,
/// mirroring `investigate.rs::router()` exactly. Reports "active"
/// unconditionally in a Pro build — see `ProFirewallSync`'s doc comment for
/// why this isn't subscription-gated.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/firewall/sync/status", get(get_sync_status))
}

async fn get_sync_status() -> impl IntoResponse {
    Json(json!({
        "status": "active",
        "message": "Firewall rules sync with the cloud console every 5 minutes.",
    }))
}
