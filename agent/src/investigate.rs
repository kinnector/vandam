use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::json;
use vandam::api::AppState;
use vandam::notifications::{InvestigationInfo, InvestigationStatus};

/// Pro's implementation of `POST /api/v1/alerts/{id}/investigate`, merged
/// into vandamd's shared UDS router via `VandamConfig::extra_routes` (see
/// `vandam::api::start_api_server`) — this overrides the OSS default
/// ("unavailable, oss_build") registered at the same path, so an OSS build
/// never has this handler at all.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/alerts/{id}/investigate", post(post_investigate))
}

async fn post_investigate(
    Path(alert_id): Path<String>,
    State(_state): State<AppState>,
) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(json!({
            "status": "upgrade_required",
            "message": "Cloud investigation is a vandam subscriber feature. Upgrade to unlock full forensic analysis, stack traces, and automated remediation guidance for this alert.",
        }));
    }

    if let Err(denied) = crate::quota_guard::get().check_and_record(crate::quota_guard::QuotaCategory::Alerts) {
        let cooldown_until = match &denied {
            crate::quota_guard::QuotaDenied::Tripped { cooldown_until, .. } => Some(*cooldown_until),
            crate::quota_guard::QuotaDenied::ManuallyDisabled => None,
        };
        return Json(json!({
            "status": "disabled",
            "reason": denied.reason(),
            "cooldown_until_unix": cooldown_until,
        }));
    }

    let requested_at = chrono::Utc::now().to_rfc3339();
    vandam::notifications::set_investigation_state(
        &alert_id,
        InvestigationInfo {
            status: InvestigationStatus::Pending,
            requested_at: requested_at.clone(),
            completed_at: None,
            summary: None,
            report_url: None,
        },
    );

    // Ship whatever forensic data vandamd already has for this alert through
    // the same OSS->cloud channel `tls_buffer::flush_on_alert` uses
    // automatically for HIGH/CRITICAL paid-tier alerts
    // (vandam/src/cloud.rs::send_forensic_payload) — an explicit investigate
    // request re-sends on the alert id even if the automatic flush already
    // ran. Resolving Pending -> Completed happens out-of-band (the cloud
    // backend delivers its analysis back via a future callback/poll — not
    // implemented here).
    let dispatched = vandam::cloud::send_forensic_payload(&alert_id, Vec::new()).await;

    Json(json!({
        "status": "pending",
        "investigation_id": alert_id,
        "requested_at": requested_at,
        "dispatched": dispatched,
    }))
}
