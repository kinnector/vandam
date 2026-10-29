use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde_json::json;
use vandam::api::AppState;

use crate::quota_guard::{QuotaCategory, QuotaDenied};

/// Pro's implementation of `POST /api/v1/access/sessions/{id}/summarize`,
/// mirroring `investigate.rs`'s shape exactly: tier-gated, quota-guarded
/// (Decision 2/Phase 2 of the Cloud Auto-Audit Quota plan — built before
/// this so it launches already gated instead of needing a retrofit), sets
/// a pending state, dispatches to cloud, resolves out-of-band. Merged into
/// vandamd's shared UDS router via `VandamConfig::extra_routes` — overrides
/// the OSS "unavailable, oss_build" default registered at this path.
pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/access/sessions/{id}/summarize", post(post_summarize))
}

async fn post_summarize(Path(session_id): Path<String>, State(_state): State<AppState>) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(json!({
            "status": "upgrade_required",
            "message": "Cloud session summarization is a vandam subscriber feature. Upgrade to get a plain-English narrative of what happened in this session.",
        }));
    }

    if let Err(denied) = crate::quota_guard::get().check_and_record(QuotaCategory::Sessions) {
        let cooldown_until = match &denied {
            QuotaDenied::Tripped { cooldown_until, .. } => Some(*cooldown_until),
            QuotaDenied::ManuallyDisabled => None,
        };
        return Json(json!({
            "status": "disabled",
            "reason": denied.reason(),
            "cooldown_until_unix": cooldown_until,
        }));
    }

    let Some((meta, commands)) = vandam::pty_session_store::read_session(&session_id) else {
        return Json(json!({ "status": "not_found", "session_id": session_id }));
    };
    let correlated_events = crate::session_correlation::read_correlated(&session_id);

    let requested_at = chrono::Utc::now().to_rfc3339();

    // Ship the session's data through the same OSS->cloud channel
    // investigate.rs uses for alerts (vandam::cloud::send_forensic_payload).
    // Resolving to a completed summary happens out-of-band, same caveat as
    // investigate.rs: there is currently no response channel for the cloud
    // to deliver that back (see the Cloud Auto-Audit Quota plan's Context
    // section) — this dispatches the request and returns `pending`, it
    // does not itself produce a summary.
    let payload_json = json!({
        "session": meta,
        "commands": commands,
        "correlated_events": correlated_events,
    })
    .to_string();
    let dispatched = vandam::cloud::send_forensic_payload(&session_id, payload_json.into_bytes()).await;

    Json(json!({
        "status": "pending",
        "session_id": session_id,
        "requested_at": requested_at,
        "dispatched": dispatched,
    }))
}
