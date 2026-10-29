//! api.rs — `/api/v1/audit/*`, entirely owned by `vandam`. Unlike
//! `investigate.rs`/`summarize.rs` (thin Pro handlers overriding a single
//! OSS-known path), these are brand-new paths OSS has never registered —
//! `api::start_api_server`'s `extra_routes` merge is a blind `app.merge`
//! for anything not already an OSS path, so no OSS placeholder is needed
//! here at all. Every handler is tier-checked (the data only exists in a
//! Pro build, there's no ungated OSS view the way Alerts has); only
//! starting a run additionally consumes quota.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use vandam::api::AppState;

use crate::quota_guard::{QuotaCategory, QuotaDenied};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/audit/runs", get(get_runs).post(post_runs))
        .route("/api/v1/audit/runs/{id}", get(get_run_detail))
        .route("/api/v1/audit/findings/{id}/remediate", post(post_remediate))
        .route("/api/v1/audit/findings/{id}/strings", get(get_finding_strings))
}

async fn get_runs() -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(upgrade_required_value());
    }
    Json(json!({ "runs": super::store::list_runs() }))
}

async fn get_run_detail(Path(run_id): Path<String>) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(upgrade_required_value());
    }
    let Some(run) = super::store::read_run(&run_id) else {
        return Json(json!({ "status": "not_found", "run_id": run_id }));
    };
    let findings = super::store::list_findings(&run_id);
    Json(json!({ "run": run, "findings": findings }))
}

async fn post_runs(State(state): State<AppState>) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(upgrade_required_value());
    }

    if let Err(denied) = crate::quota_guard::get().check_and_record(QuotaCategory::Audits) {
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

    let run = super::store::create_run(super::default_observation_window_secs());
    let run_id = run.id.clone();
    let engine = state.heuristics.clone();
    // 10-30 minutes end to end — must not block the HTTP response. The
    // caller polls GET /api/v1/audit/runs/{id} for progress, same shape as
    // every other long-running Pro dispatch (investigate/summarize) except
    // those resolve out-of-band via the cloud; this one also runs real local
    // work first.
    tokio::spawn(super::run_audit_scan(run_id, engine));

    Json(json!({ "status": "queued", "run_id": run.id, "started_at": run.started_at }))
}

async fn post_remediate(Path(finding_id): Path<String>) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(upgrade_required_value());
    }

    let Some((run_id, finding)) = super::store::find_finding(&finding_id) else {
        return Json(json!({ "status": "not_found", "finding_id": finding_id }));
    };

    let path = finding.evidence.get("path").and_then(|v| v.as_str());
    let remediation_result = match path {
        Some(path) => {
            match vandam::quarantine::quarantine_file(path, &finding.id, &finding.title, &finding.category) {
                Ok(dest) => json!({ "quarantined": true, "quarantine_path": dest.to_string_lossy() }),
                Err(e) => json!({ "quarantined": false, "error": e.to_string() }),
            }
        }
        None => json!({ "quarantined": false, "error": "finding has no associated file path" }),
    };

    super::store::set_finding_remediated(&run_id, &finding_id, true);
    Json(json!({ "status": "remediated", "finding_id": finding_id, "result": remediation_result }))
}

async fn get_finding_strings(Path(finding_id): Path<String>) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(upgrade_required_value());
    }
    let Some((run_id, _finding)) = super::store::find_finding(&finding_id) else {
        return Json(json!({ "status": "not_found", "finding_id": finding_id }));
    };
    match super::store::read_finding_strings(&run_id, &finding_id) {
        Some(content) => Json(json!({ "status": "ok", "finding_id": finding_id, "strings": content })),
        None => Json(json!({ "status": "not_available", "finding_id": finding_id })),
    }
}

fn upgrade_required_value() -> serde_json::Value {
    json!({
        "status": "upgrade_required",
        "message": "Deep Audit is a vandam subscriber feature.",
    })
}
