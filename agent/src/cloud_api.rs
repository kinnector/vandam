use axum::{extract::Path, response::IntoResponse, routing::get, Json, Router};
use serde_json::json;
use vandam::api::AppState;

use crate::quota_guard::{self, QuotaCategory};

/// Pro's implementation of the `/api/v1/cloud/*` family (plan/quota status,
/// per-category auto-audit toggle, operational log), merged into vandamd's
/// shared UDS router via `VandamConfig::extra_routes` — overrides the OSS
/// "unavailable, oss_build" defaults registered at these paths, mirroring
/// `investigate.rs::router()` exactly.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/cloud/status", get(get_cloud_status))
        .route(
            "/api/v1/cloud/auto-audit/{category}",
            get(get_auto_audit).post(post_auto_audit),
        )
        .route("/api/v1/cloud/logs", get(get_cloud_logs))
}

async fn get_cloud_status() -> impl IntoResponse {
    let tier = vandam::tls_buffer::license_tier();
    let tier_str = match tier {
        vandam::tls_buffer::LicenseTier::Max => "max",
        vandam::tls_buffer::LicenseTier::Pro => "pro",
        vandam::tls_buffer::LicenseTier::Free => "free",
    };
    Json(json!({
        "plan": tier_str,
        "categories": quota_guard::get().status(),
    }))
}

async fn get_auto_audit(Path(category): Path<String>) -> impl IntoResponse {
    let Some(cat) = QuotaCategory::from_str(&category) else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown category '{}'", category) })),
        );
    };
    let state = quota_guard::get().status().into_iter().find(|s| s.category == cat);
    (axum::http::StatusCode::OK, Json(json!({ "category": category, "state": state })))
}

#[derive(serde::Deserialize)]
struct AutoAuditReq {
    enabled: bool,
}

async fn post_auto_audit(Path(category): Path<String>, Json(payload): Json<AutoAuditReq>) -> impl IntoResponse {
    let Some(cat) = QuotaCategory::from_str(&category) else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("unknown category '{}'", category) })),
        );
    };
    quota_guard::get().set_manual(cat, payload.enabled);
    (axum::http::StatusCode::OK, Json(json!({ "status": "ok", "category": category, "enabled": payload.enabled })))
}

async fn get_cloud_logs() -> impl IntoResponse {
    Json(json!({ "logs": quota_guard::read_logs(200) }))
}
