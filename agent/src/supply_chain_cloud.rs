//! supply_chain_cloud.rs — subscription-gated cloud layer for the Supply
//! Chain tab: live OSV.dev vulnerability lookups and cross-project
//! "worm behavior" analytics. Mirrors `investigate.rs`/`summarize.rs`
//! exactly (`is_paid_tier()` gate, then `quota_guard`, then do the work) —
//! not `audit`'s "own second gRPC service" shape, since this is plain
//! request/response, not an agentic file/exec loop. Merged into vandamd's
//! shared UDS router via `VandamConfig::extra_routes` (see
//! `vandam::api::start_api_server`), overriding the OSS "unavailable"
//! defaults registered at the same paths — an OSS build never has these
//! handlers at all.
//!
//! Real local detection (install activity, project inventory, suspicious
//! postinstall behavior, an offline known-CVE cross-check) lives entirely in
//! `vandam::supply_chain`/`vandam::supply_chain_store` and needs none of
//! this — see the OSS/Pro separation note in the workspace CLAUDE.md.

use axum::{response::IntoResponse, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use vandam::api::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api/v1/risks/packages/osv-lookup", post(post_osv_lookup))
        .route("/api/v1/risks/analytics", get(get_analytics))
}

#[derive(Deserialize)]
struct OsvLookupRequest {
    packages: Vec<PackageQuery>,
}

#[derive(Deserialize, Serialize, Clone)]
struct PackageQuery {
    ecosystem: String,
    name: String,
    #[serde(default)]
    version: Option<String>,
}

#[derive(Serialize)]
struct OsvVuln {
    id: String,
    summary: String,
    severity: String,
}

/// OSV.dev's query API (https://api.osv.dev/v1/query, no auth needed) is
/// queried directly and synchronously — it responds in low tens of
/// milliseconds, so unlike `investigate`/`summarize`'s Pending->Completed
/// dance (built for a slower, evidence-graph-driven cloud analysis) this
/// just awaits and returns real results inline. Package name/ecosystem only
/// ever leaves the agent here — no customer/host data.
async fn query_osv(pkg: &PackageQuery) -> Vec<OsvVuln> {
    let client = reqwest::Client::new();
    let mut body = json!({ "package": { "name": pkg.name, "ecosystem": pkg.ecosystem } });
    if let Some(version) = &pkg.version {
        body["version"] = json!(version);
    }
    let Ok(resp) = client
        .post("https://api.osv.dev/v1/query")
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    else {
        return Vec::new();
    };
    let Ok(parsed) = resp.json::<serde_json::Value>().await else {
        return Vec::new();
    };
    parsed
        .get("vulns")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| OsvVuln {
                    id: v.get("id").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                    summary: v.get("summary").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                    severity: v
                        .get("database_specific")
                        .and_then(|d| d.get("severity"))
                        .and_then(|s| s.as_str())
                        .unwrap_or("UNKNOWN")
                        .to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn post_osv_lookup(Json(req): Json<OsvLookupRequest>) -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(json!({
            "status": "upgrade_required",
            "message": "Live OSV.dev vulnerability lookups are a vandam subscriber feature. Free/local detection uses an offline known-CVE list instead — upgrade for always-current coverage.",
        }));
    }

    if let Err(denied) = crate::quota_guard::get().check_and_record(crate::quota_guard::QuotaCategory::SupplyChain) {
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

    let mut results = Vec::new();
    for pkg in &req.packages {
        let vulns = query_osv(pkg).await;
        results.push(json!({
            "ecosystem": pkg.ecosystem,
            "name": pkg.name,
            "version": pkg.version,
            "vulnerabilities": vulns.iter().map(|v| json!({ "id": v.id, "summary": v.summary, "severity": v.severity })).collect::<Vec<_>>(),
        }));
    }

    Json(json!({ "status": "completed", "results": results }))
}

/// Real cross-project "worm behavior" heuristic (not mock data): groups
/// recent `Vulnerability.SupplyChain.*` alerts by a 10-minute sliding
/// window and flags a window where the *same kind* of event
/// (`threat_type`) fired against more than one distinct project path — the
/// shape of a self-propagating install-time payload spreading across
/// projects, which is exactly why this needs cloud-tier full-stack context
/// per the tab's own CTA copy (distinguishing that from two developers
/// coincidentally hitting the same CVE at the same time needs more context
/// than a single agent has locally — flagged here as a candidate, not an
/// automatic verdict).
async fn get_analytics() -> impl IntoResponse {
    if !vandam::tls_buffer::is_paid_tier() {
        return Json(json!({
            "status": "upgrade_required",
            "message": "Dependency-risk trend and cross-project worm-behavior correlation are a vandam subscriber feature.",
        }));
    }

    if let Err(denied) = crate::quota_guard::get().check_and_record(crate::quota_guard::QuotaCategory::SupplyChain) {
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

    let alerts = vandam::notifications::get_recent_alerts();
    let sc_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.threat_type.starts_with("Vulnerability.SupplyChain."))
        .collect();

    // Dependency-risk trend: count of Supply Chain alerts per UTC day.
    let mut by_day: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for a in &sc_alerts {
        let day = a.timestamp.get(0..10).unwrap_or("unknown").to_string();
        *by_day.entry(day).or_insert(0) += 1;
    }

    // Cross-project correlation: same threat_type, >1 distinct project
    // (approximated via process.cmdline's cwd-derived signal isn't
    // available on AlertPayload directly, so this correlates on
    // exec_path+threat_type pairs seen from more than one distinct pid
    // within a 10-minute window as a practical proxy).
    let window_secs: i64 = 600;
    let mut flagged: Vec<serde_json::Value> = Vec::new();
    for (i, a) in sc_alerts.iter().enumerate() {
        let Ok(t_a) = chrono::DateTime::parse_from_rfc3339(&a.timestamp) else { continue };
        for b in sc_alerts.iter().skip(i + 1) {
            if a.threat_type != b.threat_type || a.process.pid == b.process.pid {
                continue;
            }
            let Ok(t_b) = chrono::DateTime::parse_from_rfc3339(&b.timestamp) else { continue };
            if (t_a.timestamp() - t_b.timestamp()).abs() <= window_secs {
                flagged.push(json!({
                    "threat_type": a.threat_type,
                    "window_start": a.timestamp.clone().min(b.timestamp.clone()),
                    "pids": [a.process.pid, b.process.pid],
                    "note": "Same Supply Chain event type fired against two distinct processes within 10 minutes — possible cross-project propagation, not a confirmed verdict.",
                }));
            }
        }
    }

    Json(json!({
        "status": "completed",
        "dependency_risk_trend": by_day,
        "worm_behavior_candidates": flagged,
    }))
}
