//! audit/ — Deep Audit pipeline, entirely owned by `vandam`. See the
//! Audit deep-scan design plan for why this whole feature (not just its
//! entry point) lives here instead of following the `investigate.rs`/
//! `summarize.rs` "thin Pro handler over OSS-owned data" shape: there is no
//! OSS-independent reason for `AuditRun`/`AuditFinding` to exist at all.

pub mod api;
pub mod cloud_transport;
pub mod observe;
pub mod pkg_verify;
pub mod runtime;
pub mod snapshot;
pub mod store;
pub mod strings;
pub mod types;

use std::collections::HashSet;
use std::sync::Arc;
use types::{AuditFinding, AuditRunStatus, FindingSeverity};
use vandam::heuristics::HeuristicsEngine;

/// Default Stage 3 observation-window length — the mock UI's "10 min" was
/// for the whole pipeline; this covers the behavioral-watching stage
/// specifically, with the rest of the 10-30 min budget spent on stage 5's
/// cloud round-trip. Overridable for testing/tuning without a rebuild.
pub fn default_observation_window_secs() -> u64 {
    std::env::var("VANDAM_AUDIT_OBSERVATION_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
}

/// How long Stage 5 stays open for agentic file/dir/exec requests after the
/// evidence graph is dispatched. There is no ack/completion callback from
/// cloud yet (`cloud_transport::AuditConsoleMessage` has no "I'm done"
/// message — the same documented gap `investigate.rs`/`summarize.rs` have,
/// see the Max-tier plan design's "no ack channel" note), so this is a
/// bounded wait, not a true wait-for-completion: the run is marked Complete
/// once this elapses regardless of whether cloud actually finished.
pub fn default_cloud_correlation_window_secs() -> u64 {
    std::env::var("VANDAM_AUDIT_CLOUD_WINDOW_SECS").ok().and_then(|v| v.parse().ok()).unwrap_or(300)
}

/// Orchestrates a single deep-audit run end to end. Spawned as a background
/// task by `api::post_runs` — the whole point is that it does NOT block the
/// HTTP response, since this can legitimately run for 10-30 minutes.
pub async fn run_audit_scan(run_id: String, engine: Arc<HeuristicsEngine>) {
    store::set_status(&run_id, AuditRunStatus::Stage1Snapshot);
    let snap = snapshot::collect(&engine.config, engine.process_map.len());

    store::set_status(&run_id, AuditRunStatus::Stage2Runtime);
    let runtime_snap = runtime::collect(&engine);

    // Attribution pass: every distinct executable seen running, plus every
    // present persistence-path target, checked against package-manager
    // ownership. This is what turns "0 dpkg/rpm matches" from the old mock
    // into a real finding.
    let mut checked: HashSet<String> = HashSet::new();
    for p in &runtime_snap.processes {
        if !p.exe.is_empty() && checked.insert(p.exe.clone()) {
            attribute_and_record(&run_id, &p.exe, &format!("PID {} ({})", p.pid, p.cmdline));
        }
    }
    for path in &snap.persistence_paths_present {
        if checked.insert(path.clone()) {
            attribute_and_record(&run_id, path, "persistence location");
        }
    }

    // Snapshot the observation window's declared length before AuditRun is
    // reloaded/overwritten by the status transitions below.
    let observation_window_secs =
        store::read_run(&run_id).map(|r| r.observation_window_secs).unwrap_or_else(default_observation_window_secs);

    store::set_status(&run_id, AuditRunStatus::Stage3Observation);
    observe::observe(&run_id, &engine, observation_window_secs).await;

    store::set_status(&run_id, AuditRunStatus::Stage4Graphing);
    store::write_evidence_graph(&run_id, &serde_json::json!({ "snapshot": snap, "runtime": runtime_snap }));

    store::set_status(&run_id, AuditRunStatus::Stage5CloudCorrelation);
    let dispatched = cloud_transport::dispatch_evidence_graph(&run_id).await;
    store::append_agentic_log(
        &run_id,
        &serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "event": "stage5_dispatch",
            "dispatched": dispatched,
        }),
    );
    // Stays open for agentic requests (cloud_transport's dispatch_action
    // only services them while status == Stage5CloudCorrelation) until this
    // bounded window elapses — see default_cloud_correlation_window_secs's
    // doc comment for why this isn't a true wait-for-completion.
    tokio::time::sleep(std::time::Duration::from_secs(default_cloud_correlation_window_secs())).await;

    store::set_status(&run_id, AuditRunStatus::Complete);
}

fn attribute_and_record(run_id: &str, path: &str, context: &str) {
    let attribution = pkg_verify::attribute_binary(path);
    let (title, severity, category) = match &attribution {
        pkg_verify::PackageAttribution::Verified { .. } => return,
        pkg_verify::PackageAttribution::Unindexed => {
            (format!("Unindexed binary: {}", path), FindingSeverity::Medium, "Unindexed Binary")
        }
        pkg_verify::PackageAttribution::Tampered { package, .. } => (
            format!("Tampered package file: {} (package: {})", path, package),
            FindingSeverity::Critical,
            "Tampered Package File",
        ),
    };

    let id = uuid::Uuid::new_v4().to_string();
    // Extracted before the finding is built so its presence can be recorded
    // in the same evidence blob rather than requiring a second lookup.
    let strings_extracted = strings::extract_and_store(run_id, &id, path).is_some();

    let finding = AuditFinding {
        id,
        run_id: run_id.to_string(),
        title,
        severity,
        category: category.to_string(),
        evidence: serde_json::json!({
            "path": path,
            "context": context,
            "attribution": attribution,
            "strings_extracted": strings_extracted,
        }),
        process_tree: Vec::new(),
        remediation_suggestion: "Review the binary's origin; if unrecognized, quarantine and investigate further."
            .to_string(),
        remediated: false,
        remediated_at: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    store::append_finding(&finding);
}
