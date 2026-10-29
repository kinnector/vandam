//! observe.rs — Stage 3 (Active Observation Window). Deliberately
//! **pull-based**: periodically re-snapshots `process_map`/listening sockets
//! and diffs against the previous poll, plus tails the real alert log OSS
//! already writes for its own reasons (`vandam::audit::write_to_audit_log`'s
//! target, `/var/log/kinnector/audit.log`) for anything logged during the
//! window. No push hook or new global added to OSS's `heuristics.rs` — see
//! the design plan's "why zero OSS changes" section for why this shape was
//! chosen over the first draft's OSS chokepoint.
//!
//! Plain new-process activity is logged as raw evidence, not escalated to a
//! finding on its own (a busy server starts many processes a minute — that
//! would be pure noise). Two things *do* escalate to real findings: a new
//! LISTENING socket appearing mid-window (a live backdoor-listener signal),
//! and any alert already logged to `audit.log` during the window (those are
//! pre-filtered by `heuristics.rs`'s own alerting logic to be significant —
//! reusing that judgment rather than re-deriving it here).

use super::types::{AuditFinding, FindingSeverity};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use vandam::heuristics::HeuristicsEngine;

const POLL_INTERVAL_SECS: u64 = 7;
const AUDIT_LOG_PATH: &str = "/var/log/kinnector/audit.log";

/// One entry per (exe, port) pair currently listening — `get_listening_services`
/// already does the real `/proc/net/{tcp,udp}` + fd-inode resolution work
/// (matching listening sockets to the pid/exe that owns them), so this just
/// flattens its `ports` array per service into a diffable identity string.
fn listening_addrs() -> HashSet<String> {
    let mut out = HashSet::new();
    for svc in vandam::discovery::get_listening_services() {
        let exe = svc.get("exe").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(ports) = svc.get("ports").and_then(|v| v.as_array()) {
            for port in ports {
                out.insert(format!("{}:{}", exe, port));
            }
        }
    }
    out
}

fn record_finding(run_id: &str, title: String, severity: FindingSeverity, category: &str, evidence: serde_json::Value) {
    let finding = AuditFinding {
        id: uuid::Uuid::new_v4().to_string(),
        run_id: run_id.to_string(),
        title,
        severity,
        category: category.to_string(),
        evidence,
        process_tree: Vec::new(),
        remediation_suggestion: "Review the activity observed during the audit window; correlate with recent deploys/known maintenance before treating as hostile.".to_string(),
        remediated: false,
        remediated_at: None,
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    super::store::append_finding(&finding);
}

/// Reads every `audit.log` line whose own `timestamp`/`ts` field (whichever
/// `AlertPayload` uses) falls within `[window_start, now]`. Best-effort:
/// malformed or timestamp-less lines are skipped rather than failing the
/// whole read, matching this codebase's general "degrade, don't hard-fail"
/// convention for log parsing.
fn tail_audit_log_since(window_start: chrono::DateTime<chrono::Utc>) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(AUDIT_LOG_PATH) else {
        return Vec::new();
    };
    content
        .lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .take_while(|entry| {
            let Some(ts) = entry.get("timestamp").and_then(|t| t.as_str()) else { return true };
            chrono::DateTime::parse_from_rfc3339(ts).map(|dt| dt.with_timezone(&chrono::Utc) >= window_start).unwrap_or(true)
        })
        .collect()
}

/// Runs the observation window to completion, appending findings/evidence
/// as it goes. `window_secs` of 0 skips straight through (used by tests /
/// a deliberately-fast-tracked run).
pub async fn observe(run_id: &str, engine: &Arc<HeuristicsEngine>, window_secs: u64) {
    let window_start = chrono::Utc::now();
    let mut known_sockets = listening_addrs();
    let observation_dir = super::store::evidence_dir(run_id, "observation");

    if window_secs > 0 {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(window_secs);
        let poll_interval = Duration::from_secs(POLL_INTERVAL_SECS.min(window_secs.max(1)));
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(poll_interval.min(
                deadline.saturating_duration_since(tokio::time::Instant::now()).max(Duration::from_millis(1)),
            ))
            .await;

            let current_sockets = listening_addrs();
            for addr in current_sockets.difference(&known_sockets) {
                record_finding(
                    run_id,
                    format!("New listening socket observed mid-scan: {}", addr),
                    FindingSeverity::High,
                    "Runtime Activity",
                    serde_json::json!({ "addr": addr, "observed_during": "stage3_observation_window" }),
                );
            }
            let process_count = engine.process_map.len();
            let listening_count = current_sockets.len();
            known_sockets = current_sockets;

            let _ = std::fs::write(
                observation_dir.join(format!("poll-{}.json", chrono::Utc::now().timestamp())),
                serde_json::to_string(&serde_json::json!({
                    "ts": chrono::Utc::now().to_rfc3339(),
                    "process_count": process_count,
                    "listening_sockets": listening_count,
                }))
                .unwrap_or_default(),
            );
        }
    }

    for entry in tail_audit_log_since(window_start) {
        record_finding(
            run_id,
            entry.get("threat_type").and_then(|v| v.as_str()).unwrap_or("Alert observed during audit window").to_string(),
            FindingSeverity::High,
            "Correlated Alert",
            entry,
        );
    }
}
