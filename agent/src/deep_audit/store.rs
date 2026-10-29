//! store.rs — on-disk persistence for deep audit runs, physically separate
//! from anything OSS touches (mirrors `session_correlation.rs`'s
//! `pty_sessions_pro/` convention for the same "OSS never sees this data"
//! reason — this directory has no OSS reader or writer anywhere).
//!
//! Layout: `/var/log/kinnector/audit_runs_pro/<run_id>/{meta.json,
//! findings.jsonl, evidence/<finding_id>/..., agentic_log.jsonl}`. Raw
//! evidence (extracted strings, hash dumps) lives under `evidence/`,
//! separate from the structured `findings.jsonl` record — same split
//! `pty_session_store.rs` uses for cast files vs. commands.jsonl.

use super::types::{AuditFinding, AuditRun, AuditRunStatus};
use std::io::Write;

const BASE_DIR: &str = "/var/log/kinnector/audit_runs_pro";

/// Run/finding ids are also used as directory/file-name components — sanitize
/// unconditionally so a malformed id can never escape `BASE_DIR` via `..`.
fn sanitize(id: &str) -> String {
    id.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn run_dir(run_id: &str) -> std::path::PathBuf {
    std::path::Path::new(BASE_DIR).join(sanitize(run_id))
}

pub fn read_run(run_id: &str) -> Option<AuditRun> {
    serde_json::from_str(&std::fs::read_to_string(run_dir(run_id).join("meta.json")).ok()?).ok()
}

fn write_run(run: &AuditRun) {
    let dir = run_dir(&run.id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string_pretty(run) {
        let _ = std::fs::write(dir.join("meta.json"), json);
    }
}

/// Creates a new run in `Queued` status and persists it immediately, so a
/// concurrent `GET /api/v1/audit/runs` sees it right away even before the
/// background orchestrator task gets scheduled.
pub fn create_run(observation_window_secs: u64) -> AuditRun {
    let now = chrono::Utc::now().to_rfc3339();
    let run = AuditRun {
        id: uuid::Uuid::new_v4().to_string(),
        status: AuditRunStatus::Queued,
        started_at: now.clone(),
        stage_started_at: now,
        observation_window_secs,
        error: None,
    };
    write_run(&run);
    run
}

/// Transitions a run to `status`, updating `stage_started_at` so elapsed-in-
/// stage time reflects reality. No-op (returns `false`) if the run doesn't
/// exist — the orchestrator holds the only handle that should be calling
/// this, but a run directory could in principle be removed by a retention
/// sweep mid-flight in the future, so this stays defensive rather than
/// panicking.
pub fn set_status(run_id: &str, status: AuditRunStatus) -> bool {
    let Some(mut run) = read_run(run_id) else {
        return false;
    };
    run.status = status;
    run.stage_started_at = chrono::Utc::now().to_rfc3339();
    write_run(&run);
    true
}

/// All known runs, newest-first, for `GET /api/v1/audit/runs`.
pub fn list_runs() -> Vec<AuditRun> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(BASE_DIR) else {
        return out;
    };
    for entry in entries.flatten() {
        if let Ok(content) = std::fs::read_to_string(entry.path().join("meta.json")) {
            if let Ok(run) = serde_json::from_str::<AuditRun>(&content) {
                out.push(run);
            }
        }
    }
    out.sort_by(|a, b| b.started_at.cmp(&a.started_at));
    out
}

pub fn append_finding(finding: &AuditFinding) {
    let dir = run_dir(&finding.run_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(line) = serde_json::to_string(finding) {
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("findings.jsonl")) {
            let _ = writeln!(f, "{}", line);
        }
    }
}

pub fn list_findings(run_id: &str) -> Vec<AuditFinding> {
    let mut out = Vec::new();
    if let Ok(content) = std::fs::read_to_string(run_dir(run_id).join("findings.jsonl")) {
        for line in content.lines() {
            if let Ok(finding) = serde_json::from_str::<AuditFinding>(line) {
                out.push(finding);
            }
        }
    }
    out
}

/// Findings are addressed by id alone in the API
/// (`POST /api/v1/audit/findings/{id}/remediate`, no run id in the path,
/// matching how `alerts/{id}` doesn't require a separate scope either) — so
/// resolving one means a linear scan over every run's `findings.jsonl`. Run
/// counts are low-frequency/low-volume (a handful of runs per host, not
/// thousands), so this is fine; revisit with an index if that stops holding.
pub fn find_finding(finding_id: &str) -> Option<(String, AuditFinding)> {
    for run in list_runs() {
        for finding in list_findings(&run.id) {
            if finding.id == finding_id {
                return Some((run.id, finding));
            }
        }
    }
    None
}

/// Rewrites the finding's line in place (read-all, patch, write-back — the
/// same approach `pty_session_store::set_flagged` takes for `meta.json`,
/// applied here to one line of an otherwise-append-only file since
/// `findings.jsonl` doesn't have PTY sessions' single-record-per-file luxury).
pub fn set_finding_remediated(run_id: &str, finding_id: &str, remediated: bool) -> bool {
    let mut findings = list_findings(run_id);
    let Some(finding) = findings.iter_mut().find(|f| f.id == finding_id) else {
        return false;
    };
    finding.remediated = remediated;
    finding.remediated_at = if remediated { Some(chrono::Utc::now().to_rfc3339()) } else { None };

    let dir = run_dir(run_id);
    let Ok(mut f) = std::fs::File::create(dir.join("findings.jsonl")) else {
        return false;
    };
    for finding in &findings {
        if let Ok(line) = serde_json::to_string(finding) {
            let _ = writeln!(f, "{}", line);
        }
    }
    true
}

/// Directory for a finding's raw evidence (extracted strings, hash dumps) —
/// separate from the structured `findings.jsonl` record, size-capped by
/// each writer (see `strings.rs`), not by this helper.
pub fn evidence_dir(run_id: &str, finding_id: &str) -> std::path::PathBuf {
    let dir = run_dir(run_id).join("evidence").join(sanitize(finding_id));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Stage 4's assembled evidence graph (merged Stage 1+2 snapshots) — what
/// Stage 5 will ship to cloud. Stored as opaque JSON since its shape is just
/// whatever `snapshot::StaticSnapshot`/`runtime::RuntimeSnapshot` produce;
/// this module doesn't need to know their fields, only persist them.
pub fn write_evidence_graph<T: serde::Serialize>(run_id: &str, graph: &T) {
    let dir = run_dir(run_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string_pretty(graph) {
        let _ = std::fs::write(dir.join("evidence_graph.json"), json);
    }
}

pub fn read_evidence_graph(run_id: &str) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(run_dir(run_id).join("evidence_graph.json")).ok()?).ok()
}

/// Raw extracted-strings evidence for a finding (see `strings.rs`), for
/// `GET /api/v1/audit/findings/{id}/strings` — kept out of the finding's
/// own JSON (`findings.jsonl`) since it can be tens of KB, same reasoning as
/// keeping PTY replay bytes out of `pty_session_store::read_session`'s
/// response.
pub fn read_finding_strings(run_id: &str, finding_id: &str) -> Option<String> {
    std::fs::read_to_string(evidence_dir(run_id, finding_id).join("strings.txt")).ok()
}

/// Transparency log of every agentic (cloud-requested file/dir/exec) request
/// and its response — so an operator reviewing a completed run can see
/// exactly what the cloud asked for, not just the final findings.
pub fn append_agentic_log(run_id: &str, entry: &serde_json::Value) {
    let dir = run_dir(run_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("agentic_log.jsonl")) {
        let _ = writeln!(f, "{}", entry);
    }
}
