//! supply_chain_store.rs — on-disk persistence for vandam's free-tier
//! Supply Chain detection (package-manager install activity + a discovered
//! "protected projects" inventory).
//!
//! Layout: `/var/log/kinnector/supply_chain/activity.jsonl` (append-only feed,
//! same convention as `pty_session_store.rs`'s per-session `commands.jsonl`)
//! and `/var/log/kinnector/supply_chain/projects/<sanitized-path>.json` (one
//! file per discovered project, including the fixed [`SYSTEM_WIDE_PATH`]
//! bucket for global/OS-level package-manager activity that doesn't resolve
//! to a project manifest). Local prevention policy is a small separate file
//! under `/etc/kinnector/` (config, not telemetry — same directory
//! `firewall_rules.json`/`user_rules.json` already use).
//!
//! Security events and blocked actions are deliberately **not** a separate
//! store here — they're the existing alert pipeline
//! (`crate::notifications::AlertPayload`) filtered by the
//! `Vulnerability.SupplyChain.*` threat-type namespace (already established
//! by the pre-existing credential-path enforcement in `heuristics.rs`'s
//! `FileRead` handler), surfaced via `api.rs`'s `/api/v1/risks/events` and
//! `/blocked` handlers. See `supply_chain.rs` for the detection side.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::sync::Mutex;

const BASE_DIR: &str = "/var/log/kinnector/supply_chain";
const POLICY_PATH: &str = "/etc/kinnector/supply_chain_rules.json";

/// Synthetic project path used for global/`-g`/`--user` language-package
/// installs and every OS-distro package-manager operation (apt/dpkg/rpm/yum/
/// dnf/apk/pacman) — these never resolve to a single manifest-bearing
/// directory but must still be tracked, not dropped. See
/// `supply_chain.rs::on_process_create`.
pub const SYSTEM_WIDE_PATH: &str = "(system-wide)";

// Serializes activity.jsonl appends — cheap, low-frequency (one write per
// detected install invocation, not a per-byte firehose like tty_logger.rs).
static ACTIVITY_LOCK: Mutex<()> = Mutex::new(());

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainActivity {
    pub id: String,
    pub time: String,
    pub manager: String,
    pub command: String,
    pub details: String,
    pub project_path: String,
    pub is_system_wide: bool,
    /// "CLEAN" | "ATTENTION" — set to ATTENTION when this activity produced
    /// a correlated `Vulnerability.SupplyChain.*` alert.
    pub status: String,
}

pub fn append_activity(mut entry: SupplyChainActivity) {
    if entry.id.is_empty() {
        entry.id = uuid::Uuid::new_v4().to_string();
    }
    let _guard = ACTIVITY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if std::fs::create_dir_all(BASE_DIR).is_err() {
        return;
    }
    if let Ok(line) = serde_json::to_string(&entry) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{}/activity.jsonl", BASE_DIR))
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

/// Newest-first, capped at `limit` (the feed is unbounded on disk; callers
/// needing the full history should read the file directly — the API only
/// ever needs "recent").
pub fn list_activities(limit: usize) -> Vec<SupplyChainActivity> {
    let Ok(content) = std::fs::read_to_string(format!("{}/activity.jsonl", BASE_DIR)) else {
        return Vec::new();
    };
    let mut out: Vec<SupplyChainActivity> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    out.sort_by(|a: &SupplyChainActivity, b: &SupplyChainActivity| b.time.cmp(&a.time));
    out.truncate(limit);
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecord {
    pub path: String,
    pub framework: String,
    pub is_system_wide: bool,
    pub first_seen: String,
    pub last_seen: String,
    #[serde(default)]
    pub events_count: usize,
    #[serde(default)]
    pub filtered: bool,
}

fn project_file(path: &str) -> std::path::PathBuf {
    std::path::Path::new(BASE_DIR).join("projects").join(format!("{}.json", sanitize(path)))
}

/// Creates or refreshes a project's record. `framework` only overwrites the
/// stored value when non-empty — a later detection with an unresolved
/// framework shouldn't blank out an earlier successful resolution.
pub fn upsert_project(path: &str, framework: &str, is_system_wide: bool) {
    let file = project_file(path);
    let now = chrono::Utc::now().to_rfc3339();
    let mut record = std::fs::read_to_string(&file)
        .ok()
        .and_then(|s| serde_json::from_str::<ProjectRecord>(&s).ok())
        .unwrap_or_else(|| ProjectRecord {
            path: path.to_string(),
            framework: String::new(),
            is_system_wide,
            first_seen: now.clone(),
            last_seen: now.clone(),
            events_count: 0,
            filtered: false,
        });
    record.last_seen = now;
    if !framework.is_empty() {
        record.framework = framework.to_string();
    }
    if let Some(dir) = file.parent() {
        if std::fs::create_dir_all(dir).is_err() {
            return;
        }
    }
    if let Ok(json) = serde_json::to_string_pretty(&record) {
        let _ = std::fs::write(&file, json);
    }
}

pub fn increment_project_event_count(path: &str) {
    let file = project_file(path);
    let Some(mut record) = std::fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str::<ProjectRecord>(&s).ok()) else {
        return;
    };
    record.events_count += 1;
    if let Ok(json) = serde_json::to_string_pretty(&record) {
        let _ = std::fs::write(&file, json);
    }
}

pub fn set_project_filtered(path: &str, filtered: bool) -> bool {
    let file = project_file(path);
    let Some(mut record) = std::fs::read_to_string(&file).ok().and_then(|s| serde_json::from_str::<ProjectRecord>(&s).ok()) else {
        return false;
    };
    record.filtered = filtered;
    if let Ok(json) = serde_json::to_string_pretty(&record) {
        let _ = std::fs::write(&file, json);
        return true;
    }
    false
}

pub fn list_projects() -> Vec<ProjectRecord> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(std::path::Path::new(BASE_DIR).join("projects")) else {
        return out;
    };
    for entry in entries.flatten() {
        if let Ok(content) = std::fs::read_to_string(entry.path()) {
            if let Ok(record) = serde_json::from_str::<ProjectRecord>(&content) {
                out.push(record);
            }
        }
    }
    out.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    out
}

/// Local free-tier enforcement policy — configured via the TUI's prevention
/// rules dialog / `vandam risks policy` — never subscription-gated, this
/// is local behavior, not cloud analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainPolicy {
    #[serde(default)]
    pub block_postinstall_scripts: bool,
    #[serde(default)]
    pub registry_allowlist: Vec<String>,
    #[serde(default)]
    pub auto_quarantine_severity: Option<String>,
    #[serde(default)]
    pub excluded_project_paths: Vec<String>,
}

impl Default for SupplyChainPolicy {
    fn default() -> Self {
        SupplyChainPolicy {
            block_postinstall_scripts: false,
            registry_allowlist: Vec::new(),
            auto_quarantine_severity: None,
            excluded_project_paths: Vec::new(),
        }
    }
}

pub fn read_policy() -> SupplyChainPolicy {
    std::fs::read_to_string(POLICY_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn write_policy(policy: &SupplyChainPolicy) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(policy)?;
    std::fs::write(POLICY_PATH, json)
}
