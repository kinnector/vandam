//! types.rs — data model for deep audit runs/findings. Entirely
//! `vandam`-owned: this concept has no OSS-independent reason to exist
//! (unlike alerts/PTY sessions, which `investigate.rs`/`summarize.rs` sit on
//! top of), so unlike those two it isn't a thin Pro handler over OSS data —
//! see the Audit deep-scan design plan's "why zero OSS changes" section.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRunStatus {
    Queued,
    Stage1Snapshot,
    Stage2Runtime,
    Stage3Observation,
    Stage4Graphing,
    Stage5CloudCorrelation,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRun {
    pub id: String,
    pub status: AuditRunStatus,
    pub started_at: String,
    /// Updated every time `status` transitions — lets the TUI/CLI show real
    /// elapsed-in-stage time instead of the old mock's hardcoded "03m 45s".
    pub stage_started_at: String,
    pub observation_window_secs: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFinding {
    pub id: String,
    pub run_id: String,
    pub title: String,
    pub severity: FindingSeverity,
    /// Free-text category label ("Unindexed Binary", "Config Loophole",
    /// "Supply-Chain Dependency", ...) — deliberately a string, not a closed
    /// enum, since new detector categories will keep being added as stages
    /// mature and shouldn't require a type change each time.
    pub category: String,
    /// Structured evidence backing the finding — process tree summary,
    /// package attribution, socket info, extracted strings excerpt, etc.
    /// Shape varies by category; the TUI renders known keys and falls back
    /// to a generic dump for anything else.
    pub evidence: serde_json::Value,
    pub process_tree: Vec<vandam::notifications::ProcessTreeEntry>,
    pub remediation_suggestion: String,
    pub remediated: bool,
    pub remediated_at: Option<String>,
    pub created_at: String,
}
