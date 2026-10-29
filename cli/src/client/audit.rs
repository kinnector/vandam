use serde::{Deserialize, Serialize};

/// Real (non-mock) deep-audit run/finding records, mirroring vandamd's
/// `/api/v1/audit/*` responses. Unlike every other `*_data.rs` module in
/// this TUI, the backend for these routes lives 100% in `vandam`
/// (`vandam/src/audit/`) — there is no OSS-owned fallback shape, so an
/// OSS build or an unpaid Pro build returns `{"status":"upgrade_required",
/// "message":...}` for every endpoint here instead of this shape. Same
/// fetch/mutate shape as `alerts_data.rs`/`access_data.rs`, shared between
/// the TUI's Audit tab and the CLI's `audit` subcommands.
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    #[default]
    Queued,
    Stage1Snapshot,
    Stage2Runtime,
    Stage3Observation,
    Stage4Graphing,
    Stage5CloudCorrelation,
    Complete,
    Failed,
}

impl RunStatus {
    /// 1-indexed stage number for the progress checklist (0 for `Queued`,
    /// which hasn't entered a stage yet) — used by the TUI to render which
    /// of the 5 pipeline stages are checked off.
    pub fn stage_number(&self) -> u8 {
        match self {
            RunStatus::Queued => 0,
            RunStatus::Stage1Snapshot => 1,
            RunStatus::Stage2Runtime => 2,
            RunStatus::Stage3Observation => 3,
            RunStatus::Stage4Graphing => 4,
            RunStatus::Stage5CloudCorrelation => 5,
            RunStatus::Complete => 5,
            RunStatus::Failed => 0,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, RunStatus::Complete | RunStatus::Failed)
    }

    pub fn label(&self) -> &'static str {
        match self {
            RunStatus::Queued => "Queued",
            RunStatus::Stage1Snapshot => "Stage 1: Static System Snapshot",
            RunStatus::Stage2Runtime => "Stage 2: Runtime State Capture",
            RunStatus::Stage3Observation => "Stage 3: Active Observation",
            RunStatus::Stage4Graphing => "Stage 4: Local Evidence Graphing",
            RunStatus::Stage5CloudCorrelation => "Stage 5: Cloud Correlation",
            RunStatus::Complete => "Complete",
            RunStatus::Failed => "Failed",
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Run {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub status: RunStatus,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub stage_started_at: String,
    #[serde(default)]
    pub observation_window_secs: u64,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Finding {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub run_id: String,
    #[serde(default)]
    pub title: String,
    /// "critical" | "high" | "medium" | "low" — kept as the raw string from
    /// the daemon rather than a mirrored Rust enum, same pragmatic choice
    /// `alerts_data.rs` makes for backend-owned classification fields.
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub evidence: serde_json::Value,
    #[serde(default)]
    pub remediation_suggestion: String,
    #[serde(default)]
    pub remediated: bool,
    #[serde(default)]
    pub remediated_at: Option<String>,
    #[serde(default)]
    pub created_at: String,
}

impl Finding {
    pub fn evidence_path(&self) -> Option<&str> {
        self.evidence.get("path").and_then(|v| v.as_str())
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct RunsListData {
    /// `Some("upgrade_required")` when the daemon gated the whole endpoint
    /// (OSS build, or Pro without a subscription) — distinct from an empty
    /// `runs` list, which just means no scans have been run yet.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub runs: Vec<Run>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct RunDetailData {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub run: Option<Run>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

/// Result of `POST /api/v1/audit/runs`. `status` differs by build/license/
/// quota state — `"upgrade_required"`, `"disabled"` (local quota failsafe
/// tripped or manually disabled — see `vandam/src/quota_guard.rs`), or
/// `"queued"` (a real scan just started). The daemon is authoritative; this
/// is a thin carrier for whatever it said, not a client-side tier decision —
/// same rule `alerts_data::InvestigateResult` follows.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct StartRunResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub run_id: Option<String>,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub cooldown_until_unix: Option<i64>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct RemediateResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub finding_id: Option<String>,
    #[serde(default)]
    pub result: Option<serde_json::Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct StringsResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub strings: Option<String>,
}

pub fn fetch_runs(socket_path: &str) -> Result<RunsListData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/audit/runs", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/audit/runs response: {}", e))
}

pub fn fetch_run(socket_path: &str, run_id: &str) -> Result<RunDetailData, String> {
    let path = format!("/api/v1/audit/runs/{}", run_id);
    let value = crate::query_daemon(socket_path, "GET", &path, None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse {} response: {}", path, e))
}

pub fn start_run(socket_path: &str) -> Result<StartRunResult, String> {
    let value = crate::query_daemon(socket_path, "POST", "/api/v1/audit/runs", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse start-run response: {}", e))
}

pub fn remediate_finding(socket_path: &str, finding_id: &str) -> Result<RemediateResult, String> {
    let path = format!("/api/v1/audit/findings/{}/remediate", finding_id);
    let value = crate::query_daemon(socket_path, "POST", &path, None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse remediate response: {}", e))
}

pub fn fetch_finding_strings(socket_path: &str, finding_id: &str) -> Result<StringsResult, String> {
    let path = format!("/api/v1/audit/findings/{}/strings", finding_id);
    let value = crate::query_daemon(socket_path, "GET", &path, None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse {} response: {}", path, e))
}
