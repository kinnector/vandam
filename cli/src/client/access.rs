use serde::{Deserialize, Serialize};


/// Real (non-mock) PTY session record, mirroring vandamd's
/// `/api/v1/access/sessions` response (`PtySessionMeta` in
/// `vandam/src/pty_session.rs`, persisted by `pty_session_store.rs`).
/// Counterpart to `alerts_data.rs`/`storage_data.rs` — same fetch/mutate/
/// `build_*_targets` shape, shared between the TUI's Access tab and the
/// CLI's `access` subcommands.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Session {
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub start_time: String,
    #[serde(default)]
    pub end_time: Option<String>,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub tty: String,
    #[serde(default)]
    pub pty_type: String,
    #[serde(default)]
    pub container_or_host: String,
    #[serde(default)]
    pub source_ip: String,
    #[serde(default)]
    pub leader_pid: u32,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub flagged: bool,
    /// Set when this session's PTY origin didn't match any known login/exec
    /// daemon (sshd, docker/podman exec, sudo, console) — see
    /// `pty_session.rs`'s `PtySessionMeta::anomaly` doc comment. A real PTY
    /// with no recognizable parent is exactly what a reverse shell or other
    /// backdoor-spawned session looks like.
    #[serde(default)]
    pub anomaly: Option<String>,
    /// Number of distinct ptys tracked under this session — >1 means tmux/
    /// screen (or similar) opened extra panes inside the login/exec pty.
    /// Absent/0 from older daemons or synthetic records defaults to 1 (a
    /// session always has at least its own pty).
    #[serde(default = "one_pane")]
    pub pane_count: usize,
}

fn one_pane() -> usize {
    1
}

#[derive(Deserialize, Serialize, Default, Clone, Debug)]
pub struct AccessSessionsData {
    #[serde(default)]
    pub sessions: Vec<Session>,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct CommandEntry {
    #[serde(default)]
    pub ts: String,
    #[serde(default)]
    pub pid: u32,
    #[serde(default)]
    pub ppid: u32,
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub cmdline: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct SessionDetail {
    #[serde(default)]
    pub session: Session,
    #[serde(default)]
    pub commands: Vec<CommandEntry>,
}

/// Cross-session "Suspicious & Correlated Access" entry. Real cloud/heuristic
/// correlation lands in a later phase — vandamd's `/api/v1/access/correlations`
/// returns an empty list today (OSS) and this type exists so the wiring is
/// already in place when it doesn't.
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct Correlation {
    #[serde(default)]
    pub severity_tag: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub flow_chain: String,
    #[serde(default)]
    pub correlated_alert: Option<String>,
    /// See `SuspiciousAccessCorrelation::session_id`.
    #[serde(default)]
    pub session_id: Option<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
pub struct AccessCorrelationsData {
    #[serde(default)]
    pub correlations: Vec<Correlation>,
}

pub fn fetch(socket_path: &str) -> Result<AccessSessionsData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/access/sessions", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/access/sessions response: {}", e))
}

pub fn fetch_session(socket_path: &str, session_id: &str) -> Result<SessionDetail, String> {
    let path = format!("/api/v1/access/sessions/{}", session_id);
    let value = crate::query_daemon(socket_path, "GET", &path, None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse {} response: {}", path, e))
}

/// Every pty this session has captured replay bytes for — a session with a
/// tmux/screen pane has more than one; empty/single-element for the common
/// case. Used to build the replay modal's pane picker.
pub fn fetch_cast_ttys(socket_path: &str, session_id: &str) -> Result<Vec<String>, String> {
    let path = format!("/api/v1/access/sessions/{}/casts", session_id);
    let value = crate::query_daemon(socket_path, "GET", &path, None)?;
    let ttys = value.get("ttys").cloned().unwrap_or(serde_json::Value::Array(Vec::new()));
    serde_json::from_value(ttys).map_err(|e| format!("Failed to parse {} response: {}", path, e))
}

/// Raw asciicast-v2 body for one pty within a session (newline-delimited
/// JSON — not a single JSON value, so this goes through `query_daemon_raw`,
/// not `query_daemon`). `tty` of `None` means the session's own leader tty
/// (the daemon's default). Empty string if that pty has no captured output
/// yet.
pub fn fetch_cast(socket_path: &str, session_id: &str, tty: Option<&str>) -> Result<String, String> {
    let path = match tty {
        Some(t) => format!("/api/v1/access/sessions/{}/cast?tty={}", session_id, t),
        None => format!("/api/v1/access/sessions/{}/cast", session_id),
    };
    crate::query_daemon_raw(socket_path, "GET", &path, None)
}

pub fn set_flagged(socket_path: &str, session_id: &str, flagged: bool) -> Result<(), String> {
    let body = serde_json::json!({ "flagged": flagged });
    let path = format!("/api/v1/access/sessions/{}/flag", session_id);
    crate::query_daemon(socket_path, "POST", &path, Some(&body)).map(|_| ())
}

/// Response shape of `POST /api/v1/access/sessions/{id}/summarize`
/// (`vandam/src/summarize.rs`) — mirrors `alerts_data::InvestigateResult`
/// exactly (same `upgrade_required`/`disabled`/`pending` status family, same
/// out-of-band-resolution caveat: this dispatches the cloud request and
/// returns `pending`, it does not itself return a finished narrative).
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct SummarizeResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

pub fn summarize(socket_path: &str, session_id: &str) -> Result<SummarizeResult, String> {
    let path = format!("/api/v1/access/sessions/{}/summarize", session_id);
    let value = crate::query_daemon(socket_path, "POST", &path, None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse summarize response: {}", e))
}

pub fn fetch_correlations(socket_path: &str) -> Result<AccessCorrelationsData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/access/correlations", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/access/correlations response: {}", e))
}

/// The offset (seconds) of the *last* frame in a cast body — i.e. how long
/// this pty's captured replay actually runs. The playback modal's progress
/// bar/time display and its auto-advance cap are both driven by this, not
/// a fixed constant — session captures vary wildly in length, and the old
/// mock's hardcoded "3:15 total" bore no relation to real content, which is
/// exactly what made the progress bar look broken (it kept climbing toward
/// a fake total long after the real replay had already finished).
pub fn cast_total_secs(cast: &str) -> f64 {
    let mut max_offset = 0.0f64;
    for line in cast.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(frame) = value.as_array() else {
            continue; // the header line is a JSON object, not an array
        };
        if let Some(offset) = frame.first().and_then(|v| v.as_f64()) {
            if offset > max_offset {
                max_offset = offset;
            }
        }
    }
    max_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast_total_secs_finds_the_last_frame_offset() {
        let cast = [
            r#"{"version":2,"width":80,"height":24,"timestamp":0}"#,
            r#"[0.0,"o","a"]"#,
            r#"[5.5,"o","b"]"#,
            r#"[2.0,"o","c"]"#,
        ]
        .join("\n");
        assert_eq!(cast_total_secs(&cast), 5.5, "should take the max offset, not the last line's");
    }

    #[test]
    fn cast_total_secs_is_zero_for_empty_or_header_only_cast() {
        assert_eq!(cast_total_secs(""), 0.0);
        assert_eq!(cast_total_secs(r#"{"version":2,"width":80,"height":24,"timestamp":0}"#), 0.0);
    }

    #[test]
    fn fetch_response_shape_parses_into_sessions() {
        let value = serde_json::json!({
            "sessions": [
                { "session_id": "audit-42", "start_time": "2026-08-15T12:41:00Z", "end_time": null,
                  "user": "root", "tty": "/dev/pts/2", "pty_type": "SSH", "container_or_host": "Host",
                  "source_ip": "185.220.101.4", "leader_pid": 4821, "status": "ACTIVE", "flagged": false }
            ]
        });
        let data: AccessSessionsData = serde_json::from_value(value).unwrap();
        assert_eq!(data.sessions.len(), 1);
        assert_eq!(data.sessions[0].session_id, "audit-42");
        assert_eq!(data.sessions[0].status, "ACTIVE");
    }
}
