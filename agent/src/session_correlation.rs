//! session_correlation.rs — Pro-only storage + consumer for session-tagged
//! flagged/alert-worthy events forwarded by OSS's `heuristics.rs` over the
//! `event_tx` channel (`"event": "SessionActivity"` entries — see Decision 3
//! in the Access design plan). OSS never sees or stores this data; this
//! module owns the entire event→session correlation store on the Pro side,
//! and it is only ever read back as input to `summarize.rs`'s cloud
//! dispatch — it has no read API of its own.

use std::io::Write;
use std::path::PathBuf;

const BASE_DIR: &str = "/var/log/kinnector/pty_sessions_pro";

/// Deliberately a separate directory tree from OSS's own
/// `/var/log/kinnector/pty_sessions/` — keeps the OSS/Pro data boundary
/// physically obvious on disk, not just logical.
fn sanitize(id: &str) -> String {
    id.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

fn session_dir(session_id: &str) -> PathBuf {
    std::path::Path::new(BASE_DIR).join(sanitize(session_id))
}

/// Handle one raw JSON line from the `event_tx` channel. No-op for anything
/// that isn't a `SessionActivity` event — the git/audit/PTY-anomaly events
/// that already used this channel before Decision 3 are unaffected and stay
/// handled by `main.rs`'s existing consumer loop.
pub fn handle_event(raw_json: &str) {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw_json) else {
        return;
    };
    if value.get("event").and_then(|v| v.as_str()) != Some("SessionActivity") {
        return;
    }
    let Some(session_id) = value.get("session_id").and_then(|v| v.as_str()) else {
        return;
    };
    let dir = session_dir(session_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("correlated.jsonl")) {
        let _ = writeln!(f, "{}", raw_json);
    }
}

/// Read back a session's correlated events for `summarize.rs`'s cloud
/// dispatch — not exposed via any read API of its own.
pub fn read_correlated(session_id: &str) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(session_dir(session_id).join("correlated.jsonl")) else {
        return Vec::new();
    };
    content.lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}
