//! pty_session_store.rs — on-disk persistence for PTY sessions (Access page).
//!
//! Layout: `/var/log/kinnector/pty_sessions/<session_id>/{meta.json, commands.jsonl, cast-<tty>.jsonl...}`.
//! One `cast-<tty>.jsonl` per pty the session ever touched (not one shared
//! `cast.jsonl`) — a session can have more than one concurrent pty (e.g. a
//! tmux/screen pane), and interleaving their raw bytes into one stream
//! would make replay incoherent. See `list_cast_ttys`/`append_cast_frame`.
//! One directory per session rather than one shared log, so list/show/flag/
//! retention operations are all O(1) against a single session instead of a
//! scan over a global file. Correlated file/network events deliberately do
//! NOT live here — see Decision 3 in the Access design plan: that data only
//! exists for the Pro cloud-correlation feature and is forwarded to
//! `vandam` via the existing `event_tx` channel instead, never stored
//! or served by OSS.

use crate::pty_session::PtySessionMeta;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

const BASE_DIR: &str = "/var/log/kinnector/pty_sessions";

/// Session ids are also used as directory names and (later) URL path
/// segments — sanitize unconditionally so a malformed/attacker-influenced id
/// can never escape `BASE_DIR` via `..` or `/`.
fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn session_dir(session_id: &str) -> std::path::PathBuf {
    std::path::Path::new(BASE_DIR).join(sanitize(session_id))
}

pub fn read_meta(session_id: &str) -> Option<PtySessionMeta> {
    let dir = session_dir(session_id);
    serde_json::from_str(&std::fs::read_to_string(dir.join("meta.json")).ok()?).ok()
}

pub fn write_meta(meta: &PtySessionMeta) {
    let dir = session_dir(&meta.session_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string_pretty(meta) {
        let _ = std::fs::write(dir.join("meta.json"), json);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEntry {
    pub ts: String,
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub cmdline: String,
}

pub fn append_command(session_id: &str, pid: u32, ppid: u32, exe: &str, cmdline: &str) {
    let dir = session_dir(session_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let entry = CommandEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        pid,
        ppid,
        exe: exe.to_string(),
        cmdline: cmdline.to_string(),
    };
    if let Ok(line) = serde_json::to_string(&entry) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("commands.jsonl"))
        {
            let _ = writeln!(f, "{}", line);
        }
    }
}

/// List all known sessions (active + ended) newest-first, for
/// `GET /api/v1/access/sessions`.
pub fn list_sessions() -> Vec<PtySessionMeta> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(BASE_DIR) else {
        return out;
    };
    for entry in entries.flatten() {
        let meta_path = entry.path().join("meta.json");
        if let Ok(content) = std::fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<PtySessionMeta>(&content) {
                out.push(meta);
            }
        }
    }
    out.sort_by(|a, b| b.start_time.cmp(&a.start_time));
    out
}

/// Full detail for `GET /api/v1/access/sessions/{id}` — meta + command
/// timeline. Deliberately excludes the (much larger, later-phase) raw replay
/// stream so list/show stay cheap.
pub fn read_session(session_id: &str) -> Option<(PtySessionMeta, Vec<CommandEntry>)> {
    let dir = session_dir(session_id);
    let meta = read_meta(session_id)?;
    let mut commands = Vec::new();
    if let Ok(content) = std::fs::read_to_string(dir.join("commands.jsonl")) {
        for line in content.lines() {
            if let Ok(entry) = serde_json::from_str::<CommandEntry>(line) {
                commands.push(entry);
            }
        }
    }
    Some((meta, commands))
}

pub fn set_flagged(session_id: &str, flagged: bool) -> bool {
    let Some(mut meta) = read_meta(session_id) else {
        return false;
    };
    meta.flagged = flagged;
    write_meta(&meta);
    true
}

/// Per-(session,tty) cap on a cast file's size — the single biggest bloat
/// risk flagged in the design plan. Once a stream hits this, further frames
/// for *that pty* are silently dropped (the command timeline keeps growing
/// regardless, and other ptys in the same session are unaffected — this
/// caps each raw replay stream independently, not the session as a whole).
const MAX_CAST_BYTES: u64 = 5_000_000;

/// A session can have more than one pty concurrently — a terminal
/// multiplexer (tmux/screen) pane opens a genuinely new one distinct from
/// the session's own login pty. Replay is partitioned per-tty (a separate
/// `cast-<slug>.jsonl` per pty) rather than one shared `cast.jsonl`,
/// because interleaving concurrent panes' raw bytes into a single linear
/// asciicast stream produces a stream no single terminal emulator can
/// coherently replay (escape sequences from one pane split by bytes from
/// another). See the Access design plan's multi-pty correction.
///
/// `/dev/pts/N` and `/dev/ttyN` are the only shapes `pty_session.rs`'s
/// `read_controlling_tty` ever returns — stripping the `/dev/` prefix and
/// turning the remaining `/` into `_` is fully reversible for those shapes
/// (`slug_to_tty` inverts it exactly) without needing a lookup table.
fn tty_slug(tty: &str) -> String {
    tty.strip_prefix("/dev/").unwrap_or(tty).replace('/', "_")
}

fn slug_to_tty(slug: &str) -> String {
    format!("/dev/{}", slug.replace('_', "/"))
}

fn cast_file_name(tty: &str) -> String {
    format!("cast-{}.jsonl", tty_slug(tty))
}

/// First `TtyEvent.timestamp_ns` seen per (session, tty), so cast frames can
/// be written with an offset relative to that pty's own start (what
/// asciinema's format needs) without mixing clock domains — `timestamp_ns`
/// comes from the eBPF probe's own clock, not wall-clock time, so it can't
/// be related to `PtySessionMeta.start_time` directly. Keyed per-tty, not
/// just per-session, so a pane opened mid-session gets its own zero point
/// rather than inheriting an offset from whichever pty started first.
fn cast_start_ts() -> &'static Mutex<HashMap<(String, String), u64>> {
    static MAP: OnceLock<Mutex<HashMap<(String, String), u64>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Every pty this session has captured replay bytes for, oldest-first by
/// filesystem order — used to build a pane picker when a session has more
/// than one. The session's own leader tty (from `meta.json`) is always a
/// reasonable default to show first if present in this list.
pub fn list_cast_ttys(session_id: &str) -> Vec<String> {
    let dir = session_dir(session_id);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut ttys: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let slug = name.strip_prefix("cast-")?.strip_suffix(".jsonl")?;
            Some(slug_to_tty(slug))
        })
        .collect();
    ttys.sort();
    ttys
}

/// Raw cast-v2 file contents for one pty within a session, for
/// `GET /api/v1/access/sessions/{id}/cast` — kept out of `read_session`'s
/// response so list/show stay cheap; only the replay modal / an explicit
/// CLI flag fetches this. `tty` is `None` to mean "the session's own leader
/// tty" (the common single-pty case), resolved from `meta.json`.
pub fn read_cast(session_id: &str, tty: Option<&str>) -> Option<String> {
    let tty = match tty {
        Some(t) => t.to_string(),
        None => read_meta(session_id)?.tty,
    };
    std::fs::read_to_string(session_dir(session_id).join(cast_file_name(&tty))).ok()
}

/// Drop cached first-frame timestamps for every pty in a session — call on
/// session end so `cast_start_ts()`'s map doesn't grow for the daemon's
/// whole lifetime.
pub fn clear_cast_start(session_id: &str) {
    cast_start_ts().lock().unwrap().retain(|(sid, _), _| sid != session_id);
}

pub fn append_cast_frame(session_id: &str, tty: &str, is_output: bool, data: &[u8], timestamp_ns: u64) {
    let dir = session_dir(session_id);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join(cast_file_name(tty));

    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_CAST_BYTES {
            return;
        }
    }

    let is_new = !path.exists();
    let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else {
        return;
    };

    if is_new {
        let header = serde_json::json!({
            "version": 2,
            "width": 120,
            "height": 40,
            "timestamp": chrono::Utc::now().timestamp(),
            "tty": tty,
        });
        let _ = writeln!(f, "{}", header);
    }

    let start_ts = {
        let mut starts = cast_start_ts().lock().unwrap();
        *starts.entry((session_id.to_string(), tty.to_string())).or_insert(timestamp_ns)
    };
    let offset_secs = timestamp_ns.saturating_sub(start_ts) as f64 / 1_000_000_000.0;
    let text = String::from_utf8_lossy(data);
    if let Ok(line) = serde_json::to_string(&serde_json::json!([offset_secs, if is_output { "o" } else { "i" }, text])) {
        let _ = writeln!(f, "{}", line);
    }
}

/// Days an ENDED session's directory is kept before outright deletion.
/// Config-driven via env var so operators can tune it without a rebuild.
fn retention_days() -> i64 {
    std::env::var("VANDAM_PTY_SESSION_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30)
}

/// Total on-disk cap across every session's directory combined. Config-driven
/// via env var; oldest-ended-first eviction once exceeded, checked after the
/// TTL sweep above already ran.
fn max_total_bytes() -> u64 {
    std::env::var("VANDAM_PTY_SESSIONS_MAX_TOTAL_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|mb| mb * 1_000_000)
        .unwrap_or(500_000_000)
}

fn dir_size(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                total += meta.len();
            }
        }
    }
    total
}

/// Retention sweep: deletes ENDED session directories past
/// `VANDAM_PTY_SESSION_RETENTION_DAYS`, then — if the remaining total is
/// still over `VANDAM_PTY_SESSIONS_MAX_TOTAL_MB` — deletes the
/// oldest-ended sessions first until under it. Never touches an ACTIVE
/// session regardless of age or size pressure. Called periodically from
/// `lib.rs` (see `start_pty_session_retention_sweeper`), not on every write
/// — this is bulk directory-tree cleanup, not a per-event cost.
pub fn run_retention_sweep() {
    let Ok(entries) = std::fs::read_dir(BASE_DIR) else {
        return;
    };
    let now = chrono::Utc::now();
    let ttl = chrono::Duration::days(retention_days());

    let mut ended_sessions: Vec<(std::path::PathBuf, chrono::DateTime<chrono::Utc>)> = Vec::new();

    for entry in entries.flatten() {
        let dir = entry.path();
        let Ok(content) = std::fs::read_to_string(dir.join("meta.json")) else {
            continue;
        };
        let Ok(meta) = serde_json::from_str::<PtySessionMeta>(&content) else {
            continue;
        };
        if meta.status != "ENDED" {
            continue;
        }
        let Some(end_time) = meta
            .end_time
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&chrono::Utc))
        else {
            continue;
        };

        if now - end_time > ttl {
            let _ = std::fs::remove_dir_all(&dir);
            continue;
        }
        ended_sessions.push((dir, end_time));
    }

    let total: u64 = ended_sessions.iter().map(|(dir, _)| dir_size(dir)).sum();
    let cap = max_total_bytes();
    if total > cap {
        ended_sessions.sort_by_key(|(_, end_time)| *end_time);
        let mut freed = 0u64;
        let over = total - cap;
        for (dir, _) in ended_sessions {
            if freed >= over {
                break;
            }
            freed += dir_size(&dir);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
