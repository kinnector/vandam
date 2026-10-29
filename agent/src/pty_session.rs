//! pty_session.rs — PTY/interactive-session lifecycle tracking for the Access
//! page (SSH logins, `docker exec`/`podman exec`, `sudo -i`, console).
//!
//! This deliberately does *not* add a new telemetry firehose. It turns
//! `ProcessCreate`/`ProcessStop` events that already flow through
//! `HeuristicsEngine` into a session concept: a new session starts when an
//! interactive shell (`HeuristicsEngine::system_shells`) is exec'd under a
//! recognized PTY-origin daemon (config-driven — see
//! `linux_pty_origin_signatures.json`), and ends when that shell's pid stops.
//! Every other process created under that shell is cheaply tagged with the
//! same session id via one O(1) parent lookup (`pid_to_session`), which lets
//! other parts of the engine (e.g. flagged file/network events) attribute
//! themselves to a session without walking ancestry each time.
//!
//! See `pty_session_store.rs` for how sessions are persisted.

use crate::heuristics::HeuristicsEngine;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtySessionMeta {
    pub session_id: String,
    pub start_time: String,
    #[serde(default)]
    pub end_time: Option<String>,
    pub user: String,
    pub tty: String,
    pub pty_type: String,
    pub container_or_host: String,
    pub source_ip: String,
    pub leader_pid: u32,
    /// "ACTIVE" | "ENDED"
    pub status: String,
    #[serde(default)]
    pub flagged: bool,
    /// Set when the shell's ancestry didn't match any known PTY-origin
    /// daemon (sshd, docker/podman exec, sudo, login/console) — a real PTY
    /// exists (something is interacting with it), but nothing recognizable
    /// spawned it. This is exactly the shape of a reverse shell that
    /// allocated a pty (e.g. via `python -c 'pty.spawn(...)'`) or any other
    /// backdoor-spawned interactive shell: the session is still tracked
    /// (never silently dropped), just clearly marked as unrecognized rather
    /// than guessed at.
    #[serde(default)]
    pub anomaly: Option<String>,
}

/// Read the kernel audit session id (`/proc/<pid>/sessionid`) — the same
/// mechanism `auditd`/`sudosh` key sessions on: monotonic, assigned once at
/// login, and stable across `su`/`sudo` within that login (unlike the POSIX
/// session id, which changes on `setsid`). Returns `None` when unset (the
/// kernel's "no session" sentinel is `u32::MAX`) or unreadable (e.g. no
/// `CONFIG_AUDIT`), in which case callers fall back to a tty+time key.
fn read_audit_sessionid(pid: u32) -> Option<u32> {
    let raw = std::fs::read_to_string(format!("/proc/{}/sessionid", pid)).ok()?;
    let sid: u32 = raw.trim().parse().ok()?;
    if sid == u32::MAX {
        None
    } else {
        Some(sid)
    }
}

fn read_controlling_tty(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/fd/0", pid))
        .ok()
        .map(|p| p.to_string_lossy().to_string())
        .filter(|s| s.contains("/pts/") || s.starts_with("/dev/tty"))
}

/// Resolve the login user via the audit loginuid (stable across `su`/`sudo`
/// within a session, unlike the process's current euid).
fn read_login_user(pid: u32) -> String {
    if let Ok(raw) = std::fs::read_to_string(format!("/proc/{}/loginuid", pid)) {
        if let Ok(uid) = raw.trim().parse::<u32>() {
            if uid != u32::MAX {
                return username_for_uid(uid).unwrap_or_else(|| uid.to_string());
            }
        }
    }
    "unknown".to_string()
}

fn username_for_uid(uid: u32) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _passwd_field = fields.next();
        let entry_uid: u32 = fields.next()?.parse().ok()?;
        if entry_uid == uid {
            return Some(name.to_string());
        }
    }
    None
}

/// Best-effort SSH client source IP from the shell's own environment
/// (inherited from sshd). Absent for `docker exec`/`podman exec`/console.
fn read_ssh_source_ip(pid: u32) -> Option<String> {
    let env_bytes = std::fs::read(format!("/proc/{}/environ", pid)).ok()?;
    let env_str = String::from_utf8_lossy(&env_bytes);
    for var in env_str.split('\0') {
        if let Some(v) = var.strip_prefix("SSH_CONNECTION=") {
            return v.split_whitespace().next().map(|s| s.to_string());
        }
    }
    for var in env_str.split('\0') {
        if let Some(v) = var.strip_prefix("SSH_CLIENT=") {
            return v.split_whitespace().next().map(|s| s.to_string());
        }
    }
    None
}

/// Walk up from `parent_pid` (a handful of generations — SSH/container
/// runtimes sometimes interpose a wrapper process between the daemon and the
/// shell) looking for a basename match in the config-driven origin table.
fn classify_origin(
    parent_pid: u32,
    parent_exe: &str,
    config: &crate::rules::ConfigManager,
) -> Option<crate::rules::PtyOriginSignature> {
    let signatures = config.pty_origin_signatures();
    if signatures.is_empty() {
        return None;
    }

    let matches = |exe: &str, sig: &crate::rules::PtyOriginSignature| -> bool {
        let basename = std::path::Path::new(exe)
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let needle = sig.origin_process.to_lowercase();
        basename == needle || basename.starts_with(&needle)
    };

    if let Some(sig) = signatures.iter().find(|s| matches(parent_exe, s)) {
        return Some(sig.clone());
    }

    let mut current = parent_pid;
    for _ in 0..8 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", current)) else {
            return None;
        };
        let Some(close_paren) = stat.rfind(')') else {
            return None;
        };
        let Some(ppid_str) = stat[close_paren + 1..].split_whitespace().nth(1) else {
            return None;
        };
        let Ok(ppid) = ppid_str.parse::<u32>() else {
            return None;
        };
        if ppid <= 1 {
            return None;
        }
        let Ok(exe_link) = std::fs::read_link(format!("/proc/{}/exe", ppid)) else {
            return None;
        };
        let exe_str = exe_link.to_string_lossy().to_string();
        if let Some(sig) = signatures.iter().find(|s| matches(&exe_str, s)) {
            return Some(sig.clone());
        }
        current = ppid;
    }
    None
}

/// Called from `heuristics.rs`'s `ProcessCreate` handling, after
/// `process_map` has already been updated for `child_pid`.
pub fn on_process_create(
    engine: &HeuristicsEngine,
    child_pid: u32,
    parent_pid: u32,
    child_exe: &str,
    child_cmdline: &str,
    parent_exe: &str,
) {
    // 1. Propagate: if the parent already belongs to a tracked session, so
    //    does the child — O(1), the common case for every command run inside
    //    an existing session. Also resolve *this* pid's own controlling tty
    //    (cheap: one readlink, only on the ProcessCreate path, not per tty
    //    byte event) — most processes inherit the same tty as their parent
    //    shell, but a terminal multiplexer (tmux/screen) pane genuinely
    //    opens a new one, which is what lets cast capture be partitioned
    //    per-pty instead of interleaving concurrent panes into one stream.
    if let Some(sid) = engine.pid_to_session.get(&parent_pid).map(|v| v.clone()) {
        engine.pid_to_session.insert(child_pid, sid.clone());
        if let Some(tty) = read_controlling_tty(child_pid) {
            engine.pid_to_tty.insert(child_pid, tty);
        }
        crate::pty_session_store::append_command(&sid, child_pid, parent_pid, child_exe, child_cmdline);
        return;
    }

    // 2. Not already in a session — is this exec itself a new session leader?
    let is_shell = engine.system_shells.contains(child_exe)
        || engine.system_shells.iter().any(|s| child_exe.ends_with(s.as_str()));
    if !is_shell {
        return;
    }

    let Some(tty) = read_controlling_tty(child_pid) else {
        return;
    };

    // A real controlling tty exists (something is interacting with this
    // shell) but no recognized daemon in the ancestry — track it anyway
    // rather than silently dropping it. An unrecognized PTY origin is
    // exactly the shape of a reverse shell or other backdoor-spawned
    // interactive session; those are the ones most worth surfacing, not
    // the ones to make invisible.
    let known_origin = classify_origin(parent_pid, parent_exe, &engine.config);
    let is_known_origin = known_origin.is_some();
    let origin = known_origin.unwrap_or_else(|| crate::rules::PtyOriginSignature {
        origin_process: String::new(),
        pty_type: "unknown".to_string(),
        container_scope: false,
        orchestrator: None,
    });

    let session_id = match read_audit_sessionid(child_pid) {
        Some(sid) => format!("audit-{}", sid),
        None => format!("tty-{}-{}", tty.replace('/', "_"), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)),
    };

    // Attempt container resolution even for an unknown origin — we don't
    // actually know whether an unrecognized backdoor is host- or
    // container-scoped, so don't assume "Host" without checking.
    let container_or_host = if origin.container_scope || !is_known_origin {
        engine.resolve_container_info(child_pid).map(|c| c.name)
    } else {
        None
    }
    .unwrap_or_else(|| "Host".to_string());

    let source_ip = read_ssh_source_ip(child_pid).unwrap_or_else(|| {
        if !is_known_origin {
            "Unknown".to_string()
        } else if origin.container_scope {
            "Local Socket".to_string()
        } else if origin.pty_type == "console" {
            "Physical Console".to_string()
        } else {
            "Local Socket".to_string()
        }
    });

    let anomaly = if is_known_origin {
        None
    } else {
        Some(format!(
            "Unrecognized PTY origin (parent: {}) — no known login/exec daemon in ancestry",
            if parent_exe.is_empty() { "unknown" } else { parent_exe }
        ))
    };

    let meta = PtySessionMeta {
        session_id: session_id.clone(),
        start_time: chrono::Utc::now().to_rfc3339(),
        end_time: None,
        user: read_login_user(child_pid),
        tty,
        pty_type: origin.pty_type,
        container_or_host,
        source_ip,
        leader_pid: child_pid,
        status: "ACTIVE".to_string(),
        flagged: false,
        anomaly,
    };

    engine.pid_to_tty.insert(child_pid, meta.tty.clone());
    engine.pty_sessions.insert(session_id.clone(), meta.clone());
    engine.pid_to_session.insert(child_pid, session_id.clone());
    engine.session_leader_pid.insert(child_pid, session_id.clone());
    crate::pty_session_store::write_meta(&meta);
}

/// Called from `heuristics.rs`'s `ProcessStop` handling.
pub fn on_process_stop(engine: &HeuristicsEngine, pid: u32) {
    engine.pid_to_session.remove(&pid);
    engine.pid_to_tty.remove(&pid);

    let Some((_, session_id)) = engine.session_leader_pid.remove(&pid) else {
        return;
    };
    engine.pty_sessions.remove(&session_id);

    if let Some(mut meta) = crate::pty_session_store::read_meta(&session_id) {
        meta.status = "ENDED".to_string();
        meta.end_time = Some(chrono::Utc::now().to_rfc3339());
        crate::pty_session_store::write_meta(&meta);
    }
    crate::pty_session_store::clear_cast_start(&session_id);
}
