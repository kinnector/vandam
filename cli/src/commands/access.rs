use crate::output::{CliError, CliOutput};
use crate::client::access as access_data;
use clap::Subcommand;

/// Mirrors the TUI dashboard's "Access" tab (PTY sessions, session replay,
/// correlation) against vandamd's real `/api/v1/access/*` API (session
/// lifecycle tracking in `vandam/src/pty_session.rs`, raw replay capture in
/// `vandam/src/tty_logger.rs` + `pty_session_store.rs`). `sessions show`
/// surfaces the on-disk cast-v2 replay path rather than reimplementing a
/// terminal player here — play it with `asciinema play <path>` (assumes the
/// CLI runs on the same host as vandamd; fetch it remotely via
/// `GET /api/v1/access/sessions/{id}/cast` otherwise). Cloud correlation is
/// a later phase — see the Access design plan.
#[derive(Subcommand, Debug)]
pub enum AccessAction {
    /// Interactive/replayed session records
    Sessions {
        #[command(subcommand)]
        action: SessionsAction,
    },
    /// Cross-signal correlation views
    Correlations {
        #[command(subcommand)]
        action: CorrelationsAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum SessionsAction {
    List,
    Show { id: String },
    /// Flag a session for follow-up (mirrors the TUI's `[f]` key).
    Flag { id: String },
    /// Request a cloud narrative summary of this session (vandam
    /// subscriber feature; mirrors the TUI replay modal's `[s]` key).
    /// Dispatches the request and returns `pending` — resolution happens
    /// out-of-band, this does not itself return a finished summary.
    Summarize { id: String },
}

#[derive(Subcommand, Debug)]
pub enum CorrelationsAction {
    List,
}

const CAST_PATH_NOTE: &str = "output-only by default; capped at 5MB; empty until the session produces terminal output";

pub fn handle(output: &CliOutput, action: AccessAction, socket_path: &str) {
    match action {
        AccessAction::Sessions { action: SessionsAction::List } => {
            match access_data::fetch(socket_path) {
                Ok(data) => output.emit_ok(&data.sessions, |sessions| {
                    if sessions.is_empty() {
                        println!("No PTY sessions recorded yet.");
                        return;
                    }
                    for s in sessions {
                        println!(
                            "{:<24} {:<12} {:<10} {:<16} {:<20} {}",
                            s.session_id, s.status, s.pty_type, s.user, s.container_or_host, s.source_ip
                        );
                    }
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
        AccessAction::Sessions { action: SessionsAction::Show { id } } => {
            match access_data::fetch_session(socket_path, &id) {
                Ok(detail) => output.emit_ok(&detail, |detail| {
                    let s = &detail.session;
                    println!("Session {} ({})", s.session_id, s.pty_type);
                    println!("  user:    {}", s.user);
                    println!("  tty:     {}", s.tty);
                    println!("  target:  {}", s.container_or_host);
                    println!("  source:  {}", s.source_ip);
                    println!("  status:  {} (started {})", s.status, s.start_time);
                    if let Some(end) = &s.end_time {
                        println!("  ended:   {}", end);
                    }
                    println!("  flagged: {}", s.flagged);
                    println!();
                    if detail.commands.is_empty() {
                        println!("No commands recorded for this session yet.");
                    } else {
                        println!("Commands:");
                        for c in &detail.commands {
                            println!("  [{}] pid={} {}", c.ts, c.pid, c.cmdline);
                        }
                    }
                    println!();
                    println!(
                        "Replay: /var/log/kinnector/pty_sessions/{}/cast.jsonl ({})",
                        s.session_id, CAST_PATH_NOTE
                    );
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
        AccessAction::Sessions { action: SessionsAction::Flag { id } } => {
            match access_data::set_flagged(socket_path, &id, true) {
                Ok(()) => output.emit_ok(&serde_json::json!({ "session_id": id, "flagged": true }), |_| {
                    println!("Flagged session {}.", id);
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
        AccessAction::Sessions { action: SessionsAction::Summarize { id } } => {
            match access_data::summarize(socket_path, &id) {
                Ok(result) => output.emit_ok(&result, |result| match result.status.as_str() {
                    "pending" => println!("Cloud summary requested for session {} — resolves out-of-band, check back later.", id),
                    "upgrade_required" => println!(
                        "{}",
                        result.message.clone().unwrap_or_else(|| "Cloud session summarization is a vandam subscriber feature.".to_string())
                    ),
                    "not_found" => println!("Session {} not found on the daemon.", id),
                    "disabled" => println!("Cloud summarization is currently disabled: {}", result.reason.clone().unwrap_or_default()),
                    other => println!("Unexpected response: {}", other),
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
        AccessAction::Correlations { action: CorrelationsAction::List } => {
            match access_data::fetch_correlations(socket_path) {
                Ok(data) => output.emit_ok(&data.correlations, |correlations| {
                    if correlations.is_empty() {
                        println!("No correlated access threats. (Local heuristic correlation and cloud correlation both land in a later phase — see the Access design plan.)");
                        return;
                    }
                    for c in correlations {
                        println!("{}: {}", c.severity_tag, c.summary);
                        println!("  {}", c.flow_chain);
                    }
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
    }
}
