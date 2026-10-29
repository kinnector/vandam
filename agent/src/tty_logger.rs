//! tty_logger.rs — PTY/TTY byte stream consumer, feeding the Access page's
//! per-session replay capture (`pty_session_store::append_cast_frame`).
//!
//! Previously this wrote every byte from every PTY on the box, forever,
//! into one global flat file (`/var/log/kinnector/tty.log`) — unbounded,
//! ungrouped, no API. Per the Access design plan's bloat/redaction
//! decisions: bytes for pids that aren't part of a tracked session (see
//! `pty_session.rs`) are now dropped rather than logged globally, and only
//! `tty_write` (what appears on screen) is captured by default — `tty_read`
//! (raw keystrokes) would capture password-prompt input verbatim, so it's
//! opt-in only via `VANDAM_TTY_CAPTURE_INPUT=1`.

use crate::heuristics::HeuristicsEngine;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::UnixStream;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TtyEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub len: u32,
    pub is_write: u8,
    pub comm: [u8; 16],
    pub data: [u8; 1024],
}

pub fn start_tty_logger(engine: Arc<HeuristicsEngine>) {
    let tty_socket_path = "/var/run/kinnector/tty_telemetry.sock";

    tokio::spawn(async move {
        println!("[Vandam TTY] Starting event-driven PTY/TTY logger on socket: {}", tty_socket_path);

        loop {
            // Wait for socket to exist (it is created by the core shared library on start)
            if !std::path::Path::new(tty_socket_path).exists() {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }

            match UnixStream::connect(tty_socket_path).await {
                Ok(mut stream) => {
                    println!("[Vandam TTY] Connected to PTY/TTY telemetry stream.");
                    let event_size = std::mem::size_of::<TtyEvent>();
                    let mut buffer = vec![0u8; event_size * 4];
                    let mut bytes_in_buf = 0;

                    loop {
                        match stream.read(&mut buffer[bytes_in_buf..]).await {
                            Ok(0) => {
                                println!("[Vandam TTY] Stream EOF. Reconnecting...");
                                break;
                            }
                            Ok(n) => {
                                bytes_in_buf += n;
                                while bytes_in_buf >= event_size {
                                    let mut frame = vec![0u8; event_size];
                                    frame.copy_from_slice(&buffer[..event_size]);

                                    let event: TtyEvent = unsafe { std::ptr::read(frame.as_ptr() as *const TtyEvent) };

                                    handle_tty_event(&engine, &event);

                                    // Shift remaining bytes
                                    buffer.copy_within(event_size..bytes_in_buf, 0);
                                    bytes_in_buf -= event_size;
                                }
                            }
                            Err(e) => {
                                eprintln!("[Vandam TTY] Socket read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
    });
}

fn capture_input_enabled() -> bool {
    std::env::var("VANDAM_TTY_CAPTURE_INPUT")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn handle_tty_event(engine: &HeuristicsEngine, ev: &TtyEvent) {
    // `TtyEvent` is `#[repr(C, packed)]` — copy every field by value before
    // use rather than referencing them in place (a reference to a packed
    // field is unaligned UB; `*ev` itself copying out is fine since the
    // whole struct is `Copy`).
    let TtyEvent { timestamp_ns, pid, len, is_write, data, .. } = *ev;

    let is_output = is_write == 1;
    if !is_output && !capture_input_enabled() {
        return;
    }

    let Some(session_id) = engine.pid_to_session.get(&pid).map(|v| v.clone()) else {
        // Not part of a tracked PTY session (Access page's session concept)
        // — deliberately dropped rather than logged globally. See the
        // module doc comment.
        return;
    };
    // Resolved once at ProcessCreate time (pty_session.rs), not here — a
    // map lookup on this hot per-byte-event path instead of a syscall.
    // Most pids share the session leader's tty; a multiplexer pane's pid
    // resolves to its own, which is what makes cast capture per-pty rather
    // than one interleaved stream (see pty_session_store.rs).
    let Some(tty) = engine.pid_to_tty.get(&pid).map(|v| v.clone()) else {
        return;
    };

    let data_len = (len as usize).min(data.len());
    crate::pty_session_store::append_cast_frame(&session_id, &tty, is_output, &data[..data_len], timestamp_ns);
}
