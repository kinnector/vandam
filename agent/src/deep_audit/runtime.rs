//! runtime.rs — Stage 2 (Runtime State Capture): process tree, sockets,
//! capabilities/namespaces/mounts. Reads what `HeuristicsEngine` already
//! tracks in-memory (`process_map`) plus `/proc` directly — no new OSS
//! surface needed, everything here is already `pub`.

use serde::Serialize;
use std::sync::Arc;
use vandam::heuristics::HeuristicsEngine;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessSummary {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub cmdline: String,
    pub is_listening_server: bool,
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketEntry {
    pub proto: &'static str,
    pub local_addr: String,
    pub state: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeSnapshot {
    pub processes: Vec<ProcessSummary>,
    pub listening_services: Vec<serde_json::Value>,
    pub sockets: Vec<SocketEntry>,
}

fn process_summaries(engine: &Arc<HeuristicsEngine>) -> Vec<ProcessSummary> {
    engine
        .process_map
        .iter()
        .map(|entry| {
            let p = entry.value();
            ProcessSummary {
                pid: p.pid,
                ppid: p.ppid,
                exe: p.exe.clone(),
                cmdline: p.cmdline.clone(),
                is_listening_server: p.is_listening_server,
                service: p.service.clone(),
            }
        })
        .collect()
}

/// TCP state codes per `/proc/net/tcp[6]`'s `st` field — only the ones worth
/// surfacing distinctly in a forensic report, everything else falls back to
/// the raw hex code.
fn tcp_state_name(code: &str) -> String {
    match code {
        "01" => "ESTABLISHED",
        "0A" => "LISTEN",
        "06" => "TIME_WAIT",
        _ => return format!("UNKNOWN({})", code),
    }
    .to_string()
}

fn hex_to_ipv4(hex: &str) -> Option<String> {
    let bytes = u32::from_str_radix(hex, 16).ok()?.to_le_bytes();
    Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn parse_proc_net_tcp(path: &str, proto: &'static str) -> Vec<SocketEntry> {
    let mut out = Vec::new();
    let Ok(content) = std::fs::read_to_string(path) else { return out };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let Some((addr_hex, port_hex)) = fields[1].split_once(':') else { continue };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };
        let addr = hex_to_ipv4(addr_hex).unwrap_or_else(|| addr_hex.to_string());
        out.push(SocketEntry {
            proto,
            local_addr: format!("{}:{}", addr, port),
            state: tcp_state_name(fields[3]),
            pid: None,
        });
    }
    out
}

pub fn collect(engine: &Arc<HeuristicsEngine>) -> RuntimeSnapshot {
    let mut sockets = parse_proc_net_tcp("/proc/net/tcp", "tcp");
    sockets.extend(parse_proc_net_tcp("/proc/net/tcp6", "tcp6"));

    RuntimeSnapshot {
        processes: process_summaries(engine),
        listening_services: vandam::discovery::get_listening_services(),
        sockets,
    }
}
