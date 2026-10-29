//! cloud_transport.rs — vandam's own, independent gRPC connection for
//! the deep-audit agentic loop (cloud-requested file/dir/exec during an
//! active run's Stage 5 cloud-correlation window). Deliberately a *second*
//! connection rather than an extension point into OSS's `vandam::cloud`-
//! owned `CommandStream` — see `proto/audit.proto`'s doc comment and the
//! design plan's "why zero OSS changes" section for the trade-off this
//! makes (two concurrent gRPC connections per agent instead of one).
//!
//! Connect/reconnect loop shape deliberately mirrors
//! `vandam::cloud::start_command_listener` (re-derived here rather than
//! shared, since sharing would mean touching the OSS crate) — only identity
//! values (`get_or_create_agent_id`/`get_or_create_license_key`/
//! `DEFAULT_CLOUD_ENDPOINT`) are reused from OSS's already-`pub` helpers.

mod proto {
    tonic::include_proto!("vandam.audit");
}

use base64::Engine;
use proto::audit_service_client::AuditServiceClient;
use proto::{AuditAgentMessage, AuditConsoleMessage};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use vandam::cloud::{get_or_create_agent_id, get_or_create_license_key, DEFAULT_CLOUD_ENDPOINT};
use vandam::heuristics::HeuristicsEngine;

use super::types::AuditRunStatus;

/// Handle to the currently-connected stream's outbound sender, if any —
/// lets `mod.rs`'s orchestrator push a run's evidence graph to cloud
/// (`dispatch_evidence_graph`) when it enters Stage 5, without the
/// orchestrator needing to know anything about connection lifecycle. Mirrors
/// OSS's own `cloud.rs::GRPC_TX` pattern, scoped to this second connection.
static AUDIT_TX: OnceLock<Mutex<Option<tokio::sync::mpsc::Sender<AuditAgentMessage>>>> = OnceLock::new();

fn tx_slot() -> &'static Mutex<Option<tokio::sync::mpsc::Sender<AuditAgentMessage>>> {
    AUDIT_TX.get_or_init(|| Mutex::new(None))
}

/// Sends a run's Stage 4 evidence graph to cloud over this connection —
/// the actual "Stage 5 dispatch." Returns `false` (never blocks/retries) if
/// there's no live connection or the run has no evidence graph yet; the
/// orchestrator treats that as "cloud correlation unavailable this pass,"
/// same honest-degradation shape as every other cloud dispatch in this
/// codebase (e.g. `investigate.rs`'s `dispatched` flag).
pub async fn dispatch_evidence_graph(run_id: &str) -> bool {
    let Some(tx) = tx_slot().lock().unwrap().clone() else { return false };
    let Some(graph) = super::store::read_evidence_graph(run_id) else { return false };

    let msg = AuditAgentMessage {
        agent_id: get_or_create_agent_id(),
        license_key: get_or_create_license_key(),
        run_id: run_id.to_string(),
        request_id: String::new(),
        payload_json: serde_json::json!({ "event": "evidence_graph", "graph": graph }).to_string(),
    };
    tx.send(msg).await.is_ok()
}

struct AuditStream(tokio::sync::mpsc::Receiver<AuditAgentMessage>);

impl futures_core::Stream for AuditStream {
    type Item = AuditAgentMessage;
    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

fn cloud_endpoint() -> String {
    std::env::var("VANDAM_CLOUD_ENDPOINT").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_CLOUD_ENDPOINT.to_string())
}

/// Long-running connect/reconnect loop — spawned once from `main.rs`'s
/// `on_engine_ready` callback (needs `Arc<HeuristicsEngine>` for the
/// config-driven exclusion/allowlist checks the handlers below perform).
pub async fn run(engine: Arc<HeuristicsEngine>) {
    loop {
        let endpoint = cloud_endpoint();
        tracing::info!("[Vandam Audit Cloud] Attempting gRPC connection: {}", endpoint);
        match tonic::transport::Endpoint::from_shared(endpoint) {
            Ok(endpoint_conf) => {
                let endpoint_conf = endpoint_conf.keep_alive_while_idle(true).connect_timeout(Duration::from_secs(10));
                match endpoint_conf.connect().await {
                    Ok(channel) => {
                        tracing::info!("[Vandam Audit Cloud] gRPC connected.");
                        let mut client = AuditServiceClient::new(channel);
                        let (tx, rx) = tokio::sync::mpsc::channel::<AuditAgentMessage>(64);

                        let agent_id = get_or_create_agent_id();
                        let license_key = get_or_create_license_key();
                        let _ = tx
                            .send(AuditAgentMessage {
                                agent_id: agent_id.clone(),
                                license_key: license_key.clone(),
                                run_id: String::new(),
                                request_id: String::new(),
                                payload_json: serde_json::json!({ "event": "register" }).to_string(),
                            })
                            .await;

                        *tx_slot().lock().unwrap() = Some(tx.clone());

                        match client.audit_command_stream(AuditStream(rx)).await {
                            Ok(response) => {
                                let mut inbound = response.into_inner();
                                while let Ok(Some(msg)) = inbound.message().await {
                                    handle_console_message(msg, &tx, &agent_id, &license_key, &engine).await;
                                }
                                tracing::warn!("[Vandam Audit Cloud] stream closed by remote console.");
                            }
                            Err(e) => tracing::error!("[Vandam Audit Cloud] failed to establish stream: {}", e),
                        }

                        *tx_slot().lock().unwrap() = None;
                    }
                    Err(e) => tracing::error!("[Vandam Audit Cloud] connection failed: {}", e),
                }
            }
            Err(e) => tracing::error!("[Vandam Audit Cloud] invalid endpoint: {}", e),
        }
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
}

async fn handle_console_message(
    msg: AuditConsoleMessage,
    tx: &tokio::sync::mpsc::Sender<AuditAgentMessage>,
    agent_id: &str,
    license_key: &str,
    engine: &Arc<HeuristicsEngine>,
) {
    let request_id = msg.request_id.clone();
    let run_id = msg.run_id.clone();
    let reply_payload = dispatch_action(&msg, engine).await;

    // Transparency log: every agentic request/response pair, so an operator
    // reviewing a completed run can see exactly what the cloud asked for —
    // not just the final findings.
    if !run_id.is_empty() {
        super::store::append_agentic_log(
            &run_id,
            &serde_json::json!({
                "ts": chrono::Utc::now().to_rfc3339(),
                "request_id": request_id,
                "action": msg.action,
                "command_json": msg.command_json,
                "reply": reply_payload,
            }),
        );
    }

    let _ = tx
        .send(AuditAgentMessage {
            agent_id: agent_id.to_string(),
            license_key: license_key.to_string(),
            run_id,
            request_id,
            payload_json: reply_payload.to_string(),
        })
        .await;
}

/// Only serviced while the named run is actually in `Stage5CloudCorrelation`
/// — refusing anything else closes off standing remote-file-read/exec
/// access outside an operator-initiated, quota-guarded audit window.
async fn dispatch_action(msg: &AuditConsoleMessage, engine: &Arc<HeuristicsEngine>) -> serde_json::Value {
    let Some(run) = super::store::read_run(&msg.run_id) else {
        return serde_json::json!({ "status": "denied", "reason": "unknown run_id" });
    };
    if !matches!(run.status, AuditRunStatus::Stage5CloudCorrelation) {
        return serde_json::json!({ "status": "denied", "reason": "run is not in its cloud-correlation stage" });
    }

    let Ok(command) = serde_json::from_str::<serde_json::Value>(&msg.command_json) else {
        return serde_json::json!({ "status": "denied", "reason": "malformed command_json" });
    };

    match msg.action.as_str() {
        "audit_read_file" => handle_read_file(&msg.run_id, engine, &command),
        "audit_list_dir" => handle_list_dir(&msg.run_id, engine, &command),
        "audit_exec_command" => handle_exec_command(engine, &command).await,
        other => serde_json::json!({ "status": "denied", "reason": format!("unknown action '{}'", other) }),
    }
}

const MAX_READ_BYTES: u64 = 262_144;
const MAX_LIST_ENTRIES: usize = 500;

fn is_excluded(engine: &Arc<HeuristicsEngine>, path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    engine.config.sensitive_credential_paths().iter().any(|p| !p.is_empty() && path_str.contains(p.as_str()))
        || engine.config.sensitive_files().keys().any(|f| !f.is_empty() && path_str.contains(f.as_str()))
}

/// A run's "scope" is whatever it already touched: the directory each
/// finding's flagged path lives in, every present persistence-path target,
/// and every process exe path seen during Stage 2. Cloud can ask for more
/// detail on what the scan found — it cannot browse the filesystem at
/// large. Recomputed per-request rather than cached, since it's a handful
/// of small file reads against data already on disk, not a hot path.
fn scope_roots(run_id: &str) -> std::collections::HashSet<PathBuf> {
    let mut roots = std::collections::HashSet::new();
    let mut add = |p: &str| {
        if let Some(parent) = Path::new(p).parent() {
            roots.insert(parent.to_path_buf());
        }
    };

    for finding in super::store::list_findings(run_id) {
        if let Some(p) = finding.evidence.get("path").and_then(|v| v.as_str()) {
            add(p);
        }
    }
    if let Some(graph) = super::store::read_evidence_graph(run_id) {
        if let Some(paths) = graph.pointer("/snapshot/persistence_paths_present").and_then(|v| v.as_array()) {
            for p in paths {
                if let Some(s) = p.as_str() {
                    add(s);
                }
            }
        }
        if let Some(procs) = graph.pointer("/runtime/processes").and_then(|v| v.as_array()) {
            for p in procs {
                if let Some(exe) = p.get("exe").and_then(|v| v.as_str()) {
                    add(exe);
                }
            }
        }
    }
    roots
}

fn in_scope(run_id: &str, target: &Path) -> bool {
    let Ok(canon) = target.canonicalize() else { return false };
    scope_roots(run_id).into_iter().any(|root| canon.starts_with(&root))
}

fn handle_read_file(run_id: &str, engine: &Arc<HeuristicsEngine>, command: &serde_json::Value) -> serde_json::Value {
    let Some(path_str) = command.get("path").and_then(|v| v.as_str()) else {
        return serde_json::json!({ "status": "denied", "reason": "missing 'path'" });
    };
    let target = Path::new(path_str);

    if is_excluded(engine, target) {
        return serde_json::json!({ "status": "denied", "reason": "path matches a sensitive-credential exclusion" });
    }
    if !in_scope(run_id, target) {
        return serde_json::json!({ "status": "denied", "reason": "path is outside this run's scope" });
    }

    match std::fs::metadata(target) {
        Ok(meta) if meta.len() > MAX_READ_BYTES => {
            serde_json::json!({ "status": "denied", "reason": format!("file exceeds the {}-byte cap", MAX_READ_BYTES) })
        }
        Ok(_) => match std::fs::read(target) {
            Ok(bytes) => serde_json::json!({
                "status": "ok",
                "path": path_str,
                "content_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }),
            Err(e) => serde_json::json!({ "status": "error", "reason": e.to_string() }),
        },
        Err(e) => serde_json::json!({ "status": "error", "reason": e.to_string() }),
    }
}

fn handle_list_dir(run_id: &str, engine: &Arc<HeuristicsEngine>, command: &serde_json::Value) -> serde_json::Value {
    let Some(path_str) = command.get("path").and_then(|v| v.as_str()) else {
        return serde_json::json!({ "status": "denied", "reason": "missing 'path'" });
    };
    let target = Path::new(path_str);

    if is_excluded(engine, target) {
        return serde_json::json!({ "status": "denied", "reason": "path matches a sensitive-credential exclusion" });
    }
    if !in_scope(run_id, target) {
        return serde_json::json!({ "status": "denied", "reason": "path is outside this run's scope" });
    }

    match std::fs::read_dir(target) {
        Ok(entries) => {
            let names: Vec<String> = entries
                .flatten()
                .take(MAX_LIST_ENTRIES)
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            serde_json::json!({ "status": "ok", "path": path_str, "entries": names })
        }
        Err(e) => serde_json::json!({ "status": "error", "reason": e.to_string() }),
    }
}

const EXEC_TIMEOUT_SECS: u64 = 10;
const MAX_EXEC_OUTPUT_BYTES: usize = 65_536;

/// No shell, ever — `tokio::process::Command` with an explicit argv built
/// entirely from the config-driven allowlist (`engine.config`'s already-
/// loaded `lookup_audit_agentic_command`, not a fresh `ConfigManager` load —
/// this reuses the hot-reloadable instance the daemon already has), with at
/// most one caller-supplied `{target}` substitution. A command `name` not
/// present in the allowlist (loaded from
/// `protect-community/configs/vandam/audit_agentic_commands.json`) is
/// refused outright — this is a hard allowlist, not a pattern match. Bounded
/// by a fixed timeout so a hung diagnostic command (e.g. a `systemctl
/// status` against a wedged unit) can't tie up the agentic loop.
async fn handle_exec_command(engine: &Arc<HeuristicsEngine>, command: &serde_json::Value) -> serde_json::Value {
    let Some(name) = command.get("name").and_then(|v| v.as_str()) else {
        return serde_json::json!({ "status": "denied", "reason": "missing 'name'" });
    };
    let target = command.get("target").and_then(|v| v.as_str()).unwrap_or("");

    let Some(allowed) = engine.config.lookup_audit_agentic_command(name) else {
        return serde_json::json!({ "status": "denied", "reason": format!("'{}' is not in the agentic command allowlist", name) });
    };

    let args: Vec<String> = allowed.args.iter().map(|a| if a == "{target}" { target.to_string() } else { a.clone() }).collect();

    let child = tokio::process::Command::new(&allowed.binary).args(&args).output();
    match tokio::time::timeout(Duration::from_secs(EXEC_TIMEOUT_SECS), child).await {
        Ok(Ok(out)) => {
            let mut stdout = String::from_utf8_lossy(&out.stdout).to_string();
            stdout.truncate(MAX_EXEC_OUTPUT_BYTES);
            serde_json::json!({
                "status": "ok",
                "name": name,
                "exit_code": out.status.code(),
                "stdout": stdout,
            })
        }
        Ok(Err(e)) => serde_json::json!({ "status": "error", "reason": e.to_string() }),
        Err(_) => serde_json::json!({ "status": "error", "reason": format!("timed out after {}s", EXEC_TIMEOUT_SECS) }),
    }
}
