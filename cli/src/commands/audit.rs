use crate::output::{CliError, CliOutput};
use crate::client::audit as audit_data;
use clap::Subcommand;

/// Mirrors the TUI dashboard's "Audit" tab (deep forensic scan: config
/// safety, binary/package integrity, live process/socket/PTY context, cloud
/// correlation) against vandamd's real `/api/v1/audit/*` API. Deliberately
/// named distinctly from the real alert audit log at
/// /var/log/kinnector/audit.log (already surfaced via `alerts follow` /
/// `alerts list`) so an operator or agent can't confuse "the deep-audit
/// pipeline" with "the real alert log." The whole feature lives in
/// `vandam` (see the Audit deep-scan design plan) — an OSS build or a
/// Pro build without a subscription gets `"upgrade_required"` from every
/// endpoint here; the daemon is authoritative, this CLI does no client-side
/// tier gating.
#[derive(Subcommand, Debug)]
pub enum AuditAction {
    /// Kick off a deep forensic audit scan (runs 10-30 minutes in the background)
    Run,
    /// Status of the most recent deep audit scan
    Status,
    /// Deep audit scan runs
    Runs {
        #[command(subcommand)]
        action: RunsAction,
    },
    /// Findings produced by a deep audit scan
    Findings {
        #[command(subcommand)]
        action: FindingsAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum RunsAction {
    List,
    Show { id: String },
}

#[derive(Subcommand, Debug)]
pub enum FindingsAction {
    /// List findings for a run
    List {
        #[arg(long)]
        run: String,
    },
    Remediate { id: String },
    /// Remediate every currently-unremediated finding for a run in one call
    /// (mirrors the TUI's `[a]` key). vandamd has no bulk endpoint — this
    /// loops the per-finding `remediate` call client-side.
    RemediateAll {
        #[arg(long)]
        run: String,
    },
    /// Extracted strings evidence for a finding (from an Unindexed/Tampered binary)
    Strings { id: String },
}

fn print_run(run: &audit_data::Run) {
    println!("Run {} — {}", run.id, run.status.label());
    println!("  started:      {}", run.started_at);
    println!("  stage since:  {}", run.stage_started_at);
    if let Some(err) = &run.error {
        println!("  error:        {}", err);
    }
}

fn print_finding(f: &audit_data::Finding) {
    println!(
        "[{}] {} — {} ({}){}",
        f.severity.to_uppercase(),
        f.title,
        f.category,
        f.id,
        if f.remediated { "  [REMEDIATED]" } else { "" }
    );
}

pub fn handle(output: &CliOutput, action: AuditAction, socket_path: &str) {
    match action {
        AuditAction::Run => match audit_data::start_run(socket_path) {
            Ok(result) => output.emit_ok(&result, |result| match result.status.as_str() {
                "queued" => println!(
                    "Deep audit scan started (run {}). This runs in the background for 10-30 minutes — check progress with `audit status`.",
                    result.run_id.clone().unwrap_or_default()
                ),
                "upgrade_required" => println!(
                    "{}",
                    result.message.clone().unwrap_or_else(|| "Deep Audit is a vandam subscriber feature.".to_string())
                ),
                "disabled" => println!("Deep audit is currently disabled: {}", result.reason.clone().unwrap_or_default()),
                other => println!("Unexpected response: {}", other),
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Status => match audit_data::fetch_runs(socket_path) {
            Ok(data) => output.emit_ok(&data, |data| {
                if data.status.as_deref() == Some("upgrade_required") {
                    println!("{}", data.message.clone().unwrap_or_else(|| "Deep Audit is a vandam subscriber feature.".to_string()));
                    return;
                }
                match data.runs.first() {
                    Some(run) => print_run(run),
                    None => println!("No deep audit scans have been run yet. Start one with `audit run`."),
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Runs { action: RunsAction::List } => match audit_data::fetch_runs(socket_path) {
            Ok(data) => output.emit_ok(&data.runs, |runs| {
                if runs.is_empty() {
                    println!("No deep audit scans recorded yet.");
                    return;
                }
                for run in runs {
                    println!("{:<38} {:<28} {}", run.id, run.status.label(), run.started_at);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Runs { action: RunsAction::Show { id } } => match audit_data::fetch_run(socket_path, &id) {
            Ok(detail) => output.emit_ok(&detail, |detail| {
                let Some(run) = &detail.run else {
                    println!("Run {} not found.", id);
                    return;
                };
                print_run(run);
                println!();
                if detail.findings.is_empty() {
                    println!("No findings.");
                } else {
                    println!("Findings:");
                    for f in &detail.findings {
                        print_finding(f);
                    }
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Findings { action: FindingsAction::List { run } } => match audit_data::fetch_run(socket_path, &run) {
            Ok(detail) => output.emit_ok(&detail.findings, |findings| {
                if findings.is_empty() {
                    println!("No findings for run {}.", run);
                    return;
                }
                for f in findings {
                    print_finding(f);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Findings { action: FindingsAction::Remediate { id } } => match audit_data::remediate_finding(socket_path, &id) {
            Ok(result) => output.emit_ok(&result, |result| println!("{}: {}", id, result.status)),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Findings { action: FindingsAction::RemediateAll { run } } => match audit_data::fetch_run(socket_path, &run) {
            Ok(detail) => {
                let unremediated: Vec<String> = detail.findings.iter().filter(|f| !f.remediated).map(|f| f.id.clone()).collect();
                if unremediated.is_empty() {
                    output.emit_ok(&serde_json::json!({ "run": run, "remediated": Vec::<String>::new() }), |_| {
                        println!("No unremediated findings for run {}.", run);
                    });
                } else {
                    let results: Vec<serde_json::Value> = unremediated
                        .iter()
                        .map(|id| match audit_data::remediate_finding(socket_path, id) {
                            Ok(result) => serde_json::json!({ "id": id, "status": result.status }),
                            Err(e) => serde_json::json!({ "id": id, "error": e }),
                        })
                        .collect();
                    output.emit_ok(&results, |results| {
                        for r in results {
                            let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                            match r.get("error").and_then(|v| v.as_str()) {
                                Some(err) => println!("{}: ERROR {}", id, err),
                                None => println!("{}: {}", id, r.get("status").and_then(|v| v.as_str()).unwrap_or("?")),
                            }
                        }
                    });
                }
            }
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        AuditAction::Findings { action: FindingsAction::Strings { id } } => match audit_data::fetch_finding_strings(socket_path, &id) {
            Ok(result) => output.emit_ok(&result, |result| match result.strings.as_deref() {
                Some(s) if !s.is_empty() => println!("{}", s),
                _ => println!("No extracted strings available for finding {}.", id),
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
    }
}
