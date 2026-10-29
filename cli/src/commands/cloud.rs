use crate::output::{CliError, CliOutput};
use crate::client::cloud as cloud_data;
use clap::Subcommand;

/// Cloud auto-audit config, quota/usage status, and the local-failsafe log
/// against vandamd's real `/api/v1/cloud/*` API (`vandam/src/quota_guard.rs`,
/// `vandam/src/cloud_api.rs`). Everything here is Pro/Max-gated at the
/// daemon — on OSS or an unlicensed Pro build every call returns
/// `{"status":"unavailable"}`, surfaced here as an empty/zeroed result
/// rather than an error.
#[derive(Subcommand, Debug)]
pub enum CloudAction {
    /// Plan, per-category auto-audit state, and local-failsafe usage
    Status,
    /// Enable or disable auto-audit for one category (Max plan only)
    AutoAudit {
        /// One of: alerts, sessions, audits, supply_chain
        category: String,
        #[command(subcommand)]
        action: AutoAuditAction,
    },
    /// Operational log: why something got disabled, plan-limit-reached events
    Logs,
}

#[derive(Subcommand, Debug)]
pub enum AutoAuditAction {
    Enable,
    Disable,
}

pub fn handle(output: &CliOutput, action: CloudAction, socket_path: &str) {
    match action {
        CloudAction::Status => match cloud_data::fetch_status(socket_path) {
            Ok(status) => output.emit_ok(&status.categories, |_| {
                if status.plan.is_empty() {
                    println!("Cloud auto-audit & quota management require vandam.");
                    return;
                }
                println!("Plan: {}", status.plan.to_uppercase());
                println!();
                for cat_id in cloud_data::CATEGORY_ORDER {
                    let state = status.categories.iter().find(|c| c.category == cat_id);
                    let label = cloud_data::category_label(cat_id);
                    match state {
                        Some(s) => {
                            let auto_audit = if s.manually_disabled { "OFF" } else { "ON" };
                            let status_str = if s.tripped { "TRIPPED (local failsafe)" } else { "OK" };
                            println!(
                                "{:<14} auto-audit={:<4} usage={}/{}  status={}",
                                label, auto_audit, s.window_used, s.window_limit, status_str
                            );
                            if let Some(reason) = &s.reason {
                                println!("               reason: {}", reason);
                            }
                        }
                        None => println!("{:<14} (no data yet)", label),
                    }
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        CloudAction::AutoAudit { category, action } => {
            if cloud_data::CATEGORY_ORDER.iter().all(|c| *c != category) {
                output.emit_err(CliError::usage(format!(
                    "unknown category '{}' — expected one of: {}",
                    category,
                    cloud_data::CATEGORY_ORDER.join(", ")
                )));
            }
            let enabled = matches!(action, AutoAuditAction::Enable);
            match cloud_data::set_auto_audit(socket_path, &category, enabled) {
                Ok(()) => output.emit_ok(&serde_json::json!({ "category": category, "enabled": enabled }), |_| {
                    println!("Auto-audit for '{}' set to {}.", category, if enabled { "ON" } else { "OFF" });
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
        CloudAction::Logs => match cloud_data::fetch_logs(socket_path) {
            Ok(data) => output.emit_ok(&data.logs, |logs| {
                if logs.is_empty() {
                    println!("No cloud-quota events recorded yet.");
                    return;
                }
                for l in logs {
                    println!("[{}] {}/{}: {}", l.ts, cloud_data::category_label(&l.category), l.event, l.detail);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
    }
}
