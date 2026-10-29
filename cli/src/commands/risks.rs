use crate::output::{CliError, CliOutput};
use crate::client::risks as risks_data;
use clap::Subcommand;

/// Mirrors the TUI dashboard's "Supply Chain" tab against vandamd's real
/// `/api/v1/risks/*` API — free-tier local detection
/// (`vandam/src/supply_chain.rs`/`supply_chain_store.rs`: package-manager
/// install activity, project inventory, an offline known-CVE cross-check)
/// available in every build/subscription. `events`/`blocked` are the shared
/// alert pipeline filtered to the `Vulnerability.SupplyChain.*` threat-type
/// namespace, same data the Alerts page's `alerts list` shows — this is a
/// filtered view, not a separate log. Live OSV.dev lookups and cross-project
/// analytics are vandam subscriber-only cloud features
/// (`vandam/src/supply_chain_cloud.rs`) — an OSS build or unsubscribed
/// Pro build gets `{"status":"upgrade_required"/"unavailable",...}` for
/// those, surfaced as-is rather than treated as a CLI error.
#[derive(Subcommand, Debug)]
pub enum RisksAction {
    /// Recent package-manager activity
    Activity {
        #[command(subcommand)]
        action: ActivityAction,
    },
    /// Supply-chain security events (filtered alerts)
    Events {
        #[command(subcommand)]
        action: EventsAction,
    },
    /// Packages/actions blocked by local enforcement (filtered alerts)
    Blocked {
        #[command(subcommand)]
        action: BlockedAction,
    },
    /// Discovered projects/manifests, including the system-wide bucket
    Projects {
        #[command(subcommand)]
        action: ProjectsAction,
    },
    /// Local free-tier prevention rules (never subscription-gated)
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ListAction {
    List,
}

#[derive(Subcommand, Debug)]
pub enum ActivityAction {
    List,
    /// Full detail for one activity row (un-truncated details/command),
    /// mirrors the TUI's `[Enter]` on an Activity row. `id` comes from
    /// `activity list --output json`.
    Show { id: String },
}

#[derive(Subcommand, Debug)]
pub enum EventsAction {
    List,
    /// Mark an event inspected (mirrors the TUI's `[Enter]` on a row)
    Inspect { id: String },
}

#[derive(Subcommand, Debug)]
pub enum BlockedAction {
    List,
    /// Full detail for one enforcement action (target, engine, full command
    /// line, timestamp), mirrors the TUI's `[Enter]` on a Blocked Actions
    /// row. `id` comes from `blocked list --output json`.
    Show { id: String },
}

#[derive(Subcommand, Debug)]
pub enum ProjectsAction {
    List,
    /// Toggle whether local enforcement excludes this project path
    Filter {
        path: String,
        #[arg(long)]
        unset: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyAction {
    Show,
    /// Toggle whether a suspicious postinstall child process is killed
    /// (`log`) or logged only (`kill`).
    SetPostinstall {
        #[arg(value_enum)]
        mode: PostinstallMode,
    },
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum PostinstallMode {
    Log,
    Kill,
}

pub fn handle(output: &CliOutput, action: RisksAction, socket_path: &str) {
    match action {
        RisksAction::Activity { action: ActivityAction::List } => match risks_data::fetch_activity(socket_path) {
            Ok(data) => output.emit_ok(&data.activities, |activities| {
                if activities.is_empty() {
                    println!("No package-manager activity recorded yet.");
                    return;
                }
                for a in activities {
                    let project = if a.is_system_wide { "(system-wide)" } else { &a.project_path };
                    println!("{:<12} {:<20} {:<20} {:<10} {:<30} {}", a.id, a.time, a.manager, a.status, project, a.details);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        RisksAction::Activity { action: ActivityAction::Show { id } } => match risks_data::fetch_activity(socket_path) {
            Ok(data) => match data.activities.into_iter().find(|a| a.id == id) {
                Some(a) => output.emit_ok(&a, |a| {
                    let project = if a.is_system_wide { "(system-wide)" } else { &a.project_path };
                    println!("Time      : {}", a.time);
                    println!("Manager   : {}", a.manager);
                    println!("Command   : {}", a.command);
                    println!("Project   : {}", project);
                    println!("Status    : {}", a.status);
                    println!("Details   : {}", a.details);
                }),
                None => output.emit_err(CliError::daemon(format!("no activity record with id {}", id))),
            },
            Err(e) => output.emit_err(CliError::daemon(e)),
        },

        RisksAction::Events { action: EventsAction::List } => match risks_data::fetch_events(socket_path) {
            Ok(data) => output.emit_ok(&data.events, |events| {
                if events.is_empty() {
                    println!("No Supply Chain security events recorded yet.");
                    return;
                }
                for e in events {
                    let flag = if e.inspected { "✓" } else { " " };
                    println!("[{}] {:<10} {:<40} {:<12} {}", flag, e.severity, e.threat_type, e.id, e.remediation.status);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        RisksAction::Events { action: EventsAction::Inspect { id } } => match risks_data::inspect_event(socket_path, &id) {
            Ok(()) => output.emit_ok(&serde_json::json!({ "id": id, "inspected": true }), |_| {
                println!("Marked event {} inspected.", id);
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },

        RisksAction::Blocked { action: BlockedAction::List } => match risks_data::fetch_blocked(socket_path) {
            Ok(data) => output.emit_ok(&data.blocked, |blocked| {
                if blocked.is_empty() {
                    println!("No Supply Chain enforcement actions recorded yet.");
                    return;
                }
                for e in blocked {
                    println!("{:<12} {:<10} {:<40} {:<12} {}", e.id, e.severity, e.threat_type, e.remediation.action, e.process.exec_path);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        RisksAction::Blocked { action: BlockedAction::Show { id } } => match risks_data::fetch_blocked(socket_path) {
            Ok(data) => match data.blocked.into_iter().find(|e| e.id == id) {
                Some(e) => output.emit_ok(&e, |e| {
                    println!("Time       : {}", e.timestamp);
                    println!("Severity   : {}", e.severity);
                    println!("Threat     : {}", e.threat_type);
                    println!("Action     : {}", e.remediation.action);
                    println!("Target     : {}", e.process.exec_path);
                    println!("Cmdline    : {}", e.process.cmdline);
                    println!("Parent     : {}", e.process.parent_name);
                    println!("Status     : {}", e.remediation.status);
                }),
                None => output.emit_err(CliError::daemon(format!("no blocked action with id {}", id))),
            },
            Err(e) => output.emit_err(CliError::daemon(e)),
        },

        RisksAction::Projects { action: ProjectsAction::List } => match risks_data::fetch_projects(socket_path) {
            Ok(data) => output.emit_ok(&data.projects, |projects| {
                if projects.is_empty() {
                    println!("No projects discovered yet.");
                    return;
                }
                for p in projects {
                    let path = if p.is_system_wide { "(system-wide)" } else { &p.path };
                    let filtered = if p.filtered { " [filtered]" } else { "" };
                    println!("{:<30} {:<20} {:<3} events{}", path, p.framework, p.events_count, filtered);
                }
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        RisksAction::Projects { action: ProjectsAction::Filter { path, unset } } => {
            match risks_data::filter_project(socket_path, &path, !unset) {
                Ok(()) => output.emit_ok(&serde_json::json!({ "path": path, "filtered": !unset }), |_| {
                    println!("Project {} {}.", path, if unset { "un-filtered" } else { "filtered" });
                }),
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }

        RisksAction::Policy { action: PolicyAction::Show } => match risks_data::fetch_policy(socket_path) {
            Ok(policy) => output.emit_ok(&policy, |p| {
                println!("block_postinstall_scripts: {}", p.block_postinstall_scripts);
                println!("auto_quarantine_severity : {}", p.auto_quarantine_severity.clone().unwrap_or_else(|| "off".to_string()));
                println!("registry_allowlist        : {}", p.registry_allowlist.join(", "));
                println!("excluded_project_paths    : {}", p.excluded_project_paths.join(", "));
            }),
            Err(e) => output.emit_err(CliError::daemon(e)),
        },
        RisksAction::Policy { action: PolicyAction::SetPostinstall { mode } } => {
            match risks_data::fetch_policy(socket_path) {
                Ok(mut policy) => {
                    policy.block_postinstall_scripts = matches!(mode, PostinstallMode::Kill);
                    match risks_data::put_policy(socket_path, &policy) {
                        Ok(()) => output.emit_ok(&policy, |p| {
                            println!("block_postinstall_scripts is now {}.", p.block_postinstall_scripts);
                        }),
                        Err(e) => output.emit_err(CliError::daemon(e)),
                    }
                }
                Err(e) => output.emit_err(CliError::daemon(e)),
            }
        }
    }
}
