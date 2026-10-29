use crate::output::{CliError, CliOutput};
use crate::query_daemon;
use clap::{Args, Subcommand};
use colored::Colorize;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;

/// The bare `vandam setup` (interactive TUI wizard) is untouched and
/// stays human-only. This subcommand adds a non-interactive path so a human
/// scripting a rollout or a coding agent can apply setup choices without a
/// TTY prompt loop.
#[derive(Subcommand, Debug)]
pub enum SetupAction {
    /// Apply configuration non-interactively (no TUI)
    Configure(ConfigureArgs),
}

#[derive(Args, Debug, Default)]
pub struct ConfigureArgs {
    /// PATH:ROLE[:SITE] — registers a storage path (same as `storages add`). Repeatable.
    #[arg(long = "storage", value_name = "PATH:ROLE[:SITE]")]
    pub storages: Vec<String>,

    /// PATH — adds a file integrity watch root (same as
    /// `file-integrity watch`). Repeatable.
    #[arg(long = "file-integrity-watch", value_name = "PATH")]
    pub fim_watch: Vec<String>,

    /// TYPE:TARGET[:SCOPE] — registers a custom rule (same as `rules add`). Repeatable.
    #[arg(long = "rule", value_name = "TYPE:TARGET[:SCOPE]")]
    pub rules: Vec<String>,

    /// IMAGE — trusts a container image (same as `containers trust`). Repeatable.
    #[arg(long = "trust-container", value_name = "IMAGE")]
    pub trust_container: Vec<String>,

    /// Read a JSON config file (or `-` for stdin) describing the same fields as
    /// the flags above, as an alternative or in addition to them.
    #[arg(long)]
    pub site_config: Option<String>,

    /// Print the calls that would be made without making them
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Deserialize, Default)]
struct SiteConfigFile {
    #[serde(default)]
    storages: Vec<StorageEntry>,
    #[serde(default)]
    fim_watch: Vec<String>,
    #[serde(default)]
    rules: Vec<RuleEntry>,
    #[serde(default)]
    trust_container: Vec<String>,
}

#[derive(Deserialize)]
struct StorageEntry {
    path: String,
    role: String,
    #[serde(default)]
    site: Option<String>,
}

#[derive(Deserialize)]
struct RuleEntry {
    #[serde(rename = "type")]
    rule_type: String,
    target: String,
    #[serde(default = "default_scope")]
    scope: String,
}

fn default_scope() -> String {
    "site".to_string()
}

struct PlanItem {
    label: String,
    method: &'static str,
    path: &'static str,
    body: Value,
}

fn parse_storage(s: &str) -> Result<StorageEntry, String> {
    let mut parts = s.splitn(3, ':');
    let path = parts
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| format!("--storage '{}' is empty", s))?
        .to_string();
    let role = parts
        .next()
        .ok_or_else(|| format!("--storage '{}' missing :ROLE", s))?
        .to_string();
    let site = parts.next().map(|s| s.to_string());
    Ok(StorageEntry { path, role, site })
}

fn parse_rule(s: &str) -> Result<RuleEntry, String> {
    let mut parts = s.splitn(3, ':');
    let rule_type = parts
        .next()
        .filter(|p| !p.is_empty())
        .ok_or_else(|| format!("--rule '{}' is empty", s))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| format!("--rule '{}' missing :TARGET", s))?
        .to_string();
    let scope = parts.next().map(|s| s.to_string()).unwrap_or_else(default_scope);
    Ok(RuleEntry { rule_type, target, scope })
}

fn build_plan(args: &ConfigureArgs) -> Result<Vec<PlanItem>, String> {
    let mut cfg = SiteConfigFile::default();

    if let Some(sc) = &args.site_config {
        let contents = if sc == "-" {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| format!("Failed to read stdin: {}", e))?;
            s
        } else {
            std::fs::read_to_string(sc).map_err(|e| format!("Failed to read {}: {}", sc, e))?
        };
        cfg = serde_json::from_str(&contents)
            .map_err(|e| format!("Invalid --site-config JSON: {}", e))?;
    }

    for w in &args.storages {
        cfg.storages.push(parse_storage(w)?);
    }
    for p in &args.fim_watch {
        cfg.fim_watch.push(p.clone());
    }
    for r in &args.rules {
        cfg.rules.push(parse_rule(r)?);
    }
    for i in &args.trust_container {
        cfg.trust_container.push(i.clone());
    }

    let mut items = Vec::new();
    for w in &cfg.storages {
        items.push(PlanItem {
            label: format!("storage {} (role={})", w.path, w.role),
            method: "POST",
            path: "/api/v1/storage/add",
            body: json!({
                "path": w.path,
                "role": w.role,
                "web_root": w.site.clone().unwrap_or_default(),
            }),
        });
    }
    for p in &cfg.fim_watch {
        items.push(PlanItem {
            label: format!("file-integrity watch {}", p),
            method: "POST",
            path: "/api/v1/fim/add",
            body: json!({ "path": p }),
        });
    }
    for r in &cfg.rules {
        items.push(PlanItem {
            label: format!("rule {}={} (scope={})", r.rule_type, r.target, r.scope),
            method: "POST",
            path: "/api/v1/rules/user/add",
            body: json!({ "rule_type": r.rule_type, "target": r.target, "scope": r.scope }),
        });
    }
    for img in &cfg.trust_container {
        items.push(PlanItem {
            label: format!("trust container {}", img),
            method: "POST",
            path: "/api/v1/rules/user/add",
            // Mirrors `containers trust` exactly, including its existing
            // rule_type mismatch bug — this reuses that command's wiring
            // as-is rather than fixing it (out of scope, see plan).
            body: json!({ "rule_type": "ALLOW_CONTAINER_IMAGE", "target": img, "scope": "site" }),
        });
    }

    Ok(items)
}

pub fn handle(output: &CliOutput, socket: &str, args: ConfigureArgs) {
    let items = match build_plan(&args) {
        Ok(items) => items,
        Err(e) => output.emit_err(CliError::usage(e)),
    };

    if items.is_empty() {
        output.emit_err(CliError::usage(
            "Nothing to configure — pass --storage/--file-integrity-watch/--rule/--trust-container or --site-config"
                .to_string(),
        ));
    }

    if args.dry_run {
        let plan_json: Vec<Value> = items
            .iter()
            .map(|i| {
                json!({
                    "action": i.label,
                    "request": format!("{} {}", i.method, i.path),
                    "body": i.body,
                })
            })
            .collect();
        output.emit_ok(&plan_json, |plan| {
            println!("{}", "=== Dry run: setup configure ===".bold().cyan());
            for p in plan {
                println!(
                    "  {} -> {} {}",
                    p["action"].as_str().unwrap_or(""),
                    p["request"].as_str().unwrap_or(""),
                    p["body"]
                );
            }
            println!(
                "\n{}",
                "Note: wizard concepts with no server-side equivalent (e.g. file-integrity baseline mode, \
                 exec-policy mode as opposed to individual entries) are not represented here."
                    .bright_black()
            );
        });
        return;
    }

    let mut results = Vec::new();
    let mut all_ok = true;
    for item in &items {
        let res = query_daemon(socket, item.method, item.path, Some(&item.body));
        let ok = res.is_ok();
        all_ok &= ok;
        results.push(json!({
            "action": item.label,
            "endpoint": format!("{} {}", item.method, item.path),
            "status": if ok { "ok" } else { "error" },
            "detail": res.err(),
        }));
    }

    // Only mark the host configured if every item succeeded — a partial
    // failure with the marker set would be a false signal.
    let marked_configured = if all_ok {
        query_daemon(socket, "POST", "/api/v1/setup/configure", None).is_ok()
    } else {
        false
    };

    let summary = json!({
        "items": results,
        "all_succeeded": all_ok,
        "marked_configured": marked_configured,
    });

    output.emit_ok(&summary, |s| {
        println!("{}", "=== setup configure ===".bold().cyan());
        for r in s["items"].as_array().unwrap() {
            let status = r["status"].as_str().unwrap_or("");
            let line = format!(
                "  {} {}",
                r["action"].as_str().unwrap_or(""),
                r["endpoint"].as_str().unwrap_or("")
            );
            if status == "ok" {
                println!("{} {}", line.green(), "OK".green().bold());
            } else {
                println!(
                    "{} {} ({})",
                    line.red(),
                    "FAILED".red().bold(),
                    r["detail"].as_str().unwrap_or("")
                );
            }
        }
        if s["all_succeeded"].as_bool().unwrap_or(false) {
            println!("\n{}", "All items applied; host marked as configured.".green());
        } else {
            println!(
                "\n{}",
                "Some items failed; host NOT marked as configured (setup/configure not called)."
                    .yellow()
            );
        }
    });
}
