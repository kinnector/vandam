//! supply_chain.rs — free-tier local Supply Chain detection (package-manager
//! install activity, project inventory, suspicious postinstall behavior, an
//! offline known-CVE cross-check). Cloud-only capability (live OSV.dev
//! lookups, cross-project "worm" correlation/analytics) is subscription-gated
//! and lives entirely in `vandam/src/supply_chain_cloud.rs` — this module
//! has no Pro dependency and is fully useful on its own, matching the OSS/Pro
//! split used by `investigate.rs`/`summarize.rs` (a real OSS-owned capability
//! that Pro enriches), not `audit`'s "everything in vandam" shape.
//!
//! Follows the same separation as `pty_session.rs`: this module only
//! classifies and persists (via `supply_chain_store`); it cannot call
//! `HeuristicsEngine`'s private `emit_alert_with_detail`/
//! `terminate_threat_child` (module-private, not `pub`), so it returns a
//! [`SupplyChainAction`] describing what the caller (`heuristics.rs`'s
//! `ProcessCreate`/`ProcessStop` handlers) should do.
//!
//! Executable classification is entirely config-driven via
//! `crate::rules::package_manager_signatures()`
//! (`protect-community/configs/vandam/package_manager_signatures.json`) —
//! per this workspace's rule against hardcoded match lists in `vandam`.

use crate::heuristics::HeuristicsEngine;
use crate::rules::PackageManagerSignature;
use std::path::{Path, PathBuf};

/// What `heuristics.rs` should do in response to a classified event.
/// `on_process_create` never calls `emit_alert_with_detail`/
/// `terminate_threat_child` itself — see module doc comment.
pub enum SupplyChainAction {
    None,
    /// Log-only alert (`action` becomes `RemediationInfo.action`, e.g.
    /// `"LOG_ALERT"`).
    Alert { threat_type: String, severity: String, action: String, desc: String },
    /// Ask the caller to run `terminate_threat_child` instead — that
    /// function builds and dispatches its own `AlertPayload` (severity
    /// forced `CRITICAL`) and performs the kill, so the caller must not
    /// *also* call `emit_alert_with_detail` for this variant.
    Kill { threat_type: String, desc: String },
}

/// Per-install-root tracking, keyed by the top-level package-manager
/// invocation's pid in `HeuristicsEngine::supply_chain_installs`. Propagated
/// to every descendant pid spawned while that root is alive (e.g. `npm` ->
/// `sh` -> `curl`), the same "tag every descendant cheaply via one parent
/// lookup" shape `pty_session.rs` uses for session attribution.
#[derive(Clone)]
pub struct TrackedInstall {
    pub manager_exe: String,
    pub ecosystem: Option<String>,
    pub project_path: String,
    pub is_system_wide: bool,
}

fn read_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()
}

/// Walks up from `start` looking for `manifest_file`, capped at 8 levels —
/// deep enough for any real project layout, bounded so a pathological cwd
/// (e.g. directly under `/`) can't turn into a long stat() loop.
fn resolve_project_root(start: &Path, manifest_file: &str) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    for _ in 0..8 {
        if dir.join(manifest_file).is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Best-effort `name@version` (npm/yarn/pnpm/composer/cargo) or
/// `name==version` (pip) extraction from a package-manager invocation's
/// cmdline, for cross-checking against `known_vulnerable_packages()`. Not a
/// full argv parser for every manager's syntax — misses e.g. separately
/// pinned versions in a manifest/lockfile — this is an approximate,
/// best-effort local signal; vandam's live OSV lookup (subscriber-only)
/// resolves real installed versions from the lockfile for full coverage.
fn extract_package_and_version(cmdline: &str) -> Option<(String, String)> {
    for tok in cmdline.split_whitespace().skip(1) {
        if tok.starts_with('-') {
            continue;
        }
        if let Some((name, ver)) = tok.split_once("==") {
            if !name.is_empty() && !ver.is_empty() {
                return Some((name.to_string(), ver.to_string()));
            }
        }
        // Scoped npm packages ("@scope/name@version") have a leading '@' as
        // part of the name, not the version separator — search for the
        // version-separator '@' starting after any leading one, so
        // "@scope/name@1.0.0" splits into ("@scope/name", "1.0.0") rather
        // than misreading the scope marker itself as an (empty-name)
        // separator.
        let search_from = if tok.starts_with('@') { 1 } else { 0 };
        if let Some(rel_pos) = tok[search_from..].rfind('@') {
            let pos = search_from + rel_pos;
            let (name, ver) = (&tok[..pos], &tok[pos + 1..]);
            if !name.is_empty() && !ver.is_empty() {
                return Some((name.to_string(), ver.to_string()));
            }
        }
    }
    None
}

fn matches_manager(sig: &PackageManagerSignature, exe_basename: &str) -> bool {
    sig.executable.eq_ignore_ascii_case(exe_basename)
}

/// Called from `heuristics.rs`'s `EventType::ProcessCreate` handler, right
/// after `pty_session::on_process_create`. Two cases:
/// 1. `child_exe` itself matches a `package_manager_signatures()` entry with
///    a recognized install subcommand — classify + record activity/project,
///    start tracking this pid as an install root.
/// 2. `parent_pid` is already a tracked install root (or descendant) —
///    check `child_exe` for suspicious postinstall behavior (network tools,
///    known attacker-tool signatures) and propagate tracking to `child_pid`.
pub fn on_process_create(
    engine: &HeuristicsEngine,
    child_pid: u32,
    parent_pid: u32,
    child_exe: &str,
    child_cmdline: &str,
) -> SupplyChainAction {
    let exe_basename = Path::new(child_exe)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if exe_basename.is_empty() {
        return SupplyChainAction::None;
    }

    let signatures = engine.config.package_manager_signatures();
    if let Some(sig) = signatures.iter().find(|s| matches_manager(s, &exe_basename)) {
        let tokens: Vec<&str> = child_cmdline.split_whitespace().collect();
        let has_install_subcommand = tokens
            .iter()
            .skip(1)
            .any(|t| sig.install_subcommands.iter().any(|c| c == t));
        if !has_install_subcommand {
            return SupplyChainAction::None;
        }

        let is_global = tokens.iter().any(|t| sig.global_flags.iter().any(|g| g == t));
        let (project_path, is_system_wide) = if sig.scope == "system" || is_global {
            (crate::supply_chain_store::SYSTEM_WIDE_PATH.to_string(), true)
        } else if let (Some(manifest), Some(cwd)) = (sig.manifest_file.as_ref(), read_cwd(child_pid)) {
            match resolve_project_root(&cwd, manifest) {
                Some(root) => (root.to_string_lossy().to_string(), false),
                None => (crate::supply_chain_store::SYSTEM_WIDE_PATH.to_string(), true),
            }
        } else {
            (crate::supply_chain_store::SYSTEM_WIDE_PATH.to_string(), true)
        };

        let framework = if is_system_wide {
            sig.executable.clone()
        } else {
            crate::discovery::detect_framework_from_registry(Path::new(&project_path)).0
        };

        engine.supply_chain_installs.insert(
            child_pid,
            TrackedInstall {
                manager_exe: sig.executable.clone(),
                ecosystem: sig.ecosystem.clone(),
                project_path: project_path.clone(),
                is_system_wide,
            },
        );

        let subcommand = tokens.get(1).copied().unwrap_or("");
        crate::supply_chain_store::append_activity(crate::supply_chain_store::SupplyChainActivity {
            id: String::new(),
            time: chrono::Utc::now().to_rfc3339(),
            manager: sig.executable.clone(),
            command: format!("{} {}", sig.executable, subcommand),
            details: child_cmdline.chars().take(240).collect(),
            project_path: project_path.clone(),
            is_system_wide,
            status: "CLEAN".to_string(),
        });
        crate::supply_chain_store::upsert_project(&project_path, &framework, is_system_wide);

        if let Some(ecosystem) = sig.ecosystem.as_ref() {
            if let Some((pkg_name, pkg_version)) = extract_package_and_version(child_cmdline) {
                if let Some(vuln) = engine.config.lookup_vulnerable_package(ecosystem, &pkg_name, &pkg_version) {
                    crate::supply_chain_store::increment_project_event_count(&project_path);
                    return SupplyChainAction::Alert {
                        threat_type: "Vulnerability.SupplyChain.KnownCVE".to_string(),
                        severity: vuln.severity.clone(),
                        action: "LOG_ALERT".to_string(),
                        desc: format!(
                            "{} install pulled in {}@{}, matching known advisory {} — {}",
                            sig.executable, pkg_name, pkg_version, vuln.cve_id, vuln.summary
                        ),
                    };
                }
            }
        }
        return SupplyChainAction::None;
    }

    let Some(tracked) = engine.supply_chain_installs.get(&parent_pid).map(|v| v.clone()) else {
        return SupplyChainAction::None;
    };
    engine.supply_chain_installs.insert(child_pid, tracked.clone());

    let is_network_tool = matches!(exe_basename.as_str(), "curl" | "wget" | "nc" | "ncat" | "socat");
    let is_shell = engine.system_shells.contains(child_exe)
        || engine.system_shells.iter().any(|s| child_exe.ends_with(s.as_str()));
    let is_attacker_tool = engine.config.lookup_attacker_tool(child_exe, child_cmdline).is_some();
    // A postinstall shell that itself invokes chmod is the classic
    // curl|sh-style "make the dropped payload executable" step — flag it,
    // but a bare shell exec alone (extremely common in normal postinstall
    // scripts) is not suspicious on its own.
    let is_suspicious_shell = is_shell && child_cmdline.contains("chmod");

    if !(is_network_tool || is_attacker_tool || is_suspicious_shell) {
        return SupplyChainAction::None;
    }

    let policy = crate::supply_chain_store::read_policy();
    if policy.excluded_project_paths.iter().any(|p| p == &tracked.project_path) {
        return SupplyChainAction::None;
    }

    crate::supply_chain_store::increment_project_event_count(&tracked.project_path);
    let desc = format!(
        "{} install ({}) spawned suspicious child process: {} {}",
        tracked.manager_exe, tracked.project_path, child_exe, child_cmdline
    );
    if policy.block_postinstall_scripts {
        SupplyChainAction::Kill {
            threat_type: "Vulnerability.SupplyChain.SuspiciousPostinstall".to_string(),
            desc,
        }
    } else {
        SupplyChainAction::Alert {
            threat_type: "Vulnerability.SupplyChain.SuspiciousPostinstall".to_string(),
            severity: "HIGH".to_string(),
            action: "LOG_ALERT".to_string(),
            desc,
        }
    }
}

/// Called from `heuristics.rs`'s `EventType::ProcessStop` handler, mirroring
/// `pty_session::on_process_stop`'s cleanup shape.
pub fn on_process_stop(engine: &HeuristicsEngine, pid: u32) {
    engine.supply_chain_installs.remove(&pid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_project_root_finds_manifest_in_parent_dir() {
        let tmp = std::env::temp_dir().join(format!("kinnector_supply_chain_test_{}", std::process::id()));
        let sub = tmp.join("src").join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(tmp.join("package.json"), "{}").unwrap();

        let found = resolve_project_root(&sub, "package.json");
        assert_eq!(found, Some(tmp.clone()));

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn resolve_project_root_returns_none_when_no_manifest_within_depth() {
        let tmp = std::env::temp_dir().join(format!("kinnector_supply_chain_test_none_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(resolve_project_root(&tmp, "package.json"), None);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn extract_package_and_version_handles_npm_style_at_syntax() {
        assert_eq!(
            extract_package_and_version("npm install lodash@4.17.11"),
            Some(("lodash".to_string(), "4.17.11".to_string()))
        );
    }

    #[test]
    fn extract_package_and_version_handles_pip_style_double_equals() {
        assert_eq!(
            extract_package_and_version("pip install django==3.2.10"),
            Some(("django".to_string(), "3.2.10".to_string()))
        );
    }

    #[test]
    fn extract_package_and_version_skips_flags_and_returns_none_without_version() {
        assert_eq!(extract_package_and_version("npm install --save lodash"), None);
    }

    #[test]
    fn extract_package_and_version_ignores_bare_scoped_package_without_version() {
        // "@scope/name" alone (no "@version" suffix) must not be
        // misinterpreted as name="" version="scope/name" by matching the
        // scope's own leading '@'.
        assert_eq!(extract_package_and_version("npm install @scope/name"), None);
    }

    #[test]
    fn extract_package_and_version_handles_scoped_package_with_version() {
        assert_eq!(
            extract_package_and_version("npm install @angular/core@15.2.0"),
            Some(("@angular/core".to_string(), "15.2.0".to_string()))
        );
    }
}
