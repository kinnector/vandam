//! The agent's rules (was the `kinnector-config` library): signatures, match lists and policies,
//! read through one [`source::Source`] (the repo's `rules/` folder, or a vandam-cloud bundle in
//! memory) and held as one atomically replaced state. No FlatBuffers `rules.db` any more: its
//! input, `rules/policies/*.json`, is read directly.

pub mod source;

pub use source::Source;

use std::collections::{HashSet, HashMap};
use std::path::Path;
use std::sync::{Arc, RwLock};

/// A JSON file's `key` array of strings, from the rules root. Empty when missing.
fn load_list_from_json(src: &Source, filename: &str, key: &str) -> Vec<String> {
    src.json(filename)
        .and_then(|v| v.get(key).and_then(|a| a.as_array()).cloned())
        .map(|arr| arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default()
}

/// A JSON file's `key` object of strings, from the rules root. Empty when missing.
fn load_map_from_json(src: &Source, filename: &str, key: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(obj) = src.json(filename).and_then(|v| v.get(key).and_then(|a| a.as_object()).cloned()) {
        for (k, val) in obj {
            if let Some(s) = val.as_str() {
                map.insert(k, s.to_string());
            }
        }
    }
    map
}

/// The `key` array of `name` as typed entries; an entry that does not parse is skipped. Empty
/// when the file is missing.
fn table_entries<T: serde::de::DeserializeOwned>(src: &Source, name: &str, key: &str) -> Vec<T> {
    src.json(name)
        .and_then(|v| v.get(key).and_then(|a| a.as_array()).cloned())
        .map(|arr| arr.into_iter().filter_map(|entry| serde_json::from_value(entry).ok()).collect())
        .unwrap_or_default()
}

/// `extract` applied to `name`; empty when the file is missing.
fn from_file<T>(src: &Source, name: &str, extract: impl Fn(&serde_json::Value) -> Vec<T>) -> Vec<T> {
    src.json(name).map(|v| extract(&v)).unwrap_or_default()
}

/// The `*signature*.json` tables at the rules root, in name order (a later file's entry wins).
fn signature_tables(src: &Source) -> Vec<serde_json::Value> {
    src.json_files_in("")
        .into_iter()
        .filter(|name| name.contains("signature"))
        .filter_map(|name| src.json(&name))
        .collect()
}

/// Executable basename -> service type, from every signature table's `services` and `databases`.
fn load_signatures_from_vandam_configs(src: &Source) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for v in signature_tables(src) {
        for service in v.get("services").and_then(|a| a.as_array()).into_iter().flatten() {
            let Some(service_type) = service.get("service_type").and_then(|s| s.as_str()) else { continue };
            for ex in service.get("executables").and_then(|e| e.as_array()).into_iter().flatten() {
                if let Some(ex_str) = ex.as_str() {
                    map.insert(ex_str.to_lowercase(), service_type.to_string());
                }
            }
        }
        for db in v.get("databases").and_then(|a| a.as_array()).into_iter().flatten() {
            let Some(db_type) = db.get("db_type").and_then(|s| s.as_str()) else { continue };
            let mapped = match db_type {
                "postgresql" => "postgres",
                "mariadb" => "mysql",
                _ => db_type,
            };
            for ex in db.get("executables").and_then(|e| e.as_array()).into_iter().flatten() {
                if let Some(ex_str) = ex.as_str() {
                    map.insert(ex_str.to_lowercase(), mapped.to_string());
                }
            }
        }
    }
    map
}

/// One country's GeoIP CIDR ranges, keyed by ISO 3166-1 alpha-2 code in
/// `ConfigState::geoip_country_ranges`. Source data is
/// `rules/geoip_country_ranges.json`, ingested by
/// `protect-community/scripts/update_geoip.sh` from ipdeny.com's aggregated
/// per-country zone files — loaded unsigned and cached in `ConfigState`,
/// same as every other Vandam policy list here (`persistence_paths`,
/// `sensitive_credentials`, etc.); only the small curated core table
/// (exclusions/trusted_signers/trusted_clis/network_cdns/sensitive_files)
/// goes through the signed FlatBuffers payload.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct CountryRanges {
    pub name: String,
    #[serde(default)]
    pub cidrs_v4: Vec<String>,
    #[serde(default)]
    pub cidrs_v6: Vec<String>,
}

/// One offline-seeded known-vulnerable-package entry, keyed by (ecosystem,
/// name) in practice via `lookup_vulnerable_package`. Source data is
/// `rules/known_vulnerable_packages.json`,
/// refreshed via `protect-community/scripts/update_known_vulnerable_packages.sh`
/// from OSV.dev — loaded unsigned and cached in `ConfigState`, same convention
/// as `geoip_country_ranges` (real but non-live CVE data; the free-tier local
/// fallback — vandam's subscriber OSV.dev lookup is the live/authoritative
/// source). `ecosystem`/`name` match OSV.dev naming.
#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct KnownVulnerablePackage {
    pub ecosystem: String,
    pub name: String,
    /// Simple `<fixed_version` / `=exact_version` / `*` (always matches)
    /// strings — not OSV's full range model, this file only needs a fast
    /// local semver check. See `lookup_vulnerable_package`.
    pub vulnerable_ranges: Vec<String>,
    pub cve_id: String,
    pub severity: String,
    #[serde(default)]
    pub summary: String,
}

fn load_known_vulnerable_packages(src: &Source) -> Vec<KnownVulnerablePackage> {
    from_file(src, "known_vulnerable_packages.json", |v| {
        v.get("packages")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect())
            .unwrap_or_default()
    })
}

/// Compares two dotted-numeric version strings segment by segment (each
/// segment's leading digits as an integer; a non-numeric/missing segment
/// compares as 0). Not a full semver parser — doesn't understand
/// pre-release/build-metadata ordering — but sufficient for the simple
/// "is this installed version below the fixed version" check this file
/// needs, and degrades gracefully (never panics) on odd version strings
/// like Debian's `5.6.1+really5.4.5-1`.
fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let seg = |s: &str| -> Vec<u64> {
        s.split(|c: char| !c.is_ascii_digit() && c != '.')
            .flat_map(|chunk| chunk.split('.'))
            .map(|part| part.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (av, bv) = (seg(a), seg(b));
    for i in 0..av.len().max(bv.len()) {
        let (x, y) = (av.get(i).copied().unwrap_or(0), bv.get(i).copied().unwrap_or(0));
        match x.cmp(&y) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

/// Evaluates one `vulnerable_ranges` entry (possibly several comma-joined
/// `<op><version>` conditions, all of which must hold — see
/// `KnownVulnerablePackage::vulnerable_ranges`'s doc comment) against an
/// installed version string. `"*"` always matches (advisory with no known
/// fixed version).
fn version_in_range(version: &str, range: &str) -> bool {
    if range.trim() == "*" {
        return true;
    }
    range.split(',').all(|cond| {
        let cond = cond.trim();
        if let Some(v) = cond.strip_prefix(">=") {
            compare_versions(version, v) != std::cmp::Ordering::Less
        } else if let Some(v) = cond.strip_prefix("<=") {
            compare_versions(version, v) != std::cmp::Ordering::Greater
        } else if let Some(v) = cond.strip_prefix('>') {
            compare_versions(version, v) == std::cmp::Ordering::Greater
        } else if let Some(v) = cond.strip_prefix('<') {
            compare_versions(version, v) == std::cmp::Ordering::Less
        } else if let Some(v) = cond.strip_prefix('=') {
            compare_versions(version, v) == std::cmp::Ordering::Equal
        } else {
            compare_versions(version, cond) == std::cmp::Ordering::Equal
        }
    })
}

fn load_geoip_country_ranges(src: &Source) -> HashMap<String, CountryRanges> {
    from_file(src, "geoip_country_ranges.json", |v| {
        v.get("countries")
            .and_then(|c| c.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(code, entry)| {
                        serde_json::from_value::<CountryRanges>(entry.clone()).ok().map(|r| (code.to_uppercase(), r))
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
    .into_iter()
    .collect()
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct CredentialRule {
    pub pattern: String,
    #[serde(default)]
    pub allowed_executables: Vec<String>,
    #[serde(default)]
    pub max_reads: Option<usize>,
}

fn load_credentials_from_json(src: &Source, filename: &str) -> Vec<CredentialRule> {
    from_file(src, filename, |v| {
        let rules: Vec<CredentialRule> = v
            .get("credentials")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect())
            .unwrap_or_default();
        if !rules.is_empty() {
            return rules;
        }
        v.get("paths")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(|s| CredentialRule {
                        pattern: s.to_string(),
                        allowed_executables: Vec::new(),
                        max_reads: None,
                    }))
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Executables of every `services` entry marked `allow_socket_dup2`, from any `.json` file in
/// the rules root.
fn load_dup2_allowed_from_vandam_configs(src: &Source) -> Vec<String> {
    let mut allowed = Vec::new();
    for name in src.json_files_in("") {
        let Some(v) = src.json(&name) else { continue };
        for service in v.get("services").and_then(|a| a.as_array()).into_iter().flatten() {
            if !service.get("allow_socket_dup2").and_then(|b| b.as_bool()).unwrap_or(false) {
                continue;
            }
            for ex in service.get("executables").and_then(|e| e.as_array()).into_iter().flatten() {
                if let Some(ex_str) = ex.as_str() {
                    if !allowed.iter().any(|a| a == ex_str) {
                        allowed.push(ex_str.to_string());
                    }
                }
            }
        }
    }
    allowed
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    BrowserDb       = 0x01,
    Keyring         = 0x02,
    Wallet          = 0x04,
    AppData         = 0x08,
    SshKeys         = 0x10,
    UserKeystores   = 0x20,
    AiAgents        = 0x40,
    // Server-specific categories (vandam)
    WebProcess      = 0x80,
    SystemUpdate    = 0x100,
    PersistencePath = 0x200,
    ProtectedBinary = 0x400,
}

/// Signature entry for a known offensive-security/attacker tool. Loaded from
/// `linux_attacker_tools_signatures.json` in the protect-community config
/// dir. Per that file's own description, a match on any process context
/// triggers an alert — severity and block behaviour are config-driven, not
/// hardcoded per tool.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AttackerToolSignature {
    pub tool_type:       String,
    pub executables:     Vec<String>,
    #[serde(default)]
    pub binary_strings:  Vec<String>,
    #[serde(default)]
    pub cmdline_tokens:  Vec<String>,
    #[serde(default)]
    pub fd_signatures:   Vec<String>,
    pub severity:        String,
    #[serde(default)]
    pub block_execution: bool,
}

/// One read-only diagnostic command `vandam`'s deep-audit agentic loop
/// (cloud-requested `audit_exec_command`) is allowed to run on the agent's
/// behalf. Loaded from `audit_agentic_commands.json` in the protect-community
/// config dir — deliberately config-driven rather than hardcoded in
/// `vandam`, per this workspace's "never hardcode match/allow lists"
/// rule, since this is exactly the kind of list that must stay auditable and
/// updatable without a binary rebuild. `args` uses a single `"{target}"`
/// placeholder (substituted with the one caller-supplied argument, never
/// concatenated/interpreted as shell) rather than letting a caller supply an
/// arbitrary argv — see `vandam/src/audit/cloud_transport.rs`'s exec
/// handler for how this is enforced.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditAgenticCommand {
    /// Stable identifier the cloud references in an `audit_exec_command`
    /// request — not necessarily the same as `binary`'s basename.
    pub name: String,
    /// Absolute path only — resolved as-is via `std::process::Command`,
    /// never through `$PATH` and never through a shell.
    pub binary: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// Signature entry for classifying a PTY/interactive-session's origin (how the
/// session was reached) by matching a process basename found while walking up
/// a shell's ancestry. Loaded from `linux_pty_origin_signatures.json` in the
/// protect-community config dir — used by vandam's Access page session
/// tracking, not hardcoded, so new container runtimes/login paths can be
/// added without a rebuild.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PtyOriginSignature {
    /// Ancestor executable basename to match, e.g. "sshd", "sudo", "conmon".
    pub origin_process: String,
    /// Label surfaced on the Access page, e.g. "SSH", "sudo -i", "docker exec".
    pub pty_type: String,
    /// True when this origin implies the session runs inside a container
    /// (container name is then resolved separately via cgroup lookup).
    #[serde(default)]
    pub container_scope: bool,
    #[serde(default)]
    pub orchestrator: Option<String>,
}

/// One package-manager (language or OS-distro) tracked by vandam's Supply
/// Chain pipeline. Loaded from `package_manager_signatures.json` in the
/// protect-community config dir — see that file's own `description` field for
/// the full scope/project-vs-system semantics.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PackageManagerSignature {
    pub executable: String,
    /// "project" (resolves against a manifest file, e.g. npm/pip/composer) or
    /// "system" (OS distro manager, always system-wide).
    pub scope: String,
    /// OSV.dev ecosystem name, or `null` when OSV doesn't cover this manager
    /// (e.g. pacman/Arch) — still tracked behaviorally, just never resolves
    /// real CVEs via `lookup_vulnerable_package` or vandam's OSV lookup.
    pub ecosystem: Option<String>,
    pub install_subcommands: Vec<String>,
    pub manifest_file: Option<String>,
    pub lockfile: Option<String>,
    /// Flags that force a "project" manager's install to system-wide (e.g.
    /// npm's `-g`), so a global install off a manifest-having project isn't
    /// mis-attributed to that project's path.
    #[serde(default)]
    pub global_flags: Vec<String>,
}

/// Vandam's exec-time process-tree classification lists (`kinnector.bpf.c`'s
/// `bprm_creds_for_exec` and helpers). Loaded from `exec_control_lists.json`
/// in the protect-community config dir — replaces what used to be hardcoded
/// arrays in `vandam/src/lib.rs` (`admin_bins`) and
/// `core/src/linux/ebpf_loader.cpp` (`PopulateExeNameClasses`'s `kEntries`).
/// See that JSON file's own `description` field for the full semantics of
/// each list.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ExecControlLists {
    #[serde(default)]
    pub trusted_admin_binaries: Vec<TrustedAdminBinary>,
    #[serde(default)]
    pub admin_allowed_commands: Vec<String>,
    #[serde(default)]
    pub dangerous_tools: Vec<String>,
    #[serde(default)]
    pub priv_esc_binaries: Vec<String>,
    #[serde(default)]
    pub untrusted_library_directories: Vec<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct TrustedAdminBinary {
    pub executable: String,
    #[serde(default)]
    pub note: String,
}

fn load_exec_control_lists(src: &Source) -> ExecControlLists {
    src.json("exec_control_lists.json")
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

fn load_package_manager_signatures(src: &Source) -> Vec<PackageManagerSignature> {
    from_file(src, "package_manager_signatures.json", |v| {
        v.get("managers")
            .and_then(|a| a.as_array())
            .map(|arr| arr.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect())
            .unwrap_or_default()
    })
}

/// One `rules/policies/*.json` file: what the FlatBuffers `rules.db` used to be compiled from.
#[derive(serde::Deserialize, Default)]
struct PolicyFile {
    #[serde(default)]
    exclusions: Vec<String>,
    #[serde(default)]
    trusted_clis: Vec<PolicyPath>,
    #[serde(default)]
    sensitive_files: Vec<PolicyPath>,
    #[serde(default)]
    allowed_cdns: Vec<String>,
}

#[derive(serde::Deserialize)]
struct PolicyPath {
    path: String,
    category: Option<PolicyFlags>,
    flags: Option<PolicyFlags>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PolicyFlags {
    Number(u32),
    Single(String),
    List(Vec<String>),
}

impl PolicyPath {
    /// `category`, else `flags`, as the category bit set (the old compiler's `resolve_flags`).
    fn category_flags(&self) -> u32 {
        let one = |s: &str| match s.to_lowercase().as_str() {
            "browserdb" | "browser" | "browser_db" => 0x01,
            "wallet" | "crypto_wallet" | "crypto" => 0x04,
            "appdata" | "app_data" | "app" => 0x08,
            "sshkeys" | "ssh_keys" | "ssh" => 0x10,
            "userkeystores" | "user_keystores" | "keystores" | "keystore" => 0x20,
            "aiagents" | "ai_agents" | "agents" | "agent" => 0x40,
            "webprocess" | "web_process" | "web" => 0x80,
            "systemupdate" | "system_update" | "update" => 0x100,
            "persistencepath" | "persistence_path" | "persistence" => 0x200,
            "protectedbinary" | "protected_binary" | "protected" => 0x400,
            _ => 0,
        };
        match self.category.as_ref().or(self.flags.as_ref()) {
            Some(PolicyFlags::Number(n)) => *n,
            Some(PolicyFlags::Single(s)) => one(s),
            Some(PolicyFlags::List(l)) => l.iter().fold(0, |acc, s| acc | one(s)),
            None => 0,
        }
    }
}

/// Every policy file merged, in name order.
fn load_policies(src: &Source) -> PolicyFile {
    let mut all = PolicyFile::default();
    for name in src.json_files_in("policies") {
        let Some(p) = src.json(&name).and_then(|v| serde_json::from_value::<PolicyFile>(v).ok()) else { continue };
        all.exclusions.extend(p.exclusions);
        all.trusted_clis.extend(p.trusted_clis);
        all.sensitive_files.extend(p.sensitive_files);
        all.allowed_cdns.extend(p.allowed_cdns);
    }
    all
}

/// Signature entry for a standalone database server process.
/// Loaded from `linux_database_signatures.json` in the protect-community config dir.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DbSignature {
    pub db_type:        String,
    /// Executable basenames to match against /proc/<pid>/exe (e.g. "postgres", "java")
    pub executables:    Vec<String>,
    /// Default well-known ports for this database (used as fallback classifier)
    pub default_ports:  Vec<u16>,
    /// Filenames to look for in /proc/<pid>/fd/ symlink targets (Method A)
    pub fd_signatures:  Vec<String>,
    /// Substrings to match in /proc/<pid>/cmdline (Method B; primary for JVM databases)
    pub cmdline_tokens: Vec<String>,
    /// Strings to scan in the first 100KB of the binary via /proc/<pid>/exe (Method C)
    pub binary_strings: Vec<String>,
    /// Where to find the config file: cmdline arg flag and/or default filesystem paths.
    #[serde(default)]
    pub config_location: Option<DbConfigLocation>,
    /// Regex rules to extract data_dir / write_path / outbound_ip from the config file.
    #[serde(default)]
    pub config_rules:   Vec<DbConfigRule>,
}

/// Describes how to locate the config file for a database service.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DbConfigLocation {
    /// The cmdline flag whose value is the config file path, e.g. "--config", "-f", "-c".
    /// If the flag uses `=` form ("--config=/path") or next-arg form ("--config /path")
    /// both are tried. Set to null/None when config is not passed via cmdline.
    pub cmdline_arg: Option<String>,
    /// Alternative cmdline flag for config (e.g. "-f" in addition to "--config").
    pub alt_cmdline_arg: Option<String>,
    /// Cmdline flag whose value is the data directory; the config file is sought inside it.
    /// Used by databases that pass data dir (not config path) on cmdline, e.g. postgres `-D`.
    pub datadir_from_cmdline: Option<String>,
    /// Positional argument index (1-based) used when the config path is a bare positional arg.
    /// E.g. `redis-server /etc/redis/redis.conf` → positional_arg = 1.
    pub positional_arg: Option<usize>,
    /// Well-known default filesystem paths to try when cmdline yields nothing.
    #[serde(default)]
    pub default_paths: Vec<String>,
}

/// A single config-file extraction rule: apply `regex` to the file content;
/// capture group 1 is the extracted path value.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DbConfigRule {
    /// Semantic role of the extracted path.
    pub role:  String,
    /// Regex with exactly one capture group containing the path value.
    pub regex: String,
    /// Optional: restrict matching to lines that follow a `[section]` header.
    pub section: Option<String>,
    /// Optional: JSON pointer path for JSON/YAML configs (not used in regex mode).
    pub json_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub signer_name: String,
    pub team_id: Option<String>,
    pub is_signed: bool,
}

struct ConfigState {
    version: u32,
    epoch_timestamp: u64,
    exclusions: Vec<String>,
    trusted_signers: HashSet<(String, Option<String>)>,
    trusted_clis: HashMap<String, u32>,
    network_cdns: Vec<String>,
    sensitive_files: HashMap<String, u32>,
    web_processes:       Vec<String>,
    persistence_paths:   Vec<String>,
    protected_binaries:  Vec<String>,
    terminal_rce_patterns: Vec<String>,
    installer_binaries:  Vec<String>,
    shell_profile_paths: Vec<String>,
    sensitive_credentials: Vec<CredentialRule>,
    script_interpreters: Vec<String>,
    interactive_shells:  Vec<String>,
    browser_executables: Vec<String>,
    hvnc_monitored_gui_apps: Vec<String>,
    system_package_paths: Vec<String>,
    window_managers: Vec<String>,
    protected_application_directories: HashMap<String, String>,
    signature_names: HashMap<String, String>,
    dup2_allowed_binaries: Vec<String>,
    geoip_country_ranges: HashMap<String, CountryRanges>,
    known_vulnerable_packages: Vec<KnownVulnerablePackage>,
    // Database, PTY-origin, attacker-tool and agentic-command tables are not held here: their
    // accessors read them from the source on each call.
}

/// Builds the whole state from one source: the JSON lists, the signature tables and the
/// policies (what the FlatBuffers `rules.db` used to carry, merged the way it was).
fn build_state(src: &Source) -> ConfigState {
    let prefix = if cfg!(unix) { "linux" } else { "windows" };
    let policies = load_policies(src);

    let mut network_cdns = load_list_from_json(src, "network_cdns.json", "cdns");
    for cdn in &policies.allowed_cdns {
        if !network_cdns.contains(cdn) {
            network_cdns.push(cdn.clone());
        }
    }

    let mut web_processes = load_list_from_json(src, &format!("{}_web_processes.json", prefix), "processes");
    let mut persistence_paths = load_list_from_json(src, &format!("{}_persistence_paths.json", prefix), "paths");
    let mut protected_binaries = load_list_from_json(src, &format!("{}_protected_binaries.json", prefix), "binaries");

    let mut trusted_clis = HashMap::new();
    for cli in &policies.trusted_clis {
        let flags = cli.category_flags();
        trusted_clis.insert(cli.path.clone(), flags);
        // WebProcess = 0x80
        if flags & 0x80 != 0 && !web_processes.contains(&cli.path) {
            web_processes.push(cli.path.clone());
        }
        // ProtectedBinary = 0x400
        if flags & 0x400 != 0 && !protected_binaries.contains(&cli.path) {
            protected_binaries.push(cli.path.clone());
        }
    }
    let mut sensitive_files = HashMap::new();
    for file in &policies.sensitive_files {
        let flags = file.category_flags();
        sensitive_files.insert(file.path.clone(), flags);
        // PersistencePath = 0x200
        if flags & 0x200 != 0 && !persistence_paths.contains(&file.path) {
            persistence_paths.push(file.path.clone());
        }
    }

    let mut dup2_allowed_binaries = load_list_from_json(src, &format!("{}_dup2_allowed_binaries.json", prefix), "binaries");
    for extra in load_dup2_allowed_from_vandam_configs(src) {
        if !dup2_allowed_binaries.contains(&extra) {
            dup2_allowed_binaries.push(extra);
        }
    }

    ConfigState {
        version: 0,
        epoch_timestamp: 0,
        exclusions: policies.exclusions,
        trusted_signers: HashSet::new(),
        trusted_clis,
        network_cdns,
        sensitive_files,
        web_processes,
        persistence_paths,
        protected_binaries,
        terminal_rce_patterns: if cfg!(unix) {
            load_list_from_json(src, "linux_terminal_rce_patterns.json", "patterns")
        } else {
            Vec::new()
        },
        installer_binaries: load_list_from_json(src, &format!("{}_installer_binaries.json", prefix), "binaries"),
        shell_profile_paths: load_list_from_json(src, &format!("{}_shell_profile_paths.json", prefix), "paths"),
        sensitive_credentials: load_credentials_from_json(src, &format!("{}_sensitive_credential_paths.json", prefix)),
        script_interpreters: load_list_from_json(src, &format!("{}_script_interpreters.json", prefix), "interpreters"),
        interactive_shells: load_list_from_json(src, &format!("{}_interactive_shells.json", prefix), "shells"),
        browser_executables: load_list_from_json(src, &format!("{}_browser_executables.json", prefix), "browsers"),
        hvnc_monitored_gui_apps: load_list_from_json(src, &format!("{}_hvnc_monitored_gui_apps.json", prefix), "apps"),
        system_package_paths: load_list_from_json(src, &format!("{}_system_package_paths.json", prefix), "paths"),
        window_managers: load_list_from_json(src, &format!("{}_window_managers.json", prefix), "managers"),
        protected_application_directories: load_map_from_json(src, &format!("{}_protected_application_directories.json", prefix), "directories"),
        signature_names: load_signatures_from_vandam_configs(src),
        dup2_allowed_binaries,
        geoip_country_ranges: load_geoip_country_ranges(src),
        known_vulnerable_packages: load_known_vulnerable_packages(src),
    }
}

pub struct ConfigManager {
    state: Arc<RwLock<ConfigState>>,
}

impl ConfigManager {
    /// The rules from the current source (`source::current()`).
    pub fn load_defaults() -> Self {
        ConfigManager { state: Arc::new(RwLock::new(build_state(&source::current()))) }
    }

    /// Re-reads the current source and swaps the whole state at once.
    pub fn reload(&self) -> Result<(), Box<dyn std::error::Error>> {
        let state = build_state(&source::current());
        *self.state.write().unwrap() = state;
        Ok(())
    }

    /// Makes a rules bundle (`source::parse_bundle`) the source, held in memory, and reloads.
    pub fn reload_from_bytes(&self, bundle: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        source::set(source::parse_bundle(bundle)?);
        self.reload()
    }

    pub fn dup2_allowed_binaries(&self) -> Vec<String> {
        self.state.read().unwrap().dup2_allowed_binaries.clone()
    }

    /// Load package-manager signatures used to classify install activity for
    /// vandam's Supply Chain pipeline. Not cached in `ConfigState` (mirrors
    /// `db_signatures()`/`pty_origin_signatures()` — small file, read fresh
    /// per call rather than requiring a `reload()` round-trip to pick up
    /// edits during development).
    pub fn package_manager_signatures(&self) -> Vec<PackageManagerSignature> {
        load_package_manager_signatures(&source::current())
    }

    /// Vandam's exec-time process-tree classification lists (trusted-admin
    /// binaries, the admin-tree command allowlist, dangerous tools, priv-esc
    /// binaries). Not cached, same rationale as `package_manager_signatures()`.
    pub fn exec_control_lists(&self) -> ExecControlLists {
        load_exec_control_lists(&source::current())
    }

    /// Offline-seeded known-vulnerable-package list (free-tier Supply Chain
    /// fallback; vandam's subscriber OSV.dev lookup supersedes this when
    /// available). Cached in `ConfigState`, refreshed on `reload()`.
    pub fn known_vulnerable_packages(&self) -> Vec<KnownVulnerablePackage> {
        self.state.read().unwrap().known_vulnerable_packages.clone()
    }

    /// Matches an (ecosystem, package name, installed version) triple against
    /// the offline `known_vulnerable_packages()` list. `version` is compared
    /// against each candidate's `vulnerable_ranges` using simple `<`/`<=`/`=`
    /// prefix semantics (dotted-numeric segment comparison, not full semver
    /// pre-release/build-metadata parsing — sufficient for this file's
    /// "<fixed_version" seed data) plus a literal `"*"` always-matches entry
    /// for advisories with no known fixed version. Ecosystem/name match is
    /// case-insensitive (package registries are inconsistent about casing).
    pub fn lookup_vulnerable_package(&self, ecosystem: &str, name: &str, version: &str) -> Option<KnownVulnerablePackage> {
        self.known_vulnerable_packages().into_iter().find(|pkg| {
            pkg.ecosystem.eq_ignore_ascii_case(ecosystem)
                && pkg.name.eq_ignore_ascii_case(name)
                && pkg.vulnerable_ranges.iter().any(|range| version_in_range(version, range))
        })
    }

    /// Resolves a GeoIP country code (case-insensitive ISO 3166-1 alpha-2,
    /// e.g. "us"/"US") to its CIDR ranges. Used by vandamd's firewall
    /// reconcile pass to expand a `FirewallTarget::Country` rule into
    /// concrete CIDRs — see `vandam/src/firewall/reconcile.rs`.
    pub fn lookup_country_ranges(&self, country_code: &str) -> Option<CountryRanges> {
        self.state.read().unwrap().geoip_country_ranges.get(&country_code.to_uppercase()).cloned()
    }

    /// (ISO code, display name) for every country with GeoIP data loaded —
    /// feeds vandam's TUI country picker so it never hardcodes a country
    /// list (per this workspace's "no hardcoded match lists" rule).
    pub fn list_countries(&self) -> Vec<(String, String)> {
        let state = self.state.read().unwrap();
        let mut list: Vec<(String, String)> = state.geoip_country_ranges
            .iter()
            .map(|(code, ranges)| (code.clone(), ranges.name.clone()))
            .collect();
        list.sort_by(|a, b| a.1.cmp(&b.1));
        list
    }

    pub fn is_dup2_allowed_executable(&self, exe: &str) -> bool {
        let state = self.state.read().unwrap();
        if exe.is_empty() {
            return false;
        }
        let exe_lower = exe.to_lowercase();
        let basename = std::path::Path::new(&exe_lower)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| exe_lower.clone());

        state.dup2_allowed_binaries.iter().any(|allowed| {
            let allowed_lower = allowed.to_lowercase();
            basename == allowed_lower
                || exe_lower == allowed_lower
                || exe_lower.ends_with(&format!("/{}", allowed_lower))
        })
    }

    pub fn version(&self) -> u32 {
        self.state.read().unwrap().version
    }

    pub fn epoch_timestamp(&self) -> u64 {
        self.state.read().unwrap().epoch_timestamp
    }

    pub fn is_path_excluded(&self, path: &Path) -> bool {
        let state = self.state.read().unwrap();
        let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
        for prefix in &state.exclusions {
            let prefix_normalized = prefix.to_lowercase().replace('\\', "/");
            if path_str.starts_with(&prefix_normalized) {
                return true;
            }
        }
        false
    }

    pub fn is_trusted_vendor(&self, signer: &SignerInfo) -> bool {
        if !signer.is_signed {
            return false;
        }
        let state = self.state.read().unwrap();
        state.trusted_signers.contains(&(signer.signer_name.clone(), signer.team_id.clone()))
    }

    pub fn is_trusted_cli(&self, path: &Path, category: Category) -> bool {
        let state = self.state.read().unwrap();
        let path_str = path.to_string_lossy().to_lowercase().replace('\\', "/");
        if let Some(flags) = state.trusted_clis.get(&path_str) {
            let cat_flag = category as u32;
            return (flags & cat_flag) != 0;
        }
        false
    }

    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        let state = self.state.read().unwrap();
        for suffix in &state.network_cdns {
            if suffix.starts_with("*.") {
                let base = &suffix[2..];
                if domain == base || domain.ends_with(&format!(".{}", base)) {
                    return true;
                }
            } else if domain == suffix {
                return true;
            }
        }
        false
    }

    pub fn sensitive_files(&self) -> HashMap<String, u32> {
        let state = self.state.read().unwrap();
        state.sensitive_files.clone()
    }

    pub fn is_web_process(&self, exe: &str) -> bool {
        let state = self.state.read().unwrap();
        let exe_lower = exe.to_lowercase();
        state.web_processes.iter().any(|w| exe_lower.contains(w.as_str()))
    }

    pub fn web_processes(&self) -> Vec<String> {
        self.state.read().unwrap().web_processes.clone()
    }

    pub fn is_persistence_path(&self, path: &str) -> bool {
        let state = self.state.read().unwrap();
        let path_normalized = path.to_lowercase().replace('\\', "/");
        state.persistence_paths.iter().any(|p| {
            let p_normalized = p.to_lowercase().replace('\\', "/");
            path_normalized.starts_with(&p_normalized)
        })
    }

    pub fn persistence_paths(&self) -> Vec<String> {
        self.state.read().unwrap().persistence_paths.clone()
    }

    pub fn is_protected_binary(&self, path: &str) -> bool {
        let state = self.state.read().unwrap();
        let path_normalized = path.to_lowercase().replace('\\', "/");
        state.protected_binaries.iter().any(|b| {
            let b_normalized = b.to_lowercase().replace('\\', "/");
            path_normalized == b_normalized || path_normalized.ends_with(&format!("/{}", b_normalized))
        })
    }

    pub fn protected_binaries(&self) -> Vec<String> {
        self.state.read().unwrap().protected_binaries.clone()
    }

    pub fn terminal_rce_patterns(&self) -> Vec<String> {
        self.state.read().unwrap().terminal_rce_patterns.clone()
    }

    pub fn installer_binaries(&self) -> Vec<String> {
        self.state.read().unwrap().installer_binaries.clone()
    }

    pub fn shell_profile_paths(&self) -> Vec<String> {
        self.state.read().unwrap().shell_profile_paths.clone()
    }

    pub fn sensitive_credential_paths(&self) -> Vec<String> {
        self.state.read().unwrap().sensitive_credentials.iter().map(|c| c.pattern.clone()).collect()
    }

    pub fn sensitive_credentials(&self) -> Vec<CredentialRule> {
        self.state.read().unwrap().sensitive_credentials.clone()
    }

    pub fn script_interpreters(&self) -> Vec<String> {
        self.state.read().unwrap().script_interpreters.clone()
    }

    pub fn interactive_shells(&self) -> Vec<String> {
        self.state.read().unwrap().interactive_shells.clone()
    }

    pub fn browser_executables(&self) -> Vec<String> {
        self.state.read().unwrap().browser_executables.clone()
    }

    pub fn hvnc_monitored_gui_apps(&self) -> Vec<String> {
        self.state.read().unwrap().hvnc_monitored_gui_apps.clone()
    }

    pub fn system_package_paths(&self) -> Vec<String> {
        self.state.read().unwrap().system_package_paths.clone()
    }

    pub fn window_managers(&self) -> Vec<String> {
        self.state.read().unwrap().window_managers.clone()
    }

    pub fn protected_application_directories(&self) -> HashMap<String, String> {
        self.state.read().unwrap().protected_application_directories.clone()
    }

    pub fn lookup_signature(&self, exe: &str) -> Option<String> {
        let basename = std::path::Path::new(exe)
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        self.state.read().unwrap().signature_names.get(&basename).cloned()
    }

    /// Load database server signatures from protect-community config.
    /// Called at startup and on DB ProcessStop events (for inode refresh).
    /// Returns an empty Vec if the config file is missing (graceful degradation).
    #[cfg(unix)]
    pub fn db_signatures(&self) -> Vec<DbSignature> {
        table_entries(&source::current(), "linux_database_signatures.json", "databases")
    }

    /// Load PTY-origin classification signatures from
    /// `linux_pty_origin_signatures.json` (protect-community config dir).
    /// Returns an empty Vec if the file is missing (graceful degradation) —
    /// callers should treat that as "unable to classify", not an error.
    pub fn pty_origin_signatures(&self) -> Vec<PtyOriginSignature> {
        table_entries(&source::current(), "linux_pty_origin_signatures.json", "origins")
    }

    /// Load known offensive-security/attacker-tool signatures from
    /// `linux_attacker_tools_signatures.json` (protect-community config dir).
    /// Returns an empty Vec if the file is missing (graceful degradation).
    pub fn attacker_tool_signatures(&self) -> Vec<AttackerToolSignature> {
        table_entries(&source::current(), "linux_attacker_tools_signatures.json", "tools")
    }

    /// Match an executable basename/cmdline against the attacker-tool
    /// signature table (executables + cmdline_tokens only — `binary_strings`/
    /// `fd_signatures` need a live PID's `/proc` entry, so those are left to
    /// a fuller scan if a caller wants that depth; the exec-time hot path in
    /// `heuristics.rs` only has the exe path and cmdline available).
    pub fn lookup_attacker_tool(&self, exe: &str, cmdline: &str) -> Option<AttackerToolSignature> {
        let exe_basename = std::path::Path::new(exe)
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let cmdline_lower = cmdline.to_lowercase();
        self.attacker_tool_signatures().into_iter().find(|sig| {
            sig.executables.iter().any(|e| exe_basename == e.to_lowercase())
                || sig.cmdline_tokens.iter().any(|t| cmdline_lower.contains(&t.to_lowercase()))
        })
    }

    /// Load the deep-audit agentic exec allowlist from `audit_agentic_commands.json`. Returns an
    /// empty Vec if missing — callers must treat that as "nothing is allowed," not "allow
    /// everything," since this is a security allowlist.
    pub fn audit_agentic_commands(&self) -> Vec<AuditAgenticCommand> {
        table_entries(&source::current(), "audit_agentic_commands.json", "commands")
    }

    /// Looks up an allowlisted command by `name` — the only lookup
    /// `cloud_transport.rs`'s exec handler needs, kept here so the allowlist
    /// itself (not just its loading) lives with the rest of this
    /// workspace's config-driven signature/match-list accessors.
    pub fn lookup_audit_agentic_command(&self, name: &str) -> Option<AuditAgenticCommand> {
        self.audit_agentic_commands().into_iter().find(|c| c.name == name)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_from(src: &Source) -> ConfigManager {
        ConfigManager { state: Arc::new(RwLock::new(build_state(src))) }
    }

    #[test]
    fn version_in_range_less_than() {
        assert!(version_in_range("4.17.11", "<4.17.12"));
        assert!(!version_in_range("4.17.12", "<4.17.12"));
        assert!(!version_in_range("4.18.0", "<4.17.12"));
    }

    #[test]
    fn version_in_range_compound_and_semantics() {
        // Django-style range: >=3.2,<3.2.13 — only versions inside the
        // 3.2.x branch below the fix should match.
        assert!(version_in_range("3.2.5", ">=3.2,<3.2.13"));
        assert!(!version_in_range("3.2.13", ">=3.2,<3.2.13"));
        assert!(!version_in_range("3.1.9", ">=3.2,<3.2.13"));
    }

    #[test]
    fn version_in_range_wildcard_always_matches() {
        assert!(version_in_range("0.0.1", "*"));
        assert!(version_in_range("999.0.0", "*"));
    }

    #[test]
    fn version_in_range_degrades_gracefully_on_odd_debian_versions() {
        // Debian-style version strings aren't pure dotted-numeric, but the
        // comparison must never panic — non-numeric segments compare as 0.
        assert!(!version_in_range("999.999.999", "<5.6.1+really5.4.5-1"));
    }

    #[test]
    fn lookup_vulnerable_package_is_case_insensitive_on_ecosystem_and_name() {
        let mgr = ConfigManager {
            state: Arc::new(RwLock::new(ConfigState {
                version: 0,
                epoch_timestamp: 0,
                exclusions: Vec::new(),
                trusted_signers: HashSet::new(),
                trusted_clis: HashMap::new(),
                network_cdns: Vec::new(),
                sensitive_files: HashMap::new(),
                web_processes: Vec::new(),
                persistence_paths: Vec::new(),
                protected_binaries: Vec::new(),
                terminal_rce_patterns: Vec::new(),
                installer_binaries: Vec::new(),
                shell_profile_paths: Vec::new(),
                sensitive_credentials: Vec::new(),
                script_interpreters: Vec::new(),
                interactive_shells: Vec::new(),
                browser_executables: Vec::new(),
                hvnc_monitored_gui_apps: Vec::new(),
                system_package_paths: Vec::new(),
                window_managers: Vec::new(),
                protected_application_directories: HashMap::new(),
                signature_names: HashMap::new(),
                dup2_allowed_binaries: Vec::new(),
                geoip_country_ranges: HashMap::new(),
                known_vulnerable_packages: vec![KnownVulnerablePackage {
                    ecosystem: "npm".to_string(),
                    name: "lodash".to_string(),
                    vulnerable_ranges: vec!["<4.17.12".to_string()],
                    cve_id: "CVE-2019-10744".to_string(),
                    severity: "CRITICAL".to_string(),
                    summary: "Prototype pollution".to_string(),
                }],
            })),
        };
        assert!(mgr.lookup_vulnerable_package("NPM", "Lodash", "4.17.11").is_some());
        assert!(mgr.lookup_vulnerable_package("npm", "lodash", "4.17.12").is_none());
        assert!(mgr.lookup_vulnerable_package("PyPI", "lodash", "4.17.11").is_none());
    }

    #[test]
    fn policies_feed_what_the_rules_db_used_to() {
        let bundle = br#"{"files": {
            "policies/a.json": {"version": 1,
                "exclusions": ["/tmp/exclude"],
                "trusted_clis": [{"path": "/usr/bin/webd", "category": ["web", "protected"]}],
                "sensitive_files": [{"path": "/etc/cron.d/x", "flags": "persistence"}, {"path": "/root/.ssh/id_rsa", "category": "ssh"}],
                "allowed_cdns": ["cdn.example"]},
            "network_cdns.json": {"cdns": ["other.example"]}
        }}"#;
        let manager = manager_from(&source::parse_bundle(bundle).unwrap());
        assert!(manager.is_path_excluded(Path::new("/tmp/exclude/some_subpath")));
        assert!(manager.is_web_process("/usr/bin/webd"));
        assert!(manager.is_protected_binary("/usr/bin/webd"));
        assert!(manager.is_persistence_path("/etc/cron.d/x"));
        assert_eq!(manager.sensitive_files().get("/root/.ssh/id_rsa"), Some(&0x10));
        assert!(manager.is_domain_allowed("cdn.example"));
        assert!(manager.is_domain_allowed("other.example"));
    }

    #[test]
    fn the_repo_rules_load() {
        let manager = manager_from(&Source::Dir(std::path::PathBuf::from(source::REPO_RULES)));
        // dup2 allowed binaries, from the service tables' allow_socket_dup2
        assert!(manager.is_dup2_allowed_executable("kubectl"));
        assert!(manager.is_dup2_allowed_executable("/usr/sbin/sshd"));
        assert!(manager.is_dup2_allowed_executable("ttyd"));
        assert!(manager.is_dup2_allowed_executable("gotty"));
        assert!(!manager.is_dup2_allowed_executable("netcat"));
        // the policies' sensitive files reach the kernel registration list
        assert!(!manager.sensitive_files().is_empty());
    }

    #[test]
    fn the_database_pty_and_attacker_tool_tables_load() {
        // These three were read from protect-community's root config folder, where the files
        // never were (they lived in its vandam/ subfolder), so they always loaded empty.
        let src = Source::Dir(std::path::PathBuf::from(source::REPO_RULES));
        set_for_test(src);
        let manager = ConfigManager::load_defaults();
        assert!(!manager.db_signatures().is_empty());
        assert!(!manager.pty_origin_signatures().is_empty());
        assert!(!manager.attacker_tool_signatures().is_empty());
    }

    /// Sets the global source to the repo folder (every test that touches it sets the same one).
    fn set_for_test(src: Source) {
        source::set(src);
    }

    #[test]
    fn test_geoip_country_ranges_loading() {
        let tmp = std::env::temp_dir().join(format!("vandam_geoip_test_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(
            tmp.join("geoip_country_ranges.json"),
            r#"{
                "generated_at": "2026-01-01T00:00:00Z",
                "source": "test fixture",
                "countries": {
                    "US": { "name": "United States", "cidrs_v4": ["3.0.0.0/15"], "cidrs_v6": [] },
                    "de": { "name": "Germany", "cidrs_v4": ["85.0.0.0/8"], "cidrs_v6": ["2a01::/16"] }
                }
            }"#,
        ).unwrap();

        let map = load_geoip_country_ranges(&Source::Dir(tmp.clone()));
        assert_eq!(map.len(), 2);

        // Lowercase input keys in the source JSON are normalized to uppercase on load.
        let de = map.get("DE").expect("DE should be present under its uppercased code");
        assert_eq!(de.name, "Germany");
        assert_eq!(de.cidrs_v4, vec!["85.0.0.0/8".to_string()]);
        assert_eq!(de.cidrs_v6, vec!["2a01::/16".to_string()]);

        let us = map.get("US").expect("US should be present");
        assert_eq!(us.cidrs_v4, vec!["3.0.0.0/15".to_string()]);

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn test_lookup_country_ranges_is_case_insensitive() {
        let manager = ConfigManager::load_defaults();
        {
            let mut state = manager.state.write().unwrap();
            state.geoip_country_ranges.insert(
                "FR".to_string(),
                CountryRanges { name: "France".to_string(), cidrs_v4: vec!["1.2.3.0/24".to_string()], cidrs_v6: vec![] },
            );
        }
        assert!(manager.lookup_country_ranges("fr").is_some());
        assert!(manager.lookup_country_ranges("FR").is_some());
        assert_eq!(manager.lookup_country_ranges("fr").unwrap().name, "France");
        assert!(manager.lookup_country_ranges("zz").is_none());

        let countries = manager.list_countries();
        assert!(countries.iter().any(|(code, name)| code == "FR" && name == "France"));
    }
}
