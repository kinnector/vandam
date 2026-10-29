use std::path::{Path, PathBuf};
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use regex::Regex;
use crate::ffi;
use std::sync::OnceLock;

/// Global registry: PID → matched signature service_type name.
/// Populated by discover_and_enforce_services() for every matched process.
/// Consumed by detect_signature_name() in heuristics.rs.
static SIGNATURE_BY_PID: OnceLock<Arc<dashmap::DashMap<u32, Arc<str>>>> = OnceLock::new();

pub fn get_signature_registry() -> &'static Arc<dashmap::DashMap<u32, Arc<str>>> {
    SIGNATURE_BY_PID.get_or_init(|| Arc::new(dashmap::DashMap::new()))
}

/// Register that a PID matched a given signature name.
pub fn register_pid_signature(pid: u32, sig_name: &str) {
    get_signature_registry().insert(pid, Arc::from(sig_name));
}

/// Look up the signature name for a PID. Returns None if not a discovered service.
pub fn get_signature_for_pid(pid: u32) -> Option<Arc<str>> {
    get_signature_registry().get(&pid).map(|v| Arc::clone(v.value()))
}

/// Remove a PID from the registry (called on ProcessStop).
pub fn deregister_pid_signature(pid: u32) {
    get_signature_registry().remove(&pid);
}

// Profile & Role flags
pub const PROFILE_ZERO_EXECUTION: u32 = 0x10000000;
pub const PROFILE_RESTRICTED_EXEC: u32 = 0x20000000;
pub const PROFILE_ZERO_NETWORK: u32 = 0x80000000;
pub const PROFILE_PATH_CONSTRAINED: u32 = 0x01000000;

pub const ROLE_MAIL_GATEWAY: u32 = 0x02000000;
pub const ROLE_QUEUE_MANAGER: u32 = 0x04000000;
pub const ROLE_NTP_CLIENT: u32 = 0x08000000;
pub const ROLE_CONTROL_PANEL: u32 = 0x00080000;

// BPF Map Type IDs
const MAP_EXEC_ALLOWLIST: i32 = 13;
const MAP_INFRA_OUTBOUND_ALLOWLIST: i32 = 12;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigLocation {
    /// Primary cmdline flag whose value is the config file path (e.g. "--config", "-f").
    pub cmdline_arg: Option<String>,
    /// Alternative cmdline flag (e.g. "-c" alongside "--config").
    #[serde(default)]
    pub alt_cmdline_arg: Option<String>,
    /// Flag whose value is the *data directory*; config file is looked up inside it.
    #[serde(default)]
    pub datadir_from_cmdline: Option<String>,
    /// 1-based index of the positional argument that is the config path (e.g. redis-server <config>).
    #[serde(default)]
    pub positional_arg: Option<usize>,
    /// Default filesystem paths tried when cmdline yields nothing. Supports `*` glob patterns.
    #[serde(default)]
    pub default_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigRule {
    pub role: String,
    pub regex: String,
    #[serde(default)]
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericSignature {
    pub service_type: String,
    pub executables: Vec<String>,
    #[serde(default)]
    pub cmdline_tokens: Vec<String>,
    pub unix_sockets: Vec<String>,
    pub assigned_profile: String,
    #[serde(default)]
    pub allow_cwd: bool,
    pub config_location: ConfigLocation,
    pub config_rules: Vec<ConfigRule>,
    pub complexity_indicators: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub signature: GenericSignature,
    pub pid: u32,
    pub config_path: Option<PathBuf>,
}

/// One signature table's `services`, from the rules (`crate::rules::source`).
pub fn load_generic_signatures(filename: &str) -> Vec<GenericSignature> {
    crate::rules::source::current()
        .json(filename)
        .and_then(|val| val.get("services").and_then(|a| a.as_array()).cloned())
        .map(|arr| arr.into_iter().filter_map(|item| serde_json::from_value(item).ok()).collect())
        .unwrap_or_default()
}

fn is_container_process(pid: u32) -> bool {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
        for marker in &["docker", "containerd", "kubepods", "lxc", "podman"] {
            if content.contains(marker) {
                return true;
            }
        }
    }
    false
}

fn locate_config_file(pid: u32, loc: &ConfigLocation) -> Option<PathBuf> {
    let config_extensions = [".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".properties"];

    // Read cmdline once
    let args: Vec<String> = std::fs::read(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();

    let flags: Vec<&str> = [
        loc.cmdline_arg.as_deref(),
        loc.alt_cmdline_arg.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();

    // 1. Explicit flags: `--flag value` and `--flag=value`
    for (i, arg) in args.iter().enumerate() {
        for &flag in &flags {
            // `--flag=value` form
            let eq = format!("{}=", flag);
            if let Some(val) = arg.strip_prefix(&eq) {
                let p = PathBuf::from(val.trim());
                if p.exists() { return Some(p); }
            }
            // `--flag value` form
            if arg == flag {
                if let Some(next) = args.get(i + 1) {
                    let p = PathBuf::from(next.trim());
                    if p.exists() { return Some(p); }
                }
            }
        }
    }

    // 2. datadir_from_cmdline — flag gives a data dir, look for known config files inside
    if let Some(ref dd_flag) = loc.datadir_from_cmdline {
        for (i, arg) in args.iter().enumerate() {
            let eq = format!("{}=", dd_flag);
            let data_dir = if let Some(val) = arg.strip_prefix(&eq) {
                Some(PathBuf::from(val.trim()))
            } else if arg == dd_flag {
                args.get(i + 1).map(|v| PathBuf::from(v.trim()))
            } else {
                None
            };
            if let Some(dd) = data_dir {
                for name in &["postgresql.conf", "server.conf", "config.yml", "config.toml"] {
                    let candidate = dd.join(name);
                    if candidate.exists() { return Some(candidate); }
                }
            }
        }
    }

    // 3. positional_arg (1-based)
    if let Some(pos) = loc.positional_arg {
        if let Some(arg) = args.get(pos) {
            let p = PathBuf::from(arg.trim());
            if p.is_absolute() && !arg.starts_with('-') && p.exists() {
                return Some(p);
            }
        }
    }

    // 4. Bare positional: any arg that looks like a config file path
    if flags.is_empty() && loc.positional_arg.is_none() {
        for arg in args.iter().skip(1) {
            if !arg.starts_with('-') && config_extensions.iter().any(|ext| arg.ends_with(ext)) {
                let p = PathBuf::from(arg);
                if p.is_absolute() && p.exists() { return Some(p); }
            }
        }
    }

    // 5. Default filesystem paths (glob support)
    for path_str in &loc.default_paths {
        if path_str.contains('*') {
            if let Ok(entries) = glob::glob(path_str) {
                for entry in entries.flatten() {
                    if entry.exists() { return Some(entry); }
                }
            }
        } else {
            let p = PathBuf::from(path_str);
            if p.exists() { return Some(p); }
        }
    }

    None
}

fn enforce_service_policy(pid: u32, sig: &GenericSignature, config_path: Option<&Path>, role_flags: u32) {
    let mut flags = role_flags;

    match sig.assigned_profile.as_str() {
        "zero-execution" => flags |= PROFILE_ZERO_EXECUTION,
        "restricted-execution" => flags |= PROFILE_RESTRICTED_EXEC,
        "zero-network" => flags |= PROFILE_ZERO_NETWORK,
        "zero-network-ntp-client" => flags |= PROFILE_ZERO_NETWORK | ROLE_NTP_CLIENT,
        "path-constrained" => flags |= PROFILE_PATH_CONSTRAINED,
        _ => {}
    }

    crate::allowlist::set_pid_profile(pid, flags);

    let mut is_complex = false;
    let mut extracted_ips = Vec::new();
    let mut extracted_execs = Vec::new();

    if let Some(path) = config_path {
        let config_dir = path.parent().unwrap_or(Path::new("/"));
        if let Ok(content) = std::fs::read_to_string(path) {
            for indicator in &sig.complexity_indicators {
                if content.contains(indicator) {
                    is_complex = true;
                    break;
                }
            }

            for rule in &sig.config_rules {
                // Optional section-filter: only search within the named YAML/INI section
                let search_content: std::borrow::Cow<str> = if let Some(ref section) = rule.section {
                    let mut in_sect = false;
                    let mut buf = String::new();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !line.starts_with(' ') && !line.starts_with('\t') {
                            in_sect = trimmed.starts_with(section.as_str());
                        }
                        if trimmed == format!("[{}]", section) { in_sect = true; continue; }
                        if trimmed.starts_with('[') && trimmed.ends_with(']') { in_sect = false; }
                        if in_sect { buf.push_str(line); buf.push('\n'); }
                    }
                    std::borrow::Cow::Owned(buf)
                } else {
                    std::borrow::Cow::Borrowed(&content)
                };

                if let Ok(re) = Regex::new(&rule.regex) {
                    for cap in re.captures_iter(&*search_content) {
                        if let Some(m) = cap.get(1) {
                            let raw = m.as_str().trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                            if raw.is_empty() { continue; }
                            let match_str = raw.to_string();
                            match rule.role.as_str() {
                                "outbound_ip" => extracted_ips.push(match_str),
                                "exec_path"   => extracted_execs.push(match_str),
                                "write_path" | "data_dir" | "read_path" => {
                                    // Resolve relative paths against config dir
                                    let p = if raw.starts_with('/') {
                                        PathBuf::from(raw)
                                    } else {
                                        config_dir.join(raw)
                                    };
                                    let canonical = std::fs::canonicalize(&p).unwrap_or(p);
                                    crate::allowlist::register_signature_path(
                                        &sig.service_type,
                                        canonical,
                                    );
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    if is_complex {
        tracing::warn!(
            "[Vandam Policy] Complexity detected in service {} PID {}. Policy degraded to PARTIAL.",
            sig.service_type, pid
        );
        flags &= !PROFILE_ZERO_EXECUTION;
    }

    unsafe {
        ffi::update_process_threshold(pid, 0, flags);
    }

    for ip_str in extracted_ips {
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            let ip_u32 = u32::from_ne_bytes(ip.octets());
            unsafe {
                ffi::update_map_entry(MAP_INFRA_OUTBOUND_ALLOWLIST, pid, ip_u32 as u64, 1);
            }
        }
    }

    for exec_path in extracted_execs {
        if let Ok(meta) = std::fs::metadata(&exec_path) {
            use std::os::unix::fs::MetadataExt;
            let inode = meta.ino();
            unsafe {
                ffi::update_map_entry(MAP_EXEC_ALLOWLIST, 0, inode, 1);
            }
        }
    }
}

pub fn discover_and_enforce_services(
    signature_file: &str,
    role_flags: u32,
) -> Vec<DiscoveredService> {
    let signatures = load_generic_signatures(signature_file);
    let mut discovered = Vec::new();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return discovered;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<u32>() else { continue; };

        if is_container_process(pid) {
            continue;
        }

        let exe_path = entry.path().join("exe");
        let exe = match std::fs::read_link(&exe_path) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let exe_basename = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        for sig in &signatures {
            let matches_exe = sig.executables.iter().any(|e| {
                let el = e.to_lowercase();
                exe_basename == el
                    || (exe_basename.starts_with(&el)
                        && exe_basename
                            .as_bytes()
                            .get(el.len())
                            .map_or(false, |&c| c == b'-' || c == b'.' || c.is_ascii_digit()))
            });

            let mut matches_cmdline = false;
            if matches_exe && sig.cmdline_tokens.is_empty() {
                matches_cmdline = true;
            } else if matches_exe || matches!(
                exe_basename.as_str(),
                "java" | "python" | "python2" | "python3" | "node" | "nodejs"
                    | "ruby" | "php" | "php-fpm" | "php-cgi" | "perl" | "bun"
                    | "deno" | "dotnet" | "rr"
            ) || exe_basename.starts_with("python") || exe_basename.starts_with("php")
              || exe_basename.starts_with("ruby") || exe_basename.starts_with("perl")
            {
                let cmdline_path = format!("/proc/{}/cmdline", pid);
                if let Ok(bytes) = std::fs::read(&cmdline_path) {
                    let cmdline_str = String::from_utf8_lossy(&bytes).to_lowercase();
                    if !sig.cmdline_tokens.is_empty() {
                        for token in &sig.cmdline_tokens {
                            if cmdline_str.contains(&token.to_lowercase()) {
                                matches_cmdline = true;
                                break;
                            }
                        }
                    } else if !matches_exe {
                        for e in &sig.executables {
                            if cmdline_str.contains(&e.to_lowercase()) {
                                matches_cmdline = true;
                                break;
                            }
                        }
                    } else {
                        matches_cmdline = true;
                    }
                } else if matches_exe && sig.cmdline_tokens.is_empty() {
                    matches_cmdline = true;
                }
            }

            if matches_cmdline {
                let config_path = locate_config_file(pid, &sig.config_location);
                enforce_service_policy(pid, &sig, config_path.as_deref(), role_flags);

                if sig.allow_cwd {
                    let mut is_system = false;
                    let mut resolved_cwd = String::new();
                    if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", pid)) {
                        let cwd_str = cwd.to_string_lossy().to_string();
                        resolved_cwd = cwd_str.clone();
                        if crate::allowlist::is_system_dir(&cwd_str) {
                            is_system = true;
                        }
                    }
                    if !is_system && !resolved_cwd.is_empty() {
                        crate::allowlist::register_pid_extra_path(pid, std::path::PathBuf::from(resolved_cwd));
                    }
                }

                // Conflict 8: populate jvm_exception_pids directly from discovery so JVM
                // processes work even if kinnector-jvmti crashes or fails to attach.
                // Cleanup on exit is handled by cleanup_process_bpf_state (delete_map_entry 10).
                if exe_basename.starts_with("java") {
                    const MAP_JVM_EXCEPTION_PIDS: i32 = 10;
                    unsafe { ffi::update_map_entry(MAP_JVM_EXCEPTION_PIDS, pid, 0, 1); }
                }

                register_pid_signature(pid, &sig.service_type);

                discovered.push(DiscoveredService {
                    signature: sig.clone(),
                    pid,
                    config_path,
                });
                break;
            }
        }
    }

    discovered
}
