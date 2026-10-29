//! allowlist.rs — Git-authoritative inode allowlist for web root enforcement.
//!
//! ## Design Philosophy
//!
//! Every file that a web process may legitimately READ, EXECUTE, or WRITE must
//! be indexed in this allowlist at startup.  The allowlist is seeded from
//! `git ls-files --cached` — only files committed to the repository are
//! allowed.  There is NO timing window, NO path-extension guess, NO heuristic:
//! if the inode is not in the set, the operation is blocked.
//!
//! ## Git Commit Watcher
//!
//! A background task polls `git rev-parse HEAD` every 30 seconds per web root.
//! On any new commit it:
//!  - Emits an informational `Event.WebRoot.NewCommit` alert.
//!  - Checks the commit metadata (author, message).
//!  - If the commit is from an AI agent, automated merge, or `git pull`:
//!    - Automatically re-indexes the new tree into the allowlist so newly
//!      deployed files are immediately allowed.
//!  - Otherwise emits only the informational alert — a human must explicitly
//!    call `vandam fim register --git <root>` or push to the socket API
//!    to approve the new files.
//!
//! ## Fallback
//!
//! When `git` is unavailable, the allowlist is seeded from a full startup walk.
//! This is less secure (any file on disk at startup is trusted) but preserves
//! functionality on non-git deployments.  A WARNING is logged.

use dashmap::DashSet;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

static SEEDING_COMPLETE: AtomicBool = AtomicBool::new(false);
static WALKDIR_SHA256_MAP: OnceLock<Arc<dashmap::DashMap<String, String>>> = OnceLock::new();

pub fn is_seeding_complete() -> bool {
    SEEDING_COMPLETE.load(Ordering::Relaxed)
}

pub fn set_seeding_complete(val: bool) {
    SEEDING_COMPLETE.store(val, Ordering::Relaxed);
}

static PKG_VERIFICATION_CACHE: OnceLock<Arc<dashmap::DashMap<String, String>>> = OnceLock::new();
static PKM_VERIFICATION_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_pkm_verification_enabled(val: bool) {
    PKM_VERIFICATION_ENABLED.store(val, Ordering::Relaxed);
}

pub fn is_pkm_verification_enabled() -> bool {
    PKM_VERIFICATION_ENABLED.load(Ordering::Relaxed)
}

/// Dynamically resolves the full absolute path of a running process from `/proc/<pid>/exe`.
/// Strips any ` (deleted)` suffix and verifies the path exists on disk.
pub fn resolve_process_binary_path(pid: u32) -> Option<String> {
    let proc_exe_link = format!("/proc/{}/exe", pid);
    let resolved = std::fs::read_link(&proc_exe_link).ok()?;
    let path_str = resolved.to_string_lossy();

    let clean_path = if path_str.ends_with(" (deleted)") {
        path_str.trim_end_matches(" (deleted)").to_string()
    } else {
        path_str.to_string()
    };

    let path = std::path::Path::new(&clean_path);
    if path.exists() {
        if let Ok(canonical) = std::fs::canonicalize(path) {
            return Some(canonical.to_string_lossy().to_string());
        }
        return Some(clean_path);
    }

    None
}

pub fn get_verification_cache() -> &'static Arc<dashmap::DashMap<String, String>> {
    PKG_VERIFICATION_CACHE.get_or_init(|| Arc::new(dashmap::DashMap::new()))
}

pub fn verify_system_package_binary(exec_path: &str) -> String {
    if !is_pkm_verification_enabled() {
        return "disabled".to_string();
    }
    if exec_path.is_empty() || exec_path == "unknown" {
        return "unverified".to_string();
    }

    let cache = get_verification_cache();
    if let Some(cached) = cache.get(exec_path) {
        return cached.clone();
    }

    let verified = if let Ok(output) = std::process::Command::new("dpkg-query")
        .args(&["-S", exec_path])
        .output()
    {
        if output.status.success() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                if let Some(pkg) = stdout.split(':').next() {
                    pkg.trim().to_string()
                } else {
                    "unverified".to_string()
                }
            } else {
                "unverified".to_string()
            }
        } else {
            "unverified".to_string()
        }
    } else if let Ok(output) = std::process::Command::new("rpm")
        .args(&["-qf", exec_path])
        .output()
    {
        if output.status.success() {
            if let Ok(stdout) = String::from_utf8(output.stdout) {
                stdout.trim().to_string()
            } else {
                "unverified".to_string()
            }
        } else {
            "unverified".to_string()
        }
    } else {
        "unverified".to_string()
    };

    cache.insert(exec_path.to_string(), verified.clone());
    verified
}

pub fn get_walkdir_sha256(file_path: &str) -> Option<String> {
    WALKDIR_SHA256_MAP.get()?.get(file_path).map(|v| v.clone())
}

pub fn check_walkdir_tampering(file_path: &str) -> bool {
    if let Some(expected_hash) = get_walkdir_sha256(file_path) {
        if let Some(current_hash) = calculate_sha256(std::path::Path::new(file_path)) {
            if current_hash != expected_hash {
                return true; // Tampered!
            }
        }
    }
    false
}

fn calculate_sha256(path: &std::path::Path) -> Option<String> {
    if let Ok(content) = std::fs::read(path) {
        if let Ok(digest) = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &content) {
            return Some(digest.iter().map(|b| format!("{:02x}", b)).collect());
        }
    }
    None
}

static SENSITIVE_INODES: OnceLock<Arc<dashmap::DashSet<u64>>> = OnceLock::new();

pub fn register_sensitive_inode(inode: u64) {
    let set = SENSITIVE_INODES.get_or_init(|| Arc::new(dashmap::DashSet::new()));
    set.insert(inode);
}

pub fn is_inode_sensitive(inode: u64) -> bool {
    if let Some(set) = SENSITIVE_INODES.get() {
        set.contains(&inode)
    } else {
        false
    }
}

pub const PROFILE_ZERO_EXECUTION: u32 = 0x10000000;
pub const PROFILE_RESTRICTED_EXEC: u32 = 0x20000000;

static PID_PROFILES: OnceLock<Arc<dashmap::DashMap<u32, u32>>> = OnceLock::new();

pub fn get_pid_profiles() -> &'static Arc<dashmap::DashMap<u32, u32>> {
    PID_PROFILES.get_or_init(|| Arc::new(dashmap::DashMap::new()))
}

pub fn set_pid_profile(pid: u32, profile_flags: u32) {
    get_pid_profiles().insert(pid, profile_flags);
}

pub fn get_pid_profile(pid: u32) -> u32 {
    get_pid_profiles()
        .get(&pid)
        .map(|v| *v.value())
        .unwrap_or(0)
}

pub fn is_pid_zero_execution(pid: u32) -> bool {
    (get_pid_profile(pid) & PROFILE_ZERO_EXECUTION) != 0
}

pub fn is_pid_restricted_exec(pid: u32) -> bool {
    (get_pid_profile(pid) & PROFILE_RESTRICTED_EXEC) != 0
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Global inode allowlist — initialised once at startup, then mutated by the
/// git commit watcher and manual `register_inode` calls.
static ALLOWED_INODES: OnceLock<Arc<dashmap::DashMap<String, dashmap::DashSet<u64>>>> =
    OnceLock::new();
static CONFIG_MANAGER: OnceLock<Arc<crate::rules::ConfigManager>> = OnceLock::new();
static ALLOWED_PATHS_BY_SIGNATURE: OnceLock<
    Arc<dashmap::DashMap<String, dashmap::DashSet<std::path::PathBuf>>>,
> = OnceLock::new();

/// Per-PID extra path allowlist — populated by proxy_discovery when a backend
/// process is found to serve a specific web root.  Keyed by PID.
static PID_EXTRA_PATHS: OnceLock<Arc<dashmap::DashMap<u32, dashmap::DashSet<std::path::PathBuf>>>> =
    OnceLock::new();

/// Tracks whether the allowlist was seeded from git (true) or a startup walk

/// Tracks whether the allowlist was seeded from git (true) or a startup walk
/// (false).  Walk-seeded mode is inherently less strict.
static GIT_SEEDED: AtomicBool = AtomicBool::new(false);

static DISABLED_MONITORING_PIDS: OnceLock<Arc<DashSet<u32>>> = OnceLock::new();
static DISABLED_TLS_PIDS: OnceLock<Arc<DashSet<u32>>> = OnceLock::new();
static DISABLED_WEB_ROOTS: OnceLock<Arc<DashSet<String>>> = OnceLock::new();

pub fn get_pid_extra_paths(
) -> &'static Arc<dashmap::DashMap<u32, dashmap::DashSet<std::path::PathBuf>>> {
    PID_EXTRA_PATHS.get_or_init(|| Arc::new(dashmap::DashMap::new()))
}

/// Register an extra allowed path for a specific PID (from proxy propagation).
pub fn register_pid_extra_path(pid: u32, path: std::path::PathBuf) {
    let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
    get_pid_extra_paths()
        .entry(pid)
        .or_insert_with(|| dashmap::DashSet::new())
        .insert(canonical);
}

/// Check if a path is allowed for a specific PID via the per-PID extra paths.
pub fn is_path_allowed_for_pid(pid: u32, path: &std::path::Path) -> bool {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if let Some(set) = get_pid_extra_paths().get(&pid) {
        for allowed in set.iter() {
            if canonical.starts_with(allowed.key()) {
                return true;
            }
        }
    }
    false
}

/// Clean up per-PID state when a process exits.
pub fn deregister_pid_paths(pid: u32) {
    get_pid_extra_paths().remove(&pid);
}

pub fn init_config_manager(mgr: Arc<crate::rules::ConfigManager>) {
    let _ = CONFIG_MANAGER.set(mgr);
}

pub fn get_config_manager() -> Option<Arc<crate::rules::ConfigManager>> {
    CONFIG_MANAGER.get().cloned()
}

pub fn get_allowed_paths_registry(
) -> &'static Arc<dashmap::DashMap<String, dashmap::DashSet<std::path::PathBuf>>> {
    ALLOWED_PATHS_BY_SIGNATURE.get_or_init(|| Arc::new(dashmap::DashMap::new()))
}

/// Register a path/directory allowed specifically for a signature (e.g. "nginx", "postgres")
pub fn register_signature_path(sig_name: &str, path: std::path::PathBuf) {
    let registry = get_allowed_paths_registry();
    let canonical = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());

    registry
        .entry(sig_name.to_string())
        .or_insert_with(|| dashmap::DashSet::new())
        .insert(canonical);
}

/// Verify if a path belongs to the allowed paths of a specific signature
pub fn is_path_allowed_for_signature(path: &std::path::Path, sig_name: &str) -> bool {
    let registry = get_allowed_paths_registry();
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    if let Some(set) = registry.get(sig_name) {
        for allowed in set.iter() {
            if canonical.starts_with(allowed.key()) {
                return true;
            }
        }
    }
    false
}

/// Verify if a path belongs to the allowed paths of any registered signature
pub fn is_path_allowed_for_any_signature(path: &std::path::Path) -> bool {
    let registry = get_allowed_paths_registry();
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());

    for entry in registry.iter() {
        for allowed in entry.value().iter() {
            if canonical.starts_with(allowed.key()) {
                return true;
            }
        }
    }
    false
}

pub fn get_disabled_monitoring_pids() -> Arc<DashSet<u32>> {
    DISABLED_MONITORING_PIDS
        .get_or_init(|| Arc::new(DashSet::new()))
        .clone()
}

pub fn get_disabled_tls_pids() -> Arc<DashSet<u32>> {
    DISABLED_TLS_PIDS
        .get_or_init(|| Arc::new(DashSet::new()))
        .clone()
}

pub fn get_disabled_web_roots() -> Arc<DashSet<String>> {
    DISABLED_WEB_ROOTS
        .get_or_init(|| Arc::new(DashSet::new()))
        .clone()
}

// ---------------------------------------------------------------------------
// Seeding
// ---------------------------------------------------------------------------

/// Seed the allowlist for the given web root directories.
/// Must be called once at daemon startup before enforcement begins.
pub fn seed_inode_allowlist(
    web_roots: &[String],
) -> Arc<dashmap::DashMap<String, dashmap::DashSet<u64>>> {
    if let Some(existing_hashes) = WALKDIR_SHA256_MAP.get() {
        existing_hashes.clear();
    }
    let map = Arc::new(dashmap::DashMap::new());
    let mut any_git = false;

    for web_root in web_roots {
        let set = dashmap::DashSet::new();
        // Strategy 1: `git ls-files --cached -z` (preferred)
        if let Some(count) = git_index_into(&set, web_root) {
            if count > 0 {
                println!(
                    "[Vandam Allowlist] Seeded {} inodes from git ls-files in {}",
                    count, web_root
                );
                any_git = true;
                map.insert(web_root.clone(), set);
                continue;
            }
        }

        // Strategy 2: Full startup snapshot (walkdir) — less strict
        eprintln!(
            "[Vandam Allowlist] WARNING: git unavailable in {}. Falling back to startup walk. \
             We cannot validate the site/server and there is no guarantee that the server is clean. \
             To automatically check the server for pre-existing threats (YARA & LLM analysis), please upgrade to a paid plan.",
            web_root
        );
        walk_seed(&set, web_root);
        println!(
            "[Vandam Allowlist] Seeded {} inodes from startup walk of {}",
            set.len(),
            web_root
        );
        map.insert(web_root.clone(), set);
    }

    if let Some(existing) = ALLOWED_INODES.get() {
        existing.clear();
        for entry in map.iter() {
            existing.insert(entry.key().clone(), entry.value().clone());
        }
    } else {
        let _ = ALLOWED_INODES.set(Arc::clone(&map));
    }
    GIT_SEEDED.store(any_git, Ordering::Relaxed);
    set_seeding_complete(true);
    map
}

/// Dynamically loads standard shells from the system-wide `/etc/shells` configuration.
/// Ensures we do not hardcode a static process list, adhering to Section 1 of KINNECTOR-docs/CODE-RULEBOOK.md.

fn get_partition_for_path<'a>(
    map: &'a dashmap::DashMap<String, dashmap::DashSet<u64>>,
    file_path: &str,
) -> String {
    let mut best_match = String::new();
    for entry in map.iter() {
        if file_path.starts_with(entry.key()) && entry.key().len() > best_match.len() {
            best_match = entry.key().clone();
        }
    }
    best_match
}

pub fn load_system_shells() -> std::collections::HashSet<String> {
    let mut shells = std::collections::HashSet::new();
    if let Ok(content) = std::fs::read_to_string("/etc/shells") {
        for line in content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                shells.insert(trimmed.to_string());
                // Also insert the filename only (e.g. "bash" from "/bin/bash")
                if let Some(filename) = std::path::Path::new(trimmed)
                    .file_name()
                    .and_then(|f| f.to_str())
                {
                    shells.insert(filename.to_string());
                }
            }
        }
    }
    // Generic standard shell fallbacks if /etc/shells is not present/empty
    if shells.is_empty() {
        for s in &["sh", "bash", "dash", "zsh", "ash", "csh", "tcsh", "ksh"] {
            shells.insert(s.to_string());
            shells.insert(format!("/bin/{}", s));
            shells.insert(format!("/usr/bin/{}", s));
        }
    }
    shells
}

// ---------------------------------------------------------------------------
// Enforcement
// ---------------------------------------------------------------------------

/// Returns `true` if the file is allowed (inode in the allowlist).
/// Returns `false` if the allowlist is populated and the inode is absent.
///
/// Permissive when the allowlist has not been seeded yet (daemon initialisation
/// race — should not happen in practice given startup order).
pub fn is_inode_allowed(file_path: &str) -> bool {
    let path = std::path::Path::new(file_path);
    if let Some(mgr) = CONFIG_MANAGER.get() {
        if mgr.is_path_excluded(path) {
            return true; // Excluded paths are always allowed
        }
    }

    let Some(map) = ALLOWED_INODES.get() else {
        return true; // Not seeded yet — permissive
    };
    if map.is_empty() {
        return true;
    }
    match std::fs::metadata(file_path) {
        Ok(meta) => {
            let ino = meta.ino();
            for entry in map.iter() {
                if entry.value().contains(&ino) {
                    return true;
                }
            }
            false
        }
        // Cannot stat the file — conservatively block
        Err(_) => false,
    }
}

pub fn is_inode_allowed_for_process(file_path: &str, authorized_roots: &[String]) -> bool {
    let path = std::path::Path::new(file_path);
    if let Some(mgr) = CONFIG_MANAGER.get() {
        if mgr.is_path_excluded(path) {
            return true;
        }
    }

    let Some(map) = ALLOWED_INODES.get() else {
        return true;
    };
    if map.is_empty() {
        return true;
    }

    match std::fs::metadata(file_path) {
        Ok(meta) => {
            let ino = meta.ino();
            if authorized_roots.is_empty() {
                for entry in map.iter() {
                    if entry.value().contains(&ino) {
                        return true;
                    }
                }
                return false;
            }

            let partition_key = get_partition_for_path(map, file_path);
            if authorized_roots.contains(&partition_key) {
                if let Some(partition) = map.get(&partition_key) {
                    if partition.contains(&ino) {
                        return true;
                    }
                }
            }

            false
        }
        Err(_) => false,
    }
}

/// System-managed writable directories that should never trigger read/write
/// alerts regardless of which process accesses them.  These are kernel tmpfs
/// mounts or world-writable scratch spaces — monitoring them produces noise
/// with zero security value and kills legitimate runtimes (e.g. PHP session
/// files, WordPress transient cache, JVM temp jars).
const SYSTEM_TMP_PREFIXES: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/user/",     // user-specific XDG runtime (systemd)
    "/var/run/user/", // legacy symlink target on some distros
];

/// Returns true if `path` is inside a system-writable scratch directory.
/// Call this before any alert or quarantine logic in event handlers.
#[inline]
pub fn is_system_tmp_path(path: &str) -> bool {
    // Fast exact-prefix check — no allocation, no regex
    SYSTEM_TMP_PREFIXES
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

/// Returns true if `path` is an EXACT match for a core system directory or root.
#[inline]
pub fn is_system_dir(path: &str) -> bool {
    let p = path.trim_end_matches('/');
    if p.is_empty() {
        return true;
    } // root

    let catastrophic_exact = [
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/lib32",
        "/usr",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/lib32",
        "/usr/libexec",
        "/usr/local",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/local/lib",
        "/etc",
        "/var",
        "/var/lib",
        "/var/run",
        "/boot",
        "/dev",
        "/sys",
        "/proc",
        "/run",
        "/root",
        "/home",
        "/opt",
    ];

    catastrophic_exact.contains(&p)
}

/// Same as `is_inode_allowed` but operates directly on an already-obtained
/// inode number (avoids a redundant `stat` call in hot paths).
pub fn is_inode_number_allowed(ino: u64) -> bool {
    let Some(map) = ALLOWED_INODES.get() else {
        return true;
    };
    if map.is_empty() {
        return true;
    }
    for entry in map.iter() {
        if entry.value().contains(&ino) {
            return true;
        }
    }
    false
}

/// Returns whether the allowlist was seeded from git (`true`) or a startup
/// walk (`false`).  Used to qualify alert descriptions.
pub fn is_git_seeded() -> bool {
    GIT_SEEDED.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// Mutation
// ---------------------------------------------------------------------------

/// Register a single inode into the allowlist.
/// Called by the git commit watcher and `vandam fim register`.
pub fn register_inode(file_path: &str) -> bool {
    register_inode_get_ino(file_path).is_some()
}

/// Register a single inode and return its (dev, inode) identity.
/// Callers that later need to deregister this exact
/// entry (e.g. `deregister_inode_by_raw_ino`) need `dev` too, since a bare
/// inode is ambiguous across bind-mounts/multiple filesystems.
pub fn register_inode_get_ino(file_path: &str) -> Option<(u64, u64)> {
    let Some(map) = ALLOWED_INODES.get() else {
        return None;
    };
    let partition_key = get_partition_for_path(map, file_path);
    let partition = map
        .entry(partition_key)
        .or_insert_with(|| dashmap::DashSet::new());

    match std::fs::metadata(file_path) {
        Ok(meta) => {
            let ino = meta.ino();
            let dev = meta.dev();
            let is_new = partition.insert(ino);
            if is_new {
                println!(
                    "[Vandam Allowlist] Registered inode {} — {}",
                    ino, file_path
                );
                unsafe {
                    crate::ffi::add_protected_static_inode(dev, ino);
                }
            }
            Some((dev, ino))
        }
        Err(_) => None,
    }
}

/// Deregister a single inode from the allowlist.
/// Called by the async upload scan pipeline if a malicious file is detected.
pub fn deregister_inode(file_path: &str) -> bool {
    let Some(map) = ALLOWED_INODES.get() else {
        return false;
    };
    let partition_key = get_partition_for_path(map, file_path);
    let Some(partition) = map.get(&partition_key) else {
        return false;
    };

    match std::fs::metadata(file_path) {
        Ok(meta) => {
            let ino = meta.ino();
            let dev = meta.dev();
            let removed = partition.remove(&ino);
            if removed.is_some() {
                println!(
                    "[Vandam Allowlist] Deregistered inode {} — {}",
                    ino, file_path
                );
                unsafe {
                    crate::ffi::remove_protected_static_inode(dev, ino);
                }
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

/// Deregister an inode by its raw (dev, inode) identity.
/// `dev` is required now that the kernel map's key is
/// canonical (dev, ino) — callers must have captured it before the file
/// disappeared (e.g. from a pre-move `symlink_metadata()` call), since this
/// path exists specifically for cases where the file itself may already be
/// gone/moved by the time this runs.
pub fn deregister_inode_by_raw_ino(dev: u64, ino: u64) -> bool {
    let Some(map) = ALLOWED_INODES.get() else {
        return false;
    };
    let mut removed = false;
    for entry in map.iter() {
        if entry.value().remove(&ino).is_some() {
            removed = true;
        }
    }

    if removed {
        println!("[Vandam Allowlist] Deregistered raw inode {}", ino);
        unsafe {
            crate::ffi::remove_protected_static_inode(dev, ino);
        }
        true
    } else {
        false
    }
}

/// Register a single inode in userspace only (silences read alerts, allows BPF writes).
pub fn register_dynamic_inode(file_path: &str) -> bool {
    let Some(map) = ALLOWED_INODES.get() else {
        return false;
    };
    let partition_key = get_partition_for_path(map, file_path);
    let partition = map
        .entry(partition_key)
        .or_insert_with(|| dashmap::DashSet::new());
    match std::fs::metadata(file_path) {
        Ok(meta) => {
            let ino = meta.ino();
            partition.insert(ino); // Rust set only - no BPF call
            true
        }
        Err(_) => false,
    }
}

/// Re-index all files tracked by `git ls-files --cached` in `web_root`.
/// Returns the number of NEW inodes added (not already in the set).
pub fn reseed_from_git(web_root: &str) -> usize {
    let Some(map) = ALLOWED_INODES.get() else {
        return 0;
    };
    let partition_key = get_partition_for_path(map, web_root);
    let partition = map
        .entry(partition_key)
        .or_insert_with(|| dashmap::DashSet::new());

    let before = partition.len();
    if let Some(total) = git_index_into(&partition, web_root) {
        let added = partition.len().saturating_sub(before);
        println!(
            "[Vandam Allowlist] Git re-index of {}: {} files in tree, {} new inodes added",
            web_root, total, added
        );
        added
    } else {
        0
    }
}

/// Get a reference-counted handle to the live allowlist (for diagnostics /
/// API endpoints — do not hold across await points).
pub fn get_allowlist() -> Option<Arc<dashmap::DashMap<String, dashmap::DashSet<u64>>>> {
    ALLOWED_INODES.get().cloned()
}

// ---------------------------------------------------------------------------
// Git commit watcher
// ---------------------------------------------------------------------------

/// Information about a detected new commit.
#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub message: String,
    /// True when the commit was created by an automated process (AI agent,
    /// merge commit, `git pull --rebase`, dependabot, etc.).
    pub is_automated: bool,
}

/// Classify whether a commit should be auto-approved for allowlist re-indexing.
///
/// Returns `true` for:
/// - Merge commits (two parents — `git show --format=%P` has a space)
/// - Author names/emails containing automation markers
/// - Commit messages matching pull/merge/deploy/bot/dependabot patterns
fn classify_commit(info: &CommitInfo) -> bool {
    let msg_lower = info.message.to_lowercase();
    let author_lower = info.author.to_lowercase();

    // Merge commits
    if msg_lower.starts_with("merge ") || msg_lower.starts_with("merged ") {
        return true;
    }
    // Pull / rebase operations
    if msg_lower.contains("pull request") || msg_lower.contains("auto-merge") {
        return true;
    }
    // Deploy / CI bot patterns
    if msg_lower.contains("[deploy]")
        || msg_lower.contains("[bot]")
        || msg_lower.contains("dependabot")
    {
        return true;
    }
    // AI agent commit patterns
    if author_lower.contains("bot")
        || author_lower.contains("agent")
        || author_lower.contains("copilot")
        || author_lower.contains("claude")
        || author_lower.contains("gemini")
        || author_lower.contains("gpt")
        || author_lower.contains("cursor")
        || author_lower.contains("aider")
    {
        return true;
    }
    if msg_lower.contains("ai-generated")
        || msg_lower.contains("co-authored-by: claude")
        || msg_lower.contains("co-authored-by: gemini")
        || msg_lower.contains("co-authored-by: gpt")
        || msg_lower.contains("co-authored-by: copilot")
    {
        return true;
    }

    false
}

/// Read the HEAD commit hash in `repo_root`. Returns `None` if git is unavailable.
fn get_head_hash(repo_root: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        None
    }
}

/// Read commit metadata (author + message) for a given hash.
fn get_commit_info(repo_root: &str, hash: &str) -> Option<CommitInfo> {
    // --format="%an <%ae>%n%s" gives "Author Name <email>\nsubject"
    let out = std::process::Command::new("git")
        .args(["show", "--no-patch", "--format=%an <%ae>%n%B", hash])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut lines = text.lines();
    let author = lines.next().unwrap_or("").to_string();
    let message = lines.collect::<Vec<_>>().join("\n");

    let mut info = CommitInfo {
        hash: hash.to_string(),
        author,
        message,
        is_automated: false,
    };
    info.is_automated = classify_commit(&info);
    Some(info)
}

/// Spawn a background task that watches for new commits in `web_root` using
/// file system events on the `.git` directory instead of polling.
///
/// On any refs or HEAD changes:
///  - Emits an `Event.WebRoot.NewCommit` informational alert.
///  - If the commit is automated: re-indexes the new tree automatically.
///  - Otherwise: emits the informational alert only. A human must approve.
pub fn start_git_commit_watcher(web_root: String) {
    tokio::spawn(async move {
        let git_dir = std::path::Path::new(&web_root).join(".git");
        if !git_dir.exists() {
            return;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(_) => return,
        };

        use notify::Watcher;
        let _ = watcher.watch(
            &git_dir.join("refs/heads"),
            notify::RecursiveMode::Recursive,
        );
        let _ = watcher.watch(&git_dir.join("HEAD"), notify::RecursiveMode::NonRecursive);

        let mut last_known_hash = get_head_hash(&web_root);

        // Keep watcher alive by storing it
        let _watcher_holder = watcher;

        while let Some(_event) = rx.recv().await {
            let current = match get_head_hash(&web_root) {
                Some(h) => h,
                None => continue,
            };

            // No change in HEAD hash
            if last_known_hash.as_deref() == Some(current.as_str()) {
                continue;
            }

            let prev_hash = last_known_hash
                .clone()
                .unwrap_or_else(|| "<none>".to_string());

            let info = get_commit_info(&web_root, &current);
            let author = info
                .as_ref()
                .map(|i| i.author.as_str())
                .unwrap_or("unknown");
            let message = info.as_ref().map(|i| i.message.as_str()).unwrap_or("");
            let is_automated = info.as_ref().map(|i| i.is_automated).unwrap_or(false);

            if is_automated {
                let added = reseed_from_git(&web_root);
                println!(
                    "[Vandam GitWatch] Automated commit {} in {} — auto-indexed {} new inodes. \
                     Author: {}. Message: {:?}",
                    &current[..8.min(current.len())],
                    web_root,
                    added,
                    author,
                    message
                );
                emit_commit_alert(
                    &web_root, &current, &prev_hash, author, message, true, added,
                );
            } else {
                println!(
                    "[Vandam GitWatch] New commit {} in {} (author: {}). \
                     Allowlist NOT updated automatically. Run `vandam fim register --git {}` to approve.",
                    &current[..8.min(current.len())], web_root, author, web_root
                );
                emit_commit_alert(&web_root, &current, &prev_hash, author, message, false, 0);
            }

            last_known_hash = Some(current);
        }
    });
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Run `git ls-files --cached -z` in `web_root` and insert all discovered
/// inodes into `set`. Returns the number of paths processed, or `None` if git
/// fails.
fn git_index_into(set: &DashSet<u64>, web_root: &str) -> Option<usize> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "--cached", "-z"])
        .current_dir(web_root)
        .output()
        .ok()?;

    if !out.status.success() || out.stdout.is_empty() {
        return None;
    }

    let mut count = 0usize;
    for rel in out.stdout.split(|&b| b == 0) {
        if rel.is_empty() {
            continue;
        }
        let Ok(rel_str) = std::str::from_utf8(rel) else {
            continue;
        };
        let full = format!("{}/{}", web_root.trim_end_matches('/'), rel_str);
        let path = std::path::Path::new(&full);
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                if let Ok(target_meta) = std::fs::metadata(path) {
                    if target_meta.is_dir() {
                        resolve_and_seed_symlink_dir(set, path);
                    } else {
                        set.insert(target_meta.ino());
                    }
                }
            } else {
                set.insert(meta.ino());
            }
            count += 1;
        }
    }

    Some(count)
}

fn walk_seed_raw(set: &DashSet<u64>, root: &str) {
    fn recurse(set: &DashSet<u64>, dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.is_file() {
                    set.insert(meta.ino());
                    let map = WALKDIR_SHA256_MAP.get_or_init(|| Arc::new(dashmap::DashMap::new()));
                    if let Some(hash) = calculate_sha256(&path) {
                        map.insert(path.to_string_lossy().to_string(), hash);
                    }
                } else if meta.is_dir() {
                    recurse(set, &path);
                } else if meta.file_type().is_symlink() {
                    if let Ok(target_meta) = std::fs::metadata(&path) {
                        if target_meta.is_dir() {
                            resolve_and_seed_symlink_dir(set, &path);
                        } else {
                            set.insert(target_meta.ino());
                            let map = WALKDIR_SHA256_MAP
                                .get_or_init(|| Arc::new(dashmap::DashMap::new()));
                            if let Some(hash) = calculate_sha256(&path) {
                                map.insert(path.to_string_lossy().to_string(), hash);
                            }
                        }
                    }
                }
            }
        }
    }
    recurse(set, std::path::Path::new(root));
}

fn resolve_and_seed_symlink_dir(set: &DashSet<u64>, path: &std::path::Path) {
    if let Ok(target) = std::fs::read_link(path) {
        let resolved = if target.is_relative() {
            path.parent()
                .unwrap_or(std::path::Path::new(""))
                .join(target)
        } else {
            target
        };

        if let Ok(canonical) = resolved.canonicalize() {
            let canonical_str = canonical.to_string_lossy();
            if is_system_dir(&canonical_str)
                || is_system_tmp_path(&canonical_str)
                || canonical_str.contains("/.ssh")
                || canonical_str.contains("/.aws")
            {
                return;
            }

            if canonical.join(".git").exists() {
                let _ = git_index_into(set, &canonical_str);
            } else {
                walk_seed_raw(set, &canonical_str);
            }
        }
    }
}

fn walk_seed(set: &DashSet<u64>, root: &str) {
    fn recurse(set: &DashSet<u64>, dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                if file_name.starts_with(".uploaded_") && file_name.ends_with(".sh") {
                    continue; // Skip the marker file itself
                }
            }
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.is_file() {
                    if crate::storage_discovery::is_in_storage(&path).is_none() {
                        let file_name = path.file_name().unwrap_or_default().to_string_lossy();
                        let marker_path =
                            path.with_file_name(format!(".uploaded_{}.sh", file_name));
                        if !marker_path.exists() {
                            set.insert(meta.ino());
                            let map = WALKDIR_SHA256_MAP
                                .get_or_init(|| Arc::new(dashmap::DashMap::new()));
                            if let Some(hash) = calculate_sha256(&path) {
                                map.insert(path.to_string_lossy().to_string(), hash);
                            }

                            // OSS YARA Scan for pre-existing webshells during fallback walk
                            if crate::yara_scanner::scan_file_yara_oss(&path) {
                                let payload = crate::notifications::AlertPayload {
                                    alert_id: uuid::Uuid::new_v4().to_string(),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                    threat_type: "Warning.Allowlist.SuspiciousFileAtStartup".to_string(),
                                    severity: "CRITICAL".to_string(),
                                    confidence: 0.0,
                                    container: None,
                                    process: crate::notifications::ProcessInfo {
                                        pid: std::process::id(),
                                        exec_path: "vandamd".to_string(),
                                        cmdline: "startup_walk".to_string(),
                                        parent_exec_path: "".to_string(),
                                        parent_pid: 0,
                                        verified_package: None,
                                        envs: Vec::new(),
                                        args: Vec::new(),
                                                                            signature_name: None,
                                        service: None,
},
                                    remediation: crate::notifications::RemediationInfo {
                                        action: "FLAGGED".to_string(),
                                        status: format!("Pre-existing webshell detected by OSS YARA during startup walk: {}", path.display()),
                                        requires_cloud_decision: false,
                                                                            quarantine: None,
},
                                    rasp_context: None,
                                    origin_tree: Vec::new(),
                                    network_links: Vec::new(),
                                    container_meta: None,
                                    site: None,
                                    site_source: None,
                                                                    event_detail: None,
};
                                crate::notifications::dispatch_alert(payload);
                            }
                        } else {
                            println!("[Vandam Allowlist] Skipping uploaded executable file due to marker: {}", path.display());
                        }
                    }
                } else if meta.is_dir() {
                    recurse(set, &path);
                } else if meta.file_type().is_symlink() {
                    if let Ok(target_meta) = std::fs::metadata(&path) {
                        if target_meta.is_dir() {
                            resolve_and_seed_symlink_dir(set, &path);
                        } else {
                            set.insert(target_meta.ino());
                            let map = WALKDIR_SHA256_MAP
                                .get_or_init(|| Arc::new(dashmap::DashMap::new()));
                            if let Some(hash) = calculate_sha256(&path) {
                                map.insert(path.to_string_lossy().to_string(), hash);
                            }
                        }
                    }
                }
            }
        }
    }
    recurse(set, std::path::Path::new(root));
}

fn emit_commit_alert(
    web_root: &str,
    hash: &str,
    prev_hash: &str,
    author: &str,
    message: &str,
    auto_indexed: bool,
    new_inodes: usize,
) {
    let alert_id = uuid::Uuid::new_v4().to_string();
    let status = if auto_indexed {
        format!(
            "Automated commit {} (prev: {}) by '{}' in {} — {} new inodes auto-indexed. Message: {:?}",
            &hash[..8.min(hash.len())], &prev_hash[..8.min(prev_hash.len())],
            author, web_root, new_inodes, message
        )
    } else {
        format!(
            "Human commit {} (prev: {}) by '{}' in {}. Allowlist pending manual approval. Message: {:?}",
            &hash[..8.min(hash.len())], &prev_hash[..8.min(prev_hash.len())],
            author, web_root, message
        )
    };

    let payload = crate::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Event.WebRoot.NewCommit".to_string(),
        severity: "INFO".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "git".to_string(),
            cmdline: format!("HEAD={}", hash),
            parent_exec_path: "vandamd".to_string(),
            parent_pid: std::process::id(),
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: if auto_indexed {
                "AUTO_INDEXED"
            } else {
                "PENDING_APPROVAL"
            }
            .to_string(),
            status,
            requires_cloud_decision: false,
            quarantine: None,
        },
        rasp_context: None,
        origin_tree: Vec::new(),
        network_links: Vec::new(),
        container_meta: None,
        site: None,
        site_source: None,
        event_detail: None,
    };

    crate::notifications::dispatch_alert(payload);
}

pub fn register_path_recursive(root: &str) {
    if let Some(map) = ALLOWED_INODES.get() {
        let partition_key = get_partition_for_path(map, root);
        let partition = map
            .entry(partition_key)
            .or_insert_with(|| dashmap::DashSet::new());
        walk_seed(&partition, root);
    }
}

pub fn deregister_path_recursive(root: &str) {
    let Some(map) = ALLOWED_INODES.get() else {
        return;
    };
    let partition_key = get_partition_for_path(map, root);
    let Some(partition) = map.get(&partition_key) else {
        return;
    };

    fn recurse(set: &dashmap::DashSet<u64>, dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = std::fs::symlink_metadata(&path) {
                if meta.is_file() {
                    let ino = meta.ino();
                    if set.remove(&ino).is_some() {
                        println!(
                            "[Vandam Allowlist] Deregistered inode {} — {}",
                            ino,
                            path.display()
                        );
                    }
                } else if meta.is_dir() {
                    recurse(set, &path);
                }
            }
        }
    }
    recurse(&partition, std::path::Path::new(root));
}

pub fn sync_protected_static_inodes(config_dirs: &[std::path::PathBuf]) {
    if let Some(map) = ALLOWED_INODES.get() {
        let mut count = 0;
        for entry in map.iter() {
            // ALLOWED_INODES only stores bare
            // inode numbers per partition, not (dev, ino) pairs -- but the
            // partition key itself is the web-root/config-dir path prefix
            // (get_partition_for_path), so stat it once per partition to recover
            // a `dev` for every inode registered under it. This assumes a
            // partition doesn't itself straddle a bind-mount onto a different
            // filesystem than its own root, which holds for how partitions are
            // seeded (walk_seed/register_inode_get_ino) today.
            let partition_key = entry.key();
            if partition_key.is_empty() {
                continue;
            }
            let Ok(partition_meta) = std::fs::metadata(partition_key) else {
                continue;
            };
            let dev = partition_meta.dev();
            for item in entry.value().iter() {
                let inode = *item;
                unsafe {
                    crate::ffi::add_protected_static_inode(dev, inode);
                }
                count += 1;
            }
        }

        fn walk_config_dir(dir: &std::path::Path, count: &mut usize) {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    let path = entry.path();
                    if path.is_dir() {
                        walk_config_dir(&path, count);
                    } else if path.is_file() {
                        if let Ok(metadata) = std::fs::metadata(&path) {
                            let inode = metadata.ino();
                            let dev = metadata.dev();
                            unsafe {
                                crate::ffi::add_protected_static_inode(dev, inode);
                            }
                            *count += 1;
                        }
                    }
                }
            }
        }

        for dir in config_dirs {
            walk_config_dir(dir, &mut count);
        }

        tracing::info!("[Vandam FIM] Synchronized {} pre-existing static files to BPF protected_static_inodes map.", count);
    }
}

static LEARNING_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_learning_mode() -> bool {
    LEARNING_MODE.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn set_learning_mode(enabled: bool) {
    LEARNING_MODE.store(enabled, std::sync::atomic::Ordering::Relaxed);
    println!(
        "[Vandam Learning Mode] Dynamic learning mode set to: {}",
        enabled
    );
}

static CRON_SCHEDULED_PATHS: OnceLock<Arc<DashSet<std::path::PathBuf>>> = OnceLock::new();

pub fn get_cron_scheduled_paths() -> &'static Arc<DashSet<std::path::PathBuf>> {
    CRON_SCHEDULED_PATHS.get_or_init(|| Arc::new(DashSet::new()))
}

pub fn is_cron_scheduled_path(path: &std::path::Path) -> bool {
    if let Ok(canon) = std::fs::canonicalize(path) {
        get_cron_scheduled_paths().contains(&canon)
    } else {
        get_cron_scheduled_paths().contains(path)
    }
}

pub fn seed_cron_scheduled_paths() {
    let set = get_cron_scheduled_paths();
    set.clear();

    // 1. Scan cron script directories
    let script_dirs = [
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ];
    for dir in &script_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(canon) = std::fs::canonicalize(&path) {
                        set.insert(canon);
                    } else {
                        set.insert(path);
                    }
                }
            }
        }
    }

    // Helper to clean a path token (e.g. remove trailing semicolons, redirection symbols, quotes)
    fn clean_path_token(token: &str) -> std::path::PathBuf {
        let cleaned = token
            .trim_matches(|c| {
                c == '\'' || c == '"' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>'
            })
            .split('>') // handle redirections like /path/to/log>/dev/null
            .next()
            .unwrap_or(token);
        std::path::PathBuf::from(cleaned)
    }

    // 2. Parse system crontabs (/etc/crontab and /etc/cron.d/*)
    let mut all_system_files = vec![std::path::PathBuf::from("/etc/crontab")];
    if let Ok(entries) = std::fs::read_dir("/etc/cron.d") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                all_system_files.push(p);
            }
        }
    }

    for file_path in all_system_files {
        if let Ok(content) = std::fs::read_to_string(&file_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains('=') {
                    continue;
                }
                let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                if tokens.len() >= 7 {
                    // System cron format: minute hour mday month wday user command...
                    for token in &tokens[6..] {
                        if token.starts_with('/') {
                            let p = clean_path_token(token);
                            if p.exists() {
                                if let Ok(canon) = std::fs::canonicalize(&p) {
                                    set.insert(canon);
                                } else {
                                    set.insert(p);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Parse user crontabs (/var/spool/cron/crontabs/* and /var/spool/cron/*)
    let user_dirs = vec![
        std::path::PathBuf::from("/var/spool/cron"),
        std::path::PathBuf::from("/var/spool/cron/crontabs"),
    ];
    for dir in user_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_file() {
                    if let Ok(content) = std::fs::read_to_string(&p) {
                        for line in content.lines() {
                            let trimmed = line.trim();
                            if trimmed.is_empty()
                                || trimmed.starts_with('#')
                                || trimmed.contains('=')
                            {
                                continue;
                            }
                            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                            if tokens.len() >= 6 {
                                // User cron format: minute hour mday month wday command...
                                for token in &tokens[5..] {
                                    if token.starts_with('/') {
                                        let p = clean_path_token(token);
                                        if p.exists() {
                                            if let Ok(canon) = std::fs::canonicalize(&p) {
                                                set.insert(canon);
                                            } else {
                                                set.insert(p);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    tracing::info!(
        "[Vandam Cron] Indexed {} cron-scheduled scripts/executables for write protection.",
        set.len()
    );
}
