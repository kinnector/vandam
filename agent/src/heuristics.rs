use chrono::Utc;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

static RASP_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Generic capability flag OSS exposes for `vandam` to set — mirrors the
/// `on_engine_ready` extension-point pattern (see `VandamConfig`). OSS itself
/// never sets this; it just reports whatever vandam told it. Used so
/// `/api/v1/status` can honestly report whether RASP (and everything that
/// depends on it, like PHP site attribution) is actually available on this
/// install — which tracks "is this the Pro binary," not "is it licensed".
pub fn set_rasp_active(active: bool) {
    RASP_ACTIVE.store(active, Ordering::Relaxed);
}

pub fn is_rasp_active() -> bool {
    RASP_ACTIVE.load(Ordering::Relaxed)
}

static STARTUP_EVENT_QUEUE: OnceLock<Mutex<VecDeque<TelemetryEventRaw>>> = OnceLock::new();

fn get_startup_event_queue() -> &'static Mutex<VecDeque<TelemetryEventRaw>> {
    STARTUP_EVENT_QUEUE.get_or_init(|| Mutex::new(VecDeque::with_capacity(1024)))
}

use crate::types::{
    DNSQueryDetails, Dup2Details, EventType, FileDeleteDetails, FileOpenDetails, FileRenameDetails,
    FileWriteDetails, IPCAccessDetails, MemoryMapDetails, MemoryProtectDetails,
    NetworkAcceptDetails, NetworkConnectDetails, PrivilegeChangeDetails, ProcessCreateDetails,
    PtraceAttachDetails, SSHAuthDetails, SignalDeliveryDetails, TelemetryEventRaw,
    TerminalCommandDetails,
};

// PROT_EXEC flag for mmap/mprotect detection
const PROT_EXEC: u32 = 4;
// MAP_ANONYMOUS flag
const MAP_ANONYMOUS: u32 = 32;

#[derive(Clone, Debug)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
    pub cmdline: String,
    pub is_listening_server: bool,
    /// True if this process was identified as a standalone database server at startup.
    /// Used to apply exec-spawn alerting (e.g., postgres spawning /bin/bash).
    pub is_database: bool,
    pub is_install_context: bool,
    pub is_top_level_install: bool,
    pub install_root_pid: u32,
    pub depth: u32,
    pub loaded_scripts: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    pub signature_name: Option<std::sync::Arc<str>>,
    pub service: Option<String>,
}

#[derive(Clone)]
pub struct HeuristicsEngine {
    pub process_map: Arc<DashMap<u32, ProcessNode>>,
    pub ssh_attempts: Arc<DashMap<String, Vec<i64>>>,
    pub config: Arc<crate::rules::ConfigManager>,
    /// Tracks last-seen timestamp (Unix secs) per PID for TTL eviction (P1-13 / B-10 fix).
    pub process_seen: Arc<DashMap<u32, i64>>,
    pub credential_reads: Arc<DashMap<String, usize>>,
    pub web_roots: Vec<String>,
    pub system_shells: std::collections::HashSet<String>,
    pub listening_pids: Arc<dashmap::DashSet<u32>>,
    pub audit_mode: bool,
    pub(crate) ext_tx: Option<tokio::sync::mpsc::Sender<String>>,
    /// Active PTY/interactive sessions (Access page), keyed by session id.
    /// Ended sessions are removed here and live only on disk — see
    /// `pty_session_store`. Small: bounded by concurrently-open sessions.
    pub pty_sessions: Arc<DashMap<String, crate::pty_session::PtySessionMeta>>,
    /// pid -> session id, for O(1) session attribution of any descendant of a
    /// session's leader shell. Self-cleaning: removed on that pid's `ProcessStop`.
    pub pid_to_session: Arc<DashMap<u32, String>>,
    /// session leader pid -> session id, so `ProcessStop` can cheaply check
    /// "does this pid ending also end a session" without scanning `pty_sessions`.
    pub session_leader_pid: Arc<DashMap<u32, String>>,
    /// pid -> that pid's own controlling tty, for every pid tracked in
    /// `pid_to_session` (not just session leaders). Lets `tty_logger.rs`'s
    /// hot per-byte-event path do a cheap map lookup instead of a
    /// `/proc/<pid>/fd/0` syscall per event — the resolution happens once,
    /// in `pty_session.rs`, at `ProcessCreate` time instead. Most processes
    /// resolve to the *same* tty as their parent shell (inherited fd); a
    /// terminal multiplexer (tmux/screen) pane resolves to a genuinely new
    /// one, which is exactly what lets replay be partitioned per-pty
    /// instead of interleaving concurrent panes into one stream.
    pub pid_to_tty: Arc<DashMap<u32, String>>,
    /// Install-root pid -> tracked package-manager install, for vandam's
    /// Supply Chain pipeline. Propagated to every descendant pid of a
    /// tracked root (see `supply_chain::on_process_create`); self-cleaning,
    /// removed on that pid's `ProcessStop`.
    pub supply_chain_installs: Arc<DashMap<u32, crate::supply_chain::TrackedInstall>>,
}

#[inline]
fn safe_read_details<T: Copy>(buf: &[u8]) -> Option<T> {
    if buf.len() >= std::mem::size_of::<T>() {
        unsafe { Some(std::ptr::read(buf.as_ptr() as *const T)) }
    } else {
        tracing::warn!(
            "[Vandam MemorySafety] Telemetry details buffer truncated: expected {} bytes, got {}",
            std::mem::size_of::<T>(),
            buf.len()
        );
        None
    }
}

impl HeuristicsEngine {
    pub fn new(
        config: Arc<crate::rules::ConfigManager>,
        web_roots: Vec<String>,
        system_shells: std::collections::HashSet<String>,
        ext_tx: Option<tokio::sync::mpsc::Sender<String>>,
    ) -> Self {
        let listening_set = dashmap::DashSet::new();
        for pid in crate::discovery::discover_listening_pids() {
            println!("[Vandam Startup] Discovered listening server PID: {}", pid);
            listening_set.insert(pid);
        }
        let audit_mode = std::env::var("VANDAM_AUDIT")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if audit_mode {
            println!("[Vandam Heuristics] Active Mode: AUDIT / COLLECT (No prevention containment will be executed)");
        } else {
            println!("[Vandam Heuristics] Active Mode: PREVENTION / ENFORCEMENT");
        }
        Self {
            process_map: Arc::new(DashMap::new()),
            ssh_attempts: Arc::new(DashMap::new()),
            process_seen: Arc::new(DashMap::new()),
            credential_reads: Arc::new(DashMap::new()),
            config,
            web_roots,
            system_shells,
            listening_pids: Arc::new(listening_set),
            audit_mode,
            ext_tx,
            pty_sessions: Arc::new(DashMap::new()),
            pid_to_session: Arc::new(DashMap::new()),
            session_leader_pid: Arc::new(DashMap::new()),
            pid_to_tty: Arc::new(DashMap::new()),
            supply_chain_installs: Arc::new(DashMap::new()),
        }
    }

    pub fn handle_raw_event(&self, raw: TelemetryEventRaw) {
        crate::ebpf_health::track_sequence_number(raw.header.sequence_number);
        if !crate::allowlist::is_seeding_complete() {
            let queue_mutex = get_startup_event_queue();
            if let Ok(mut queue) = queue_mutex.lock() {
                if queue.len() >= 1024 {
                    queue.pop_front();
                }
                queue.push_back(raw);
            }
            return;
        }

        let mut queued = Vec::new();
        {
            let queue_mutex = get_startup_event_queue();
            if let Ok(mut queue) = queue_mutex.lock() {
                if !queue.is_empty() {
                    queued = queue.drain(..).collect();
                }
            }
        }

        for event in queued {
            self.handle_raw_event_internal(event);
        }

        self.handle_raw_event_internal(raw);
    }

    fn handle_raw_event_internal(&self, raw: TelemetryEventRaw) {
        let start_time = std::time::Instant::now();
        let header = raw.header;
        let event_pid = header.pid;

        if crate::allowlist::get_disabled_monitoring_pids().contains(&event_pid) {
            return;
        }

        // An event number this agent has no arm for (core's antitheft and Windows/macOS events).
        let Some(event_type) = header.event_type() else {
            return;
        };

        match event_type {
            // ---------------------------------------------------------------
            // ProcessCreate — S-A shell spawn, S-H unregistered inode exec,
            //                  S-J supply-chain deep subprocess
            // ---------------------------------------------------------------
            EventType::ProcessCreate => {
                let Some(details) = safe_read_details::<ProcessCreateDetails>(&raw.details_buffer)
                else {
                    return;
                };

                let child_pid = details.child_pid;
                let parent_pid = details.real_parent_pid;
                let child_exe = null_terminated_str(&details.child_image_path);
                let child_cmdline = null_terminated_str(&details.child_command_line);

                let mut is_parent_server = false;
                let mut is_parent_install = false;
                let mut install_root_pid = 0u32;
                let mut parent_exe = String::new();
                let mut depth = 0u32;
                let mut parent_sig: Option<std::sync::Arc<str>> = None;

                if let Some(parent) = self.process_map.get(&parent_pid) {
                    is_parent_server =
                        parent.is_listening_server || self.listening_pids.contains(&parent_pid);
                    is_parent_install = parent.is_install_context;
                    install_root_pid = parent.install_root_pid;
                    parent_exe = parent.exe.clone();
                    depth = parent.depth + 1;
                    parent_sig = parent.signature_name.clone();
                } else {
                    // Parent not yet tracked — read exe from /proc/<ppid>/exe (Q-07 / P1-5 fix)
                    if let Ok(path) = std::fs::read_link(format!("/proc/{}/exe", parent_pid)) {
                        parent_exe = path.to_string_lossy().to_string();
                        parent_sig = detect_signature_name(&parent_exe, &self.config);
                    }
                    if !parent_exe.is_empty()
                        && (self.config.is_web_process(&parent_exe)
                            || self.listening_pids.contains(&parent_pid))
                    {
                        is_parent_server = true;
                    }
                }

                let is_parent_cp = if let Some(ref sig) = parent_sig {
                    crate::control_panel_discovery::is_control_panel_signature(sig)
                } else {
                    false
                };
                if is_parent_cp {
                    is_parent_server = false;
                }

                // Check for PID reuse anomaly without preceding ProcessStop
                if let Some(existing) = self.process_map.get(&child_pid) {
                    if existing.exe != child_exe && !existing.exe.is_empty() {
                        self.emit_alert(
                            "Warning.Process.PIDReuse",
                            "WARNING",
                            child_pid,
                            &child_exe,
                            &child_cmdline,
                            &parent_exe,
                            parent_pid,
                            "REBIND",
                            &format!("PID reuse anomaly: PID {} recycled from '{}' to '{}' without exit signal", child_pid, existing.exe, child_exe),
                        );
                    }
                }

                // Update last-seen for TTL eviction (P1-13)
                self.process_seen.insert(child_pid, Utc::now().timestamp());

                // Classify child
                let mut is_child_server = self.config.is_web_process(&child_exe)
                    || self.listening_pids.contains(&child_pid);
                let child_lower = child_exe.to_lowercase();

                let is_child_install = self.config.installer_binaries().iter().any(|kw| {
                    let kw_lower = kw.to_lowercase();
                    child_lower == kw_lower || child_lower.ends_with(&format!("/{}", kw_lower))
                });

                let is_top_level_install = is_child_install && !is_parent_install;
                let final_install_root = if is_top_level_install {
                    child_pid
                } else {
                    install_root_pid
                };

                let child_sig = crate::generic_discovery::get_signature_for_pid(child_pid)
                    .or_else(|| detect_signature_name(&child_exe, &self.config))
                    .or(parent_sig);

                let is_child_cp = if let Some(ref sig) = child_sig {
                    crate::control_panel_discovery::is_control_panel_signature(sig)
                } else {
                    false
                };
                if is_child_cp {
                    is_child_server = false;
                }

                let child_service = crate::discovery::detect_systemd_service_for_pid(child_pid);
                self.process_map.insert(
                    child_pid,
                    ProcessNode {
                        pid: child_pid,
                        ppid: parent_pid,
                        exe: child_exe.clone(),
                        cmdline: child_cmdline.clone(),
                        is_listening_server: is_child_server || is_parent_server,
                        is_database: false, // DB children inherit via BPF fork propagation
                        is_install_context: is_child_install || is_parent_install,
                        is_top_level_install,
                        install_root_pid: final_install_root,
                        depth,
                        loaded_scripts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                        signature_name: child_sig,
                        service: child_service,
                    },
                );

                // --- Access page: PTY/interactive-session tracking ---
                crate::pty_session::on_process_create(
                    self, child_pid, parent_pid, &child_exe, &child_cmdline, &parent_exe,
                );

                // --- Supply Chain: package-manager install activity,
                // project inventory, suspicious postinstall behavior, known
                // offline-CVE cross-check. See supply_chain.rs's doc comment
                // for why this returns an action instead of alerting itself.
                match crate::supply_chain::on_process_create(self, child_pid, parent_pid, &child_exe, &child_cmdline) {
                    crate::supply_chain::SupplyChainAction::Alert { threat_type, severity, action, desc } => {
                        self.emit_alert_with_detail(
                            &threat_type, &severity, child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid, &action, &desc, None,
                        );
                    }
                    crate::supply_chain::SupplyChainAction::Kill { threat_type, desc } => {
                        self.terminate_threat_child(child_pid, &child_exe, &child_cmdline, &parent_exe, parent_pid, &threat_type, &desc);
                    }
                    crate::supply_chain::SupplyChainAction::None => {}
                }

                // --- Attacker-tool detection: config-driven via
                // linux_attacker_tools_signatures.json (kinnector-config), not
                // hardcoded. Applies in any process context, per that file's
                // own description — unlike the web-process-scoped checks
                // below, this isn't gated on is_parent_server.
                if let Some(sig) = self.config.lookup_attacker_tool(&child_exe, &child_cmdline) {
                    let threat_type = format!("Threat.Server.AttackerTool.{}", sig.tool_type);
                    let desc = format!(
                        "Known offensive-security tool detected: {} ({})",
                        sig.tool_type, child_exe
                    );
                    if sig.block_execution {
                        self.terminate_threat_child(
                            child_pid,
                            &child_exe,
                            &child_cmdline,
                            &parent_exe,
                            parent_pid,
                            &threat_type,
                            &desc,
                        );
                        return;
                    } else {
                        self.emit_alert(
                            &threat_type,
                            &sig.severity,
                            child_pid,
                            &child_exe,
                            &child_cmdline,
                            &parent_exe,
                            parent_pid,
                            "LOG_ALERT",
                            &desc,
                        );
                    }
                }

                if is_top_level_install {
                    snapshot_lock_files(child_pid, &self.web_roots);
                }
                check_and_alert_ld_preload(
                    child_pid,
                    &child_exe,
                    &child_cmdline,
                    parent_pid,
                    &parent_exe,
                );

                // Propagate parent proxy allowances to newly spawned worker child
                crate::proxy_discovery::propagate_to_new_pid(child_pid, &child_exe, parent_pid);

                // Strict inheritance: if the parent had any explicitly snapshotted allowed paths,
                // the child strictly inherits them. This prevents child processes from expanding
                // scope via changing their CWD.
                if let Some(parent_paths) = crate::allowlist::get_pid_extra_paths().get(&parent_pid)
                {
                    let child_paths_entry = crate::allowlist::get_pid_extra_paths()
                        .entry(child_pid)
                        .or_insert_with(|| dashmap::DashSet::new());
                    for p in parent_paths.iter() {
                        child_paths_entry.insert(p.key().clone());
                    }
                }

                // --- Domain 2: Service Restart Detection ---
                let child_basename = std::path::Path::new(&child_exe)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_lowercase())
                    .unwrap_or_default();

                if self.config.lookup_signature(&child_basename).is_some() {
                    tracing::info!("[Vandam Restart] Recognized service process started: {} (PID {}). Re-running discovery/enforcement.", child_exe, child_pid);
                    let config_clone = Arc::clone(&self.config);
                    tokio::spawn(async move {
                        crate::database_discovery::enforce_database_policies(&config_clone);
                        crate::web_discovery::enforce_web_policies();
                        crate::mail_discovery::enforce_mail_policies();
                        crate::mq_discovery::enforce_mq_policies();
                        crate::filesharing_discovery::enforce_filesharing_policies();
                        crate::infra_discovery::enforce_infra_policies();
                        crate::monitoring_discovery::enforce_monitoring_policies();
                        crate::security_discovery::enforce_security_policies();
                        crate::remote_access_discovery::enforce_remote_access_policies();
                        crate::control_panel_discovery::enforce_control_panel_policies();
                    });
                }

                // --- Audit Git execution & write operations (Fire-and-forget) ---
                let is_parent_monitored_server = is_parent_server
                    || self
                        .process_map
                        .get(&parent_pid)
                        .map(|p| p.signature_name.is_some() && !p.is_install_context)
                        .unwrap_or(false);

                if is_parent_monitored_server && child_basename.as_str() == "git" {
                    if let Some(ref tx) = self.ext_tx {
                        let json = serde_json::json!({"threat_type": "Telemetry.Audit.GitExecution", "pid": child_pid, "exe": child_exe, "cmd": child_cmdline}).to_string();
                        let _ = tx.try_send(json);
                    }
                }

                if child_basename.as_str() == "git" {
                    let cmd_lower = child_cmdline.to_lowercase();
                    let is_write_git = cmd_lower.contains(" commit")
                        || cmd_lower.contains(" add")
                        || cmd_lower.contains(" push")
                        || cmd_lower.contains(" checkout")
                        || cmd_lower.contains(" reset")
                        || cmd_lower.contains(" init")
                        || cmd_lower.contains(" config")
                        || cmd_lower.contains(" rm ");
                    if is_write_git {
                        let ctx = crate::api::resolve_caller_context(parent_pid);
                        if ctx != "god_mode" && ctx != "local_ssh" {
                            if let Some(ref tx) = self.ext_tx {
                                let json = serde_json::json!({"threat_type": "Telemetry.Audit.GitWriteOperation", "pid": child_pid, "exe": child_exe, "cmd": child_cmdline}).to_string();
                                let _ = tx.try_send(json);
                            }
                        }
                    }
                }

                // --- S-A: Web process spawned a shell interpreter ---
                if is_parent_server {
                    if let Some(storage) =
                        crate::storage_discovery::is_in_storage(&std::path::Path::new(&child_exe))
                    {
                        use crate::storage_discovery::StorageRole;
                        if storage.roles.iter().any(|r| {
                            matches!(
                                r,
                                StorageRole::UploadDirectory
                                    | StorageRole::TempDirectory
                                    | StorageRole::SessionStorage
                                    | StorageRole::AppStorage
                                    | StorageRole::CompiledCache
                                    | StorageRole::ObjectPassthrough
                            )
                        }) {
                            self.terminate_threat_child(
                                child_pid,
                                &child_exe,
                                &child_cmdline,
                                &parent_exe,
                                parent_pid,
                                "Threat.Upload.ExecutionFromStorageDir",
                                &format!(
                                    "Process execution attempted from storage directory: {}",
                                    child_exe
                                ),
                            );
                            return;
                        }
                    }

                    let in_tmp = child_exe.starts_with("/tmp/")
                        || child_exe.starts_with("/var/tmp/")
                        || child_exe.starts_with("/dev/shm/");
                    if in_tmp {
                        self.terminate_threat_child(
                            child_pid,
                            &child_exe,
                            &child_cmdline,
                            &parent_exe,
                            parent_pid,
                            "Threat.Upload.ExecutionFromStorageDir",
                            &format!(
                                "Process execution attempted from system temp directory: {}",
                                child_exe
                            ),
                        );
                        return;
                    }
                    let is_shell = self.system_shells.contains(&child_exe)
                        || self.system_shells.contains(&child_lower)
                        || self.system_shells.iter().any(|s| child_exe.ends_with(s));

                    if is_shell {
                        self.terminate_threat_child(
                            child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid,
                            "Threat.Server.ShellSpawnAttempt",
                            "Web process spawned interactive shell interpreter. Terminated child process."
                        );
                    }

                    // --- S-H: Binary execution policy check ---
                    if !child_exe.is_empty() {
                        let is_zero_exec = crate::allowlist::is_pid_zero_execution(parent_pid)
                            || crate::allowlist::is_pid_zero_execution(child_pid);
                        let is_restricted = crate::allowlist::is_pid_restricted_exec(parent_pid)
                            || crate::allowlist::is_git_seeded();

                        if is_zero_exec {
                            // Deny Case A: Strict zero-execution policy violation
                            self.terminate_threat_child(
                                child_pid, &child_exe, &child_cmdline,
                                &parent_exe, parent_pid,
                                "Threat.Server.ZeroExecutionViolation",
                                "Binary execution attempted by process under strict zero-execution policy. Terminated child process."
                            );
                        } else if is_restricted {
                            // Deny Case B: Restricted execution policy violation (unregistered non-system binary)
                            let is_system_path = child_exe.starts_with("/bin/")
                                || child_exe.starts_with("/sbin/")
                                || child_exe.starts_with("/usr/bin/")
                                || child_exe.starts_with("/usr/sbin/")
                                || child_exe.starts_with("/usr/local/bin/")
                                || child_exe.starts_with("/usr/libexec/")
                                || child_exe.starts_with("/lib/")
                                || child_exe.starts_with("/lib64/")
                                || child_exe.starts_with("/usr/lib/")
                                || child_exe.starts_with("/usr/lib64/");

                            if !is_system_path
                                && !crate::allowlist::is_inode_allowed_for_process(
                                    &child_exe,
                                    &self.web_roots,
                                )
                            {
                                self.terminate_threat_child(
                                    child_pid, &child_exe, &child_cmdline,
                                    &parent_exe, parent_pid,
                                    "Threat.Server.ExploitInjection",
                                    "Unregistered binary execution attempted by process under restricted execution policy. Terminated child process."
                                );
                            }
                        }
                    }

                    // --- S-J Trigger 2: Protected binary re-executed by web process ---
                    if self.config.is_protected_binary(&child_exe) {
                        self.terminate_threat_child(
                            child_pid, &child_exe, &child_cmdline,
                            &parent_exe, parent_pid,
                            "Threat.Server.BinaryOrSourcePoisoned",
                            "Web process re-executed a protected server binary. Terminated child process."
                        );
                    }
                }

                // --- S-J: Deep install-context subprocess ---
                if is_parent_install && depth >= 2 {
                    let alert_id = format!("wpn-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: Utc::now().to_rfc3339(),
                        threat_type: "Threat.Server.BinaryOrSourcePoisoned".to_string(),
                        severity: "HIGH".to_string(),
                        confidence: 0.0,
                        container: self.resolve_container_info(child_pid),
                        process: crate::notifications::ProcessInfo {
                            pid: child_pid,
                            exec_path: child_exe.clone(),
                            cmdline: child_cmdline,
                            parent_exec_path: parent_exe,
                            parent_pid,
                            verified_package: Some(crate::allowlist::verify_system_package_binary(&child_exe)),
                            envs: Vec::new(),
                            args: Vec::new(),
                                                    signature_name: None,
                            service: None,
},
                        remediation: crate::notifications::RemediationInfo {
                            action: "AUDIT_WARNING".to_string(),
                            status: format!("Deep subprocess (depth {}) in install context: potential supply chain poisoning.", depth),
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
                    log_and_dispatch(payload);
                }
            }

            // ---------------------------------------------------------------
            // ProcessStop — evict from map
            // ---------------------------------------------------------------
            EventType::ProcessStop => {
                let mut is_top_level = false;
                let mut top_level_node = None;
                if let Some(proc) = self.process_map.get(&event_pid) {
                    if proc.is_top_level_install {
                        is_top_level = true;
                        top_level_node = Some(proc.clone());
                    }
                }

                // Clean up any stale {pid, 0} map entries in BPF
                cleanup_process_bpf_state(event_pid);
                self.credential_reads
                    .retain(|k, _| !k.starts_with(&format!("{}:", event_pid)));

                // Evict the dead process to prevent memory leaks
                self.process_map.remove(&event_pid);
                self.process_seen.remove(&event_pid);
                crate::link_tracker::cleanup_dead_process_links(event_pid);
                crate::pty_session::on_process_stop(self, event_pid);
                crate::supply_chain::on_process_stop(self, event_pid);

                if is_top_level {
                    if let Some(ref node) = top_level_node {
                        check_and_alert_lock_file_mutation(event_pid, &self.web_roots, node);
                    }
                    let root_pid = event_pid;
                    let engine = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                        let mut pids_to_kill = Vec::new();
                        for entry in engine.process_map.iter() {
                            if entry.value().install_root_pid == root_pid
                                && entry.key() != &root_pid
                            {
                                pids_to_kill.push(*entry.key());
                            }
                        }

                        for child_pid in pids_to_kill {
                            if let Some(child_proc) = engine.process_map.get(&child_pid) {
                                let exe = child_proc.exe.clone();
                                let cmd = child_proc.cmdline.clone();
                                let ppid = child_proc.ppid;
                                drop(child_proc);

                                engine.terminate_threat_child(
                                    child_pid, &exe, &cmd, "", ppid,
                                    "Vulnerability.SupplyChain.PersistentProcess",
                                    "Process continued running after package installation completed. Terminated process."
                                );
                            }
                        }
                        engine.process_map.remove(&root_pid);
                        engine.process_seen.remove(&root_pid);
                    });
                } else {
                    self.process_map.remove(&event_pid);
                    self.process_seen.remove(&event_pid);
                }
            }

            // ---------------------------------------------------------------
            // FileOpen — Allowlist enforcement (LFI / unregistered file read)
            //
            // Any file opened by a web-context process MUST have its inode in
            // the git-seeded allowlist.  There is no timing window, no path
            // extension guess, no "sensitive file" list.  The allowlist IS the
            // policy.  Exceptions: the kernel-synthesised /proc and /dev paths
            // are never allowlist-checked (they have no stable inodes).
            // ---------------------------------------------------------------
            EventType::FileOpen => {
                let details: FileOpenDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const FileOpenDetails)
                };
                let path = null_terminated_str(&details.file_path);

                // --- PTY Creation Check ---
                let is_pty_creation =
                    path == "/dev/ptmx" || path == "/dev/pts/ptmx" || path.starts_with("/dev/pts/");
                if is_pty_creation {
                    if let Some(proc) = self.get_or_create_process_node(event_pid) {
                        if proc.is_install_context {
                            let exe = proc.exe.clone();
                            let cmd = proc.cmdline.clone();
                            let ppid = proc.ppid;
                            self.terminate_threat_child(
                                event_pid, &exe, &cmd, "", ppid,
                                "Vulnerability.SupplyChain.PtyReverseShell",
                                "Package install process created pseudo-terminal (PTY) — likely PTY reverse shell. Terminated process tree."
                            );
                            return;
                        }
                        let is_monitored =
                            proc.is_listening_server || proc.signature_name.is_some();
                        if !is_monitored {
                            let alert_id = uuid::Uuid::new_v4().to_string();
                            let payload = crate::notifications::AlertPayload {
                                alert_id,
                                timestamp: Utc::now().to_rfc3339(),
                                threat_type: "Telemetry.Anomaly.PTYCreated".to_string(),
                                severity: "HIGH".to_string(),
                                confidence: 0.9,
                                container: self.resolve_container_info(event_pid),
                                process: crate::notifications::ProcessInfo {
                                    pid: event_pid,
                                    exec_path: proc.exe.clone(),
                                    cmdline: proc.cmdline.clone(),
                                    parent_exec_path: "".to_string(),
                                    parent_pid: proc.ppid,
                                    verified_package: Some(
                                        crate::allowlist::verify_system_package_binary(&proc.exe),
                                    ),
                                    envs: get_process_environ(event_pid),
                                    args: get_process_args(event_pid),
                                    signature_name: None,
                                    service: None,
                                },
                                remediation: crate::notifications::RemediationInfo {
                                    action: "LOG_ALERT".to_string(),
                                    status: format!(
                                        "Unmonitored process created a pseudo-terminal (PTY): {}",
                                        proc.exe
                                    ),
                                    requires_cloud_decision: false,
                                    quarantine: None,
                                },
                                rasp_context: None,
                                origin_tree: self.build_origin_tree(event_pid),
                                network_links: crate::link_tracker::get_process_network_links(
                                    event_pid,
                                ),
                                container_meta: self.build_container_meta(event_pid),
                                site: None,
                                site_source: None,
                                event_detail: None,
                            };
                            if let Some(ref tx) = self.ext_tx {
                                if let Ok(json) = serde_json::to_string(&payload) {
                                    let _ = tx.try_send(json);
                                }
                            }
                        }
                    }
                }

                // Skip kernel virtual filesystems
                if path.starts_with("/proc/")
                    || path.starts_with("/dev/")
                    || path.starts_with("/sys/")
                {
                    return;
                }

                // Skip system-writable scratch dirs — no alert value, causes false
                // positives on PHP sessions, WP transient cache, JVM temp jars, etc.
                if crate::allowlist::is_system_tmp_path(&path) {
                    return;
                }

                // --- Credentials File Read Check ---
                if is_credential_file(&self.config, &path) {
                    if let Some(proc) = self.get_or_create_process_node(event_pid) {
                        let is_monitored =
                            proc.is_listening_server || proc.signature_name.is_some();
                        if !is_monitored {
                            let mut target_pid = event_pid;
                            let mut current_exe = proc.exe.clone();
                            let mut current_cmd = proc.cmdline.clone();
                            let mut current_ppid = proc.ppid;

                            if is_cat_like_or_shell(&current_exe, &current_cmd) {
                                let mut curr_pid = event_pid;
                                while let Some(curr_proc) = self.process_map.get(&curr_pid) {
                                    if !is_cat_like_or_shell(&curr_proc.exe, &curr_proc.cmdline) {
                                        target_pid = curr_pid;
                                        current_exe = curr_proc.exe.clone();
                                        current_cmd = curr_proc.cmdline.clone();
                                        current_ppid = curr_proc.ppid;
                                        break;
                                    }
                                    curr_pid = curr_proc.ppid;
                                    if curr_pid <= 1 {
                                        break;
                                    }
                                }
                            }

                            let is_pkm_valid =
                                crate::allowlist::verify_system_package_binary(&current_exe)
                                    != "unverified";
                            let has_memory_inj = has_memory_injection(target_pid);
                            let is_during_pkm =
                                is_during_package_manager_install(target_pid, &self.process_map);

                            if !is_pkm_valid || has_memory_inj || is_during_pkm {
                                let alert_id = uuid::Uuid::new_v4().to_string();
                                let payload = crate::notifications::AlertPayload {
                                    alert_id,
                                    timestamp: Utc::now().to_rfc3339(),
                                    threat_type: "Telemetry.Anomaly.CredentialRead".to_string(),
                                    severity: "HIGH".to_string(),
                                    confidence: 0.8,
                                    container: self.resolve_container_info(target_pid),
                                    process: crate::notifications::ProcessInfo {
                                        pid: target_pid,
                                        exec_path: current_exe.clone(),
                                        cmdline: current_cmd.clone(),
                                        parent_exec_path: "".to_string(),
                                        parent_pid: current_ppid,
                                        verified_package: Some(
                                            crate::allowlist::verify_system_package_binary(
                                                &current_exe,
                                            ),
                                        ),
                                        envs: get_process_environ(target_pid),
                                        args: get_process_args(target_pid),
                                        signature_name: None,
                                        service: None,
                                    },
                                    remediation: crate::notifications::RemediationInfo {
                                        action: "LOG_ALERT".to_string(),
                                        status: format!(
                                            "Unusual process accessed credentials file: {} -> {}",
                                            current_exe, path
                                        ),
                                        requires_cloud_decision: false,
                                        quarantine: None,
                                    },
                                    rasp_context: None,
                                    origin_tree: self.build_origin_tree(target_pid),
                                    network_links: crate::link_tracker::get_process_network_links(
                                        target_pid,
                                    ),
                                    container_meta: self.build_container_meta(target_pid),
                                    site: None,
                                    site_source: None,
                                    event_detail: None,
                                };
                                if let Some(ref tx) = self.ext_tx {
                                    if let Ok(json) = serde_json::to_string(&payload) {
                                        let _ = tx.try_send(json);
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    let is_server = proc.is_listening_server;
                    let is_install = proc.is_install_context;
                    let exe = proc.exe.clone();
                    let cmd = proc.cmdline.clone();
                    let ppid = proc.ppid;
                    if is_server {
                        let ext = std::path::Path::new(&path)
                            .extension()
                            .and_then(|s| s.to_str())
                            .unwrap_or_default()
                            .to_lowercase();
                        if ext == "php"
                            || ext == "js"
                            || ext == "py"
                            || ext == "rb"
                            || ext == "jar"
                            || ext == "class"
                        {
                            if let Ok(mut list) = proc.loaded_scripts.lock() {
                                if !list.contains(&path) {
                                    if list.len() >= 10 {
                                        list.remove(0);
                                    }
                                    list.push(path.clone());
                                }
                            }
                        }
                    }
                    drop(proc);

                    if is_server {
                        // Check for hardlink LFI targeting sensitive files
                        use std::os::unix::fs::MetadataExt;
                        if let Ok(meta) = std::fs::metadata(&path) {
                            let ino = meta.ino();
                            if self.web_roots.iter().any(|r| path.starts_with(r))
                                && crate::allowlist::is_inode_sensitive(ino)
                            {
                                let alert_id = uuid::Uuid::new_v4().to_string();
                                let reason = format!(
                                    "Web process accessed a hardlink pointing to sensitive system file: {} (Inode: {})",
                                    path, ino
                                );
                                let _ = crate::quarantine::quarantine_file(
                                    &path,
                                    &alert_id,
                                    &reason,
                                    "Threat.Server.HardlinkToSensitiveFile",
                                );
                                self.emit_threat_with_id(
                                    alert_id,
                                    event_pid,
                                    &exe,
                                    &cmd,
                                    "",
                                    ppid,
                                    "Threat.Server.HardlinkToSensitiveFile",
                                    &reason,
                                );
                                return;
                            }
                        }

                        let is_storage_disabled =
                            crate::storage_discovery::is_storage_disabled_for_exe(&exe)
                                || crate::storage_discovery::is_storage_disabled_for_path(
                                    &path,
                                    &self.web_roots,
                                );
                        if is_storage_disabled {
                            crate::allowlist::register_inode(&path);
                            return;
                        }
                        // Check if it's a compiled binary server (Go, Rust, C/C++)
                        let is_compiled = {
                            let stack = crate::discovery::detect_process_stack(event_pid, &exe);
                            stack == "Go (Compiled)"
                                || stack == "Rust (Compiled)"
                                || stack == "Native (C/C++)"
                        };
                        if is_compiled {
                            let in_tmp = path.starts_with("/tmp/")
                                || path.starts_with("/var/tmp/")
                                || path.starts_with("/dev/shm/");
                            let in_cwd = if let Ok(cwd) =
                                std::fs::read_link(format!("/proc/{}/cwd", event_pid))
                            {
                                std::path::Path::new(&path).starts_with(&cwd)
                            } else {
                                false
                            };
                            if in_tmp || in_cwd {
                                let lower_path = path.to_lowercase();
                                let is_so_file =
                                    lower_path.ends_with(".so") || lower_path.contains(".so.");
                                if is_so_file {
                                    let alert_id = uuid::Uuid::new_v4().to_string();
                                    let reason = format!(
                                        "Compiled server process attempted to load shared library (.so) from temp/CWD: {}",
                                        path
                                    );
                                    let _ = crate::quarantine::quarantine_file(
                                        &path,
                                        &alert_id,
                                        &reason,
                                        "Threat.Server.SOInjectionBlocked",
                                    );
                                    self.emit_threat_with_id(
                                        alert_id,
                                        event_pid,
                                        &exe,
                                        &cmd,
                                        "",
                                        ppid,
                                        "Threat.Server.SOInjectionBlocked",
                                        &reason,
                                    );
                                    return;
                                }
                                crate::allowlist::register_dynamic_inode(&path);
                                return;
                            }
                        }

                        if let Some(storage) =
                            crate::storage_discovery::is_in_storage(std::path::Path::new(&path))
                        {
                            if !storage.allow_script_extensions {
                                let lower = path.to_lowercase();
                                let is_script = lower.ends_with(".php")
                                    || lower.ends_with(".py")
                                    || lower.ends_with(".rb")
                                    || lower.ends_with(".pl")
                                    || lower.ends_with(".jsp")
                                    || lower.ends_with(".aspx");
                                if is_script {
                                    let alert_id = uuid::Uuid::new_v4().to_string();
                                    let reason = format!(
                                        "Web process attempted to read/interpret script in storage directory: {}",
                                        path
                                    );
                                    let _ = crate::quarantine::quarantine_file(
                                        &path,
                                        &alert_id,
                                        &reason,
                                        "Threat.Upload.ScriptInterpretationBlocked",
                                    );
                                    self.emit_threat_with_id(
                                        alert_id,
                                        event_pid, &exe, &cmd, "", ppid,
                                        "Threat.Upload.ScriptInterpretationBlocked",
                                        &format!("Web process attempted to interpret script file inside storage directory: {}", path)
                                    );
                                    return;
                                }
                            }
                            // File in storage and script check passed -> register and allow
                            crate::allowlist::register_dynamic_inode(&path);
                            return;
                        }

                        let in_tmp = path.starts_with("/tmp/")
                            || path.starts_with("/var/tmp/")
                            || path.starts_with("/dev/shm/");
                        if in_tmp {
                            let lower = path.to_lowercase();
                            let is_script = lower.ends_with(".php")
                                || lower.ends_with(".py")
                                || lower.ends_with(".rb")
                                || lower.ends_with(".pl")
                                || lower.ends_with(".jsp")
                                || lower.ends_with(".aspx");
                            if is_script {
                                let alert_id = uuid::Uuid::new_v4().to_string();
                                let reason = format!(
                                    "Web process attempted to read/interpret script in system temp directory: {}",
                                    path
                                );
                                let _ = crate::quarantine::quarantine_file(
                                    &path,
                                    &alert_id,
                                    &reason,
                                    "Threat.Upload.ScriptInterpretationBlocked",
                                );
                                self.emit_threat_with_id(
                                    alert_id,
                                    event_pid, &exe, &cmd, "", ppid,
                                    "Threat.Upload.ScriptInterpretationBlocked",
                                    &format!("Web process attempted to interpret script file inside system temp directory: {}", path)
                                );
                                return;
                            } else {
                                crate::allowlist::register_dynamic_inode(&path);
                                return;
                            }
                        }

                        let is_tampered = !crate::allowlist::is_git_seeded()
                            && crate::allowlist::check_walkdir_tampering(&path);
                        if !crate::allowlist::is_inode_allowed_for_process(&path, &self.web_roots)
                            || is_tampered
                        {
                            if crate::allowlist::is_learning_mode() {
                                crate::allowlist::register_inode(&path);
                                return;
                            }
                            let mode = if crate::allowlist::is_git_seeded() {
                                "git-indexed"
                            } else {
                                "startup-walk-indexed"
                            };
                            let alert_id = uuid::Uuid::new_v4().to_string();
                            let reason = if is_tampered {
                                format!(
                                    "Web process read a file whose content changed since startup walk seeding (SHA256 mismatch): {}",
                                    path
                                )
                            } else {
                                format!(
                                    "Web process read a file not present in the {} allowlist: {}",
                                    mode, path
                                )
                            };

                            // Quarantine the file (Heuristic S-B Containment Action)
                            let _ = crate::quarantine::quarantine_file(
                                &path,
                                &alert_id,
                                &reason,
                                "Threat.Server.ProjectFileTampered",
                            );

                            self.emit_threat_with_id(
                                alert_id,
                                event_pid,
                                &exe,
                                &cmd,
                                "",
                                ppid,
                                if is_tampered {
                                    "Threat.Server.ProjectFileTampered"
                                } else {
                                    "Threat.Server.UnregisteredFileRead"
                                },
                                &reason,
                            );
                        }
                    }

                    if is_install {
                        let path_lower = path.to_lowercase();
                        if path_lower.contains("/var/run/docker.sock")
                            || path_lower.contains("/run/containerd/containerd.sock")
                        {
                            self.terminate_threat_child(
                                event_pid, &exe, &cmd, "", ppid,
                                "Vulnerability.SupplyChain.DockerSocketAccess",
                                &format!("Package install process attempted to access container runtime socket: {}", path)
                            );
                            return;
                        }

                        // .env* file read auditing (fire-and-forget warning)
                        let path_basename = std::path::Path::new(&path_lower)
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if path_basename.starts_with(".env") {
                            if let Some(ref proc_node) = self.process_map.get(&event_pid) {
                                let install_root = proc_node.install_root_pid;
                                let tracking_key = format!("{}:{}", install_root, path_lower);
                                if !get_created_envs_cache().contains(&tracking_key) {
                                    let alert_cache_key = format!("{}:{}", event_pid, path_lower);
                                    let alert_cache = get_env_read_alert_cache();
                                    if !alert_cache.contains(&alert_cache_key) {
                                        alert_cache.insert(alert_cache_key);
                                        let payload = crate::notifications::AlertPayload {
                                            alert_id: uuid::Uuid::new_v4().to_string(),
                                            timestamp: chrono::Utc::now().to_rfc3339(),
                                            threat_type: "Warning.SupplyChain.CredentialExfiltrationAttempt".to_string(),
                                            severity: "HIGH".to_string(),
                                            confidence: 0.0,
                                            container: None,
                                            process: crate::notifications::ProcessInfo {
                                                pid: event_pid,
                                                exec_path: exe.clone(),
                                                cmdline: cmd.clone(),
                                                parent_exec_path: "".to_string(),
                                                parent_pid: ppid,
                                                verified_package: None,
                                                envs: Vec::new(),
                                                args: Vec::new(),
                                                                                            signature_name: None,
                                                service: None,
},
                                            remediation: crate::notifications::RemediationInfo {
                                                action: "LOG_ALERT".to_string(),
                                                status: format!("Package installer process attempted to read pre-existing environment secrets file: {}", path),
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
                                        if let Some(ref tx) = self.ext_tx {
                                            if let Ok(json) = serde_json::to_string(&payload) {
                                                let _ = tx.try_send(json);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // FFI/ctypes capability loading check (fire-and-forget warning)
                        let path_basename = std::path::Path::new(&path_lower)
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_default();
                        if path_basename.contains("ffi")
                            || path_basename.contains("ctypes")
                            || path_basename.contains("fiddle")
                        {
                            let cache_key = format!("{}:{}", event_pid, path_lower);
                            let ffi_cache = get_ffi_alert_cache();
                            if !ffi_cache.contains(&cache_key) {
                                ffi_cache.insert(cache_key);
                                let payload = crate::notifications::AlertPayload {
                                    alert_id: uuid::Uuid::new_v4().to_string(),
                                    timestamp: chrono::Utc::now().to_rfc3339(),
                                    threat_type: "Warning.SupplyChain.FFICapabilityLoaded".to_string(),
                                    severity: "HIGH".to_string(),
                                    confidence: 0.0,
                                    container: None,
                                    process: crate::notifications::ProcessInfo {
                                        pid: event_pid,
                                        exec_path: exe.clone(),
                                        cmdline: cmd.clone(),
                                        parent_exec_path: "".to_string(),
                                        parent_pid: ppid,
                                        verified_package: None,
                                        envs: Vec::new(),
                                        args: Vec::new(),
                                                                            signature_name: None,
                                        service: None,
},
                                    remediation: crate::notifications::RemediationInfo {
                                        action: "LOG_ALERT".to_string(),
                                        status: format!("Dynamic installer process loaded foreign function interface (FFI) capability library: {}", path),
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
                                if let Some(ref tx) = self.ext_tx {
                                    if let Ok(json) = serde_json::to_string(&payload) {
                                        let _ = tx.try_send(json);
                                    }
                                }
                            }
                        }

                        // Dynamic credential ownership & access count enforcement
                        let exe_lower = exe.to_lowercase();
                        let exe_basename = std::path::Path::new(&exe_lower)
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_default();

                        let rules = self.config.sensitive_credentials();
                        for rule in rules {
                            if path_lower.contains(&rule.pattern.to_lowercase()) {
                                let is_allowed = rule.allowed_executables.iter().any(|allowed| {
                                    let allowed_lower = allowed.to_lowercase();
                                    exe_basename == allowed_lower
                                        || exe_lower.contains(&format!("/{}", allowed_lower))
                                });

                                if is_allowed {
                                    if !verify_allowed_executable_integrity(
                                        &self.config,
                                        &exe,
                                        &exe_basename,
                                    ) {
                                        self.terminate_threat_child(
                                            event_pid, &exe, &cmd, "", ppid,
                                            "Vulnerability.SupplyChain.CredentialAccessAttempt",
                                            &format!("Package install process attempted to access credentials using tampered/unauthorized binary (executable path: {}): {}", exe, path)
                                        );
                                        return;
                                    }
                                } else {
                                    self.terminate_threat_child(
                                        event_pid, &exe, &cmd, "", ppid,
                                        "Vulnerability.SupplyChain.CredentialAccessAttempt",
                                        &format!("Package install process (executable: {}) attempted to read unauthorized credentials: {}", exe_basename, path)
                                    );
                                    return;
                                }

                                if let Some(max_reads) = rule.max_reads {
                                    let tracking_key = format!("{}:{}", event_pid, rule.pattern);
                                    let mut count =
                                        self.credential_reads.entry(tracking_key).or_insert(0);
                                    *count += 1;
                                    if *count > max_reads {
                                        self.terminate_threat_child(
                                            event_pid, &exe, &cmd, "", ppid,
                                            "Vulnerability.SupplyChain.CredentialAccessAttempt",
                                            &format!("Package install process (executable: {}) exceeded credential read limit ({} > {}): {}", exe_basename, *count, max_reads, path)
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // MemoryMap — S-A anonymous mmap(PROT_EXEC) shellcode (SIGKILL)
            // ---------------------------------------------------------------
            EventType::MemoryMap => {
                let details: MemoryMapDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const MemoryMapDetails)
                };

                let is_anon_exec = (details.prot_flags & PROT_EXEC) != 0
                    && (details.map_flags & MAP_ANONYMOUS) != 0
                    && details.fd == -1;

                if is_anon_exec {
                    if let Some(proc) = self.get_or_create_process_node(event_pid) {
                        if proc.is_listening_server {
                            let exe = proc.exe.clone();
                            let cmd = proc.cmdline.clone();
                            let ppid = proc.ppid;
                            let depth = proc.depth;
                            drop(proc);

                            let is_exempt =
                                has_sys_ptrace_capability(event_pid) || is_jit_runtime(&exe, &cmd);
                            if is_exempt {
                                self.emit_threat(
                                    event_pid, &exe, &cmd, "", ppid,
                                    "Threat.Server.MemoryShellcode",
                                    &format!("Monitored process created anonymous executable memory mapping — permitted JIT/ptrace context (depth {}).", depth)
                                );
                            } else {
                                self.terminate_threat_child(
                                    event_pid, &exe, &cmd, "", ppid,
                                    "Threat.Server.MemoryShellcode",
                                    &format!("Monitored process created anonymous executable memory mapping — likely in-memory shellcode (depth {}). Terminated process.", depth)
                                );
                            }
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // MemoryProtect — S-A anonymous mprotect(PROT_EXEC) shellcode (SIGKILL)
            // ---------------------------------------------------------------
            EventType::MemoryProtect => {
                let details: MemoryProtectDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const MemoryProtectDetails)
                };

                let new_flags = null_terminated_str(&details.prot_flags);
                let old_flags = null_terminated_str(&details.old_prot_flags);

                let made_executable =
                    new_flags.contains("PROT_EXEC") && !old_flags.contains("PROT_EXEC");

                if made_executable {
                    let pid = details.target_pid;
                    if let Some(proc) = self.get_or_create_process_node(pid) {
                        if proc.is_listening_server {
                            let is_anon = is_anonymous_mapping(pid, details.address);
                            if is_anon {
                                let exe = proc.exe.clone();
                                let cmd = proc.cmdline.clone();
                                let ppid = proc.ppid;
                                let depth = proc.depth;
                                drop(proc);

                                let is_exempt =
                                    has_sys_ptrace_capability(pid) || is_jit_runtime(&exe, &cmd);
                                if is_exempt {
                                    self.emit_threat(
                                        pid, &exe, &cmd, "", ppid,
                                        "Threat.Server.MemoryShellcode",
                                        &format!("Monitored process modified anonymous memory mapping protection to make it executable (mprotect PROT_EXEC) — permitted JIT/ptrace context (depth {}).", depth)
                                    );
                                } else {
                                    self.terminate_threat_child(
                                        pid, &exe, &cmd, "", ppid,
                                        "Threat.Server.MemoryShellcode",
                                        &format!("Monitored process modified anonymous memory mapping protection to make it executable (mprotect PROT_EXEC) — likely in-memory shellcode (depth {}). Terminated process.", depth)
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // Dup2 — S-G reverse shell: socket fd dup'd to stdin/stdout (SIGKILL)
            // ---------------------------------------------------------------
            EventType::Dup2 => {
                let details: Dup2Details =
                    unsafe { std::ptr::read(raw.details_buffer.as_ptr() as *const Dup2Details) };

                // old_fd_type == 2 means socket; new_fd == 0/1/2 = stdin/stdout/stderr
                let is_reverse_shell = details.old_fd_type == 2
                    && (details.new_fd == 0 || details.new_fd == 1 || details.new_fd == 2);

                if is_reverse_shell {
                    if let Some(proc) = self.process_map.get(&event_pid) {
                        let is_allowed_exe = self.config.is_dup2_allowed_executable(&proc.exe);
                        let is_parent_allowed =
                            if let Some(parent) = self.process_map.get(&proc.ppid) {
                                self.config.is_dup2_allowed_executable(&parent.exe)
                            } else {
                                false
                            };

                        if is_allowed_exe || is_parent_allowed {
                            tracing::info!(
                                "[Vandam Heuristics] Socket dup2 permitted for configured allowed binary: PID {} ({})",
                                event_pid, proc.exe
                            );
                            return;
                        }

                        if proc.is_listening_server || proc.is_install_context {
                            let exe = proc.exe.clone();
                            let cmd = proc.cmdline.clone();
                            let ppid = proc.ppid;
                            let is_server = proc.is_listening_server;
                            drop(proc);

                            let (threat_type, msg) = if is_server {
                                ("Threat.Server.ReverseShell", "Web process duplicated socket fd to stdin/stdout — classic reverse shell pattern. Terminated process tree.")
                            } else {
                                ("Vulnerability.SupplyChain.ReverseShell", "Package install process duplicated socket fd to stdin/stdout — classic reverse shell pattern. Terminated process tree.")
                            };

                            self.terminate_threat_child(
                                event_pid,
                                &exe,
                                &cmd,
                                "",
                                ppid,
                                threat_type,
                                msg,
                            );
                        }
                    }
                }
            }

            // ---------------------------------------------------------------
            // FileWrite / FileCreate — allowlist enforcement + persistence/S-J
            //
            // A web process writing a file that is NOT in the git allowlist is
            // the canonical unrestricted-upload / RFI-staging pattern.  No
            // timing window needed: the write itself is the indicator.
            // ---------------------------------------------------------------
            EventType::FileWrite | EventType::FileCreate => {
                let path = if event_type == EventType::FileWrite {
                    let d: FileWriteDetails = unsafe {
                        std::ptr::read(raw.details_buffer.as_ptr() as *const FileWriteDetails)
                    };
                    null_terminated_str(&d.file_path)
                } else {
                    let d: crate::types::FileCreateDetails = unsafe {
                        std::ptr::read(
                            raw.details_buffer.as_ptr() as *const crate::types::FileCreateDetails
                        )
                    };
                    null_terminated_str(&d.file_path)
                };

                // Skip kernel virtual filesystems
                if path.starts_with("/proc/")
                    || path.starts_with("/dev/")
                    || path.starts_with("/sys/")
                {
                    return;
                }

                // Skip system-writable scratch dirs — never alert on tmp writes
                if crate::allowlist::is_system_tmp_path(&path) {
                    return;
                }
                let is_profile = is_profile_like_path(&path);

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0u32;
                let mut is_server = false;
                let mut is_install = false;

                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                    is_server = proc.is_listening_server;
                    is_install = proc.is_install_context;
                }

                let path_lower_git = path.to_lowercase();
                if path_lower_git.contains("/.git/config")
                    || path_lower_git.contains("/.git/hooks/")
                {
                    let ctx = crate::api::resolve_caller_context(event_pid);
                    if ctx != "god_mode" && ctx != "local_ssh" {
                        if let Some(ref tx) = self.ext_tx {
                            let json = serde_json::json!({"threat_type": "Telemetry.Audit.GitTamperingAttempt", "pid": event_pid, "exe": exe, "cmd": cmd}).to_string();
                            let _ = tx.try_send(json);
                        }
                    }
                }

                // Block Cron Scheduled path modifications (for both install context and monitored server)
                if (is_install || is_server)
                    && crate::allowlist::is_cron_scheduled_path(std::path::Path::new(&path))
                {
                    let threat_type = if is_install {
                        "Vulnerability.SupplyChain.CronHijackAttempt"
                    } else {
                        "Threat.Server.CronHijackAttempt"
                    };
                    self.terminate_threat_child(
                        event_pid, &exe, &cmd, "", ppid,
                        threat_type,
                        &format!("Process attempted to modify/overwrite a cron-scheduled script or executable: {}", path)
                    );
                    return;
                }

                if is_install {
                    let path_lower = path.to_lowercase();
                    let file_name = std::path::Path::new(&path_lower)
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if file_name.starts_with(".env") {
                        if let Some(proc) = self.process_map.get(&event_pid) {
                            let tracking_key = format!("{}:{}", proc.install_root_pid, path_lower);
                            get_created_envs_cache().insert(tracking_key);
                        }
                    }
                }

                // --- Allowlist enforcement: web process writes unregistered file ---
                if is_server {
                    let in_tmp = path.starts_with("/tmp/")
                        || path.starts_with("/var/tmp/")
                        || path.starts_with("/dev/shm/");
                    if in_tmp {
                        crate::allowlist::register_dynamic_inode(&path);
                        return;
                    }

                    let is_storage_disabled =
                        crate::storage_discovery::is_storage_disabled_for_exe(&exe)
                            || crate::storage_discovery::is_storage_disabled_for_path(
                                &path,
                                &self.web_roots,
                            );
                    if is_storage_disabled {
                        crate::allowlist::register_dynamic_inode(&path);
                        return;
                    }
                    // Check if it's a compiled binary server (Go, Rust, C/C++)
                    let is_compiled = {
                        let stack = crate::discovery::detect_process_stack(event_pid, &exe);
                        stack == "Go (Compiled)"
                            || stack == "Rust (Compiled)"
                            || stack == "Native (C/C++)"
                    };
                    if is_compiled {
                        let is_self_modification = path == exe;
                        if !is_self_modification {
                            let in_cwd = if let Ok(cwd) =
                                std::fs::read_link(format!("/proc/{}/cwd", event_pid))
                            {
                                std::path::Path::new(&path).starts_with(&cwd)
                            } else {
                                false
                            };
                            let exe_dir = std::path::Path::new(&exe).parent();
                            let in_exe_dir = if let Some(parent) = exe_dir {
                                std::path::Path::new(&path).starts_with(parent)
                            } else {
                                false
                            };
                            if in_cwd || in_exe_dir {
                                let lower_path = path.to_lowercase();
                                let is_so_file =
                                    lower_path.ends_with(".so") || lower_path.contains(".so.");
                                if is_so_file {
                                    let alert_id = uuid::Uuid::new_v4().to_string();
                                    let reason = format!(
                                        "Compiled server process attempted to write shared library (.so) to CWD/binary directory: {}",
                                        path
                                    );
                                    let _ = crate::quarantine::quarantine_file(
                                        &path,
                                        &alert_id,
                                        &reason,
                                        "Threat.Server.SOInjectionBlocked",
                                    );
                                    self.emit_threat_with_id(
                                        alert_id,
                                        event_pid,
                                        &exe,
                                        &cmd,
                                        "",
                                        ppid,
                                        "Threat.Server.SOInjectionBlocked",
                                        &reason,
                                    );
                                    return;
                                }

                                crate::allowlist::register_dynamic_inode(&path);
                                return;
                            }
                        }
                    }

                    let path_p = std::path::Path::new(&path);
                    if let Some(_storage) = crate::storage_discovery::is_in_storage(path_p) {
                        let alert_id = uuid::Uuid::new_v4().to_string();
                        // Synchronous header scan — no window between write and access decision.
                        crate::storage_discovery::handle_upload_write(&path, &alert_id);

                        if !crate::allowlist::is_git_seeded() {
                            let lower = path.to_lowercase();
                            let is_executable = lower.ends_with(".php")
                                || lower.ends_with(".phtml")
                                || lower.ends_with(".php3")
                                || lower.ends_with(".php4")
                                || lower.ends_with(".php5")
                                || lower.ends_with(".php7")
                                || lower.ends_with(".phar")
                                || lower.ends_with(".py")
                                || lower.ends_with(".rb")
                                || lower.ends_with(".pl")
                                || lower.ends_with(".sh")
                                || lower.ends_with(".jsp")
                                || lower.ends_with(".cgi")
                                || lower.ends_with(".aspx")
                                || lower.ends_with(".lua")
                                || lower.ends_with(".ts")
                                || lower.ends_with(".mjs")
                                || lower.ends_with(".cjs")
                                || lower.ends_with(".groovy")
                                || lower.ends_with(".cfm")
                                || lower.ends_with(".rhtml")
                                || lower.ends_with(".erb")
                                || lower.ends_with(".volt")
                                || lower.ends_with(".twig")
                                || lower.ends_with(".blade.php")
                                || lower.ends_with(".shtml");

                            if is_executable {
                                if let Some(file_name) = path_p.file_name().and_then(|f| f.to_str())
                                {
                                    if let Some(parent) = path_p.parent() {
                                        let marker =
                                            parent.join(format!(".uploaded_{}.sh", file_name));
                                        let _ = std::fs::write(
                                            &marker,
                                            b"# Auto-generated marker for uploaded executable",
                                        );
                                    }
                                }
                            }
                        }

                        return;
                    }
                }

                // Grained check: if this process has a matched signature, verify path is
                // within the signature's registered write_path / data_dir scope.
                // Falls back to the global git-seeded inode allowlist if no signature scope.
                let path_p_check = std::path::Path::new(&path);
                let is_tampered = !crate::allowlist::is_git_seeded()
                    && crate::allowlist::check_walkdir_tampering(&path);
                let path_grained_allowed = {
                    let sig = self
                        .process_map
                        .get(&event_pid)
                        .and_then(|p| p.signature_name.clone());
                    let mut base_allowed = if let Some(ref sig_name) = sig {
                        crate::allowlist::is_path_allowed_for_signature(path_p_check, sig_name)
                            || crate::allowlist::is_inode_allowed_for_process(
                                &path,
                                &self.web_roots,
                            )
                    } else {
                        crate::allowlist::is_inode_allowed_for_process(&path, &self.web_roots)
                    };
                    if base_allowed && is_tampered {
                        base_allowed = false;
                    }
                    if base_allowed {
                        true
                    } else if crate::allowlist::is_path_allowed_for_pid(event_pid, path_p_check) {
                        true
                    } else {
                        false
                    }
                };
                if is_server && !path_grained_allowed {
                    if path.ends_with("wp-config.php") {
                        self.emit_alert(
                            "Warning.Server.WordPressConfigModified", "WARNING",
                            event_pid, &exe, &cmd,
                            "", ppid,
                            "LOG_ALERT",
                            &format!("WordPress config modified by web process (permitted with warning): {}", path),
                        );
                        crate::allowlist::register_inode(&path);
                        return;
                    }

                    let mode = if crate::allowlist::is_git_seeded() {
                        "git-indexed"
                    } else {
                        "startup-walk-indexed"
                    };
                    let alert_id = uuid::Uuid::new_v4().to_string();
                    let reason = if is_tampered {
                        format!(
                            "Web process wrote a file whose content changed since startup walk seeding (SHA256 mismatch): {}",
                            path
                        )
                    } else {
                        format!(
                            "Web process wrote a file not present in the {} allowlist: {}",
                            mode, path
                        )
                    };

                    // Quarantine the file (Heuristic S-B / S-H Containment Action)
                    let _ = crate::quarantine::quarantine_file(
                        &path,
                        &alert_id,
                        &reason,
                        "Threat.Server.ProjectFileTampered",
                    );

                    self.emit_threat_with_id(
                        alert_id,
                        event_pid, &exe, &cmd, "", ppid,
                        if is_tampered { "Threat.Server.ProjectFileTampered" } else { "Threat.Server.UnregisteredFileWrite" },
                        &format!(
                            "Web process wrote a file not present in the {} allowlist: {}. \
                             Possible unrestricted upload / RFI staging / webshell drop. File isolated in quarantine.",
                            mode, path
                        ),
                    );
                }

                if is_install
                    && (path.contains("/var/run/docker.sock")
                        || path.contains("/run/containerd/containerd.sock"))
                {
                    self.terminate_threat_child(
                        event_pid, &exe, &cmd, "", ppid,
                        "Vulnerability.SupplyChain.DockerSocketAccess",
                        &format!("Package install process attempted to write to container runtime socket: {}", path),
                    );
                    return;
                }

                // --- S-I: Persistence path / profile monitoring ---
                let is_persistence = is_profile || self.config.is_persistence_path(&path);
                if is_persistence {
                    if is_install {
                        self.terminate_threat_child(
                            event_pid,
                            &exe,
                            &cmd,
                            "",
                            ppid,
                            "Vulnerability.SupplyChain.PersistenceAttempt",
                            &format!(
                                "Package install process attempted to establish persistence: {}",
                                path
                            ),
                        );
                    } else {
                        let threat_type = if is_profile {
                            "Threat.Server.ProfileModified"
                        } else {
                            "Threat.Server.PersistenceTampered"
                        };
                        self.emit_threat(
                            event_pid,
                            &exe,
                            &cmd,
                            "",
                            ppid,
                            threat_type,
                            &format!("Process modified persistence/profile path: {}", path),
                        );
                    }
                }

                // --- S-J Trigger 1: Protected binary written outside package manager ---
                if self.config.is_protected_binary(&path) {
                    let trusted = self.config.is_trusted_cli(
                        std::path::Path::new(&exe),
                        crate::rules::Category::SystemUpdate,
                    );
                    if !trusted {
                        self.emit_alert(
                            "Threat.Server.BinaryOrSourcePoisoned",
                            "CRITICAL",
                            event_pid,
                            &exe,
                            &cmd,
                            "",
                            ppid,
                            "LOG_ALERT",
                            &format!(
                                "Protected binary modified outside package manager: {}",
                                path
                            ),
                        );
                    }
                }

                // If a cron definition file or cron script was modified successfully, refresh the scheduled paths registry
                let path_lower = path.to_lowercase();
                if path_lower == "/etc/crontab"
                    || path_lower.starts_with("/etc/cron.d/")
                    || path_lower.starts_with("/var/spool/cron/")
                    || path_lower.starts_with("/etc/cron.daily/")
                    || path_lower.starts_with("/etc/cron.hourly/")
                    || path_lower.starts_with("/etc/cron.weekly/")
                    || path_lower.starts_with("/etc/cron.monthly/")
                {
                    crate::allowlist::seed_cron_scheduled_paths();
                }
            }

            // ---------------------------------------------------------------
            // FileRename — S-J protected binary swap via rename
            // ---------------------------------------------------------------
            EventType::FileRename => {
                let details: FileRenameDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const FileRenameDetails)
                };
                let src = null_terminated_str(&details.source_path);
                let dest = null_terminated_str(&details.destination_path);

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0u32;
                let mut is_server = false;
                let mut is_install = false;

                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                    is_server = proc.is_listening_server;
                    is_install = proc.is_install_context;
                }

                // Block Cron Scheduled path modifications (for both install context and monitored server)
                if (is_install || is_server)
                    && crate::allowlist::is_cron_scheduled_path(std::path::Path::new(&dest))
                {
                    let threat_type = if is_install {
                        "Vulnerability.SupplyChain.CronHijackAttempt"
                    } else {
                        "Threat.Server.CronHijackAttempt"
                    };
                    self.terminate_threat_child(
                        event_pid, &exe, &cmd, "", ppid,
                        threat_type,
                        &format!("Process attempted to overwrite a cron-scheduled script or executable via rename: {} -> {}", src, dest)
                    );
                    return;
                }

                if is_server {
                    let dst_in_web_root = self.web_roots.iter().any(|r| dest.starts_with(r));
                    if dst_in_web_root {
                        if dest.ends_with("wp-config.php") {
                            self.emit_alert(
                                "Warning.Server.WordPressConfigModified", "WARNING",
                                event_pid, &exe, &cmd,
                                "", ppid,
                                "LOG_ALERT",
                                &format!("WordPress config modified via rename (permitted with warning): {} -> {}", src, dest),
                            );
                            crate::allowlist::register_inode(&dest);
                            return;
                        } else if let Some(_storage) =
                            crate::storage_discovery::is_in_storage(std::path::Path::new(&dest))
                        {
                            let alert_id = uuid::Uuid::new_v4().to_string();
                            crate::storage_discovery::handle_upload_write(&dest, &alert_id);
                        } else {
                            let src_in_tmp = src.starts_with("/tmp/")
                                || src.starts_with("/var/tmp/")
                                || src.starts_with("/dev/shm/");
                            if src_in_tmp {
                                // Allow the rename without quarantine/alert so /tmp movement is seamless
                                return;
                            }

                            let alert_id = uuid::Uuid::new_v4().to_string();
                            let reason = format!(
                                "Web process attempted to write/rename file outside storage: {} -> {}",
                                src, dest
                            );
                            let _ = crate::quarantine::quarantine_file(
                                &dest,
                                &alert_id,
                                &reason,
                                "Threat.Upload.RenameIntoWebRoot",
                            );
                            self.emit_threat_with_id(
                                alert_id,
                                event_pid, &exe, &cmd, "", ppid,
                                "Threat.Upload.RenameIntoWebRoot",
                                &format!("Web process attempted to rename file to a non-storage location in the web root: {} -> {}", src, dest)
                            );
                        }
                    }
                }

                if self.config.is_protected_binary(&dest) {
                    if let Some(proc) = self.process_map.get(&event_pid) {
                        let exe = proc.exe.clone();
                        let cmd = proc.cmdline.clone();
                        let ppid = proc.ppid;
                        let trusted = self.config.is_trusted_cli(
                            std::path::Path::new(&exe),
                            crate::rules::Category::SystemUpdate,
                        );
                        drop(proc);
                        if !trusted {
                            self.emit_alert(
                                "Threat.Server.BinaryOrSourcePoisoned",
                                "CRITICAL",
                                event_pid,
                                &exe,
                                &cmd,
                                "",
                                ppid,
                                "LOG_ALERT",
                                &format!("Protected binary replaced via rename to: {}", dest),
                            );
                        }
                    }
                }

                // If a cron definition file or cron script was modified successfully via rename, refresh the scheduled paths registry
                let dest_lower = dest.to_lowercase();
                if dest_lower == "/etc/crontab"
                    || dest_lower.starts_with("/etc/cron.d/")
                    || dest_lower.starts_with("/var/spool/cron/")
                    || dest_lower.starts_with("/etc/cron.daily/")
                    || dest_lower.starts_with("/etc/cron.hourly/")
                    || dest_lower.starts_with("/etc/cron.weekly/")
                    || dest_lower.starts_with("/etc/cron.monthly/")
                {
                    crate::allowlist::seed_cron_scheduled_paths();
                }
            }

            // ---------------------------------------------------------------
            // NetworkConnect — S-J install-context outbound
            // ---------------------------------------------------------------
            EventType::NetworkConnect => {
                let details: NetworkConnectDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const NetworkConnectDetails)
                };
                let dest_ip = null_terminated_str(&details.destination_ip);
                let dest_port = details.destination_port;

                crate::link_tracker::record_connection(
                    event_pid,
                    "0.0.0.0".to_string(),
                    0,
                    dest_ip.clone(),
                    dest_port,
                );

                if let Some(proc) = self.process_map.get(&event_pid) {
                    if proc.is_install_context && proc.depth >= 2 {
                        let exe = proc.exe.clone();
                        let cmd = proc.cmdline.clone();
                        let ppid = proc.ppid;
                        drop(proc);

                        let alert_id =
                            format!("wpn-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: Utc::now().to_rfc3339(),
                            threat_type: "Threat.Server.BinaryOrSourcePoisoned".to_string(),
                            severity: "HIGH".to_string(),
                            confidence: 0.0,
                            container: self.resolve_container_info(event_pid),
                            process: crate::notifications::ProcessInfo {
                                pid: event_pid,
                                exec_path: exe,
                                cmdline: cmd,
                                parent_exec_path: String::new(),
                                parent_pid: ppid,
                                verified_package: Some(
                                    crate::allowlist::verify_system_package_binary(&String::new()),
                                ),
                                envs: Vec::new(),
                                args: Vec::new(),
                                signature_name: None,
                                service: None,
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "AUDIT_WARNING".to_string(),
                                status: format!(
                                    "InstallContext process initiated outbound connection to {}:{}",
                                    dest_ip, dest_port
                                ),
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
                        log_and_dispatch(payload);
                    }
                }
            }

            // ---------------------------------------------------------------
            // SSHAuth — brute force detection + iptables block
            // ---------------------------------------------------------------
            EventType::SSHAuth => {
                let details: SSHAuthDetails =
                    unsafe { std::ptr::read(raw.details_buffer.as_ptr() as *const SSHAuthDetails) };
                let username = null_terminated_str(&details.username);
                let ip = null_terminated_str(&details.source_ip);
                let status = null_terminated_str(&details.status);

                let status_lower = status.to_lowercase();
                if status_lower == "failure" {
                    let now = Utc::now().timestamp();
                    let mut attempts = self.ssh_attempts.entry(ip.clone()).or_insert_with(Vec::new);
                    attempts.push(now);
                    attempts.retain(|&t| now - t < 60);

                    if attempts.len() > 5 {
                        let len = attempts.len();
                        drop(attempts);

                        let alert_id =
                            format!("ssh-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: Utc::now().to_rfc3339(),
                            threat_type: "Event.Server.SSHAuth (BruteForce)".to_string(),
                            severity: "HIGH".to_string(),
                            confidence: 0.0,
                            container: None,
                            process: crate::notifications::ProcessInfo {
                                pid: 0,
                                exec_path: "/usr/sbin/sshd".to_string(),
                                cmdline: format!("Target user: {}", username),
                                parent_exec_path: "systemd".to_string(),
                                parent_pid: 1,
                                verified_package: None,
                                envs: Vec::new(),
                                args: Vec::new(),
                                                            signature_name: None,
                                service: None,
},
                            remediation: crate::notifications::RemediationInfo {
                                action: "WARN_AND_AUDIT".to_string(),
                                status: format!("SSH brute-force detected from IP {}: {} failures in 60s (Auto-block disabled: Warn & Audit active)", ip, len),
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
                        log_and_dispatch(payload);
                        trigger_firewall_block(&ip);
                    }
                } else if status_lower == "success" {
                    let alert_id = format!("ssh-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0));
                    let payload = crate::notifications::AlertPayload {
                        alert_id,
                        timestamp: Utc::now().to_rfc3339(),
                        threat_type: "Event.Server.SSHAuth".to_string(),
                        severity: "INFO".to_string(),
                        confidence: 0.0,
                        container: None,
                        process: crate::notifications::ProcessInfo {
                            pid: 0,
                            exec_path: "/usr/sbin/sshd".to_string(),
                            cmdline: format!("User: {}", username),
                            parent_exec_path: "systemd".to_string(),
                            parent_pid: 1,
                            verified_package: None,
                            envs: Vec::new(),
                            args: Vec::new(),
                            signature_name: None,
                            service: None,
                        },
                        remediation: crate::notifications::RemediationInfo {
                            action: "LOG_ALERT".to_string(),
                            status: format!(
                                "Successful SSH login for user {} from IP {}",
                                username, ip
                            ),
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
                    log_and_dispatch(payload);
                }
            }

            // ---------------------------------------------------------------
            // TerminalCommand — S-G: RCE pattern analysis + audit log
            // ---------------------------------------------------------------
            EventType::TerminalCommand => {
                let details: TerminalCommandDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const TerminalCommandDetails)
                };
                let tty = null_terminated_str(&details.tty_device);
                let cmd = null_terminated_str(&details.command);
                let cmd_lower = cmd.to_lowercase();

                // Always audit-log
                let log_entry = serde_json::json!({
                    "ts": Utc::now().to_rfc3339(),
                    "event": "TerminalCommand",
                    "pid": event_pid,
                    "tty": tty,
                    "command": cmd
                });
                if let Ok(s) = serde_json::to_string(&log_entry) {
                    let _ = crate::audit::write_to_audit_log(&s);
                }

                // Pattern analysis from config
                for pattern in self.config.terminal_rce_patterns() {
                    if cmd_lower.contains(pattern.as_str()) {
                        let alert_id = uuid::Uuid::new_v4().to_string();
                        let payload = crate::notifications::AlertPayload {
                            alert_id,
                            timestamp: Utc::now().to_rfc3339(),
                            threat_type: "Threat.Server.ShellSpawnAttempt".to_string(),
                            severity: "CRITICAL".to_string(),
                            confidence: 0.0,
                            container: self.resolve_container_info(event_pid),
                            process: crate::notifications::ProcessInfo {
                                pid: event_pid,
                                exec_path: tty.clone(),
                                cmdline: cmd.clone(),
                                parent_exec_path: String::new(),
                                parent_pid: 0,
                                verified_package: Some(
                                    crate::allowlist::verify_system_package_binary(&String::new()),
                                ),
                                envs: Vec::new(),
                                args: Vec::new(),
                                signature_name: None,
                                service: None,
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "LOG_ALERT".to_string(),
                                status: format!(
                                    "Terminal command matched RCE pattern '{}': {}",
                                    pattern, cmd
                                ),
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
                        log_and_dispatch(payload);
                        break;
                    }
                }
            }

            EventType::Listen => {
                if !self.listening_pids.contains(&event_pid) {
                    println!("[Vandam Heuristics] PID {} called listen() -> dynamically promoting to SERVER context.", event_pid);
                    self.listening_pids.insert(event_pid);
                }
                if let Some(mut proc) = self.process_map.get_mut(&event_pid) {
                    if !proc.is_listening_server {
                        proc.is_listening_server = true;
                    }
                }

                // Trigger discovery/enforcement immediately on listen() to prevent policy latency/blind spots
                let config_clone = Arc::clone(&self.config);
                let roots_clone = self.web_roots.clone();
                tokio::spawn(async move {
                    crate::proxy_discovery::discover_and_propagate(&roots_clone);
                    crate::database_discovery::enforce_database_policies(&config_clone);
                    crate::web_discovery::enforce_web_policies();
                    crate::mail_discovery::enforce_mail_policies();
                    crate::mq_discovery::enforce_mq_policies();
                    crate::filesharing_discovery::enforce_filesharing_policies();
                    crate::infra_discovery::enforce_infra_policies();
                    crate::monitoring_discovery::enforce_monitoring_policies();
                    crate::security_discovery::enforce_security_policies();
                    crate::remote_access_discovery::enforce_remote_access_policies();
                });
            }

            // ---------------------------------------------------------------
            // PtraceAttach — I-5: debugger attach from a web process
            //
            // ptrace(PTRACE_ATTACH) or ptrace(PTRACE_SEIZE) issued by a web
            // process is a strong post-exploitation signal.  An attacker who
            // already has code execution inside a web worker may try to pivot
            // into another process (e.g. a privileged side-car) by attaching a
            // debugger.  We SIGKILL the attaching process and emit a HIGH alert.
            // ---------------------------------------------------------------
            EventType::PtraceAttach => {
                let details: PtraceAttachDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const PtraceAttachDetails)
                };
                let mode = null_terminated_str(&details.mode);
                // Copy packed field to local to avoid UB reference to unaligned field
                let target_pid: u32 = details.target_pid;

                // Only act if the attaching process is a tracked web-context process.
                let mut is_server = false;
                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0u32;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    is_server = proc.is_listening_server;
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                }

                if is_server {
                    self.terminate_threat_child(
                        event_pid, &exe, &cmd, "", ppid,
                        "Threat.Server.DebuggerAttach",
                        &format!(
                            "Web process attached a debugger (ptrace mode: {}) to target PID {}. \
                             Possible post-exploitation process pivot. Attaching process terminated.",
                            mode, target_pid
                        ),
                    );
                }
            }

            EventType::NetworkAccept => {
                let details: NetworkAcceptDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const NetworkAcceptDetails)
                };
                let source_port = details.source_port;
                let local_port = details.local_port;

                let ip_str = if details.source_ip[0] == 0x04 {
                    format!(
                        "{}.{}.{}.{}",
                        details.source_ip[1],
                        details.source_ip[2],
                        details.source_ip[3],
                        details.source_ip[4]
                    )
                } else if details.source_ip[0] == 0x06 {
                    (1..17)
                        .map(|i| format!("{:02x}", details.source_ip[i]))
                        .collect::<Vec<_>>()
                        .join(":")
                } else {
                    String::from_utf8_lossy(&details.source_ip)
                        .trim_matches('\0')
                        .to_string()
                };

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                }

                self.emit_alert_with_detail(
                    "Info.Server.InboundConnection",
                    "INFO",
                    event_pid,
                    &exe,
                    &cmd,
                    "",
                    ppid,
                    "LOG_INFO",
                    &format!(
                        "Inbound connection accepted from {}:{} to local port {}",
                        ip_str, source_port, local_port
                    ),
                    Some(crate::notifications::AlertEventDetail::NetworkAccept {
                        source_ip: ip_str.clone(),
                        source_port,
                        local_port,
                    }),
                );
            }

            EventType::DNSQuery => {
                let details: DNSQueryDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const DNSQueryDetails)
                };

                let mut query = String::new();
                let mut idx = 0;
                while idx < 127 {
                    let len = details.query_name[idx] as usize;
                    if len == 0 || idx + len + 1 > 127 {
                        break;
                    }
                    if !query.is_empty() {
                        query.push('.');
                    }
                    for i in 0..len {
                        let c = details.query_name[idx + 1 + i];
                        if c >= 32 && c <= 126 {
                            query.push(c as char);
                        }
                    }
                    idx += len + 1;
                }

                if query.is_empty() {
                    query = String::from_utf8_lossy(&details.query_name)
                        .trim_matches('\0')
                        .to_string();
                }

                let ip_str = if details.server_ip[0] == 0x04 {
                    format!(
                        "{}.{}.{}.{}",
                        details.server_ip[1],
                        details.server_ip[2],
                        details.server_ip[3],
                        details.server_ip[4]
                    )
                } else if details.server_ip[0] == 0x06 {
                    (1..17)
                        .map(|i| format!("{:02x}", details.server_ip[i]))
                        .collect::<Vec<_>>()
                        .join(":")
                } else {
                    String::new()
                };
                let server_port = details.server_port;

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                }

                self.emit_alert_with_detail(
                    "Info.Server.DNSQuery",
                    "INFO",
                    event_pid,
                    &exe,
                    &cmd,
                    "",
                    ppid,
                    "LOG_INFO",
                    &format!(
                        "Process resolved DNS query for domain '{}' via DNS server {}:{}",
                        query, ip_str, server_port
                    ),
                    Some(crate::notifications::AlertEventDetail::DnsQuery {
                        domain: query.clone(),
                        server_ip: ip_str.clone(),
                        server_port,
                    }),
                );
            }

            EventType::FileDelete => {
                let details: FileDeleteDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const FileDeleteDetails)
                };
                let path = String::from_utf8_lossy(&details.file_path)
                    .trim_matches('\0')
                    .to_string();

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                let mut is_server = false;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                    is_server = proc.is_listening_server;
                }

                let is_critical_dir = path.starts_with("/bin/")
                    || path.starts_with("/sbin/")
                    || path.starts_with("/usr/bin/")
                    || path.starts_with("/usr/sbin/")
                    || path.starts_with("/lib/")
                    || path.starts_with("/lib64/")
                    || path.starts_with("/etc/")
                    || path.contains("access.log")
                    || path.contains("auth.log")
                    || path.contains("secure")
                    || path.starts_with("/var/quarantine/");

                if is_critical_dir {
                    if is_server {
                        self.terminate_threat_child(
                            event_pid,
                            &exe,
                            &cmd,
                            "",
                            ppid,
                            "Threat.Server.CriticalFileDeleted",
                            &format!("Web process deleted critical system file or log: {}", path),
                        );
                    } else {
                        self.emit_alert_with_detail(
                            "Warning.Server.CriticalFileDeleted",
                            "WARNING",
                            event_pid,
                            &exe,
                            &cmd,
                            "",
                            ppid,
                            "LOG_WARNING",
                            &format!("Critical file deleted: {}", path),
                            Some(crate::notifications::AlertEventDetail::FileDelete {
                                path: path.clone(),
                                is_critical_dir,
                            }),
                        );
                    }
                }

                // If a cron definition file was deleted, refresh the scheduled paths registry
                let path_lower = path.to_lowercase();
                if path_lower == "/etc/crontab"
                    || path_lower.starts_with("/etc/cron.d/")
                    || path_lower.starts_with("/var/spool/cron/")
                    || path_lower.starts_with("/etc/cron.daily/")
                    || path_lower.starts_with("/etc/cron.hourly/")
                    || path_lower.starts_with("/etc/cron.weekly/")
                    || path_lower.starts_with("/etc/cron.monthly/")
                {
                    crate::allowlist::seed_cron_scheduled_paths();
                }
            }

            EventType::SignalDelivery => {
                let details: SignalDeliveryDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const SignalDeliveryDetails)
                };
                let target_pid = details.target_pid;
                let sig = details.signal;

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                }

                let mut target_exe = String::new();
                if let Some(tproc) = self.process_map.get(&target_pid) {
                    target_exe = tproc.exe.clone();
                }

                self.emit_alert_with_detail(
                    "Warning.Server.SignalDelivery",
                    "WARNING",
                    event_pid,
                    &exe,
                    &cmd,
                    "",
                    ppid,
                    "LOG_WARNING",
                    &format!(
                        "Process sent signal {} to target PID {} ({})",
                        sig, target_pid, target_exe
                    ),
                    Some(crate::notifications::AlertEventDetail::Signal {
                        target_pid,
                        signal: sig,
                    }),
                );
            }

            EventType::PrivilegeChange => {
                let details: PrivilegeChangeDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const PrivilegeChangeDetails)
                };
                let old_uid = details.old_uid;
                let new_uid = details.new_uid;

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                }

                if old_uid != 0 && new_uid == 0 {
                    self.terminate_threat_child(
                        event_pid,
                        &exe,
                        &cmd,
                        "",
                        ppid,
                        "Threat.Server.PrivilegeEscalation",
                        &format!(
                            "Monitored process escalated privileges from UID {} to root (UID 0)",
                            old_uid
                        ),
                    );
                } else {
                    self.emit_alert(
                        "Info.Server.PrivilegeChange",
                        "INFO",
                        event_pid,
                        &exe,
                        &cmd,
                        "",
                        ppid,
                        "LOG_INFO",
                        &format!("Process changed UID from {} to {}", old_uid, new_uid),
                    );
                }
            }

            EventType::IPCAccess => {
                let details: IPCAccessDetails = unsafe {
                    std::ptr::read(raw.details_buffer.as_ptr() as *const IPCAccessDetails)
                };
                let shmid = details.shmid;
                let creator_uid = details.creator_uid;

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                let mut is_server = false;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                    is_server = proc.is_listening_server;
                }

                let is_root_server_process = if is_server {
                    use std::os::unix::fs::MetadataExt;
                    std::fs::metadata(format!("/proc/{}", event_pid))
                        .map(|m| m.uid() == 0)
                        .unwrap_or(false)
                } else {
                    false
                };

                if is_server && creator_uid == 0 && !is_root_server_process {
                    self.terminate_threat_child(
                        event_pid, &exe, &cmd, "", ppid,
                        "Threat.Server.IPCSecurityViolation",
                        &format!("Web process attached to shared memory segment {} owned by root (possible credential theft/memory scraping)", shmid)
                    );
                } else {
                    self.emit_alert(
                        "Info.Server.IPCAccess",
                        "INFO",
                        event_pid,
                        &exe,
                        &cmd,
                        "",
                        ppid,
                        "LOG_INFO",
                        &format!(
                            "Process attached to shared memory segment {} (creator UID: {})",
                            shmid, creator_uid
                        ),
                    );
                }
            }

            EventType::FileBatch => {
                let details: crate::types::FileBatchDetails = unsafe {
                    std::ptr::read(
                        raw.details_buffer.as_ptr() as *const crate::types::FileBatchDetails
                    )
                };
                let op_type = details.op_type;
                let count = details.count;
                let file_path = null_terminated_str(&details.file_path);

                let mut exe = String::new();
                let mut cmd = String::new();
                let mut ppid = 0;
                if let Some(proc) = self.get_or_create_process_node(event_pid) {
                    exe = proc.exe.clone();
                    cmd = proc.cmdline.clone();
                    ppid = proc.ppid;
                }

                let (op_str, threat_type) = match op_type {
                    1 => ("READ", "Telemetry.Batch.FileActivity"),
                    2 => ("WRITE", "Telemetry.Batch.FileActivity"),
                    3 => ("DELETE", "Telemetry.Batch.FileActivity"),
                    4 => ("MMAP_EXEC", "Telemetry.Batch.FileActivity"),
                    5 => ("EXEC", "Telemetry.Batch.FileActivity"),
                    6 => ("SYSCALL", "Telemetry.Batch.FileActivity"),
                    7 => ("NETWORK_CONNECT", "Telemetry.Batch.NetworkActivity"),
                    8 => ("DNS_QUERY", "Telemetry.Batch.NetworkActivity"),
                    _ => ("UNKNOWN", "Telemetry.Batch.UnknownActivity"),
                };

                self.emit_alert(
                    threat_type,
                    "INFO",
                    event_pid,
                    &exe,
                    &cmd,
                    "",
                    ppid,
                    "LOG_INFO",
                    &format!(
                        "Installer/Monitored process batch trace: {} count={}, path={}",
                        op_str, count, file_path
                    ),
                );
            }

            _ => {}
        }

        let elapsed_us = start_time.elapsed().as_micros() as u64;
        crate::perf_monitor::record_event_processed(elapsed_us);
    }

    pub fn build_origin_tree(&self, pid: u32) -> Vec<crate::notifications::ProcessTreeEntry> {
        let mut tree = Vec::new();
        let mut current_pid = pid;
        while current_pid > 1 {
            if let Some(proc) = self.process_map.get(&current_pid) {
                let pkg = crate::allowlist::verify_system_package_binary(&proc.exe);
                let ports = crate::discovery::get_process_ports_with_probing(current_pid);
                tree.push(crate::notifications::ProcessTreeEntry {
                    pid: current_pid,
                    ppid: proc.ppid,
                    exec_path: proc.exe.clone(),
                    cmdline: proc.cmdline.clone(),
                    verified_package: Some(pkg),
                    service: proc.service.clone(),
                    ports,
                });
                current_pid = proc.ppid;
            } else {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", current_pid)) {
                    if let Some(close_paren) = stat.rfind(')') {
                        let rest = &stat[close_paren + 1..].trim();
                        let fields: Vec<&str> = rest.split_whitespace().collect();
                        if let Some(ppid_str) = fields.get(1) {
                            if let Ok(ppid) = ppid_str.parse::<u32>() {
                                let exe = std::fs::read_link(format!("/proc/{}/exe", current_pid))
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|_| "unknown".to_string());
                                let pkg = crate::allowlist::verify_system_package_binary(&exe);
                                let service =
                                    crate::discovery::detect_systemd_service_for_pid(current_pid);
                                let ports =
                                    crate::discovery::get_process_ports_with_probing(current_pid);
                                tree.push(crate::notifications::ProcessTreeEntry {
                                    pid: current_pid,
                                    ppid,
                                    exec_path: exe,
                                    cmdline: "unknown".to_string(),
                                    verified_package: Some(pkg),
                                    service,
                                    ports,
                                });
                                current_pid = ppid;
                                continue;
                            }
                        }
                    }
                }
                break;
            }
        }
        tree
    }

    pub fn build_container_meta(&self, pid: u32) -> Option<crate::notifications::ContainerMeta> {
        let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
        for line in cgroup.lines() {
            if line.contains("/docker/") {
                if let Some(id_part) = line.split("/docker/").nth(1) {
                    let id = id_part.trim();
                    let short_id = if id.len() > 12 { &id[..12] } else { id };
                    // Look up the real name/image from the live Docker-API-populated
                    // registry (same one `discovery::get_process_container_name`
                    // uses) instead of fabricating a placeholder — falls back to a
                    // synthesized name/image only if the container isn't (yet)
                    // in the registry, e.g. discovery hasn't run since it started.
                    let (container_name, container_image) =
                        crate::discovery::get_active_containers()
                            .get(short_id)
                            .map(|c| (c.name.clone(), c.image.clone()))
                            .unwrap_or_else(|| {
                                (format!("docker-{}", short_id), "unknown".to_string())
                            });
                    return Some(crate::notifications::ContainerMeta {
                        container_id: short_id.to_string(),
                        container_name,
                        container_image,
                        orchestrator: "docker".to_string(),
                        namespace: None,
                        pod_uid: None,
                    });
                }
            } else if line.contains("/kubepods") {
                let parts: Vec<&str> = line.split('/').collect();
                if let Some(pod_part) = parts.iter().find(|p| p.starts_with("pod")) {
                    return Some(crate::notifications::ContainerMeta {
                        container_id: pod_part.to_string(),
                        container_name: pod_part.to_string(),
                        container_image: "k8s_pod".to_string(),
                        orchestrator: "kubernetes".to_string(),
                        namespace: Some("default".to_string()),
                        pod_uid: Some(pod_part.to_string()),
                    });
                }
            }
        }
        None
    }

    pub fn get_loaded_scripts_for_pid(&self, pid: u32) -> Option<Vec<String>> {
        self.process_map.get(&pid).and_then(|p| {
            if let Ok(list) = p.loaded_scripts.lock() {
                if !list.is_empty() {
                    return Some(list.clone());
                }
            }
            None
        })
    }

    pub fn report_in_memory_execution(&self, pid: u32, function: &str, code: &str) {
        self.report_in_memory_execution_with_context(
            pid,
            function,
            code,
            serde_json::Value::Null,
            "",
            "",
        );
    }

    pub fn report_in_memory_execution_with_context(
        &self,
        pid: u32,
        function: &str,
        code: &str,
        trace: serde_json::Value,
        lang_hint: &str,
        web_root_hint: &str,
    ) {
        let (exe, cmdline, parent_exe, parent_pid) = if let Some(proc) = self.process_map.get(&pid)
        {
            let (p_exe, p_pid) = if let Some(parent) = self.process_map.get(&proc.ppid) {
                (parent.exe.clone(), parent.pid)
            } else {
                ("".to_string(), proc.ppid)
            };
            (proc.exe.clone(), proc.cmdline.clone(), p_exe, p_pid)
        } else {
            let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "php".to_string());
            (exe, "in-memory eval".to_string(), "".to_string(), 0)
        };

        let snippet = if code.len() > 120 { &code[..120] } else { code };
        let desc = format!(
            "In-memory dynamic code execution detected via RASP ({}): '{}'",
            function, snippet
        );

        let web_root = if !web_root_hint.is_empty() {
            web_root_hint
        } else {
            self.web_roots
                .first()
                .map(|s| s.as_str())
                .unwrap_or("/var/www/html")
        };

        let rich_ctx = crate::discovery::build_rich_rasp_context(pid, function, lang_hint, web_root, trace);

        let alert_id = uuid::Uuid::new_v4().to_string();
        crate::tls_buffer::flush_on_alert(pid, &alert_id);

        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: "Threat.Server.InMemoryCode".to_string(),
            severity: "CRITICAL".to_string(),
            confidence: 0.90,
            container: self.resolve_container_info(pid),
            process: crate::notifications::ProcessInfo {
                pid,
                exec_path: exe.clone(),
                cmdline,
                parent_exec_path: parent_exe,
                parent_pid,
                verified_package: Some(crate::allowlist::verify_system_package_binary(&exe)),
                envs: Vec::new(),
                args: Vec::new(),
                signature_name: None,
                service: None,
            },
            remediation: crate::notifications::RemediationInfo {
                action: "LOG_ALERT".to_string(),
                status: desc,
                requires_cloud_decision: false,
                quarantine: None,
            },
            rasp_context: Some(rich_ctx),
            origin_tree: self.build_origin_tree(pid),
            network_links: crate::link_tracker::get_process_network_links(pid),
            container_meta: self.build_container_meta(pid),
            site: None,
            site_source: None,
            event_detail: None,
        };
        log_and_dispatch(payload);
    }

    pub fn report_rasp_blocked(
        &self,
        pid: u32,
        function: &str,
        path: &str,
        trace: serde_json::Value,
    ) {
        let (exe, cmdline, parent_exe, parent_pid) = if let Some(proc) = self.process_map.get(&pid)
        {
            let (p_exe, p_pid) = if let Some(parent) = self.process_map.get(&proc.ppid) {
                (parent.exe.clone(), parent.pid)
            } else {
                ("".to_string(), proc.ppid)
            };
            (proc.exe.clone(), proc.cmdline.clone(), p_exe, p_pid)
        } else {
            let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| "php".to_string());
            (exe, "rasp blocked call".to_string(), "".to_string(), 0)
        };

        let desc = format!(
            "Synchronous execution of {}('{}') BLOCKED by RASP engine",
            function, path
        );
        let web_root = self
            .web_roots
            .first()
            .map(|s| s.as_str())
            .unwrap_or("/var/www/html");
        let rich_ctx = crate::discovery::build_rich_rasp_context(pid, function, "", web_root, trace);

        let alert_id = uuid::Uuid::new_v4().to_string();
        crate::tls_buffer::flush_on_alert(pid, &alert_id);

        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: "Threat.Server.RaspBlocked".to_string(),
            severity: "CRITICAL".to_string(),
            confidence: 1.0,
            container: self.resolve_container_info(pid),
            process: crate::notifications::ProcessInfo {
                pid,
                exec_path: exe.clone(),
                cmdline,
                parent_exec_path: parent_exe,
                parent_pid,
                verified_package: Some(crate::allowlist::verify_system_package_binary(&exe)),
                envs: Vec::new(),
                args: Vec::new(),
                signature_name: None,
                service: None,
            },
            remediation: crate::notifications::RemediationInfo {
                action: "BLOCKED_BY_RASP".to_string(),
                status: desc,
                requires_cloud_decision: false,
                quarantine: None,
            },
            rasp_context: Some(rich_ctx),
            origin_tree: self.build_origin_tree(pid),
            network_links: crate::link_tracker::get_process_network_links(pid),
            container_meta: self.build_container_meta(pid),
            site: None,
            site_source: None,
            event_detail: None,
        };
        log_and_dispatch(payload);
    }

    /// Emit a structured threat alert for a process event.
    /// Never sends any signal — observation only.
    fn emit_threat(
        &self,
        pid: u32,
        exe: &str,
        cmdline: &str,
        parent_exe: &str,
        parent_pid: u32,
        threat_type: &str,
        desc: &str,
    ) {
        let alert_id = uuid::Uuid::new_v4().to_string();
        self.emit_threat_with_id(
            alert_id,
            pid,
            exe,
            cmdline,
            parent_exe,
            parent_pid,
            threat_type,
            desc,
        );
    }

    pub fn emit_threat_with_id(
        &self,
        alert_id: String,
        pid: u32,
        exe: &str,
        cmdline: &str,
        parent_exe: &str,
        parent_pid: u32,
        threat_type: &str,
        desc: &str,
    ) {
        // Trigger Forensic TLS Buffer flush (Paid tier)
        crate::tls_buffer::flush_on_alert(pid, &alert_id);

        let (signature_name, service) = self
            .process_map
            .get(&pid)
            .map(|node| {
                (
                    node.signature_name.as_ref().map(|s| s.to_string()),
                    node.service.clone(),
                )
            })
            .unwrap_or((None, None));

        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: threat_type.to_string(),
            severity: "CRITICAL".to_string(),
            confidence: 0.0,
            container: self.resolve_container_info(pid),
            process: crate::notifications::ProcessInfo {
                pid,
                exec_path: exe.to_string(),
                cmdline: cmdline.to_string(),
                parent_exec_path: parent_exe.to_string(),
                parent_pid,
                verified_package: Some(crate::allowlist::verify_system_package_binary(&parent_exe)),
                envs: Vec::new(),
                args: Vec::new(),
                signature_name,
                service,
            },
            remediation: crate::notifications::RemediationInfo {
                action: "LOG_ALERT".to_string(),
                status: desc.to_string(),
                requires_cloud_decision: false,
                quarantine: None,
            },
            rasp_context: None,
            origin_tree: self.build_origin_tree(pid),
            network_links: crate::link_tracker::get_process_network_links(pid),
            container_meta: self.build_container_meta(pid),
            site: None,
            site_source: None,
            event_detail: None,
        };
        log_and_dispatch(payload);
    }
}

pub fn safe_kill_process(pid: u32, sig: i32) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let res = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0u32) };
        if res >= 0 {
            let pidfd = res as libc::c_int;
            let kill_res = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    sig,
                    std::ptr::null::<libc::siginfo_t>(),
                    0u32,
                )
            };
            unsafe {
                libc::close(pidfd);
            }
            if kill_res == 0 {
                return Ok(());
            } else {
                return Err(std::io::Error::last_os_error());
            }
        }
    }

    let res = unsafe { libc::kill(pid as i32, sig) };
    if res == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl HeuristicsEngine {
    fn terminate_threat_child(
        &self,
        child_pid: u32,
        child_exe: &str,
        child_cmdline: &str,
        parent_exe: &str,
        parent_pid: u32,
        threat_type: &str,
        desc: &str,
    ) {
        // Check if the target process is a legitimate server/web process itself.
        // We do NOT SIGKILL web servers or databases to prevent production outages.
        let mut is_server =
            self.listening_pids.contains(&child_pid) || self.config.is_web_process(child_exe);

        if !is_server {
            if let Some(node) = self.process_map.get(&child_pid) {
                // If it is a database or a web process, don't kill it
                if node.is_database || self.config.is_web_process(&node.exe) {
                    is_server = true;
                }
            }
        }

        let alert_id = uuid::Uuid::new_v4().to_string();

        let action = if is_server {
            tracing::info!("[Vandam Containment] Blocked threat action from Server PID {} ({}) - bypassing SIGKILL to keep production running", child_pid, child_exe);
            "BLOCKED".to_string()
        } else {
            if self.audit_mode || crate::maintenance::is_maintenance_active() {
                println!(
                    "[Vandam Heuristics AUDIT/MAINTENANCE] Would SIGKILL child PID {} ({})",
                    child_pid, child_exe
                );
            } else {
                let _ = safe_kill_process(child_pid, libc::SIGKILL);
            }
            "SIGKILL".to_string()
        };

        // Trigger Forensic TLS Buffer flush (Paid tier)
        crate::tls_buffer::flush_on_alert(child_pid, &alert_id);

        let (signature_name, service) = self
            .process_map
            .get(&child_pid)
            .map(|node| {
                (
                    node.signature_name.as_ref().map(|s| s.to_string()),
                    node.service.clone(),
                )
            })
            .unwrap_or((None, None));

        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: threat_type.to_string(),
            severity: "CRITICAL".to_string(),
            confidence: 0.0,
            container: self.resolve_container_info(child_pid),
            process: crate::notifications::ProcessInfo {
                pid: child_pid,
                exec_path: child_exe.to_string(),
                cmdline: child_cmdline.to_string(),
                parent_exec_path: parent_exe.to_string(),
                parent_pid,
                verified_package: Some(crate::allowlist::verify_system_package_binary(&parent_exe)),
                envs: Vec::new(),
                args: Vec::new(),
                signature_name,
                service,
            },
            remediation: crate::notifications::RemediationInfo {
                action,
                status: if is_server {
                    format!("Action blocked by kernel LSM filter. {}", desc)
                } else {
                    format!("Remediation: SUCCESSFUL. {}", desc)
                },
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
        log_and_dispatch(payload);
    }

    fn emit_alert(
        &self,
        threat_type: &str,
        severity: &str,
        pid: u32,
        exe: &str,
        cmd: &str,
        parent_exe: &str,
        parent_pid: u32,
        action: &str,
        desc: &str,
    ) {
        self.emit_alert_with_detail(
            threat_type,
            severity,
            pid,
            exe,
            cmd,
            parent_exe,
            parent_pid,
            action,
            desc,
            None,
        )
    }

    /// Same as `emit_alert`, but also attaches structured `event_detail` for
    /// the triggering eBPF event (see `notifications::AlertEventDetail`) —
    /// used by the event handlers that already parse a typed details struct
    /// off `raw.details_buffer`, instead of leaving those fields only in the
    /// free-text `desc`/`status` string.
    fn emit_alert_with_detail(
        &self,
        threat_type: &str,
        severity: &str,
        pid: u32,
        exe: &str,
        cmd: &str,
        parent_exe: &str,
        parent_pid: u32,
        action: &str,
        desc: &str,
        event_detail: Option<crate::notifications::AlertEventDetail>,
    ) {
        let alert_id = uuid::Uuid::new_v4().to_string();

        // Trigger Forensic TLS Buffer flush on HIGH or CRITICAL alert (Paid tier)
        let sev_upper = severity.to_uppercase();
        if sev_upper == "HIGH" || sev_upper == "CRITICAL" {
            crate::tls_buffer::flush_on_alert(pid, &alert_id);
        }

        let (signature_name, service) = self
            .process_map
            .get(&pid)
            .map(|node| {
                (
                    node.signature_name.as_ref().map(|s| s.to_string()),
                    node.service.clone(),
                )
            })
            .unwrap_or((None, None));

        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: threat_type.to_string(),
            severity: severity.to_string(),
            confidence: 0.0,
            container: self.resolve_container_info(pid),
            process: crate::notifications::ProcessInfo {
                pid,
                exec_path: exe.to_string(),
                cmdline: cmd.to_string(),
                parent_exec_path: parent_exe.to_string(),
                parent_pid,
                verified_package: Some(crate::allowlist::verify_system_package_binary(&parent_exe)),
                envs: get_process_environ(pid),
                args: get_process_args(pid),
                signature_name,
                service,
            },
            remediation: crate::notifications::RemediationInfo {
                action: action.to_string(),
                status: desc.to_string(),
                requires_cloud_decision: false,
                quarantine: None,
            },
            rasp_context: None,
            origin_tree: Vec::new(),
            network_links: Vec::new(),
            container_meta: None,
            site: None,
            site_source: None,
            event_detail,
        };

        // --- Access page: forward to vandam's session-correlation
        // consumer (Decision 3, Access design plan). A single chokepoint
        // here — rather than scattering this per `EventType` match arm —
        // catches every alert-worthy event for a session-tagged pid, not
        // just File/Network specifically, since any of them is useful
        // context for that session's eventual cloud summary. Severity-gated
        // (skip INFO) so this isn't a new firehose, just forwarding
        // judgments already being made; same `None`-safe, tier-agnostic
        // shape as every other `ext_tx` send in this file — OSS never
        // stores or serves any of this itself.
        if sev_upper != "INFO" {
            if let Some(session_id) = self.pid_to_session.get(&pid).map(|v| v.clone()) {
                if let Some(ref tx) = self.ext_tx {
                    let json = serde_json::json!({
                        "event": "SessionActivity",
                        "session_id": session_id,
                        "pid": pid,
                        "threat_type": payload.threat_type,
                        "severity": payload.severity,
                        "exe": payload.process.exec_path,
                        "desc": payload.remediation.status,
                        "ts": payload.timestamp,
                    })
                    .to_string();
                    let _ = tx.try_send(json);
                }
            }
        }

        log_and_dispatch(payload);
    }

    /// Retrieve a ProcessNode from process_map, or dynamically reconstruct it from /proc
    /// if it's missing (e.g., due to pre-existing startup or telemetry event loss).
    pub fn get_or_create_process_node(&self, pid: u32) -> Option<ProcessNode> {
        if let Some(proc) = self.process_map.get(&pid) {
            return Some(proc.clone());
        }

        // Reconstruct from /proc
        if let Ok(exe_path) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
            let exe = exe_path.to_string_lossy().to_string();

            // Read cmdline
            let cmdline = if let Ok(cmdline_bytes) = std::fs::read(format!("/proc/{}/cmdline", pid))
            {
                cmdline_bytes
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect::<Vec<String>>()
                    .join(" ")
            } else {
                String::new()
            };

            // Read ppid
            let mut ppid = 0;
            if let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid)) {
                for line in status.lines() {
                    if line.starts_with("PPid:") {
                        if let Some(ppid_str) = line.split_whitespace().nth(1) {
                            ppid = ppid_str.parse().unwrap_or(0);
                        }
                        break;
                    }
                }
            }

            let is_server = self.config.is_web_process(&exe) || self.listening_pids.contains(&pid);
            // Check the global PID registry (populated by all discovery modules) first,
            // then fall back to basename matching for processes not yet in the registry.
            let sig_name = crate::generic_discovery::get_signature_for_pid(pid)
                .or_else(|| detect_signature_name(&exe, &self.config));
            let service = crate::discovery::detect_systemd_service_for_pid(pid);
            let node = ProcessNode {
                pid,
                ppid,
                exe,
                cmdline,
                is_listening_server: is_server,
                is_database: false,
                is_install_context: false,
                is_top_level_install: false,
                install_root_pid: 0,
                depth: 1, // default fallback depth
                loaded_scripts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                signature_name: sig_name,
                service,
            };

            // Cache it in process_map to avoid /proc access next time
            self.process_map.insert(pid, node.clone());
            self.process_seen.insert(pid, Utc::now().timestamp());

            Some(node)
        } else {
            None
        }
    }

    /// Evict stale entries from process_map (B-10 / P1-13 fix).
    /// Call this periodically from a background task.
    pub fn evict_stale_processes(&self) {
        const TTL_SECS: i64 = 1800; // 30 minutes
        let now = Utc::now().timestamp();
        let stale_pids: Vec<u32> = self
            .process_seen
            .iter()
            .filter(|entry| now - *entry.value() > TTL_SECS)
            .map(|entry| *entry.key())
            .collect();
        for pid in stale_pids {
            if !std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                self.process_map.remove(&pid);
                self.process_seen.remove(&pid);
            }
        }
    }

    pub fn resolve_container_info(&self, pid: u32) -> Option<crate::notifications::ContainerInfo> {
        let cid = get_container_id(pid)?;
        if let Some(cinfo) = crate::discovery::get_active_containers().get(&cid) {
            Some(cinfo.value().clone())
        } else {
            Some(crate::notifications::ContainerInfo {
                id: cid.clone(),
                name: format!("container-{}", &cid[..std::cmp::min(12, cid.len())]),
                image: "unknown".to_string(),
                image_id: None,
                status: None,
                attached: false,
            })
        }
    }
}

fn get_container_id(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = std::fs::read_to_string(cgroup_path) {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                let path = parts[2];
                if let Some(pos) = path.rfind('/') {
                    let last_part = &path[pos + 1..];
                    let clean_id = last_part
                        .trim_start_matches("cri-containerd-")
                        .trim_start_matches("docker-")
                        .trim_end_matches(".scope");
                    if clean_id.len() == 64 && clean_id.chars().all(|c| c.is_ascii_hexdigit()) {
                        return Some(clean_id[..12].to_string());
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn null_terminated_str(buf: &[u8]) -> String {
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn log_and_dispatch(payload: crate::notifications::AlertPayload) {
    crate::notifications::dispatch_alert(payload);
}

/// B-05 fix: Validate IP address and log audit warning (automatic IP blocking disabled).
fn trigger_firewall_block(ip: &str) {
    let ip_addr = match IpAddr::from_str(ip) {
        Ok(addr) => addr,
        Err(_) => {
            eprintln!(
                "[Vandam Heuristics] Refusing to process invalid IP address: {:?}",
                ip
            );
            return;
        }
    };

    println!(
        "[Vandam Heuristics AUDIT] SSH brute-force detected from IP {}. Automatic IP blocking is DISABLED (Warn & Audit mode). Dispatched security alert.",
        ip_addr
    );
}

fn is_profile_like_path(path: &str) -> bool {
    let path_lower = path.to_lowercase();
    path_lower.ends_with("/.bashrc")
        || path_lower.ends_with("/.profile")
        || path_lower.ends_with("/.bash_profile")
        || path_lower.ends_with("/.bash_login")
        || path_lower.ends_with("/.bash_logout")
        || path_lower.ends_with("/.zshrc")
        || path_lower.ends_with("/.zprofile")
        || path_lower.ends_with("/.zshenv")
        || path_lower.ends_with("/.zlogout")
        || path_lower.contains("/etc/profile")
        || path_lower.ends_with("/etc/bash.bashrc")
        || path_lower.contains("/etc/profile.d/")
}

fn is_anonymous_mapping(pid: u32, address: u64) -> bool {
    let maps_path = format!("/proc/{}/maps", pid);
    let Ok(content) = std::fs::read_to_string(maps_path) else {
        return false;
    };
    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let addr_range = parts[0];
        let inode_str = parts[4];

        let range_parts: Vec<&str> = addr_range.split('-').collect();
        if range_parts.len() != 2 {
            continue;
        }
        let start = u64::from_str_radix(range_parts[0], 16).unwrap_or(0);
        let end = u64::from_str_radix(range_parts[1], 16).unwrap_or(0);

        if address >= start && address < end {
            // Found the memory region!
            // Check if it has inode == 0
            if let Ok(inode) = inode_str.parse::<u64>() {
                if inode == 0 {
                    return true;
                }
            }
            // Check if pathname is empty or anonymous special mapping
            if parts.len() == 5 {
                return true;
            }
            let pathname = parts[5];
            if pathname.starts_with('[') || pathname.is_empty() {
                return true;
            }
            return false;
        }
    }
    false
}

fn cleanup_process_bpf_state(pid: u32) {
    unsafe {
        // Clear maps where userspace might have written start_time = 0
        crate::ffi::delete_map_entry(0, pid, 0); // CategoryFlags
        crate::ffi::delete_map_entry(1, pid, 0); // PendingNetwork
        crate::ffi::delete_map_entry(2, pid, 0); // TrustedRoots
        crate::ffi::delete_map_entry(4, pid, 0); // TaintedProcess
        crate::ffi::delete_map_entry(6, pid, 0); // ProcessThreshold
        crate::ffi::delete_map_entry(9, pid, 0); // PidTreeType
        crate::ffi::delete_map_entry(10, pid, 0); // JvmExceptionPids
        crate::ffi::delete_map_entry(11, pid, 0); // DbOutboundAllowlist
        crate::ffi::delete_map_entry(12, pid, 0); // InfraOutboundAllowlist
        crate::ffi::delete_map_entry(13, pid, 0); // ExecAllowlistMap
        crate::ffi::delete_map_entry(14, pid, 0); // AdminSessionPids
        crate::ffi::delete_map_entry(15, pid, 0); // TrustedAdminBinaries
    }
    // Clean up Rust-side PID registry so recycled PIDs don't inherit a stale signature_name
    crate::generic_discovery::deregister_pid_signature(pid);
}

pub fn detect_signature_name(
    exe: &str,
    config: &crate::rules::ConfigManager,
) -> Option<std::sync::Arc<str>> {
    config.lookup_signature(exe).map(std::sync::Arc::from)
}

fn has_sys_ptrace_capability(pid: u32) -> bool {
    let status_path = format!("/proc/{}/status", pid);
    if let Ok(content) = std::fs::read_to_string(&status_path) {
        for line in content.lines() {
            if line.starts_with("CapEff:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(cap_mask) = u64::from_str_radix(parts[1], 16) {
                        let cap_sys_ptrace_bit = 1 << 19;
                        return (cap_mask & cap_sys_ptrace_bit) != 0;
                    }
                }
            }
        }
    }
    true
}

fn is_jit_runtime(exe: &str, cmdline: &str) -> bool {
    let exe_lower = exe.to_lowercase();
    let cmdline_lower = cmdline.to_lowercase();

    let jit_keywords = [
        "node", "php", "pypy", "hhvm", "java", "jvm", "python", "ruby", "dotnet", "mono", "julia",
        "luajit", "wasmtime", "wasmer", "bun", "deno", "llvm",
    ];

    jit_keywords
        .iter()
        .any(|&kw| exe_lower.contains(kw) || cmdline_lower.contains(kw))
}

static LOCK_FILE_SNAPSHOTS: OnceLock<Arc<dashmap::DashMap<String, String>>> = OnceLock::new();
static FFI_ALERT_CACHE: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();
static PRELOAD_ALERT_CACHE: OnceLock<Arc<dashmap::DashSet<u32>>> = OnceLock::new();

fn get_lock_file_snapshots() -> &'static Arc<dashmap::DashMap<String, String>> {
    LOCK_FILE_SNAPSHOTS.get_or_init(|| Arc::new(dashmap::DashMap::new()))
}

fn get_ffi_alert_cache() -> &'static Arc<dashmap::DashSet<String>> {
    FFI_ALERT_CACHE.get_or_init(|| Arc::new(dashmap::DashSet::new()))
}

fn get_preload_alert_cache() -> &'static Arc<dashmap::DashSet<u32>> {
    PRELOAD_ALERT_CACHE.get_or_init(|| Arc::new(dashmap::DashSet::new()))
}

fn is_manifest_or_lock_file(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "package-lock.json"
            | "package.json"
            | "cargo.lock"
            | "cargo.toml"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "poetry.lock"
            | "pyproject.toml"
            | "setup.py"
            | "requirements.txt"
            | "composer.lock"
            | "composer.json"
            | "gemfile"
            | "go.mod"
    )
}

pub fn snapshot_lock_files(install_pid: u32, web_roots: &[String]) {
    let snapshots = get_lock_file_snapshots();
    for root in web_roots {
        let root_path = std::path::Path::new(root);
        let mut dirs_to_scan = vec![root_path.to_path_buf()];
        if let Some(parent) = root_path.parent() {
            dirs_to_scan.push(parent.to_path_buf());
        }

        for dir in dirs_to_scan {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            let name_lower = name.to_lowercase();
                            if is_manifest_or_lock_file(&name_lower) {
                                if let Ok(content) = std::fs::read_to_string(&path) {
                                    snapshots.insert(
                                        format!("{}_{}", install_pid, path.to_string_lossy()),
                                        content,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn find_lock_file_diff(old: &str, new: &str) -> String {
    let old_lines: std::collections::HashSet<&str> = old.lines().map(|l| l.trim()).collect();
    let mut added = Vec::new();
    for line in new.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !old_lines.contains(trimmed) {
            if added.len() < 10 {
                added.push(line.to_string());
            } else {
                added.push("... (truncated)".to_string());
                break;
            }
        }
    }
    if added.is_empty() {
        "Content changed but no line additions detected".to_string()
    } else {
        format!("Added lines:\n  {}", added.join("\n  "))
    }
}

pub fn check_and_alert_lock_file_mutation(
    install_pid: u32,
    web_roots: &[String],
    proc: &ProcessNode,
) {
    let snapshots = get_lock_file_snapshots();
    let mut mutated = Vec::new();

    for root in web_roots {
        let root_path = std::path::Path::new(root);
        let mut dirs_to_scan = vec![root_path.to_path_buf()];
        if let Some(parent) = root_path.parent() {
            dirs_to_scan.push(parent.to_path_buf());
        }

        for dir in dirs_to_scan {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                            let name_lower = name.to_lowercase();
                            if is_manifest_or_lock_file(&name_lower) {
                                let key = format!("{}_{}", install_pid, path.to_string_lossy());
                                if let Some((_, old_content)) = snapshots.remove(&key) {
                                    if let Ok(new_content) = std::fs::read_to_string(&path) {
                                        if old_content != new_content {
                                            let diff =
                                                find_lock_file_diff(&old_content, &new_content);
                                            mutated.push(format!("{}: {}", path.display(), diff));
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

    if !mutated.is_empty() {
        let reason = format!(
            "Package manager installation completed and lock files were mutated:\n{}",
            mutated.join("\n")
        );

        let payload = crate::notifications::AlertPayload {
            alert_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            threat_type: "Warning.SupplyChain.LockFileMutated".to_string(),
            severity: "HIGH".to_string(),
            confidence: 0.0,
            container: None,
            process: crate::notifications::ProcessInfo {
                pid: proc.pid,
                exec_path: proc.exe.clone(),
                cmdline: proc.cmdline.clone(),
                parent_exec_path: "".to_string(),
                parent_pid: proc.ppid,
                verified_package: None,
                envs: Vec::new(),
                args: Vec::new(),
                signature_name: None,
                service: None,
            },
            remediation: crate::notifications::RemediationInfo {
                action: "LOG_ALERT".to_string(),
                status: reason,
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
}

fn check_and_alert_ld_preload(pid: u32, exe: &str, cmd: &str, ppid: u32, parent_exe: &str) {
    let cache = get_preload_alert_cache();
    if cache.contains(&pid) {
        return;
    }

    if let Ok(env_bytes) = std::fs::read(format!("/proc/{}/environ", pid)) {
        for pair in env_bytes.split(|&b| b == 0) {
            if let Ok(pair_str) = std::str::from_utf8(pair) {
                if pair_str.starts_with("LD_PRELOAD=") {
                    let val = &pair_str["LD_PRELOAD=".len()..];
                    if !val.trim().is_empty() {
                        cache.insert(pid);
                        let payload = crate::notifications::AlertPayload {
                            alert_id: uuid::Uuid::new_v4().to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            threat_type: "Warning.SupplyChain.LDPreloadInjected".to_string(),
                            severity: "HIGH".to_string(),
                            confidence: 0.0,
                            container: None,
                            process: crate::notifications::ProcessInfo {
                                pid,
                                exec_path: exe.to_string(),
                                cmdline: cmd.to_string(),
                                parent_exec_path: parent_exe.to_string(),
                                parent_pid: ppid,
                                verified_package: Some(
                                    crate::allowlist::verify_system_package_binary(&parent_exe),
                                ),
                                envs: Vec::new(),
                                args: Vec::new(),
                                signature_name: None,
                                service: None,
                            },
                            remediation: crate::notifications::RemediationInfo {
                                action: "LOG_ALERT".to_string(),
                                status: format!(
                                    "Process spawned with LD_PRELOAD environment variable set: {}",
                                    val
                                ),
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
                }
            }
        }
    }
}

pub fn scan_preexisting_ld_preloads() {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<u32>() {
                if let Ok(env_bytes) = std::fs::read(format!("/proc/{}/environ", pid)) {
                    for pair in env_bytes.split(|&b| b == 0) {
                        if let Ok(pair_str) = std::str::from_utf8(pair) {
                            if pair_str.starts_with("LD_PRELOAD=") {
                                let val = &pair_str["LD_PRELOAD=".len()..];
                                if !val.trim().is_empty() {
                                    let cmdline =
                                        std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                                            .unwrap_or_default()
                                            .replace('\0', " ");
                                    let exe = std::fs::read_link(format!("/proc/{}/exe", pid))
                                        .map(|p| p.to_string_lossy().to_string())
                                        .unwrap_or_default();

                                    let payload = crate::notifications::AlertPayload {
                                        alert_id: uuid::Uuid::new_v4().to_string(),
                                        timestamp: chrono::Utc::now().to_rfc3339(),
                                        threat_type: "Warning.Server.UnregisteredLibraryLoaded".to_string(),
                                        severity: "HIGH".to_string(),
                                        confidence: 0.0,
                                        container: None,
                                        process: crate::notifications::ProcessInfo {
                                            pid,
                                            exec_path: exe,
                                            cmdline,
                                            parent_exec_path: "".to_string(),
                                            parent_pid: 0,
                                            verified_package: None,
                                            envs: Vec::new(),
                                            args: Vec::new(),
                                                                                    signature_name: None,
                                            service: None,
},
                                        remediation: crate::notifications::RemediationInfo {
                                            action: "LOG_ALERT".to_string(),
                                            status: format!("Pre-existing process detected running with LD_PRELOAD: {}", val),
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
                            }
                        }
                    }
                }
            }
        }
    }
}

static CREATED_ENVS_CACHE: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();
static ENV_READ_ALERT_CACHE: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();

fn get_created_envs_cache() -> &'static Arc<dashmap::DashSet<String>> {
    CREATED_ENVS_CACHE.get_or_init(|| Arc::new(dashmap::DashSet::new()))
}

fn get_env_read_alert_cache() -> &'static Arc<dashmap::DashSet<String>> {
    ENV_READ_ALERT_CACHE.get_or_init(|| Arc::new(dashmap::DashSet::new()))
}

static SYSTEM_BINARY_HASHES: OnceLock<Arc<dashmap::DashMap<String, String>>> = OnceLock::new();

fn get_system_binary_hashes(
    config: &crate::rules::ConfigManager,
) -> &'static Arc<dashmap::DashMap<String, String>> {
    SYSTEM_BINARY_HASHES.get_or_init(|| {
        let map = dashmap::DashMap::new();
        // Dynamically iterate over all configured protected binaries
        for bin in config.protected_binaries() {
            let path_p = std::path::Path::new(&bin);
            let basename = path_p
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_else(|| bin.clone());

            let paths_to_try = if path_p.is_absolute() {
                vec![bin.clone()]
            } else {
                vec![
                    format!("/usr/bin/{}", bin),
                    format!("/bin/{}", bin),
                    format!("/usr/sbin/{}", bin),
                    format!("/sbin/{}", bin),
                ]
            };

            for path in paths_to_try {
                if let Some(hash) = calculate_file_sha256(&path) {
                    map.insert(basename.clone(), hash);
                    break;
                }
            }
        }
        Arc::new(map)
    })
}

fn calculate_file_sha256(path: &str) -> Option<String> {
    if let Ok(content) = std::fs::read(path) {
        if let Ok(digest) = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), &content) {
            return Some(digest.iter().map(|b| format!("{:02x}", b)).collect());
        }
    }
    None
}

fn verify_allowed_executable_integrity(
    config: &crate::rules::ConfigManager,
    exe_path: &str,
    basename: &str,
) -> bool {
    let path = std::path::Path::new(exe_path);
    if !path.exists() {
        return false;
    }

    if let Ok(metadata) = path.metadata() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let uid = metadata.uid();
        let mode = metadata.permissions().mode();

        let is_system_path = exe_path.starts_with("/usr/")
            || exe_path.starts_with("/bin/")
            || exe_path.starts_with("/sbin/")
            || exe_path.starts_with("/opt/");

        let current_uid = nix::unistd::getuid().as_raw();
        if is_system_path && uid != 0 && uid != current_uid && uid >= 1000 {
            tracing::warn!("[Vandam Whitelist Integrity] Blocked access because system binary {} is not owned by root, current user, or system user (owner UID: {})", exe_path, uid);
            return false;
        }

        if (mode & 0o002) != 0 {
            tracing::warn!("[Vandam Whitelist Integrity] Blocked access because binary {} is world-writable (mode: {:o})", exe_path, mode);
            return false;
        }
    }

    // Dynamic config checks for whitelisted/protected binaries integrity
    if config.is_protected_binary(exe_path) {
        let hashes = get_system_binary_hashes(config);
        if let Some(expected_hash) = hashes.get(basename) {
            if let Some(current_hash) = calculate_file_sha256(exe_path) {
                if current_hash != *expected_hash {
                    tracing::warn!("[Vandam Whitelist Integrity] Blocked access because hash of {} does not match authentic startup hash", exe_path);
                    return false;
                }
            } else {
                return false;
            }
        }
    }

    true
}

pub fn is_credential_file(config: &crate::rules::ConfigManager, path: &str) -> bool {
    let lower = path.to_lowercase();
    if lower.ends_with(".env") || lower.contains("/.env.") {
        return true;
    }
    for cred in config.sensitive_credentials() {
        if lower.contains(&cred.pattern.to_lowercase()) {
            return true;
        }
    }
    false
}

pub fn is_cat_like_or_shell(exe: &str, _cmd: &str) -> bool {
    let lower_exe = exe.to_lowercase();
    let basename = std::path::Path::new(&lower_exe)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();
    matches!(
        basename.as_str(),
        "cat"
            | "grep"
            | "egrep"
            | "fgrep"
            | "head"
            | "tail"
            | "awk"
            | "sed"
            | "cut"
            | "tee"
            | "echo"
            | "cp"
            | "mv"
            | "bash"
            | "sh"
            | "zsh"
            | "dash"
            | "ash"
            | "fish"
            | "tcsh"
            | "csh"
            | "vim"
            | "nano"
            | "emacs"
            | "vi"
            | "less"
            | "more"
    )
}

fn has_memory_injection(pid: u32) -> bool {
    if let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
        for line in maps.lines() {
            if line.contains("rwxp") {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 {
                    return true;
                }
            }
        }
    }
    false
}

fn is_during_package_manager_install(pid: u32, process_map: &DashMap<u32, ProcessNode>) -> bool {
    let mut curr = pid;
    while curr > 1 {
        if let Some(proc) = process_map.get(&curr) {
            let exe_lower = proc.exe.to_lowercase();
            if exe_lower.contains("dpkg")
                || exe_lower.contains("apt")
                || exe_lower.contains("rpm")
                || exe_lower.contains("yum")
                || exe_lower.contains("dnf")
                || exe_lower.contains("apk")
                || exe_lower.contains("pacman")
            {
                return true;
            }
            curr = proc.ppid;
        } else {
            break;
        }
    }

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) {
                let comm_trim = comm.trim();
                if comm_trim == "dpkg"
                    || comm_trim == "apt-get"
                    || comm_trim == "apt"
                    || comm_trim == "rpm"
                    || comm_trim == "yum"
                    || comm_trim == "dnf"
                {
                    return true;
                }
            }
        }
    }
    false
}

fn get_process_environ(pid: u32) -> Vec<String> {
    let mut envs = Vec::new();
    if let Ok(content) = std::fs::read(format!("/proc/{}/environ", pid)) {
        let parts: Vec<&[u8]> = content.split(|&b| b == 0).collect();
        for part in parts {
            if !part.is_empty() {
                if let Ok(s) = String::from_utf8(part.to_vec()) {
                    envs.push(s);
                }
            }
        }
    }
    envs
}

fn get_process_args(pid: u32) -> Vec<String> {
    let mut args = Vec::new();
    if let Ok(content) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
        let parts: Vec<&[u8]> = content.split(|&b| b == 0).collect();
        for part in parts {
            if !part.is_empty() {
                if let Ok(s) = String::from_utf8(part.to_vec()) {
                    args.push(s);
                }
            }
        }
    }
    args
}
