use std::sync::Arc;
use std::path::Path;
use crate::types::{TelemetryEventRaw, RAW_EVENT_SIZE};
use crate::heuristics::HeuristicsEngine;

pub mod rules;
pub mod cloud_rules;
pub mod types;
pub mod heuristics;
pub mod notifications;
pub mod scanner;
pub mod discovery;
pub mod fim;
pub mod install_date;
pub mod ffi;
pub mod allowlist;
pub mod audit;
pub mod ssh_monitor;
pub mod quarantine;
pub mod api;
pub mod tty_logger;
pub mod pty_session;
pub mod pty_session_store;
pub mod supply_chain;
pub mod supply_chain_store;
pub mod tls_buffer;
pub mod cloud;
pub mod kube_discovery;
pub mod ebpf_health;
pub mod cpu_monitor;
pub mod ssh_hardening;
pub mod storage_discovery;
pub mod upload_scan;
pub mod generic_discovery;
pub mod proxy_discovery;
pub mod container_discovery;
pub mod restart_policy;
pub mod link_tracker;
pub mod database_discovery;
pub mod web_discovery;
pub mod mail_discovery;
pub mod mq_discovery;
pub mod filesharing_discovery;
pub mod perf_monitor;
pub mod maintenance;
pub mod infra_discovery;
pub mod monitoring_discovery;
pub mod security_discovery;
pub mod remote_access_discovery;
pub mod yara_scanner;

pub mod declarative;
pub mod control_panel_discovery;
pub mod trust;
pub mod firewall;


pub struct VandamConfig {
    pub telemetry_socket: String,
    pub web_root: String,
    pub telemetry_enabled: bool,
    pub event_tx: Option<tokio::sync::mpsc::Sender<String>>,
    pub on_engine_ready: Option<Box<dyn FnOnce(Arc<HeuristicsEngine>) + Send>>,
    /// Extra routes merged into vandamd's UDS HTTP router before it starts
    /// listening — the extension point that lets `vandam` own genuinely
    /// tiered behavior (today: `POST /api/v1/alerts/{id}/investigate`)
    /// without OSS's `api.rs` containing any Pro-branded logic. See
    /// `api::start_api_server`'s doc comment for how a route supplied here
    /// overrides the OSS default at the same path.
    pub extra_routes: Option<axum::Router<api::AppState>>,
    /// Cloud-authored firewall rule sync — `None` in OSS. A real
    /// implementation (bidirectional push/pull, *not* subscription-gated —
    /// see `firewall::cloud_sync::CloudFirewallSync`'s doc comment) is
    /// `vandam/src/firewall_sync.rs`, structured just like
    /// `extra_routes` above. Basic remote block_ip/unblock_ip (see
    /// `cloud.rs`) works in every build regardless of this field — that's
    /// OSS-owned transport, this is the Pro-build bidirectional sync on
    /// top of it.
    pub firewall_cloud_sync: Option<std::sync::Arc<dyn firewall::cloud_sync::CloudFirewallSync>>,
}

pub async fn run_vandam(config: VandamConfig) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("=== vandam Server EDR Daemon (vandamd) starting... ===");

    // Check for root privileges (necessary for process containment/killing and socket bindings)
    if unsafe { libc::getuid() } != 0 {
        tracing::error!("Error: vandamd must be run with root privileges (sudo).");
        std::process::exit(1);
    }

    // 0. Kernel floor verification
    if let Ok(sys_uname) = nix::sys::utsname::uname() {
        let release_str = sys_uname.release().to_string_lossy();
        let version_parts: Vec<&str> = release_str.split('.').collect();
        if version_parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (version_parts[0].parse::<u32>(), version_parts[1].parse::<u32>()) {
                if major < 5 || (major == 5 && minor < 7) {
                    tracing::warn!(
                        "[Vandam Kernel Floor] Linux Kernel version is {}. Requires >= 5.7 for full eBPF LSM support. Vandam will run in fallback tracepoint mode.",
                        release_str
                    );
                } else {
                    tracing::info!("[Vandam Kernel Floor] Linux Kernel version {} is sufficient.", release_str);
                }
            }
        }
    }

    // Check BTF validation (CONFIG_DEBUG_INFO_BTF)
    let btf_path = Path::new("/sys/kernel/btf/vmlinux");
    if btf_path.exists() {
        tracing::info!("[Vandam BTF] CONFIG_DEBUG_INFO_BTF verified. Kernel BTF symbols available.");
    } else {
        tracing::warn!("[Vandam BTF] WARNING: CONFIG_DEBUG_INFO_BTF not found (no /sys/kernel/btf/vmlinux). eBPF loading may fail or fallback to tracepoint/mock mode.");
    }

    // 1. Resolve BPF object path
    let bpf_path = "/usr/lib/kinnector/kinnector.bpf.o";
    if !std::path::Path::new(bpf_path).exists() {
        // Also allow the path to be overridden via KINNECTOR_BPF_PATH env var for dev builds
        let env_path = std::env::var("KINNECTOR_BPF_PATH").ok();
        if env_path.as_deref().map(|p| std::path::Path::new(p).exists()).unwrap_or(false) {
            // env override exists — use it (development mode)
            tracing::info!("[Vandam] DEV: Using BPF object from KINNECTOR_BPF_PATH env override.");
        } else {
            tracing::error!(
                "[Vandam] Fatal: BPF object not found at '{}'. \
                 Install the kinnector-core package or set KINNECTOR_BPF_PATH for development builds.",
                bpf_path
            );
            std::process::exit(1);
        }
    }
    let bpf_path = std::env::var("KINNECTOR_BPF_PATH")
        .unwrap_or_else(|_| bpf_path.to_string());

    // B-08 & Section 1: Load config values from /etc/kinnector/core.conf dynamically
    let telemetry_socket = config.telemetry_socket.clone();
    let core_conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
    
    let auth_token = core_conf.lines()
        .find(|l| l.starts_with("auth_token="))
        .map(|l| l.trim_start_matches("auth_token=").trim().to_string())
        .unwrap_or_default();

    let quarantine_dir = core_conf.lines()
        .find(|l| l.starts_with("quarantine_dir="))
        .map(|l| l.trim_start_matches("quarantine_dir=").trim().to_string())
        .unwrap_or_else(|| "/var/quarantine/kinnector".to_string());
    quarantine::init_quarantine_dir(quarantine_dir);

    let pid_file_path = core_conf.lines()
        .find(|l| l.starts_with("pid_file="))
        .map(|l| l.trim_start_matches("pid_file=").trim().to_string())
        .unwrap_or_else(|| "/var/run/kinnector/vandamd.pid".to_string());

    let scan_interval_hours: u64 = core_conf.lines()
        .find(|l| l.starts_with("scan_interval_hours="))
        .and_then(|l| l.trim_start_matches("scan_interval_hours=").trim().parse().ok())
        .unwrap_or(12);

    let osv_db_path = core_conf.lines()
        .find(|l| l.starts_with("osv_db_path="))
        .map(|l| l.trim_start_matches("osv_db_path=").trim().to_string())
        .unwrap_or_else(|| "/etc/kinnector/osv.json".to_string());
    scanner::init_osv_db_path(osv_db_path);

    // Write PID file
    if let Some(parent) = std::path::Path::new(&pid_file_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let pid = std::process::id();
    if let Err(e) = std::fs::write(&pid_file_path, pid.to_string()) {
        tracing::warn!("[Vandam] Warning: could not write PID file {}: {}", pid_file_path, e);
    } else {
        tracing::info!("[Vandam] PID {} written to {}", pid, pid_file_path);
    }

    // Apply declarative conf.d rules
    crate::declarative::apply_declarative_configs();

    // Scan and register cron scheduled paths for write-protection
    allowlist::seed_cron_scheduled_paths();

    // 2. Initialize FFI low-level C++ telemetry engine
    let bpf_path_c = std::ffi::CString::new(bpf_path)?;
    let socket_path_c = std::ffi::CString::new(telemetry_socket)?;
    let auth_token_c = std::ffi::CString::new(auth_token)?;

    tracing::info!("[Vandam] Initializing low-level C++ telemetry engine...");
    let init_success = unsafe {
        ffi::initialize_telemetry_engine(
            bpf_path_c.as_ptr(),
            socket_path_c.as_ptr(),
            auth_token_c.as_ptr(),
        )
    };

    if !init_success {
        tracing::error!("[Vandam] Failed to initialize C++ telemetry engine via FFI!");
        std::process::exit(1);
    }

    tracing::info!("[Vandam] Starting low-level C++ telemetry engine...");
    let start_success = unsafe { ffi::start_telemetry_engine() };
    if !start_success {
        tracing::error!("[Vandam] Failed to start C++ telemetry engine!");
        std::process::exit(1);
    }

    // Temporarily disable BPF-level blocking during startup/initialization
    // to prevent blocking legitimate operations before allowlists are fully seeded.
    unsafe {
        ffi::set_config_value(0, 0); // CONFIG_BLOCKING_ENABLED = 0 (disabled)
    }

    // Critical constraint: kinnector.bpf.c is shared
    // production code between vandamd and antitheft-agent. Declaring MODE_WARDEN
    // here keeps Antitheft-only branches (Phase 3's resource_owner_map, Phase 5's
    // protected_owner_pids) gated off for this deployment.
    unsafe {
        ffi::set_config_value(5, 1); // CONFIG_DEPLOYMENT_MODE = 5, MODE_WARDEN = 1
    }

    // SSHD Pre-Auth Zero-Trust Lockdown:
    // Resolve the unprivileged sshd system user's UID and pass it to BPF.
    // If the sshd user doesn't exist, we send 0 (safely disabling the lockdown).
    {
        let sshd_uid = match nix::unistd::User::from_name("sshd") {
            Ok(Some(user)) => user.uid.as_raw(),
            _ => 0,
        };
        if sshd_uid > 0 {
            tracing::info!("[Vandam] SSHD unprivileged user UID resolved to: {}", sshd_uid);
            unsafe {
                ffi::set_config_value(1, sshd_uid); // CONFIG_SSHD_UID = 1
            }
        } else {
            tracing::info!("[Vandam] SSHD unprivileged user not found on system. Pre-auth RCE mitigation inactive.");
        }
    }

    // Set Host Namespace IDs for Container escaping and privilege auditing
    {
        if let Some(mnt_ns) = get_ns_id("mnt") {
            tracing::info!("[Vandam] Host mount namespace ID resolved to: {}", mnt_ns);
            unsafe { ffi::set_config_value(2, mnt_ns); } // CONFIG_HOST_MNT_NS = 2
        }
        if let Some(pid_ns) = get_ns_id("pid") {
            tracing::info!("[Vandam] Host PID namespace ID resolved to: {}", pid_ns);
            unsafe { ffi::set_config_value(3, pid_ns); } // CONFIG_HOST_PID_NS = 3
        }
        if let Some(net_ns) = get_ns_id("net") {
            tracing::info!("[Vandam] Host Net namespace ID resolved to: {}", net_ns);
            unsafe { ffi::set_config_value(4, net_ns); } // CONFIG_HOST_NET_NS = 4
        }
    }

    // 3. Load the rules (rules::source) and register sensitive inodes in the kernel BPF maps.
    //    With a cloud, its first bundle is waited for here, so everything below reads it.
    let cloud = cloud_rules::CloudRules::configured();
    let have_rules = match &cloud {
        Some(c) => cloud_rules::first(c).await,
        None if cfg!(debug_assertions) => None,
        None => {
            tracing::error!("[Vandam Rules] this build has no cloud (VANDAM_CLOUD_URL / VANDAM_ISSUER_KEY): it has no rules");
            None
        }
    };
    let config_arc = Arc::new(rules::ConfigManager::load_defaults());
    if let Some(c) = cloud {
        tokio::spawn(cloud_rules::keep_current(c, Arc::clone(&config_arc), have_rules));
    }
    {
        let sensitive_files = config_arc.sensitive_files();
        tracing::info!("[Vandam] Rules loaded: {} sensitive files", sensitive_files.len());
        use std::os::unix::fs::MetadataExt;
        for (path_str, category_flags) in sensitive_files {
            if let Ok(metadata) = std::fs::metadata(&path_str) {
                let inode = metadata.ino();
                let dev = metadata.dev();
                tracing::debug!("[Vandam] Registering sensitive file: {} (Inode: {}, Category: {:#x})", path_str, inode, category_flags);
                allowlist::register_sensitive_inode(inode);
                unsafe {
                    ffi::add_sensitive_inode(dev, inode, category_flags);
                }
            }
        }
    }
    allowlist::init_config_manager(Arc::clone(&config_arc));

    // Register trusted admin binaries (Cascade 3 logrotate/sendmail postrotate
    // exception) and the exec-classification table (TREE_TRUSTED_ADMIN's own
    // command allowlist plus dangerous-tool/priv-esc flags). Both used to be
    // hardcoded arrays here and in core's ebpf_loader.cpp respectively - now
    // config-driven from protect-community/configs/vandam/exec_control_lists.json
    // via crate::rules::exec_control_lists(), same pattern Phase 4 below
    // already established for package-manager signatures. Resolved via $PATH
    // search rather than a hardcoded absolute path, more portable across distro
    // layouts than the old "/usr/sbin/logrotate" literal.
    {
        const MAP_TRUSTED_ADMIN_BINARIES: i32 = 15;
        const CONFIG_EXE_CLASSES_READY: u32 = 8;
        const EXE_CLASS_ADMIN_ALLOWED: u32 = 0x1;
        const EXE_CLASS_DANGEROUS_TOOL: u32 = 0x2;
        const EXE_CLASS_PRIV_ESC: u32 = 0x4;
        use std::os::unix::fs::MetadataExt;
        let lists = config_arc.exec_control_lists();

        for bin in &lists.trusted_admin_binaries {
            if let Some(resolved) = resolve_in_path(&bin.executable) {
                if let Ok(metadata) = std::fs::metadata(&resolved) {
                    let inode = metadata.ino();
                    tracing::info!("[Vandam] Registering trusted admin binary: {} ({}) (Inode: {})", bin.executable, resolved.display(), inode);
                    unsafe {
                        ffi::update_map_entry(MAP_TRUSTED_ADMIN_BINARIES, 0, inode, 1);
                    }
                }
            }
        }

        for dir_name in &lists.untrusted_library_directories {
            if let Ok(cname) = std::ffi::CString::new(dir_name.as_str()) {
                unsafe {
                    ffi::add_untrusted_dir_name(cname.as_ptr());
                }
            }
        }

        let classified = [
            (&lists.admin_allowed_commands, EXE_CLASS_ADMIN_ALLOWED),
            (&lists.dangerous_tools, EXE_CLASS_DANGEROUS_TOOL),
            (&lists.priv_esc_binaries, EXE_CLASS_PRIV_ESC),
        ];
        let mut exe_classes_ok = true;
        for (names, class_bit) in classified {
            for name in names {
                if let Ok(cname) = std::ffi::CString::new(name.as_str()) {
                    let ok = unsafe { ffi::add_exe_name_class(cname.as_ptr(), class_bit) };
                    if !ok {
                        exe_classes_ok = false;
                        tracing::warn!("[Vandam] failed to register exe_name_class entry: {}", name);
                    }
                }
            }
        }
        // The admin-command rule this table feeds is an ALLOWLIST - only flip
        // it ready if every entry above actually landed, matching the old
        // PopulateExeNameClasses()'s all-or-nothing semantics (a half-seeded
        // table would deny every exec in a TREE_TRUSTED_ADMIN tree instead of
        // allowing the safe ones).
        if exe_classes_ok {
            unsafe {
                ffi::set_config_value(CONFIG_EXE_CLASSES_READY, 1);
            }
        } else {
            tracing::warn!("[Vandam] exe_name_class_map not fully populated; name-classified exec rules stay disabled");
        }
    }

    // Register configured package-manager binaries
    // in the kernel's install_binary_map, resolved via PATH search from
    // package_manager_signatures() (protect-community/configs/vandam/
    // package_manager_signatures.json) -- replaces the hardcoded npm/yarn/pip/...
    // string scan kinnector.bpf.c's bprm_creds_for_exec used to do, so adding a new
    // ecosystem is a config change, not a kernel-object rebuild.
    {
        const MAP_INSTALL_BINARY: i32 = 16;
        use std::os::unix::fs::MetadataExt;
        for sig in config_arc.package_manager_signatures() {
            if let Some(resolved) = resolve_in_path(&sig.executable) {
                if let Ok(metadata) = std::fs::metadata(&resolved) {
                    let inode = metadata.ino();
                    tracing::debug!("[Vandam] Registering install binary: {} ({}) (Inode: {})", sig.executable, resolved.display(), inode);
                    unsafe {
                        ffi::update_map_entry(MAP_INSTALL_BINARY, 0, inode, 1);
                    }
                }
            }
        }
    }

    // 4. Agnostic dynamic web-roots auto-detection & shell loading
    let mut web_roots = discovery::discover_web_roots(&config_arc);
    // Merge user-supplied parameter if not already discovered
    if !config.web_root.is_empty() && !web_roots.contains(&config.web_root) {
        web_roots.push(config.web_root.clone());
    }

    // 6. Auto-discover Reverse Proxies
    let proxies = discovery::auto_discover_proxies();
    let mut config_dirs = Vec::new();
    for proxy in proxies {
        tracing::info!("[Vandam Discovery] Discovered active reverse proxy: {}", proxy.name);
        for conf_dir in proxy.config_dirs {
            config_dirs.push(conf_dir);
        }
    }

    // P6-1/P6-3: Auto-discover Docker container mounts at startup
    let docker_containers = discovery::discover_docker_containers().await;
    for container in docker_containers {
        tracing::info!("[Vandam Docker] Monitoring Docker container: {} (Image: {})", container.name, container.image);
        let mut mounts = Vec::new();
        for wr in container.web_roots {
            let wr_str = wr.to_string_lossy().to_string();
            if !web_roots.contains(&wr_str) {
                web_roots.push(wr_str);
            }
            mounts.push(wr);
        }
        for cd in container.config_dirs {
            if !config_dirs.contains(&cd) {
                config_dirs.push(cd.clone());
            }
            mounts.push(cd);
        }
        discovery::register_container_mounts(&container.id, mounts);
    }

    // P6-4: Start event-driven Docker listener to dynamically watch new containers in real-time
    discovery::start_docker_event_listener();

    // Enforce container runtime policies (Docker/containerd/Kubelet APIs and namespace checks)
    container_discovery::enforce_container_policies();


    tracing::info!("[Vandam WebRoots] Actively monitoring web roots: {:?}", web_roots);

    let system_shells = allowlist::load_system_shells();
    tracing::info!("[Vandam Shells] Dynamically loaded {} login shells from /etc/shells", system_shells.len());

    // 4b. Seed inode allowlist from git (git-authoritative enforcement)
    let _allowlist = allowlist::seed_inode_allowlist(&web_roots);
    allowlist::sync_protected_static_inodes(&config_dirs);

    // 4c. Start git commit watchers for all discovered web roots
    for root in &web_roots {
        allowlist::start_git_commit_watcher(root.clone());
    }

    // 4d. Discover and register storage directories
    tracing::info!("[Vandam Storage] Running agnostic storage discovery...");
    let listening_pids = discovery::discover_listening_pids();
    for root in &web_roots {
        // P1: Scan all web process environ/cmdline
        for pid in &listening_pids {
            let paths = storage_discovery::scan_process_env_for_storage(*pid);
            for p in paths { storage_discovery::register(p); }
        }
        // P2: Framework config rules
        let paths = storage_discovery::run_framework_rules(root);
        for p in paths { storage_discovery::register(p); }
        // P3: UID-writable untracked dirs
        let web_uid = storage_discovery::resolve_web_uid(root);
        let paths = storage_discovery::scan_uid_writable_untracked(root, web_uid);
        for p in paths { storage_discovery::register(p); }
        // P4: gitignore cross-reference (confirmatory only)
        storage_discovery::cross_reference_gitignore(root);

        // Zero storage path warning check
        let mut found_any = false;
        for entry in storage_discovery::get_registry().iter() {
            if entry.key().starts_with(root) {
                found_any = true;
                break;
            }
        }
        if !found_any {
            storage_discovery::emit_no_storage_detected_warning(root);
        }
    }
    tracing::info!("[Vandam Storage] Registry contains {} storage paths.", storage_discovery::get_registry().len());

    // 5. Initialize EDR Heuristics Engine
    let heuristics = Arc::new(HeuristicsEngine::new(
        Arc::clone(&config_arc),
        web_roots.clone(),
        system_shells,
        config.event_tx.clone(),
    ));

    // Fire extension callback (e.g. Pro RASP startup)
    if let Some(callback) = config.on_engine_ready {
        let engine_cb = Arc::clone(&heuristics);
        tokio::spawn(async move { callback(engine_cb); });
    }

    // Spawn background preexisting LD_PRELOAD scanner
    tokio::spawn(async move {
        heuristics::scan_preexisting_ld_preloads();
    });

    // Spawn background Kubernetes Pod Discovery task
    tokio::spawn(async move {
        kube_discovery::run_kubernetes_discovery().await;
    });

    // Spawn background eBPF and Telemetry Health Monitor task
    let heuristics_health = Arc::clone(&heuristics);
    tokio::spawn(async move {
        ebpf_health::start_ebpf_health_monitor(heuristics_health).await;
    });

    // 5b. Seed process_map with pre-existing processes from /proc at startup
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else { continue; };
            let exe_path = format!("/proc/{}/exe", pid);
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            let exe = std::fs::read_link(&exe_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let cmdline = std::fs::read_to_string(&cmdline_path)
                .map(|s| s.replace('\0', " ").trim().to_string())
                .unwrap_or_default();
            if !exe.is_empty() {
                let is_server = heuristics.config.is_web_process(&exe)
                    || heuristics.listening_pids.contains(&pid);
                if is_server {
                    let sig_name = heuristics::detect_signature_name(&exe, &config_arc);
                    let service = discovery::detect_systemd_service_for_pid(pid);
                    heuristics.process_map.insert(pid, heuristics::ProcessNode {
                        pid,
                        ppid: 1,
                        exe: exe.clone(),
                        cmdline,
                        is_listening_server: is_server,
                        is_database: false,
                        is_install_context: false,
                        is_top_level_install: false,
                        install_root_pid: 0,
                        depth: 0,
                        loaded_scripts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                        signature_name: sig_name,
                        service,
                    });
                    tracing::info!("[Vandam Startup] Pre-seeded process map: PID {} ({})", pid, exe);
                }
            }
        }
    }

    // Firewall: apply the persisted rule store (including any Cloud-provenance
    // rules from a previous session) before anything else starts accepting
    // traffic-adjacent work — mirrors the discovery/enforce_*_policies calls
    // below, but for firewall rules rather than service-role classification.
    let firewall_report = firewall::reconcile::reconcile_firewall(&heuristics.config);
    if !firewall_report.errors.is_empty() {
        tracing::warn!("[Vandam Firewall] startup reconcile errors: {:?}", firewall_report.errors);
    }

    // DB-2 / Domain 2: Run all dynamic service discovery and auto-grain policies
    database_discovery::enforce_database_policies(&heuristics.config);
    web_discovery::enforce_web_policies();
    mail_discovery::enforce_mail_policies();
    mq_discovery::enforce_mq_policies();
    filesharing_discovery::enforce_filesharing_policies();
    infra_discovery::enforce_infra_policies();
    monitoring_discovery::enforce_monitoring_policies();
    security_discovery::enforce_security_policies();
    remote_access_discovery::enforce_remote_access_policies();
    control_panel_discovery::enforce_control_panel_policies();


    // Back-fill process_map for any PID that discovery modules registered in the signature
    // registry but that wasn't seeded in the initial web-process scan above.
    // This ensures every matched server (DB, mail, MQ, security, etc.) has a ProcessNode
    // with the correct signature_name before any BPF events arrive for it.
    {
        let registry = generic_discovery::get_signature_registry();
        for entry in registry.iter() {
            let pid = *entry.key();
            if heuristics.process_map.contains_key(&pid) {
                // Already seeded (e.g., a web process that is also in a sig) — just update sig_name
                if let Some(mut node) = heuristics.process_map.get_mut(&pid) {
                    if node.signature_name.is_none() {
                        node.signature_name = Some(std::sync::Arc::clone(entry.value()));
                    }
                }
                continue;
            }
            let exe_path = format!("/proc/{}/exe", pid);
            let exe = std::fs::read_link(&exe_path)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            if exe.is_empty() {
                continue;
            }
            let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                .map(|s| s.replace('\0', " ").trim().to_string())
                .unwrap_or_default();
            let is_server = heuristics.config.is_web_process(&exe)
                || heuristics.listening_pids.contains(&pid);
            let service = discovery::detect_systemd_service_for_pid(pid);
            heuristics.process_map.insert(pid, heuristics::ProcessNode {
                pid,
                ppid: 0,
                exe: exe.clone(),
                cmdline,
                is_listening_server: is_server,
                is_database: false,
                is_install_context: false,
                is_top_level_install: false,
                install_root_pid: 0,
                depth: 0,
                loaded_scripts: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
                signature_name: Some(std::sync::Arc::clone(entry.value())),
                service,
            });
            tracing::info!(
                "[Vandam Startup] Seeded discovered service PID {} ({}) sig={:?}",
                pid, exe, entry.value()
            );
        }
    }


    // P4-5 & P4-6: Add system persistence and SSL/TLS directories to FIM watch list
    let extra_fim_paths = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.monthly",
        "/etc/cron.weekly",
        "/etc/crontab",
        "/var/spool/cron",
        "/etc/profile",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/ssl",
        "/etc/letsencrypt",
        "/etc/systemd/system",
    ];
    for path_str in &extra_fim_paths {
        let path = std::path::Path::new(path_str);
        if path.exists() {
            config_dirs.push(std::path::PathBuf::from(path_str));
        }
    }

    // 7. Start File Integrity Monitoring (FIM) on the main web roots
    for root in &web_roots {
        fim::start_fim_watcher(root.clone(), config_dirs.clone());
    }

    // 8. Start Dependency Vulnerabilities OSV Scanner
    for root in &web_roots {
        scanner::start_scanner(root.clone(), scan_interval_hours);
    }

    // 8b. Start SSH brute-force monitor
    ssh_monitor::start_ssh_monitor(Arc::clone(&heuristics));

    // 8c. Start HTTP-over-UDS REST API server
    api::start_api_server(Arc::clone(&heuristics), web_roots.clone(), config.extra_routes);

    // 8cb. Start Unix Socket (/run/vandam/alerts.sock) Alert Server
    notifications::start_alert_socket_server();

    // 8d. Start PTY/TTY logging monitor
    tty_logger::start_tty_logger(Arc::clone(&heuristics));

    // 8d-2. Periodic retention sweep for /var/log/kinnector/pty_sessions/
    // (Access design plan, phase 5) — hourly is plenty for a TTL measured
    // in days and a size cap measured in hundreds of MB.
    tokio::spawn(async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            pty_session_store::run_retention_sweep();
        }
    });

    // 8e. Start Forensic TLS Request Buffer server (Paid Tier)
    tls_buffer::start_tls_telemetry_server();


    // 8g. Start CPU Anomaly/Miner Monitor
    cpu_monitor::start_cpu_monitor(Arc::clone(&heuristics));



    // 8f. Start Cloud Services
    cloud::start_cloud_services(Arc::clone(&heuristics));

    // 8f-2. Firewall cloud sync (Pro-build-only, not subscription-gated —
    // see VandamConfig::firewall_cloud_sync's doc comment). Pull results
    // are merged and trigger an immediate reconcile so cloud-issued rules
    // take effect promptly.
    if let Some(sync) = config.firewall_cloud_sync.clone() {
        let heuristics_sync = Arc::clone(&heuristics);
        tokio::spawn(async move {
            loop {
                let local_rules: Vec<_> = firewall::read_firewall_rules()
                    .into_iter()
                    .filter(|r| r.provenance == firewall::FirewallProvenance::Local)
                    .collect();
                if let Err(e) = sync.push_local_rules(&local_rules).await {
                    tracing::debug!("[Vandam Firewall] cloud push skipped/failed: {}", e);
                }
                match sync.pull_cloud_rules().await {
                    Ok(cloud_rules) => {
                        if !cloud_rules.is_empty() {
                            firewall::reconcile::merge_cloud_rules(cloud_rules);
                            let _ = firewall::reconcile::reconcile_firewall(&heuristics_sync.config);
                        }
                    }
                    Err(e) => tracing::debug!("[Vandam Firewall] cloud pull skipped/failed: {}", e),
                }
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            }
        });
    }

    // 8g. Start SSH Hardening Audit and Adaptive MOTD Updater
    tokio::spawn(async {
        loop {
            let hardened = ssh_hardening::audit_ssh_2fa();
            ssh_hardening::update_motd(hardened);
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    });

    // 9. Periodic process-map TTL eviction
    {
        let engine_evict = Arc::clone(&heuristics);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
                engine_evict.evict_stale_processes();
            }
        });
    }

    // 10. Connect to core eBPF telemetry loop
    let telemetry_path = config.telemetry_socket.clone();
    let engine_clone = Arc::clone(&heuristics);
    
    tokio::spawn(async move {
        tracing::info!("[Vandam Telemetry] Attempting connection to telemetry stream: {}", telemetry_path);
        loop {
            match tokio::net::UnixStream::connect(&telemetry_path).await {
                Ok(mut stream) => {
                    tracing::info!("[Vandam Telemetry] Connected to eBPF telemetry socket successfully.");
                    let mut buffer = vec![0u8; RAW_EVENT_SIZE * 4];
                    let mut bytes_in_buf = 0;

                    loop {
                        use tokio::io::AsyncReadExt;
                        match stream.read(&mut buffer[bytes_in_buf..]).await {
                            Ok(0) => {
                                tracing::info!("[Vandam Telemetry] Stream EOF. Reconnecting...");
                                break;
                            }
                            Ok(n) => {
                                bytes_in_buf += n;
                                while bytes_in_buf >= RAW_EVENT_SIZE {
                                    let mut frame = [0u8; RAW_EVENT_SIZE];
                                    frame.copy_from_slice(&buffer[..RAW_EVENT_SIZE]);
                                    
                                    let raw_event: TelemetryEventRaw = unsafe {
                                        std::ptr::read(frame.as_ptr() as *const TelemetryEventRaw)
                                    };

                                    engine_clone.handle_raw_event(raw_event);

                                    buffer.copy_within(RAW_EVENT_SIZE..bytes_in_buf, 0);
                                    bytes_in_buf -= RAW_EVENT_SIZE;
                                }
                            }
                            Err(e) => {
                                tracing::error!("[Vandam Telemetry] Socket read error: {}. Reconnecting...", e);
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            }
        }
    });

    // Enable BPF-level blocking now that initialization and allowlist seeding are complete
    tracing::info!("[Vandam] Initialization complete. Enabling BPF-level active blocking.");
    unsafe {
        ffi::set_config_value(0, 1); // CONFIG_BLOCKING_ENABLED = 1 (enabled)
    }

    // Keep daemon main thread running
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Vandam shutdown requested via Ctrl-C");
        }
        _ = signal.recv() => {
            tracing::info!("Vandam shutdown requested via SIGTERM");
        }
    }

    tracing::info!("Vandam daemon stopped.");
    // Disable BPF blocking on exit so system/administrator is not locked out
    unsafe {
        ffi::set_config_value(0, 0); // CONFIG_BLOCKING_ENABLED = 0 (disabled)
    }

    ssh_hardening::remove_motd_banners();
    let _ = std::fs::remove_file(pid_file_path);
    unsafe { ffi::stop_telemetry_engine(); }
    Ok(())
}

fn get_ns_id(ns_type: &str) -> Option<u32> {
    let path = format!("/proc/1/ns/{}", ns_type);
    let target = std::fs::read_link(path).ok()?;
    let target_str = target.to_str()?;
    let start = target_str.find('[')? + 1;
    let end = target_str.find(']')?;
    target_str[start..end].parse::<u32>().ok()
}

// Resolve a package-manager executable name
// (e.g. "npm") to its on-disk path via $PATH search, so install_binary_map can be
// populated by inode without hardcoding install locations.
fn resolve_in_path(name: &str) -> Option<std::path::PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
