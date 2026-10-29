use std::os::raw::c_char;

extern "C" {
    pub fn initialize_telemetry_engine(
        bpf_obj_path: *const c_char,
        socket_path: *const c_char,
        auth_token: *const c_char,
    ) -> bool;

    pub fn start_telemetry_engine() -> bool;

    pub fn stop_telemetry_engine();

    /// Register a sensitive file inode in the kernel map (triggers read telemetry + blocking).
    /// `dev` (MetadataExt::dev()) makes the identity
    /// canonical across bind-mounts/multiple filesystems with overlapping inode ranges.
    pub fn add_sensitive_inode(dev: u64, inode: u64, category: u32) -> bool;

    /// Register a protected static file inode in the kernel map (triggers synchronous write blocking)
    pub fn add_protected_static_inode(dev: u64, inode: u64) -> bool;

    /// Remove a protected static file inode from the kernel map
    pub fn remove_protected_static_inode(dev: u64, inode: u64) -> bool;

    /// Register a directory inode as a DB data-dir bypass.
    /// Write telemetry is suppressed for any process carrying ROLE_DATABASE that writes
    /// to a file whose dentry ancestry (up to 4 levels) hits this inode.
    pub fn add_bypassed_directory_inode(dev: u64, inode: u64) -> bool;

    /// Remove a directory inode from the bypass map (called on DB ProcessStop / upgrade).
    pub fn remove_bypassed_directory_inode(dev: u64, inode: u64) -> bool;

    /// Register a trusted executable inode (suppresses exec telemetry for known-good binaries)
    pub fn add_trusted_exec_inode(inode: u64, trust_level: u32) -> bool;

    /// Dynamically update the process threshold for a running process.
    /// threshold values: 1 = Untrusted, 2 = Verified, 3 = Naked TTY.
    /// To mark as DB role, OR in ROLE_DATABASE (0x80000000) with the threshold value.
    pub fn update_process_threshold(pid: u32, start_time: u64, threshold: u32) -> bool;

    /// Update/Delete BPF map entries dynamically from userspace
    pub fn update_map_entry(map_type: i32, pid: u32, start_time: u64, value: u32) -> bool;
    pub fn delete_map_entry(map_type: i32, pid: u32, start_time: u64) -> bool;

    /// Set a kernel config value (index 0 = blocking_enabled, 8 = CONFIG_EXE_CLASSES_READY)
    pub fn set_config_value(index: u32, value: u32) -> bool;

    /// Register one executable basename in exe_name_class_map (EXE_CLASS_ADMIN_ALLOWED
    /// = 0x1, EXE_CLASS_DANGEROUS_TOOL = 0x2, EXE_CLASS_PRIV_ESC = 0x4, OR'd together
    /// if a name needs more than one). Config-driven from protect-community's
    /// exec_control_lists.json (via crate::rules::exec_control_lists()) - caller
    /// MUST call set_config_value(8, 1) once every name is added, see that map's own
    /// doc for why (it's an ALLOWLIST).
    pub fn add_exe_name_class(name: *const c_char, classes: u32) -> bool;

    /// Register one ancestor-directory basename (e.g. "tmp") as untrusted for
    /// is_library_open_from_untrusted_dir()'s .so-injection check. A denylist -
    /// no "ready" flag needed, unlike add_exe_name_class.
    pub fn add_untrusted_dir_name(name: *const c_char) -> bool;

    pub fn is_lsm_active() -> bool;

    /// Firewall (vandam/src/firewall) — `addr` must point to 4 bytes
    /// (`is_v6 = false`) or 16 bytes (`is_v6 = true`), network byte order.
    /// `prefixlen` is in bits. See `core/src/linux/ebpf/kinnector.bpf.c`'s
    /// `fw_key4`/`fw_key6`/`fw_value` for the wire shape this mirrors.
    pub fn add_firewall_cidr(
        is_v6: bool,
        addr: *const u8,
        prefixlen: u32,
        rule_id: u32,
        port: u16,
        proto: u8,
        direction: u8,
        action: u8,
    ) -> bool;
    pub fn remove_firewall_cidr(is_v6: bool, addr: *const u8, prefixlen: u32) -> bool;
    /// Anti-tamper: total live entries across both firewall tries, or -1 if
    /// unavailable (mock mode / not loaded) — see `ebpf_health.rs`.
    pub fn count_firewall_entries() -> i64;
}

