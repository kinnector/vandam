
use crate::rules::ConfigManager;
use crate::discovery::discover_databases;
use crate::ffi;

// Profile & Role flags
const PROFILE_ZERO_EXECUTION: u32 = 0x10000000;
const ROLE_DATABASE: u32 = 0x80000000;

// BpfMapType enum values
const MAP_DB_OUTBOUND_ALLOWLIST: i32 = 11;

pub fn enforce_database_policies(config: &ConfigManager) {
    let databases = discover_databases(config);

    for db in databases {
        tracing::info!("[Vandam DB] Applying policies for {} PID {}", db.db_type, db.pid);
        // Register the matched signature name for this DB PID so detect_signature_name() finds it
        crate::generic_discovery::register_pid_signature(db.pid, &db.db_type);

        // Check config freshness
        for cfg_path in &db.config_paths {
            match crate::restart_policy::check_config_freshness(db.pid, cfg_path) {
                crate::restart_policy::ConfigFreshnessResult::ConfigNewerThanProcess { delta_secs, .. } => {
                    if delta_secs < 30 {
                        tracing::warn!(
                            "[Vandam DB] Config modified recently ({}s ago) for {} PID {}. Service may not have restarted yet.",
                            delta_secs, db.db_type, db.pid
                        );
                    } else {
                        tracing::warn!(
                            "[Vandam DB] Config modified {}s ago but service {} PID {} has not restarted. Restart recommended.",
                            delta_secs, db.db_type, db.pid
                        );
                    }
                }
                _ => {}
            }
        }

        // Start config watcher
        let config_paths = db.config_paths.clone();
        let db_type_clone = db.db_type.clone();
        let pid_clone = db.pid;
        crate::restart_policy::start_config_watcher(config_paths, move |path| {
            tracing::info!(
                "[Vandam DB Watch] Config modified: {} for {} PID {}. Re-evaluating policy.",
                path.display(), db_type_clone, pid_clone
            );
        });

        let mut flags = ROLE_DATABASE | PROFILE_ZERO_EXECUTION;
        let mut is_complex = false;
        let mut peer_ips = Vec::new();

        for cfg_path in &db.config_paths {
            if let Ok(content) = std::fs::read_to_string(cfg_path) {
                if content.contains("loadmodule") || content.contains("sentinel monitor") {
                    is_complex = true;
                }
                for line in content.lines() {
                    if line.contains("replicaof") || line.contains("slaveof") || line.contains("sentinel monitor") {
                        for word in line.split_whitespace() {
                            if word.parse::<std::net::Ipv4Addr>().is_ok() {
                                peer_ips.push(word.to_string());
                            }
                        }
                    }
                }
            }
        }

        if is_complex {
            tracing::warn!(
                "[Vandam DB] Complexity detected in database {} PID {}. Policy degraded to PARTIAL.",
                db.db_type, db.pid
            );
            flags = ROLE_DATABASE;
        }

        unsafe {
            ffi::update_process_threshold(db.pid, 0, flags);
        }

        for ip_str in peer_ips {
            if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                let ip_u32 = u32::from_ne_bytes(ip.octets());
                unsafe {
                    ffi::update_map_entry(MAP_DB_OUTBOUND_ALLOWLIST, db.pid, ip_u32 as u64, 1);
                }
                tracing::info!(
                    "[Vandam DB] Added allowlisted peer IP {} (u32: {:#x}) for DB PID {}",
                    ip_str, ip_u32, db.pid
                );
            }
        }

        for data_dir in &db.data_dirs {
            if let Ok(meta) = std::fs::metadata(data_dir) {
                use std::os::unix::fs::MetadataExt;
                let inode = meta.ino();
                let dev = meta.dev();
                unsafe {
                    ffi::add_bypassed_directory_inode(dev, inode);
                }
            }
        }

        for data_dir in &db.data_dirs {
            crate::allowlist::register_signature_path(
                &db.db_type,
                data_dir.clone()
            );
        }
    }
}
