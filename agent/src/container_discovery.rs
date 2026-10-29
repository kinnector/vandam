use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerServiceSignature {
    pub service_type: String,
    pub executables: Vec<String>,
    pub unix_sockets: Vec<String>,
    pub assigned_profile: String,
    pub escape_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerServiceDatabase {
    pub description: String,
    pub services: Vec<ContainerServiceSignature>,
}

pub struct DiscoveredContainerService {
    pub service_type: String,
    pub pid: u32,
    pub signature: ContainerServiceSignature,
}

pub fn discover_container_services() -> Vec<DiscoveredContainerService> {
    // From the rules. This read a protect-community path where the file never was, so container
    // signatures always loaded empty.
    let Some(data) = crate::rules::source::current().read("linux_container_signatures.json") else {
        return Vec::new();
    };
    
    let db: ContainerServiceDatabase = match serde_json::from_str(&data) {
        Ok(parsed) => parsed,
        Err(_) => return Vec::new(),
    };
    
    let mut discovered = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else { return Vec::new(); };
    
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        if !pid_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };
        
        let exe_link = entry.path().join("exe");
        let Ok(target) = std::fs::read_link(&exe_link) else { continue; };
        let exe_name = target.file_name().unwrap_or_default().to_string_lossy();
        
        for sig in &db.services {
            if sig.executables.iter().any(|e| e == &*exe_name) {
                discovered.push(DiscoveredContainerService {
                    service_type: sig.service_type.clone(),
                    pid,
                    signature: sig.clone(),
                });
            }
        }
    }
    discovered
}

pub fn enforce_container_policies() {
    let services = discover_container_services();
    for svc in services {
        if svc.signature.assigned_profile == "manual-graining" {
            tracing::warn!(
                "[Vandam] NO_POLICY for container runtime {} PID {} — Daemon-level sandboxing bypassed. Container-level host-protection rules active.",
                svc.service_type,
                svc.pid
            );
            continue;
        }
        
        if svc.signature.assigned_profile == "zero-execution" {
            tracing::info!(
                "[Vandam] Strict zero-execution policy applied to container service {} PID {}",
                svc.service_type,
                svc.pid
            );
            crate::allowlist::set_pid_profile(svc.pid, crate::allowlist::PROFILE_ZERO_EXECUTION);
            // Apply PROFILE_ZERO_EXECUTION (0x10000000) and PROFILE_ZERO_NETWORK (0x80000000)
            unsafe {
                crate::ffi::update_process_threshold(svc.pid, 0, 0x10000000 | 0x80000000);
            }
        }

        // Apply container-scoped declarative rules from conf.d/
        for decl_cfg in crate::declarative::get_configs_for_container(&svc.service_type) {
            for storage in decl_cfg.storage {
                crate::allowlist::register_inode(&storage.path);
                crate::allowlist::register_pid_extra_path(svc.pid, std::path::PathBuf::from(&storage.path));
            }
            for exec_path in decl_cfg.execution.allow_paths {
                crate::allowlist::register_inode(&exec_path);
                crate::allowlist::register_pid_extra_path(svc.pid, std::path::PathBuf::from(&exec_path));
            }
        }
    }
}
