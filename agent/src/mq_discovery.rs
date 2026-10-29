use crate::generic_discovery::{discover_and_enforce_services, ROLE_QUEUE_MANAGER};

pub fn enforce_mq_policies() {
    let services = discover_and_enforce_services("linux_mq_signatures.json", ROLE_QUEUE_MANAGER);
    tracing::info!("[Vandam MQ] Discovered {} message queue services.", services.len());

    // Cascade 9: Redis Sentinel Discovery & Policy Enforcement
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };
            if let Ok(target) = std::fs::read_link(entry.path().join("exe")) {
                let exe_name = target.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                
                let is_sentinel = exe_name == "redis-sentinel";
                let mut is_server_sentinel = false;
                let mut config_file = None;
                
                if exe_name == "redis-server" || is_sentinel {
                    if let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) {
                        let args: Vec<String> = cmdline
                            .split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect();
                        
                        if is_sentinel {
                            config_file = args.get(1).cloned();
                        } else if args.iter().any(|arg| arg == "--sentinel") {
                            is_server_sentinel = true;
                            config_file = args.iter().find(|arg| arg.ends_with(".conf")).cloned();
                        }
                    }
                }
                
                if is_sentinel || is_server_sentinel {
                    tracing::info!("[Vandam MQ] Discovered Redis Sentinel PID: {} (Config: {:?})", pid, config_file);
                    crate::generic_discovery::register_pid_signature(pid, "redis-sentinel");
                    
                    // Apply Zero-Execution (0x10000000) and Zero-Network (0x80000000)
                    unsafe {
                        crate::ffi::update_process_threshold(pid, 0, 0x10000000 | 0x80000000);
                    }
                    
                    if let Some(cf) = config_file {
                        if let Ok(content) = std::fs::read_to_string(cf) {
                            for line in content.lines() {
                                let trimmed = line.trim();
                                if trimmed.starts_with("sentinel monitor") {
                                    let fields: Vec<&str> = trimmed.split_whitespace().collect();
                                    if fields.len() > 3 {
                                        let ip_str = fields[3];
                                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                            let ip_u32 = u32::from_ne_bytes(ip.octets());
                                            tracing::info!("[Vandam MQ] Redis Sentinel allowlisting master IP: {} (u32: {})", ip_str, ip_u32);
                                            unsafe {
                                                crate::ffi::update_map_entry(12, pid, ip_u32 as u64, 1); // 12 = MAP_INFRA_OUTBOUND_ALLOWLIST
                                            }
                                        }
                                    }
                                }
                                if trimmed.starts_with("sentinel known-sentinel") {
                                    let fields: Vec<&str> = trimmed.split_whitespace().collect();
                                    if fields.len() > 3 {
                                        let ip_str = fields[3];
                                        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
                                            let ip_u32 = u32::from_ne_bytes(ip.octets());
                                            tracing::info!("[Vandam MQ] Redis Sentinel allowlisting peer Sentinel IP: {} (u32: {})", ip_str, ip_u32);
                                            unsafe {
                                                crate::ffi::update_map_entry(12, pid, ip_u32 as u64, 1);
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
}
