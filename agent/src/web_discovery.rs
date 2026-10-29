use crate::generic_discovery::discover_and_enforce_services;
use crate::ffi;

const MAP_JVM_EXCEPTION_PIDS: i32 = 10;

pub fn enforce_web_policies() {
    let services = discover_and_enforce_services("linux_web_signatures.json", 0);
    tracing::info!("[Vandam Web] Discovered {} web services.", services.len());

    if check_php_jit_enabled() {
        if let Ok(proc_dir) = std::fs::read_dir("/proc") {
            for entry in proc_dir.flatten() {
                let name = entry.file_name();
                let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };
                if let Ok(target) = std::fs::read_link(entry.path().join("exe")) {
                    let exe_name = target.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                    if exe_name.contains("php-fpm") || exe_name.contains("php") {
                        unsafe {
                            ffi::update_map_entry(MAP_JVM_EXCEPTION_PIDS, pid, 0, 1);
                        }
                    }
                }
            }
        }
    }

    // Discovery of Node.js Cluster Mode for Cascade 7
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };
            if let Ok(target) = std::fs::read_link(entry.path().join("exe")) {
                let exe_name = target.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                if exe_name == "node" {
                    if let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) {
                        let args: Vec<String> = cmdline
                            .split(|&b| b == 0)
                            .filter(|s| !s.is_empty())
                            .map(|s| String::from_utf8_lossy(s).to_string())
                            .collect();
                        
                        if let Some(script_path) = args.iter().find(|arg| arg.ends_with(".js") || arg.ends_with(".mjs") || arg.ends_with(".cjs")) {
                            if let Ok(script_content) = std::fs::read_to_string(script_path) {
                                let has_cluster = script_content.lines().take(200).any(|line| {
                                    line.contains("require('cluster')") ||
                                    line.contains("require(\"cluster\")") ||
                                    line.contains("from 'cluster'") ||
                                    line.contains("from \"cluster\"") ||
                                    line.contains("cluster.fork(") ||
                                    line.contains("cluster.isMaster") ||
                                    line.contains("cluster.isPrimary")
                                });
                                
                                if has_cluster {
                                    use std::os::unix::fs::MetadataExt;
                                    if let Ok(meta) = std::fs::metadata(&target) {
                                        let inode = meta.ino();
                                        tracing::info!("[Vandam Web] Node.js cluster mode detected for script: {} (PID: {}). Self-exec allowlisted.", script_path, pid);
                                        unsafe {
                                            ffi::update_map_entry(13, 0, inode, 1);
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

pub fn check_php_jit_enabled() -> bool {
    let paths = [
        "/etc/php/8.3/fpm/php.ini",
        "/etc/php/8.3/cli/php.ini",
        "/etc/php/8.2/fpm/php.ini",
        "/etc/php/8.1/fpm/php.ini",
        "/etc/php/fpm/php.ini",
    ];
    for p in &paths {
        if let Ok(content) = std::fs::read_to_string(p) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("opcache.jit") {
                    let parts: Vec<&str> = trimmed.split('=').collect();
                    if parts.len() > 1 {
                        let val = parts[1].trim();
                        if val != "off" && val != "0" && !val.is_empty() {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}
