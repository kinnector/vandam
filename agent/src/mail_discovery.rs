use crate::generic_discovery::{discover_and_enforce_services, ROLE_MAIL_GATEWAY};

pub fn enforce_mail_policies() {
    let services = discover_and_enforce_services("linux_mail_signatures.json", ROLE_MAIL_GATEWAY);
    tracing::info!("[Vandam Mail] Discovered {} mail gateway services.", services.len());

    // 1. Discover amavisd-new
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };
            if let Ok(target) = std::fs::read_link(entry.path().join("exe")) {
                let exe_name = target.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
                if exe_name.contains("amavisd") {
                    tracing::info!("[Vandam Mail] Discovered amavisd-new PID: {}", pid);
                    crate::generic_discovery::register_pid_signature(pid, "amavisd");
                    // Apply PROFILE_RESTRICTED_EXEC (0x20000000)
                    unsafe {
                        crate::ffi::update_process_threshold(pid, 0, 0x20000000);
                    }

                    // Register standard mail scanners in MAP_EXEC_ALLOWLIST (13)
                    let standard_scanners = [
                        "/usr/bin/spamc", "/usr/bin/spamassassin",
                        "/usr/bin/clamdscan", "/usr/bin/clamscan",
                        "/usr/bin/razor-check", "/usr/bin/razor-report",
                        "/usr/bin/pyzor", "/usr/bin/dccproc",
                        "/usr/sbin/opendkim", "/usr/sbin/opendmarc",
                        "/usr/bin/altermime", "/usr/bin/reformime",
                        "/usr/bin/cat", "/usr/bin/gzip", "/usr/bin/gunzip"
                    ];
                    use std::os::unix::fs::MetadataExt;
                    for path in &standard_scanners {
                        if let Ok(meta) = std::fs::metadata(path) {
                            let inode = meta.ino();
                            unsafe {
                                crate::ffi::update_map_entry(13, 0, inode, 1);
                            }
                        }
                    }

                    // Dynamically scan /etc/amavis/conf.d/ or config files for custom scanner paths
                    let conf_paths = [
                        "/etc/amavis/amavisd.conf",
                        "/etc/amavis/conf.d/15-content_filter_vscan",
                        "/etc/amavis/conf.d/50-user"
                    ];
                    for cp in &conf_paths {
                        if let Ok(content) = std::fs::read_to_string(cp) {
                            for word in content.split_whitespace() {
                                let cleaned = word.trim_matches(|c| c == '\'' || c == '"' || c == '[' || c == ']' || c == ',' || c == ';');
                                if cleaned.starts_with('/') && (cleaned.contains("/bin/") || cleaned.contains("/sbin/")) {
                                    if let Ok(meta) = std::fs::metadata(cleaned) {
                                        let inode = meta.ino();
                                        tracing::info!("[Vandam Mail] Discovered custom amavisd scanner path: {} (Inode: {})", cleaned, inode);
                                        unsafe {
                                            crate::ffi::update_map_entry(13, 0, inode, 1);
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

    // Cascade 8 Sendmail pipe alias transport scanner
    let aliases_paths = ["/etc/aliases", "/etc/mail/aliases"];
    for ap in &aliases_paths {
        if let Ok(content) = std::fs::read_to_string(ap) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains(':') {
                    continue;
                }
                if let Some(pipe_idx) = trimmed.find('|') {
                    let cmd_part = &trimmed[pipe_idx + 1..];
                    let clean_cmd = cmd_part.trim_matches(|c| c == '"' || c == '\'' || c == ' ');
                    let binary = clean_cmd.split_whitespace().next().unwrap_or("");
                    if binary.starts_with('/') {
                        use std::os::unix::fs::MetadataExt;
                        if let Ok(meta) = std::fs::metadata(binary) {
                            let inode = meta.ino();
                            tracing::info!("[Vandam Mail] Discovered Sendmail pipe alias binary: {} (Inode: {}). Allowlisted.", binary, inode);
                            unsafe {
                                crate::ffi::update_map_entry(13, 0, inode, 1);
                            }
                        }
                    }
                }
            }
        }
    }
}
