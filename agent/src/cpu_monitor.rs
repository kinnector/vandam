use crate::heuristics::HeuristicsEngine;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;

pub fn start_cpu_monitor(heuristics: Arc<HeuristicsEngine>) {
    tokio::spawn(async move {
        let last_ticks: DashMap<u32, u64> = DashMap::new();
        let anomaly_checks: DashMap<u32, u32> = DashMap::new();

        let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
        let num_cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as f64;
        let interval_secs = 5.0;

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;

            // Gather all active pids from process map
            let pids: Vec<u32> = heuristics
                .process_map
                .iter()
                .map(|entry| *entry.key())
                .collect();

            for pid in pids {
                // Skip if the pid has been excluded
                if crate::allowlist::get_disabled_monitoring_pids().contains(&pid) {
                    continue;
                }

                if let Some(total_ticks) = get_process_cpu_ticks(pid) {
                    if let Some(prev) = last_ticks.get(&pid) {
                        let diff_ticks = total_ticks.saturating_sub(*prev);
                        let diff_secs = (diff_ticks as f64) / clk_tck;
                        let cpu_percent = 100.0 * diff_secs / (interval_secs * num_cores);

                        // If cpu utilization exceeds 75% (heavy mining or CPU abuse)
                        if cpu_percent > 75.0 {
                            let count = anomaly_checks.get(&pid).map(|c| *c).unwrap_or(0) + 1;
                            anomaly_checks.insert(pid, count);

                            // If it exceeds the threshold for 3 consecutive checks (15 seconds)
                            if count >= 3 {
                                if let Some(proc) = heuristics.process_map.get(&pid) {
                                    emit_cpu_anomaly_alert(
                                        pid,
                                        &proc.exe,
                                        &proc.cmdline,
                                        cpu_percent,
                                    );
                                }
                                // Reset count to prevent spamming
                                anomaly_checks.insert(pid, 0);
                            }
                        } else {
                            // Reset count if it goes below 75%
                            anomaly_checks.insert(pid, 0);
                        }
                    }
                    last_ticks.insert(pid, total_ticks);
                } else {
                    // Process died or stats unavailable, clean up maps
                    last_ticks.remove(&pid);
                    anomaly_checks.remove(&pid);
                }
            }
        }
    });
}

fn get_process_cpu_ticks(pid: u32) -> Option<u64> {
    let path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(path).ok()?;
    let start_idx = content.rfind(')')?;
    let fields_str = &content[start_idx + 1..];
    let fields: Vec<&str> = fields_str.split_whitespace().collect();
    if fields.len() >= 13 {
        let utime = fields[11].parse::<u64>().ok()?;
        let stime = fields[12].parse::<u64>().ok()?;
        Some(utime + stime)
    } else {
        None
    }
}

fn emit_cpu_anomaly_alert(pid: u32, exe: &str, cmdline: &str, cpu_usage: f64) {
    let alert_id = uuid::Uuid::new_v4().to_string();
    let payload = crate::notifications::AlertPayload {
        alert_id,
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Threat.Server.CPUAnomalyMiner".to_string(),
        severity: "CRITICAL".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid,
            exec_path: exe.to_string(),
            cmdline: cmdline.to_string(),
            parent_exec_path: String::new(),
            parent_pid: 0,
            verified_package: Some(crate::allowlist::verify_system_package_binary(&String::new())),
            envs: Vec::new(),
            args: Vec::new(),
                    signature_name: None,
            service: None,
},
        remediation: crate::notifications::RemediationInfo {
            action: "LOG_ALERT".to_string(),
            status: format!(
                "High CPU usage anomaly detected ({:.1}% CPU on {} cores). Possible cryptominer or infinite loop.",
                cpu_usage,
                unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) }
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
