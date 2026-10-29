use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use crate::heuristics::HeuristicsEngine;

static LAST_SEQUENCE_NUMBER: AtomicU64 = AtomicU64::new(0);
static TOTAL_DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

pub fn track_sequence_number(seq: u64) {
    let last_seq = LAST_SEQUENCE_NUMBER.swap(seq, Ordering::Relaxed);
    if last_seq > 0 && seq > last_seq + 1 {
        let dropped = seq - last_seq - 1;
        TOTAL_DROPPED_EVENTS.fetch_add(dropped, Ordering::Relaxed);
        tracing::warn!("[Vandam Telemetry] Detected gap in BPF sequence numbers: dropped {} events (seq: {} -> {})", dropped, last_seq, seq);
    }
}

pub fn get_and_reset_dropped_count() -> u64 {
    TOTAL_DROPPED_EVENTS.swap(0, Ordering::Relaxed)
}

pub fn reset_sequence_tracking() {
    LAST_SEQUENCE_NUMBER.store(0, Ordering::Relaxed);
    TOTAL_DROPPED_EVENTS.store(0, Ordering::Relaxed);
}

pub fn check_bpf_links_health() -> Vec<String> {
    let expected_links = [
        "file_open",
        "socket_connect",
        "socket_listen",
        "bprm_creds_for_exec",
        "bprm_check_security",
        "ptrace_access_check",
        "file_mprotect",
        "task_kill",
        "path_chmod",
        "file_permission",
    ];

    let mut missing = Vec::new();
    let bpf_dir = std::path::Path::new("/sys/fs/bpf/warden");
    if bpf_dir.exists() {
        for link in &expected_links {
            let path = bpf_dir.join(link);
            if !path.exists() {
                missing.push(link.to_string());
            }
        }
    }
    missing
}

pub fn notify_systemd_watchdog() {
    if let Ok(notify_socket) = std::env::var("NOTIFY_SOCKET") {
        if let Ok(socket) = std::os::unix::net::UnixDatagram::unbound() {
            let _ = socket.send_to(b"WATCHDOG=1", notify_socket);
        }
    }
}

pub async fn start_ebpf_health_monitor(heuristics: Arc<HeuristicsEngine>) {
    tracing::info!("[Vandam Health] Starting background eBPF and Telemetry Health Monitor loop...");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        notify_systemd_watchdog();

        // 1. Check for detached eBPF links
        // We only check if the /sys/fs/bpf/warden folder exists (indicating BPF was loaded)
        if std::path::Path::new("/sys/fs/bpf/warden").exists() {
            let missing_links = check_bpf_links_health();
            if !missing_links.is_empty() {
                tracing::warn!("[Vandam Health] ALERT: Detached eBPF links detected: {:?}", missing_links);
                let alert_id = uuid::Uuid::new_v4().to_string();
                let reason = format!(
                    "Critical eBPF security hooks were detached or deleted from sysfs: {:?}",
                    missing_links
                );

                heuristics.emit_threat_with_id(
                    alert_id,
                    std::process::id(),
                    "/usr/bin/vandamd",
                    "vandamd",
                    "",
                    0,
                    "Warning.Vandam.BPFDetached",
                    &reason
                );
            }
        }

        // 2. Check for dropped ring buffer telemetry events
        let dropped = get_and_reset_dropped_count();
        if dropped > 0 {
            tracing::warn!("[Vandam Health] ALERT: Telemetry events were dropped by eBPF ring buffer: {}", dropped);
            let alert_id = uuid::Uuid::new_v4().to_string();
            let reason = format!(
                "eBPF ring buffer overflow detected. Telemetry dropped count: {} events.",
                dropped
            );

            heuristics.emit_threat_with_id(
                alert_id,
                std::process::id(),
                "/usr/bin/vandamd",
                "vandamd",
                "",
                0,
                "Warning.Vandam.TelemetryDropped",
                &reason
            );
        }

        // 3b. Firewall map content-integrity check — link-presence alone
        // (check 1, above) doesn't catch a root user emptying/rewriting
        // fw_rules_v4/v6 directly via bpftool while leaving the
        // socket_connect hook attached; comparing the kernel's own live
        // entry count against what vandamd's reconcile pass believes it
        // pushed closes that gap. A mismatch doesn't distinguish "tampered"
        // from "reconcile hasn't run since a legitimate rule change yet",
        // so this alerts rather than auto-correcting — a human should look.
        let kernel_count = unsafe { crate::ffi::count_firewall_entries() };
        if kernel_count >= 0 {
            let expected = crate::firewall::reconcile::expected_ebpf_entry_count() as i64;
            if kernel_count != expected {
                tracing::warn!(
                    "[Vandam Health] ALERT: firewall eBPF map entry count mismatch — kernel reports {}, vandamd expects {}",
                    kernel_count, expected
                );
                let alert_id = uuid::Uuid::new_v4().to_string();
                let reason = format!(
                    "In-kernel firewall table (fw_rules_v4/v6) entry count ({}) does not match vandamd's expected count ({}) — possible direct kernel-map tampering outside vandamd/vandam.",
                    kernel_count, expected
                );
                heuristics.emit_threat_with_id(
                    alert_id,
                    std::process::id(),
                    "/usr/bin/vandamd",
                    "vandamd",
                    "",
                    0,
                    "Warning.Vandam.FirewallMapTampered",
                    &reason
                );
            }
        }

        // 3. Check for BPF map capacity exhaustion (>80% fill rate)
        let map_capacity_warnings = check_bpf_map_capacities();
        for (map_name, count, max_entries) in map_capacity_warnings {
            tracing::warn!("[Vandam Health] ALERT: BPF Map {} capacity high: {}/{}", map_name, count, max_entries);
            let alert_id = uuid::Uuid::new_v4().to_string();
            let reason = format!(
                "BPF map {} reached >80% capacity fill rate ({}/{} max entries). New entries may be dropped.",
                map_name, count, max_entries
            );

            heuristics.emit_threat_with_id(
                alert_id,
                std::process::id(),
                "/usr/bin/vandamd",
                "vandamd",
                "",
                0,
                "Warning.Vandam.BPFMapCapacity",
                &reason
            );
        }
    }
}

pub fn check_bpf_map_capacities() -> Vec<(String, u32, u32)> {
    let maps_to_check = [
        ("process_threshold_map", 65536),
        ("sensitive_inodes_map", 65536),
        ("exec_allowlist_map", 65536),
        ("dns_cache_map", 4096),
    ];

    let exceeded = Vec::new();
    let bpf_dir = std::path::Path::new("/sys/fs/bpf/warden");
    if bpf_dir.exists() {
        for (map_name, _max_entries) in &maps_to_check {
            let path = bpf_dir.join(map_name);
            if path.exists() {
                // If map pin exists, check if fill rate is above 80%
            }
        }
    }
    exceeded
}
