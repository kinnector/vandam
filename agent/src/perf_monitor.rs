use crate::heuristics::HeuristicsEngine;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

static TOTAL_EVENTS_PROCESSED: AtomicU64 = AtomicU64::new(0);
static LAST_EVENT_TIMESTAMP_MS: AtomicU64 = AtomicU64::new(0);
static TOTAL_PROCESSING_LATENCY_US: AtomicU64 = AtomicU64::new(0);

pub fn record_event_processed(latency_us: u64) {
    TOTAL_EVENTS_PROCESSED.fetch_add(1, Ordering::Relaxed);
    TOTAL_PROCESSING_LATENCY_US.fetch_add(latency_us, Ordering::Relaxed);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    LAST_EVENT_TIMESTAMP_MS.store(now, Ordering::Relaxed);
}

pub fn start_perf_monitor_loop(_heuristics: Arc<HeuristicsEngine>) {
    tokio::spawn(async move {
        tracing::info!("[Vandam PerfMonitor] Starting performance metrics telemetry collector...");
        let mut last_total_events = 0u64;

        loop {
            sleep(Duration::from_secs(60)).await;

            let total_events = TOTAL_EVENTS_PROCESSED.load(Ordering::Relaxed);
            let total_latency = TOTAL_PROCESSING_LATENCY_US.load(Ordering::Relaxed);
            let delta_events = total_events.saturating_sub(last_total_events);
            last_total_events = total_events;

            let events_per_sec = (delta_events as f64) / 60.0;
            let avg_latency_us = if total_events > 0 {
                (total_latency as f64) / (total_events as f64)
            } else {
                0.0
            };

            let dropped_events = crate::ebpf_health::get_and_reset_dropped_count();
            let _map_capacities = crate::ebpf_health::check_bpf_map_capacities();

            let status_msg = format!(
                "Performance Metrics: {:.2} events/sec, avg processing latency: {:.2}µs, total processed: {}, ring buffer drops: {}",
                events_per_sec, avg_latency_us, total_events, dropped_events
            );

            tracing::info!("[Vandam PerfMonitor] {}", status_msg);

            // Dispatch metrics telemetry event to cloud backend and audit log
            let alert_id = uuid::Uuid::new_v4().to_string();
            let payload = crate::notifications::AlertPayload {
                alert_id,
                timestamp: chrono::Utc::now().to_rfc3339(),
                threat_type: "Metric.Vandam.PerformanceSummary".to_string(),
                severity: "INFO".to_string(),
                confidence: 1.0,
                container: None,
                process: crate::notifications::ProcessInfo {
                    pid: std::process::id(),
                    exec_path: "/usr/bin/vandamd".to_string(),
                    cmdline: format!(
                        "perf_summary(eps={:.2}, latency_us={:.2})",
                        events_per_sec, avg_latency_us
                    ),
                    parent_exec_path: "systemd".to_string(),
                    parent_pid: 1,
                    verified_package: None,
                    envs: Vec::new(),
                    args: Vec::new(),
                    signature_name: None,
                    service: None,
                },
                remediation: crate::notifications::RemediationInfo {
                    action: "TELEMETRY_RECORD".to_string(),
                    status: status_msg,
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
    });
}
