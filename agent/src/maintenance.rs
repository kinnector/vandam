use chrono::Utc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Mutex, OnceLock};

static MAINTENANCE_ACTIVE: AtomicBool = AtomicBool::new(false);
static MAINTENANCE_EXPIRES_AT: AtomicI64 = AtomicI64::new(0);
static MAINTENANCE_REASON: OnceLock<Mutex<String>> = OnceLock::new();

fn get_reason_lock() -> &'static Mutex<String> {
    MAINTENANCE_REASON.get_or_init(|| Mutex::new(String::from("Scheduled maintenance")))
}

pub fn is_maintenance_active() -> bool {
    if !MAINTENANCE_ACTIVE.load(Ordering::Relaxed) {
        return false;
    }
    let expires = MAINTENANCE_EXPIRES_AT.load(Ordering::Relaxed);
    if expires > 0 && Utc::now().timestamp() > expires {
        MAINTENANCE_ACTIVE.store(false, Ordering::Relaxed);
        tracing::info!(
            "[Vandam Maintenance] Maintenance window expired. Protection enforcement restored."
        );
        false
    } else {
        true
    }
}

pub fn enable_maintenance_mode(duration_minutes: u64, reason: &str) {
    MAINTENANCE_ACTIVE.store(true, Ordering::Relaxed);
    let expires = if duration_minutes > 0 {
        Utc::now().timestamp() + (duration_minutes * 60) as i64
    } else {
        0
    };
    MAINTENANCE_EXPIRES_AT.store(expires, Ordering::Relaxed);
    if let Ok(mut guard) = get_reason_lock().lock() {
        *guard = reason.to_string();
    }

    let duration_str = if duration_minutes == 0 {
        "indefinite (no timeout)".to_string()
    } else {
        format!("{} minutes", duration_minutes)
    };

    tracing::info!(
        "[Vandam Maintenance] Maintenance mode ENABLED for {} (Reason: '{}')",
        duration_str,
        reason
    );

    // Dispatch notification
    let alert_id = uuid::Uuid::new_v4().to_string();
    let payload = crate::notifications::AlertPayload {
        alert_id,
        timestamp: Utc::now().to_rfc3339(),
        threat_type: "Event.Vandam.MaintenanceModeEnabled".to_string(),
        severity: "WARNING".to_string(),
        confidence: 1.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: std::process::id(),
            exec_path: "/usr/bin/vandamd".to_string(),
            cmdline: format!(
                "maintenance_enable(mins={}, reason='{}')",
                duration_minutes, reason
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
            action: "MAINTENANCE_ON".to_string(),
            status: format!(
                "Protection enforcement paused for maintenance. Duration: {}. Reason: {}",
                duration_str, reason
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

pub fn disable_maintenance_mode() {
    let was_active = MAINTENANCE_ACTIVE.swap(false, Ordering::Relaxed);
    MAINTENANCE_EXPIRES_AT.store(0, Ordering::Relaxed);

    if was_active {
        tracing::info!(
            "[Vandam Maintenance] Maintenance mode DISABLE. Full protection enforcement active."
        );

        let alert_id = uuid::Uuid::new_v4().to_string();
        let payload = crate::notifications::AlertPayload {
            alert_id,
            timestamp: Utc::now().to_rfc3339(),
            threat_type: "Event.Vandam.MaintenanceModeDisabled".to_string(),
            severity: "INFO".to_string(),
            confidence: 1.0,
            container: None,
            process: crate::notifications::ProcessInfo {
                pid: std::process::id(),
                exec_path: "/usr/bin/vandamd".to_string(),
                cmdline: "maintenance_disable()".to_string(),
                parent_exec_path: "systemd".to_string(),
                parent_pid: 1,
                verified_package: None,
                envs: Vec::new(),
                args: Vec::new(),
                signature_name: None,
                service: None,
            },
            remediation: crate::notifications::RemediationInfo {
                action: "MAINTENANCE_OFF".to_string(),
                status: "Protection enforcement fully restored.".to_string(),
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
}

pub fn get_maintenance_status() -> serde_json::Value {
    let active = is_maintenance_active();
    let expires = MAINTENANCE_EXPIRES_AT.load(Ordering::Relaxed);
    let reason = get_reason_lock()
        .lock()
        .map(|g| g.clone())
        .unwrap_or_default();

    serde_json::json!({
        "active": active,
        "expires_at_unix": expires,
        "reason": reason,
    })
}
