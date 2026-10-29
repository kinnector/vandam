/// Real (non-mock) daemon health data for the Status tab's "Daemon Engine &
/// Security Databases" block. Counterpart to `state.rs`'s `MockState` — kept
/// in a separate module so the mock/real boundary stays visible as more
/// dashboard pages get wired to `vandamd` in later passes.
pub struct DaemonHealth {
    pub version: String,
    pub lsm_active: bool,
    pub custom_config_active: bool,
    pub quarantine_count: u64,
    pub firewall_blocks_count: u64,
    /// Unix seconds this Linux root filesystem was created
    /// (`vandam::install_date`, read live from `/lost+found`'s filesystem
    /// birth time — not daemon uptime, and deliberately not when Vandam
    /// itself was configured either: a system that's been running exposed
    /// for years and only just got Vandam installed is the highest-risk
    /// case for trusting a fresh baseline, and needs to read as *old*, not
    /// brand-new just because Vandam is new here). `None` if unreadable.
    /// Used (thresholded, e.g. ~6 months) as one half of the file-integrity
    /// re-baseline advisory's trigger — see
    /// `site_config::draw_site_config`'s `show_reaudit_advisory` doc
    /// comment for why this and audit history, not local heuristic hits,
    /// are the basis for that advisory.
    pub installed_at_unix: Option<i64>,
    pub file_integrity_active: bool,
    pub rules_db_ok: bool,
    pub rules_db_path: String,
    /// Real daemon license state (`daemon.tier == "paid"`), not the TUI's own
    /// mock `Tier` enum (which is env-var-driven demo state for the dashboard
    /// gating and unrelated to what's actually licensed on this daemon).
    pub is_paid: bool,
    /// True only for vandam with its RASP telemetry listener actually
    /// running — independent of `is_paid` (a Pro binary with no license
    /// still has this true; OSS never does). Drives whether PHP site
    /// attribution is even possible at all, which is a base Pro-binary
    /// capability, not something requiring an active subscription.
    pub rasp_active: bool,
    /// Row 2's data — same `ServersData` shape as `/api/v1/servers`, since
    /// vandamd's `get_status()` embeds the exact same `get_servers_data()`
    /// output. Reused here so Status row 2 doesn't need a second round trip.
    pub discovered_servers: crate::client::servers::ServersData,
    /// Row 3's data — same shape as `/api/v1/containers`, embedded in
    /// `get_status()` the same way `discovered_servers` is. Reused for both
    /// Status row 3 and the Containers tab's initial load, so neither needs
    /// a second round trip on startup.
    pub discovered_containers: crate::client::containers::ContainersData,
}

pub enum DaemonStatus {
    Connected(DaemonHealth),
    Unreachable(String),
}

/// Parses a `/api/v1/status` response body. Defensive field access mirrors
/// the `.get(...).unwrap_or(...)` style already used for the same endpoint
/// in `src/lib.rs`'s `Commands::Status` handler.
pub fn parse(value: &serde_json::Value) -> DaemonHealth {
    let daemon = &value["daemon"];
    let security_state = &value["security_state"];
    let config = &value["config"];

    DaemonHealth {
        version: daemon.get("version").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        lsm_active: security_state.get("lsm_active").and_then(|v| v.as_bool()).unwrap_or(false),
        custom_config_active: daemon.get("custom_config_active").and_then(|v| v.as_bool()).unwrap_or(false),
        quarantine_count: security_state.get("quarantine_count").and_then(|v| v.as_u64()).unwrap_or(0),
        firewall_blocks_count: security_state.get("firewall_blocks_count").and_then(|v| v.as_u64()).unwrap_or(0),
        installed_at_unix: daemon.get("installed_at_unix").and_then(|v| v.as_i64()),
        file_integrity_active: security_state.get("fim").and_then(|f| f.get("active")).and_then(|v| v.as_bool()).unwrap_or(false),
        rules_db_ok: config.get("rules_db").and_then(|d| d.get("ok")).and_then(|v| v.as_bool()).unwrap_or(false),
        rules_db_path: config.get("rules_db").and_then(|d| d.get("path")).and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
        is_paid: daemon.get("tier").and_then(|v| v.as_str()).map(|t| t == "paid").unwrap_or(false),
        rasp_active: daemon.get("rasp_active").and_then(|v| v.as_bool()).unwrap_or(false),
        discovered_servers: crate::client::servers::from_status_json(value),
        discovered_containers: crate::client::containers::from_status_json(value),
    }
}

pub fn fetch(socket_path: &str) -> DaemonStatus {
    match crate::query_daemon(socket_path, "GET", "/api/v1/status", None) {
        Ok(value) => DaemonStatus::Connected(parse(&value)),
        Err(e) => DaemonStatus::Unreachable(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_full_payload_reads_every_field() {
        let value = json!({
            "daemon": { "version": "0.4.1", "custom_config_active": true, "tier": "paid", "rasp_active": true, "installed_at_unix": 1_700_000_000 },
            "security_state": {
                "lsm_active": true,
                "quarantine_count": 3,
                "firewall_blocks_count": 7,
                "fim": { "active": true }
            },
            "config": {
                "rules_db": { "path": "/etc/kinnector/rules.db", "ok": true }
            }
        });

        let health = parse(&value);
        assert_eq!(health.version, "0.4.1");
        assert!(health.lsm_active);
        assert!(health.custom_config_active);
        assert_eq!(health.quarantine_count, 3);
        assert_eq!(health.firewall_blocks_count, 7);
        assert_eq!(health.installed_at_unix, Some(1_700_000_000));
        assert!(health.file_integrity_active);
        assert!(health.rules_db_ok);
        assert_eq!(health.rules_db_path, "/etc/kinnector/rules.db");
        assert!(health.is_paid);
        assert!(health.rasp_active);
    }

    #[test]
    fn parse_free_tier_reports_not_paid() {
        let health = parse(&json!({ "daemon": { "tier": "free" } }));
        assert!(!health.is_paid);
    }

    #[test]
    fn parse_unlicensed_pro_reports_rasp_active_without_paid() {
        // A Pro binary with no license: rasp_active true, is_paid false —
        // the two are independent signals.
        let health = parse(&json!({ "daemon": { "tier": "free", "rasp_active": true } }));
        assert!(health.rasp_active);
        assert!(!health.is_paid);
    }

    #[test]
    fn parse_missing_fields_falls_back_to_safe_defaults() {
        let health = parse(&json!({}));
        assert_eq!(health.version, "unknown");
        assert!(!health.lsm_active);
        assert!(!health.custom_config_active);
        assert_eq!(health.quarantine_count, 0);
        assert_eq!(health.firewall_blocks_count, 0);
        assert_eq!(health.installed_at_unix, None);
        assert!(!health.file_integrity_active);
        assert!(!health.rules_db_ok);
        assert_eq!(health.rules_db_path, "unknown");
        assert!(!health.is_paid);
        assert!(!health.rasp_active);
    }
}
