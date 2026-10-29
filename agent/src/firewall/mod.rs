//! Unified firewall rule store — the single source of truth reconciled out to
//! iptables/nftables (`backend.rs`) and, for explicit IP/CIDR rules plus a
//! budget-capped subset of country rules, the in-kernel eBPF table
//! (`reconcile.rs`, `EbpfBackend`). Rules may target an IP/CIDR directly or a
//! GeoIP country code (resolved via `crate::rules::lookup_country_ranges`
//! at reconcile time — see `reconcile.rs`).
//!
//! Persisted as a versioned-envelope JSON file at
//! `/etc/kinnector/firewall_rules.json`, following this workspace's existing
//! flat-JSON-under-/etc/kinnector convention (no embedded DB exists here —
//! see `user_rules.json`, `notifications.json`). `read_firewall_rules()`
//! transparently migrates the pre-existing flat-array schema (a bare
//! `Vec<FirewallRule>` with an `ip_or_cidr: String` field) on first read.

pub mod backend;
pub mod cloud_sync;
pub mod reconcile;

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write as IoWrite};
use std::path::Path;

const FIREWALL_RULES_PATH: &str = "/etc/kinnector/firewall_rules.json";
const SCHEMA_VERSION: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum FirewallTarget {
    /// A single IPv4/IPv6 address or CIDR block, e.g. "203.0.113.0/24".
    IpCidr(String),
    /// ISO 3166-1 alpha-2 country code, e.g. "US". Resolved to concrete
    /// CIDRs at reconcile time via `crate::rules::lookup_country_ranges`
    /// — never stored pre-resolved, so a GeoIP data refresh is picked up
    /// automatically on the next reconcile pass.
    Country(String),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallProvenance {
    /// Created via the local UDS API (vandam TUI/CLI, a real
    /// SSH/console session — see `api::resolve_caller_context`).
    Local,
    /// Created by a cloud-issued command (fleet dashboard / gRPC remote
    /// command channel). Cloud-provenance rules are `locked` — the local
    /// API refuses to mutate or delete them; see `api.rs`'s firewall
    /// handlers for the enforcement of that rule.
    Cloud,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirewallRule {
    pub id: String,
    pub target: FirewallTarget,
    /// "inbound" | "outbound"
    pub direction: String,
    /// "DROP" | "REJECT" | "ACCEPT"
    pub action: String,
    /// `None` = any port. Only `IptablesBackend` enforces this precisely —
    /// `NftablesBackend` and the eBPF layer apply CIDR-scoped rules without
    /// port granularity in this pass (see `backend.rs`/`reconcile.rs`), so a
    /// rule with both a CIDR target and a port is routed through iptables
    /// specifically to avoid silently over-blocking. See `reconcile.rs`'s
    /// `select_backend_for_rule`.
    pub port: Option<u16>,
    /// "site" | "global"
    pub scope: String,
    pub site: Option<String>,
    pub reason: Option<String>,
    pub provenance: FirewallProvenance,
    /// True for `Cloud`-provenance rules — blocks local mutation regardless
    /// of caller context (even `god_mode`). Not user-settable directly.
    pub locked: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FirewallRulesFile {
    schema_version: u32,
    rules: Vec<FirewallRule>,
}

/// Pre-v2 on-disk shape (flat array, `ip_or_cidr: String`, no provenance/
/// locking) — kept only to migrate `firewall_rules.json` files written by
/// earlier builds. Upconverted to `FirewallTarget::IpCidr` /
/// `FirewallProvenance::Local` / `locked: false` on first read.
#[derive(Deserialize)]
struct LegacyFirewallRule {
    id: String,
    ip_or_cidr: String,
    direction: String,
    action: String,
    scope: String,
    site: Option<String>,
    reason: Option<String>,
    created_at: String,
}

pub fn read_firewall_rules() -> Vec<FirewallRule> {
    let Ok(mut file) = File::open(FIREWALL_RULES_PATH) else {
        return Vec::new();
    };
    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() {
        return Vec::new();
    }

    if let Ok(envelope) = serde_json::from_str::<FirewallRulesFile>(&content) {
        return envelope.rules;
    }

    // Fall back to the legacy flat-array schema and migrate it in place.
    if let Ok(legacy_rules) = serde_json::from_str::<Vec<LegacyFirewallRule>>(&content) {
        let migrated: Vec<FirewallRule> = legacy_rules
            .into_iter()
            .map(|r| FirewallRule {
                id: r.id,
                target: FirewallTarget::IpCidr(r.ip_or_cidr),
                direction: r.direction,
                action: r.action,
                port: None,
                scope: r.scope,
                site: r.site,
                reason: r.reason,
                provenance: FirewallProvenance::Local,
                locked: false,
                created_at: r.created_at.clone(),
                updated_at: r.created_at,
            })
            .collect();
        write_firewall_rules(&migrated);
        return migrated;
    }

    Vec::new()
}

pub fn write_firewall_rules(rules: &[FirewallRule]) -> bool {
    if let Some(parent) = Path::new(FIREWALL_RULES_PATH).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let envelope = FirewallRulesFile {
        schema_version: SCHEMA_VERSION,
        rules: rules.to_vec(),
    };
    let Ok(mut file) = File::create(FIREWALL_RULES_PATH) else {
        return false;
    };
    let Ok(content) = serde_json::to_string_pretty(&envelope) else {
        return false;
    };
    file.write_all(content.as_bytes()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_legacy_flat_array_shape() {
        let legacy_json = r#"[
            {"id":"abc123","ip_or_cidr":"203.0.113.0/24","direction":"inbound","action":"DROP","scope":"global","site":null,"reason":"test","created_at":"2026-01-01"}
        ]"#;
        let legacy_rules: Vec<LegacyFirewallRule> = serde_json::from_str(legacy_json).unwrap();
        assert_eq!(legacy_rules.len(), 1);

        let migrated = FirewallRule {
            id: legacy_rules[0].id.clone(),
            target: FirewallTarget::IpCidr(legacy_rules[0].ip_or_cidr.clone()),
            direction: legacy_rules[0].direction.clone(),
            action: legacy_rules[0].action.clone(),
            port: None,
            scope: legacy_rules[0].scope.clone(),
            site: legacy_rules[0].site.clone(),
            reason: legacy_rules[0].reason.clone(),
            provenance: FirewallProvenance::Local,
            locked: false,
            created_at: legacy_rules[0].created_at.clone(),
            updated_at: legacy_rules[0].created_at.clone(),
        };
        assert_eq!(migrated.target, FirewallTarget::IpCidr("203.0.113.0/24".to_string()));
        assert!(!migrated.locked);
        assert_eq!(migrated.provenance, FirewallProvenance::Local);
    }

    #[test]
    fn envelope_round_trips_through_serde() {
        let rule = FirewallRule {
            id: "r1".to_string(),
            target: FirewallTarget::Country("US".to_string()),
            direction: "inbound".to_string(),
            action: "DROP".to_string(),
            port: None,
            scope: "global".to_string(),
            site: None,
            reason: None,
            provenance: FirewallProvenance::Cloud,
            locked: true,
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-01-01".to_string(),
        };
        let envelope = FirewallRulesFile { schema_version: SCHEMA_VERSION, rules: vec![rule] };
        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: FirewallRulesFile = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.rules[0].target, FirewallTarget::Country("US".to_string()));
        assert!(parsed.rules[0].locked);
    }
}
