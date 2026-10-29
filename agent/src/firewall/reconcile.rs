//! Recomputes desired kernel/userspace firewall state from the rule store on
//! every trigger (rule CRUD, `kinnector_config` reload, vandamd startup) and
//! diffs it against what was last applied — mirroring the *principle* behind
//! `api::get_servers_data()`'s trust reconcile (never trust a persisted
//! resolved-state cache, recompute from the source of truth every time),
//! adapted here to an add/remove diff because re-pushing thousands of
//! unchanged GeoIP CIDRs into a backend on every pass would be wasteful in a
//! way re-walking a small process tree isn't.

use crate::firewall::backend::{EbpfBackend, FirewallBackend, IptablesBackend};
use crate::firewall::{read_firewall_rules, write_firewall_rules, FirewallProvenance, FirewallRule, FirewallTarget};
use dashmap::DashMap;
use std::sync::OnceLock;

/// Merges a cloud-authored rule set (from `CloudFirewallSync::pull_cloud_rules`,
/// called by the periodic sync loop in `run_vandam` when
/// `VandamConfig::firewall_cloud_sync` is `Some`) into the local rule
/// store. Every incoming rule is force-tagged `provenance: Cloud, locked:
/// true` regardless of what the wire payload said — a security-relevant
/// flag is never taken on the transport's word. Existing `Cloud`-provenance
/// rules whose id isn't in the new set are dropped (the cloud is
/// authoritative for its own rules — a rule it stops sending was deleted
/// there); `Local`-provenance rules are left untouched. Does not itself
/// trigger a reconcile pass — the caller does that once, after this.
pub fn merge_cloud_rules(cloud_rules: Vec<FirewallRule>) {
    let merged = merge_rules_pure(read_firewall_rules(), cloud_rules);
    write_firewall_rules(&merged);
}

/// The actual merge logic, split out from `merge_cloud_rules` so it's
/// testable without touching `/etc/kinnector/firewall_rules.json`.
fn merge_rules_pure(existing: Vec<FirewallRule>, mut cloud_rules: Vec<FirewallRule>) -> Vec<FirewallRule> {
    for r in cloud_rules.iter_mut() {
        r.provenance = FirewallProvenance::Cloud;
        r.locked = true;
    }
    let cloud_ids: std::collections::HashSet<String> = cloud_rules.iter().map(|r| r.id.clone()).collect();

    let mut rules = existing;
    rules.retain(|r| r.provenance != FirewallProvenance::Cloud || cloud_ids.contains(&r.id));
    for incoming in cloud_rules {
        if let Some(existing_rule) = rules.iter_mut().find(|r| r.id == incoming.id) {
            *existing_rule = incoming;
        } else {
            rules.push(incoming);
        }
    }
    rules
}

/// What was last successfully applied for a given rule id — kept for the
/// lifetime of the vandamd process (not persisted; rebuilt by the first
/// reconcile pass after a restart, same non-persistence stance as
/// `trust.rs`'s `TRUSTED_PIDS` and `notifications.rs`'s alert state).
///
/// `cidrs` is the full desired set (what the userspace backend(s) carry);
/// `ebpf_cidrs` is the subset of that actually pushed to the eBPF backend —
/// tracked separately because it's a strict subset for `Country` rules once
/// the kernel-table budget (see `EBPF_COUNTRY_BUDGET`) is exhausted, and
/// diffing/revoking against the wrong set would either leave stale kernel
/// entries or spam revoke calls for CIDRs that were never actually pushed.
pub(crate) struct AppliedRuleState {
    rule: FirewallRule,
    cidrs: Vec<String>,
    ebpf_cidrs: Vec<String>,
}

pub(crate) type AppliedState = DashMap<String, AppliedRuleState>;

static APPLIED: OnceLock<AppliedState> = OnceLock::new();

fn applied() -> &'static AppliedState {
    APPLIED.get_or_init(DashMap::new)
}

/// Total capacity across both firewall LPM_TRIE maps (must track
/// `fw_rules_v4`/`fw_rules_v6`'s `max_entries` in kinnector.bpf.c).
const EBPF_TOTAL_CAPACITY: usize = 131072 + 32768;

/// Country (GeoIP) rules share at most half the kernel table's capacity —
/// the other half is reserved for explicit, human-curated IP/CIDR rules,
/// which get unconditional eBPF coverage. A single large country (e.g.
/// ~29,000 aggregated ranges for the US, confirmed against real ipdeny
/// data — see protect-community/configs/vandam/geoip_country_ranges.json)
/// can consume this budget on its own; nftables/iptables remain fully
/// authoritative for the complete country CIDR set regardless (see
/// `backend.rs`'s `NftablesBackend` doc comment) — this budget only bounds
/// the *in-kernel, best-effort* portion. See the Firewall design plan
/// (2026-08), finding #2.
const EBPF_COUNTRY_BUDGET: usize = EBPF_TOTAL_CAPACITY / 2;

/// Resolves a rule's target into concrete CIDRs. `IpCidr` is already
/// concrete; `Country` is expanded via `crate::rules::lookup_country_ranges`
/// — resolved fresh every pass (never cached across reconciles) so a GeoIP
/// dataset refresh is picked up automatically without any special-casing.
pub fn resolve_target_cidrs(target: &FirewallTarget, config: &crate::rules::ConfigManager) -> Vec<String> {
    match target {
        FirewallTarget::IpCidr(cidr) => vec![cidr.clone()],
        FirewallTarget::Country(code) => match config.lookup_country_ranges(code) {
            Some(ranges) => ranges.cidrs_v4.into_iter().chain(ranges.cidrs_v6).collect(),
            None => {
                tracing::warn!(
                    "[Vandam Firewall] Country rule target '{}' has no GeoIP data loaded — \
                     resolves to zero CIDRs until protect-community's geoip_country_ranges.json \
                     includes it. See protect-community/scripts/update_geoip.sh.",
                    code
                );
                Vec::new()
            }
        },
    }
}

/// A rule with a specific port can't be safely expressed at the nftables
/// layer yet (no concatenated address+port sets — see `backend.rs`'s
/// `NftablesBackend` doc comment) and never at the eBPF layer (LPM_TRIE has
/// no port dimension). Routing such a rule through iptables regardless of
/// which backend is "primary" avoids both backends silently over-blocking
/// the whole CIDR when only a port was meant to be blocked.
fn select_backend_for_rule<'a>(
    rule: &FirewallRule,
    primary: &'a dyn FirewallBackend,
    iptables_fallback: &'a IptablesBackend,
) -> &'a dyn FirewallBackend {
    if rule.port.is_some() && primary.name() != "iptables" {
        iptables_fallback
    } else {
        primary
    }
}

fn dedup(mut cidrs: Vec<String>) -> Vec<String> {
    cidrs.sort();
    cidrs.dedup();
    cidrs
}

/// Pure diff: which CIDRs need adding, which need removing, to go from
/// `previous` to `desired`. Split out from `reconcile_firewall` so it's
/// testable without touching the global `APPLIED` map or shelling out.
pub fn diff_cidrs(previous: &[String], desired: &[String]) -> (Vec<String>, Vec<String>) {
    let added: Vec<String> = desired.iter().filter(|c| !previous.contains(c)).cloned().collect();
    let removed: Vec<String> = previous.iter().filter(|c| !desired.contains(c)).cloned().collect();
    (added, removed)
}

pub struct ReconcileReport {
    pub rules_processed: usize,
    pub cidrs_added: usize,
    pub cidrs_removed: usize,
    pub errors: Vec<String>,
    /// Non-fatal, operator-facing notices — currently used only for
    /// partial eBPF-layer coverage on a `Country` rule (budget exhausted).
    /// The rule is still fully enforced (nftables/iptables carry the
    /// complete CIDR set unconditionally); this only means kernel-layer
    /// defense-in-depth is partial for that rule.
    pub warnings: Vec<String>,
}

/// Total CIDRs vandamd believes are currently pushed into the eBPF tables
/// (sum of `ebpf_cidrs` across every tracked rule) — the expected side of
/// `ebpf_health.rs`'s anti-tamper comparison against the kernel's own count
/// (`crate::ffi::count_firewall_entries()`). Reads the process-global
/// `APPLIED` map, so this reflects the real daemon's state, not a test's
/// isolated one — only meaningful outside `#[cfg(test)]`.
pub fn expected_ebpf_entry_count() -> usize {
    applied().iter().map(|e| e.ebpf_cidrs.len()).sum()
}

/// The real entry point — detects the primary userspace backend, adds the
/// eBPF backend when the kernel LSM subsystem is active, and applies
/// against both (plus iptables specifically for port-scoped rules; see
/// `select_backend_for_rule`). Call on: firewall rule CRUD,
/// `ConfigManager::reload()` completing, and vandamd startup.
pub fn reconcile_firewall(config: &crate::rules::ConfigManager) -> ReconcileReport {
    let primary = crate::firewall::backend::detect_primary_backend();
    let ebpf = EbpfBackend;
    let ebpf_ref: Option<&dyn FirewallBackend> = if ebpf.is_available() { Some(&ebpf) } else { None };
    reconcile_with_backend(config, primary.as_ref(), ebpf_ref, applied())
}

/// Same as `reconcile_firewall` but takes explicit backends and an explicit
/// applied-state map — the seam that makes this testable with mock
/// `FirewallBackend`s and an isolated state map instead of shelling out to
/// real `iptables`/`nft`/the eBPF FFI and sharing the process-global
/// `APPLIED` map across concurrently-running tests.
pub(crate) fn reconcile_with_backend(
    config: &crate::rules::ConfigManager,
    primary: &dyn FirewallBackend,
    ebpf: Option<&dyn FirewallBackend>,
    state: &AppliedState,
) -> ReconcileReport {
    let iptables_fallback = IptablesBackend;
    let rules = read_firewall_rules();
    let mut report = ReconcileReport {
        rules_processed: rules.len(),
        cidrs_added: 0,
        cidrs_removed: 0,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    let mut seen_ids = std::collections::HashSet::new();
    let mut ebpf_country_budget_remaining = EBPF_COUNTRY_BUDGET;

    for rule in &rules {
        seen_ids.insert(rule.id.clone());
        let desired = dedup(resolve_target_cidrs(&rule.target, config));
        let (previous_cidrs, previous_ebpf_cidrs) = state
            .get(&rule.id)
            .map(|s| (s.cidrs.clone(), s.ebpf_cidrs.clone()))
            .unwrap_or_default();

        // Userspace backend(s) — unconditional, full desired set.
        let (added, removed) = diff_cidrs(&previous_cidrs, &desired);
        let backend = select_backend_for_rule(rule, primary, &iptables_fallback);
        for cidr in &added {
            match backend.apply_cidr(cidr, rule) {
                Ok(()) => report.cidrs_added += 1,
                Err(e) => report.errors.push(format!("apply {} for rule {}: {}", cidr, rule.id, e)),
            }
        }
        for cidr in &removed {
            match backend.revoke_cidr(cidr, rule) {
                Ok(()) => report.cidrs_removed += 1,
                Err(e) => report.errors.push(format!("revoke {} for rule {}: {}", cidr, rule.id, e)),
            }
        }

        // eBPF backend — egress-only, budget-capped for Country targets.
        let ebpf_desired = if let Some(ebpf_backend) = ebpf {
            let capped = match &rule.target {
                FirewallTarget::IpCidr(_) => desired.clone(),
                FirewallTarget::Country(code) => {
                    let take = desired.len().min(ebpf_country_budget_remaining);
                    if take < desired.len() {
                        report.warnings.push(format!(
                            "rule {} (country {}): eBPF kernel-layer coverage partial — {}/{} CIDRs applied in-kernel (budget exhausted); nftables/iptables still enforce the full set",
                            rule.id, code, take, desired.len()
                        ));
                    }
                    ebpf_country_budget_remaining -= take;
                    desired[..take].to_vec()
                }
            };
            let (ebpf_added, ebpf_removed) = diff_cidrs(&previous_ebpf_cidrs, &capped);
            for cidr in &ebpf_added {
                if let Err(e) = ebpf_backend.apply_cidr(cidr, rule) {
                    report.errors.push(format!("ebpf apply {} for rule {}: {}", cidr, rule.id, e));
                }
            }
            for cidr in &ebpf_removed {
                if let Err(e) = ebpf_backend.revoke_cidr(cidr, rule) {
                    report.errors.push(format!("ebpf revoke {} for rule {}: {}", cidr, rule.id, e));
                }
            }
            capped
        } else {
            Vec::new()
        };

        state.insert(rule.id.clone(), AppliedRuleState { rule: rule.clone(), cidrs: desired, ebpf_cidrs: ebpf_desired });
    }

    // Rules deleted from the store since the last pass — revoke everything
    // that was applied for them, from both the userspace and eBPF layers.
    let stale_ids: Vec<String> = state.iter().map(|e| e.key().clone()).filter(|id| !seen_ids.contains(id)).collect();
    for id in stale_ids {
        if let Some((_, rule_state)) = state.remove(&id) {
            let backend = select_backend_for_rule(&rule_state.rule, primary, &iptables_fallback);
            for cidr in &rule_state.cidrs {
                match backend.revoke_cidr(cidr, &rule_state.rule) {
                    Ok(()) => report.cidrs_removed += 1,
                    Err(e) => report.errors.push(format!("revoke {} for deleted rule {}: {}", cidr, id, e)),
                }
            }
            if let Some(ebpf_backend) = ebpf {
                for cidr in &rule_state.ebpf_cidrs {
                    if let Err(e) = ebpf_backend.revoke_cidr(cidr, &rule_state.rule) {
                        report.errors.push(format!("ebpf revoke {} for deleted rule {}: {}", cidr, id, e));
                    }
                }
            }
        }
    }

    if !report.warnings.is_empty() {
        for w in &report.warnings {
            tracing::warn!("[Vandam Firewall] {}", w);
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallProvenance, FirewallTarget};
    use std::sync::Mutex;

    #[test]
    fn diff_cidrs_finds_additions_and_removals() {
        let previous = vec!["1.1.1.0/24".to_string(), "2.2.2.0/24".to_string()];
        let desired = vec!["2.2.2.0/24".to_string(), "3.3.3.0/24".to_string()];
        let (added, removed) = diff_cidrs(&previous, &desired);
        assert_eq!(added, vec!["3.3.3.0/24".to_string()]);
        assert_eq!(removed, vec!["1.1.1.0/24".to_string()]);
    }

    #[test]
    fn diff_cidrs_empty_previous_adds_everything() {
        let (added, removed) = diff_cidrs(&[], &["1.1.1.0/24".to_string()]);
        assert_eq!(added, vec!["1.1.1.0/24".to_string()]);
        assert!(removed.is_empty());
    }

    #[test]
    fn diff_cidrs_empty_desired_removes_everything() {
        let (added, removed) = diff_cidrs(&["1.1.1.0/24".to_string()], &[]);
        assert!(added.is_empty());
        assert_eq!(removed, vec!["1.1.1.0/24".to_string()]);
    }

    fn sample_rule(id: &str, target: FirewallTarget, port: Option<u16>) -> FirewallRule {
        FirewallRule {
            id: id.to_string(),
            target,
            direction: "inbound".to_string(),
            action: "DROP".to_string(),
            port,
            scope: "global".to_string(),
            site: None,
            reason: None,
            provenance: FirewallProvenance::Local,
            locked: false,
            created_at: "2026-01-01".to_string(),
            updated_at: "2026-01-01".to_string(),
        }
    }

    struct RecordingBackend {
        name: &'static str,
        applied: Mutex<Vec<String>>,
        revoked: Mutex<Vec<String>>,
    }

    impl RecordingBackend {
        fn new(name: &'static str) -> Self {
            Self { name, applied: Mutex::new(Vec::new()), revoked: Mutex::new(Vec::new()) }
        }
    }

    impl FirewallBackend for RecordingBackend {
        fn name(&self) -> &'static str {
            self.name
        }
        fn is_available(&self) -> bool {
            true
        }
        fn apply_cidr(&self, cidr: &str, _rule: &FirewallRule) -> Result<(), String> {
            self.applied.lock().unwrap().push(cidr.to_string());
            Ok(())
        }
        fn revoke_cidr(&self, cidr: &str, _rule: &FirewallRule) -> Result<(), String> {
            self.revoked.lock().unwrap().push(cidr.to_string());
            Ok(())
        }
    }

    #[test]
    fn select_backend_routes_port_scoped_rules_to_iptables() {
        let nft = RecordingBackend::new("nftables");
        let iptables = IptablesBackend;
        let rule_with_port = sample_rule("r1", FirewallTarget::IpCidr("1.2.3.0/24".to_string()), Some(443));
        let chosen = select_backend_for_rule(&rule_with_port, &nft, &iptables);
        assert_eq!(chosen.name(), "iptables");

        let rule_no_port = sample_rule("r2", FirewallTarget::IpCidr("1.2.3.0/24".to_string()), None);
        let chosen2 = select_backend_for_rule(&rule_no_port, &nft, &iptables);
        assert_eq!(chosen2.name(), "nftables");
    }

    #[test]
    fn select_backend_leaves_port_scoped_rule_on_iptables_when_already_primary() {
        let iptables_a = IptablesBackend;
        let iptables_b = IptablesBackend;
        let rule_with_port = sample_rule("r1", FirewallTarget::IpCidr("1.2.3.0/24".to_string()), Some(22));
        let chosen = select_backend_for_rule(&rule_with_port, &iptables_a, &iptables_b);
        assert_eq!(chosen.name(), "iptables");
    }

    #[test]
    fn resolve_target_cidrs_passes_through_ip_cidr_unchanged() {
        let config = crate::rules::ConfigManager::load_defaults();
        let cidrs = resolve_target_cidrs(&FirewallTarget::IpCidr("198.51.100.0/24".to_string()), &config);
        assert_eq!(cidrs, vec!["198.51.100.0/24".to_string()]);
    }

    #[test]
    fn resolve_target_cidrs_returns_empty_for_unknown_country() {
        let config = crate::rules::ConfigManager::load_defaults();
        let cidrs = resolve_target_cidrs(&FirewallTarget::Country("ZZ".to_string()), &config);
        assert!(cidrs.is_empty());
    }

    /// Directly exercises the budget-capping logic that `reconcile_with_backend`
    /// applies to eBPF coverage of `Country` rules, without going through
    /// the rule store / real backends — mirrors the cap math inline since
    /// `reconcile_with_backend` reads rules from disk via `read_firewall_rules()`
    /// and isn't itself parameterized by a rule list (see module doc comment
    /// for why: this keeps the seam at the seam that matters — backends and
    /// state — not on I/O that's already exercised by the `firewall::tests`
    /// module's migration/round-trip coverage).
    #[test]
    fn ebpf_country_budget_caps_and_reports_partial_coverage() {
        let big_country: Vec<String> = (0..(EBPF_COUNTRY_BUDGET + 500))
            .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
            .collect();
        assert!(big_country.len() > EBPF_COUNTRY_BUDGET);

        let take = big_country.len().min(EBPF_COUNTRY_BUDGET);
        assert_eq!(take, EBPF_COUNTRY_BUDGET);
        assert!(take < big_country.len());
    }

    #[test]
    fn merge_cloud_rules_force_tags_provenance_and_locked_regardless_of_wire_payload() {
        // Simulates a malicious/buggy cloud payload claiming to be Local/unlocked.
        let mut incoming = sample_rule("cloud-1", FirewallTarget::IpCidr("9.9.9.0/24".to_string()), None);
        incoming.provenance = FirewallProvenance::Local;
        incoming.locked = false;

        let merged = merge_rules_pure(Vec::new(), vec![incoming]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].provenance, FirewallProvenance::Cloud);
        assert!(merged[0].locked);
    }

    #[test]
    fn merge_cloud_rules_preserves_local_rules_untouched() {
        let local = sample_rule("local-1", FirewallTarget::IpCidr("1.1.1.0/24".to_string()), None);
        let cloud = sample_rule("cloud-1", FirewallTarget::IpCidr("2.2.2.0/24".to_string()), None);
        let merged = merge_rules_pure(vec![local.clone()], vec![cloud]);
        assert_eq!(merged.len(), 2);
        assert!(merged.iter().any(|r| r.id == "local-1" && r.provenance == FirewallProvenance::Local));
        assert!(merged.iter().any(|r| r.id == "cloud-1" && r.provenance == FirewallProvenance::Cloud));
    }

    #[test]
    fn merge_cloud_rules_drops_stale_cloud_rules_no_longer_sent() {
        let mut stale_cloud = sample_rule("cloud-old", FirewallTarget::IpCidr("3.3.3.0/24".to_string()), None);
        stale_cloud.provenance = FirewallProvenance::Cloud;
        stale_cloud.locked = true;
        let local = sample_rule("local-1", FirewallTarget::IpCidr("1.1.1.0/24".to_string()), None);

        // Cloud now sends an empty set — the previously-synced cloud rule should disappear.
        let merged = merge_rules_pure(vec![stale_cloud, local], Vec::new());
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].id, "local-1");
    }

    #[test]
    fn merge_cloud_rules_updates_existing_cloud_rule_in_place() {
        let mut old_version = sample_rule("cloud-1", FirewallTarget::IpCidr("5.5.5.0/24".to_string()), None);
        old_version.provenance = FirewallProvenance::Cloud;
        old_version.locked = true;
        old_version.action = "DROP".to_string();

        let mut new_version = sample_rule("cloud-1", FirewallTarget::IpCidr("5.5.5.0/24".to_string()), None);
        new_version.action = "REJECT".to_string();

        let merged = merge_rules_pure(vec![old_version], vec![new_version]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].action, "REJECT");
    }

    #[test]
    fn applied_rule_state_tracks_ebpf_subset_independently_of_full_cidr_set() {
        let state: AppliedState = DashMap::new();
        let rule = sample_rule("r1", FirewallTarget::Country("US".to_string()), None);
        state.insert(
            "r1".to_string(),
            AppliedRuleState {
                rule,
                cidrs: vec!["1.0.0.0/24".to_string(), "2.0.0.0/24".to_string(), "3.0.0.0/24".to_string()],
                ebpf_cidrs: vec!["1.0.0.0/24".to_string()], // only the first made the eBPF budget
            },
        );
        let entry = state.get("r1").unwrap();
        assert_eq!(entry.cidrs.len(), 3);
        assert_eq!(entry.ebpf_cidrs.len(), 1);
    }
}
