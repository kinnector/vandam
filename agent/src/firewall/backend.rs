//! Userspace enforcement backends. `IptablesBackend` refactors the
//! pre-existing `apply_iptables` shell-out (previously in `api.rs`);
//! `NftablesBackend` is new, and is the authoritative layer for full-scale
//! GeoIP country blocking (nftables sets resize dynamically, unlike the
//! in-kernel eBPF table's fixed `max_entries` — see the Firewall design
//! plan, 2026-08, finding #2). The in-kernel `EbpfBackend` lands separately
//! (core/ + FFI plumbing) and applies alongside whichever of these two is
//! selected as the primary userspace backend — it's a distinct enforcement
//! plane, not a fallback choice.

use crate::firewall::FirewallRule;
use std::process::Command;

pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn apply_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String>;
    fn revoke_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String>;
}

pub(crate) fn is_ipv6(cidr: &str) -> bool {
    cidr.contains(':')
}

// ---------------------------------------------------------------------
// iptables
// ---------------------------------------------------------------------

pub struct IptablesBackend;

impl IptablesBackend {
    fn binary(cidr: &str) -> &'static str {
        if is_ipv6(cidr) { "ip6tables" } else { "iptables" }
    }

    fn chain(direction: &str) -> &'static str {
        if direction == "outbound" { "OUTPUT" } else { "INPUT" }
    }

    fn jump(action: &str) -> &'static str {
        match action {
            "ACCEPT" => "ACCEPT",
            "REJECT" => "REJECT",
            _ => "DROP",
        }
    }

    fn build_args(cidr: &str, rule: &FirewallRule, insert: bool) -> Vec<String> {
        // ACCEPT is inserted at the head of the chain (-I) rather than
        // appended (-A) so it's evaluated before any overlapping DROP/REJECT
        // for the same address — an explicit allow always wins over a
        // broader block, matching ordinary firewall allowlist semantics.
        let verb = if insert {
            if rule.action == "ACCEPT" { "-I" } else { "-A" }
        } else {
            "-D"
        };

        let mut args = vec![
            verb.to_string(),
            Self::chain(&rule.direction).to_string(),
            "-s".to_string(),
            cidr.to_string(),
        ];
        if let Some(port) = rule.port {
            args.push("-p".to_string());
            args.push("tcp".to_string());
            args.push("--dport".to_string());
            args.push(port.to_string());
        }
        args.push("-j".to_string());
        args.push(Self::jump(&rule.action).to_string());
        args
    }

    fn run(cidr: &str, rule: &FirewallRule, insert: bool) -> Result<(), String> {
        let binary = Self::binary(cidr);
        let args = Self::build_args(cidr, rule, insert);
        let output = Command::new(binary)
            .args(&args)
            .output()
            .map_err(|e| format!("failed to execute {}: {}", binary, e))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }
}

impl FirewallBackend for IptablesBackend {
    fn name(&self) -> &'static str {
        "iptables"
    }

    fn is_available(&self) -> bool {
        Command::new("iptables").arg("-V").output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn apply_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String> {
        Self::run(cidr, rule, true)
    }

    fn revoke_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String> {
        Self::run(cidr, rule, false)
    }
}

// ---------------------------------------------------------------------
// nftables
// ---------------------------------------------------------------------

/// Bootstraps and maintains one `inet kinnector_fw` table with an `input`
/// and `output` chain, each dispatching into per-(action,family) named sets
/// (`kinnector_fw_{in,out}_{accept,drop,reject}_{v4,v6}`). Rule
/// apply/revoke is then just `nft add/delete element` on the relevant set —
/// O(1) against nftables' own set implementation, not a linear rule scan,
/// which is what makes this the right layer for GeoIP-scale CIDR lists.
///
/// Port matching is intentionally **not** implemented here in this pass —
/// a concatenated `ipv4_addr . inet_service` set type would be needed and
/// isn't built yet, so a rule with a specific port is routed to
/// `IptablesBackend` instead of this backend (see
/// `reconcile::select_backend_for_rule`) to avoid this backend silently
/// over-blocking a whole CIDR when only a port was meant to be blocked.
pub struct NftablesBackend;

impl NftablesBackend {
    fn run_nft(args: &[&str]) -> Result<std::process::Output, String> {
        Command::new("nft").args(args).output().map_err(|e| format!("failed to execute nft: {}", e))
    }

    fn direction_tag(direction: &str) -> &'static str {
        if direction == "outbound" { "out" } else { "in" }
    }

    fn action_tag(action: &str) -> &'static str {
        match action {
            "ACCEPT" => "accept",
            "REJECT" => "reject",
            _ => "drop",
        }
    }

    fn set_name(direction: &str, action: &str, is_v6: bool) -> String {
        format!(
            "kinnector_fw_{}_{}_{}",
            Self::direction_tag(direction),
            Self::action_tag(action),
            if is_v6 { "v6" } else { "v4" }
        )
    }

    /// Idempotent — `nft add table/chain/set` no-ops if the object already
    /// exists (unlike `nft create ...`, which errors). Rules have no such
    /// primitive, so dispatch-rule creation is guarded by checking for a
    /// `comment` tag in the chain listing first.
    fn ensure_bootstrapped() -> Result<(), String> {
        Self::run_nft(&["add", "table", "inet", "kinnector_fw"])?;
        for (chain, hook) in [("kinnector_fw_in", "input"), ("kinnector_fw_out", "output")] {
            Self::run_nft(&[
                "add", "chain", "inet", "kinnector_fw", chain,
                &format!("{{ type filter hook {} priority 0; policy accept; }}", hook),
            ])?;
        }

        for direction in ["in", "out"] {
            for action in ["accept", "drop", "reject"] {
                for (fam_type, suffix) in [("ipv4_addr", "v4"), ("ipv6_addr", "v6")] {
                    let set = format!("kinnector_fw_{}_{}_{}", direction, action, suffix);
                    Self::run_nft(&[
                        "add", "set", "inet", "kinnector_fw", &set,
                        &format!("{{ type {}; flags interval; }}", fam_type),
                    ])?;
                }
            }
        }

        // Dispatch rules, ACCEPT sets first per chain so an explicit allow
        // overrides an overlapping DROP/REJECT — same ordering rationale as
        // IptablesBackend's `-I` for ACCEPT.
        for (chain, direction) in [("kinnector_fw_in", "in"), ("kinnector_fw_out", "out")] {
            let existing = Self::run_nft(&["list", "chain", "inet", "kinnector_fw", chain])
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
                .unwrap_or_default();
            for action in ["accept", "drop", "reject"] {
                for (proto, suffix) in [("ip", "v4"), ("ip6", "v6")] {
                    let comment = format!("kinnector_fw_dispatch_{}_{}", action, suffix);
                    if existing.contains(&comment) {
                        continue;
                    }
                    let set = format!("kinnector_fw_{}_{}_{}", direction, action, suffix);
                    Self::run_nft(&[
                        "add", "rule", "inet", "kinnector_fw", chain,
                        &format!("{} saddr @{} {} comment \"{}\"", proto, set, action, comment),
                    ])?;
                }
            }
        }
        Ok(())
    }
}

impl FirewallBackend for NftablesBackend {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn is_available(&self) -> bool {
        Command::new("nft").arg("-v").output().map(|o| o.status.success()).unwrap_or(false)
    }

    fn apply_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String> {
        Self::ensure_bootstrapped()?;
        let set = Self::set_name(&rule.direction, &rule.action, is_ipv6(cidr));
        let output = Self::run_nft(&["add", "element", "inet", "kinnector_fw", &set, &format!("{{ {} }}", cidr)])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }

    fn revoke_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String> {
        let set = Self::set_name(&rule.direction, &rule.action, is_ipv6(cidr));
        let output = Self::run_nft(&["delete", "element", "inet", "kinnector_fw", &set, &format!("{{ {} }}", cidr)])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).into_owned())
        }
    }
}

/// Picks the primary userspace backend at startup: nftables if the `nft`
/// binary is present and runnable, else iptables. Both are constructed
/// unconditionally elsewhere for the port-scoped-rule override (see
/// `reconcile::select_backend_for_rule`) — this only decides the *default*.
pub fn detect_primary_backend() -> Box<dyn FirewallBackend> {
    let nft = NftablesBackend;
    if nft.is_available() {
        Box::new(nft)
    } else {
        Box::new(IptablesBackend)
    }
}

// ---------------------------------------------------------------------
// eBPF (in-kernel, egress-only)
// ---------------------------------------------------------------------

/// Parses a CIDR string into (is_v6, address bytes, prefixlen). A bare IP
/// with no `/prefix` is treated as a single-address match (/32 or /128).
fn parse_cidr(cidr: &str) -> Option<(bool, Vec<u8>, u32)> {
    let (addr_part, prefix_part) = match cidr.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (cidr, None),
    };

    if let Ok(v4) = addr_part.parse::<std::net::Ipv4Addr>() {
        let prefixlen = match prefix_part {
            Some(p) => p.parse::<u32>().ok()?,
            None => 32,
        };
        if prefixlen > 32 {
            return None;
        }
        return Some((false, v4.octets().to_vec(), prefixlen));
    }
    if let Ok(v6) = addr_part.parse::<std::net::Ipv6Addr>() {
        let prefixlen = match prefix_part {
            Some(p) => p.parse::<u32>().ok()?,
            None => 128,
        };
        if prefixlen > 128 {
            return None;
        }
        return Some((true, v6.octets().to_vec(), prefixlen));
    }
    None
}

/// In-kernel enforcement via the LPM_TRIE maps in `kinnector.bpf.c`
/// (`fw_rules_v4`/`fw_rules_v6`), reached through the FFI bindings in
/// `crate::ffi`. Egress-only (see that file's `socket_listen` comment for
/// why inbound isn't covered here) and ACCEPT is not meaningfully
/// distinguishable from "no rule" at this layer yet (no allowlist-override
/// semantics like `IptablesBackend`'s `-I`), so this backend only writes
/// DROP/REJECT entries — an ACCEPT rule is a no-op here and relies on the
/// userspace backend for its effect.
pub struct EbpfBackend;

impl EbpfBackend {
    fn fw_action(action: &str) -> u8 {
        if action == "ACCEPT" { 0 } else { 1 } // FW_ACTION_ALLOW = 0, FW_ACTION_DENY = 1
    }
}

impl FirewallBackend for EbpfBackend {
    fn name(&self) -> &'static str {
        "ebpf"
    }

    fn is_available(&self) -> bool {
        unsafe { crate::ffi::is_lsm_active() }
    }

    fn apply_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String> {
        let action = Self::fw_action(&rule.action);
        if action == 0 {
            // ACCEPT: no-op at this layer, see struct doc comment.
            return Ok(());
        }
        let Some((is_v6, addr, prefixlen)) = parse_cidr(cidr) else {
            return Err(format!("invalid CIDR for eBPF backend: {}", cidr));
        };
        let rule_id_hash = crc32_str(&rule.id);
        let ok = unsafe {
            crate::ffi::add_firewall_cidr(
                is_v6,
                addr.as_ptr(),
                prefixlen,
                rule_id_hash,
                rule.port.unwrap_or(0),
                0,
                0,
                action,
            )
        };
        if ok { Ok(()) } else { Err(format!("add_firewall_cidr failed for {}", cidr)) }
    }

    fn revoke_cidr(&self, cidr: &str, rule: &FirewallRule) -> Result<(), String> {
        if Self::fw_action(&rule.action) == 0 {
            return Ok(());
        }
        let Some((is_v6, addr, prefixlen)) = parse_cidr(cidr) else {
            return Err(format!("invalid CIDR for eBPF backend: {}", cidr));
        };
        let ok = unsafe { crate::ffi::remove_firewall_cidr(is_v6, addr.as_ptr(), prefixlen) };
        if ok { Ok(()) } else { Err(format!("remove_firewall_cidr failed for {}", cidr)) }
    }
}

/// `fw_value.rule_id` is a `u32` used only for audit/introspection (see
/// kinnector.bpf.c) — vandamd's rule ids are UUID strings, so this folds
/// one into the other with a simple, dependency-free hash. Collisions don't
/// affect correctness (nothing keys enforcement or removal on this value;
/// userspace tracks CIDR-to-rule ownership itself — see `reconcile.rs`),
/// only the accuracy of an operator reading `bpftool map dump` by hand.
fn crc32_str(s: &str) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in s.bytes() {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB88320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{FirewallProvenance, FirewallTarget};

    fn sample_rule(direction: &str, action: &str, port: Option<u16>) -> FirewallRule {
        FirewallRule {
            id: "r1".to_string(),
            target: FirewallTarget::IpCidr("203.0.113.0/24".to_string()),
            direction: direction.to_string(),
            action: action.to_string(),
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

    #[test]
    fn iptables_inbound_drop_targets_input_chain_append() {
        let rule = sample_rule("inbound", "DROP", None);
        let args = IptablesBackend::build_args("203.0.113.0/24", &rule, true);
        assert_eq!(args, vec!["-A", "INPUT", "-s", "203.0.113.0/24", "-j", "DROP"]);
    }

    #[test]
    fn iptables_outbound_targets_output_chain() {
        let rule = sample_rule("outbound", "DROP", None);
        let args = IptablesBackend::build_args("203.0.113.0/24", &rule, true);
        assert_eq!(args[1], "OUTPUT");
    }

    #[test]
    fn iptables_accept_inserts_at_head_not_appended() {
        let rule = sample_rule("inbound", "ACCEPT", None);
        let args = IptablesBackend::build_args("203.0.113.0/24", &rule, true);
        assert_eq!(args[0], "-I");
        assert_eq!(args.last().unwrap(), "ACCEPT");
    }

    #[test]
    fn iptables_revoke_uses_delete_flag() {
        let rule = sample_rule("inbound", "DROP", None);
        let args = IptablesBackend::build_args("203.0.113.0/24", &rule, false);
        assert_eq!(args[0], "-D");
    }

    #[test]
    fn iptables_port_adds_tcp_dport_match() {
        let rule = sample_rule("inbound", "DROP", Some(443));
        let args = IptablesBackend::build_args("203.0.113.0/24", &rule, true);
        assert!(args.contains(&"--dport".to_string()));
        assert!(args.contains(&"443".to_string()));
    }

    #[test]
    fn ipv6_cidr_selects_ip6tables_binary() {
        assert_eq!(IptablesBackend::binary("2001:db8::/32"), "ip6tables");
        assert_eq!(IptablesBackend::binary("203.0.113.0/24"), "iptables");
    }

    #[test]
    fn nft_set_names_are_stable_and_family_scoped() {
        assert_eq!(NftablesBackend::set_name("inbound", "DROP", false), "kinnector_fw_in_drop_v4");
        assert_eq!(NftablesBackend::set_name("outbound", "ACCEPT", true), "kinnector_fw_out_accept_v6");
        assert_eq!(NftablesBackend::set_name("inbound", "REJECT", false), "kinnector_fw_in_reject_v4");
    }

    #[test]
    fn parse_cidr_handles_v4_with_and_without_prefix() {
        assert_eq!(parse_cidr("203.0.113.0/24"), Some((false, vec![203, 0, 113, 0], 24)));
        assert_eq!(parse_cidr("203.0.113.5"), Some((false, vec![203, 0, 113, 5], 32)));
    }

    #[test]
    fn parse_cidr_handles_v6_with_and_without_prefix() {
        let (is_v6, addr, prefixlen) = parse_cidr("2001:db8::/32").unwrap();
        assert!(is_v6);
        assert_eq!(addr.len(), 16);
        assert_eq!(prefixlen, 32);

        let (is_v6, _addr, prefixlen) = parse_cidr("::1").unwrap();
        assert!(is_v6);
        assert_eq!(prefixlen, 128);
    }

    #[test]
    fn parse_cidr_rejects_garbage_and_out_of_range_prefix() {
        assert_eq!(parse_cidr("not-an-ip"), None);
        assert_eq!(parse_cidr("203.0.113.0/99"), None);
    }

    #[test]
    fn ebpf_backend_treats_accept_as_noop() {
        let backend = EbpfBackend;
        let rule = sample_rule("outbound", "ACCEPT", None);
        // No real FFI call happens for ACCEPT (fw_action returns 0 early) —
        // this must succeed even with no eBPF subsystem loaded in this test
        // process, since the ACCEPT branch returns before touching FFI.
        assert!(backend.apply_cidr("203.0.113.0/24", &rule).is_ok());
        assert!(backend.revoke_cidr("203.0.113.0/24", &rule).is_ok());
    }

    #[test]
    fn ebpf_backend_rejects_invalid_cidr_before_touching_ffi() {
        let backend = EbpfBackend;
        let rule = sample_rule("outbound", "DROP", None);
        assert!(backend.apply_cidr("not-a-cidr", &rule).is_err());
    }

    #[test]
    fn crc32_str_is_deterministic() {
        assert_eq!(crc32_str("same-id"), crc32_str("same-id"));
        assert_ne!(crc32_str("id-a"), crc32_str("id-b"));
    }
}
