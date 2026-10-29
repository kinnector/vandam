use serde::{Deserialize, Serialize};

/// Mirrors vandamd's `vandam::firewall::FirewallTarget` (`vandam/src/firewall/mod.rs`).
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "type", content = "value")]
pub enum FirewallTarget {
    IpCidr(String),
    Country(String),
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallProvenance {
    Local,
    Cloud,
}

/// Real (non-mock) firewall rule, mirroring vandamd's `GET /api/v1/firewall`
/// response shape. Counterpart to `containers_data.rs`/`alerts_data.rs` —
/// replaces the old fully-mock `SystemFirewallRule` in `dashboard/firewall.rs`.
#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct FirewallRuleData {
    pub id: String,
    pub target: FirewallTarget,
    pub direction: String,
    pub action: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub scope: String,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    pub provenance: FirewallProvenance,
    pub locked: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Fields for creating or editing a rule — kept separate from
/// `FirewallRuleData` since a create/update request only ever supplies one
/// of `ip_or_cidr`/`country` (the daemon rejects both or neither on create;
/// on update, both absent means "keep the existing target" — see
/// `vandam/src/api.rs`'s `merge_target_for_update`).
#[derive(Clone, Debug, Default)]
pub struct NewFirewallRule {
    pub ip_or_cidr: Option<String>,
    pub country: Option<String>,
    pub direction: String,
    pub action: String,
    pub port: Option<u16>,
    pub scope: String,
    pub site: Option<String>,
    pub reason: Option<String>,
}

fn build_body(rule: &NewFirewallRule) -> serde_json::Value {
    serde_json::json!({
        "ip_or_cidr": rule.ip_or_cidr,
        "country": rule.country,
        "direction": rule.direction,
        "action": rule.action,
        "port": rule.port,
        "scope": rule.scope,
        "site": rule.site,
        "reason": rule.reason,
    })
}

pub fn fetch(socket_path: &str) -> Result<Vec<FirewallRuleData>, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/firewall", None)?;
    let rules = value.get("firewall_rules").cloned().unwrap_or(serde_json::Value::Array(Vec::new()));
    serde_json::from_value(rules).map_err(|e| format!("Failed to parse /api/v1/firewall response: {}", e))
}

/// (ISO code, display name) — sourced live from vandamd's
/// `crate::rules::list_countries()`, never hardcoded here.
pub fn list_countries(socket_path: &str) -> Result<Vec<(String, String)>, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/firewall/countries", None)?;
    let countries = value.get("countries").cloned().unwrap_or(serde_json::Value::Array(Vec::new()));
    serde_json::from_value(countries).map_err(|e| format!("Failed to parse /api/v1/firewall/countries response: {}", e))
}

pub fn create(socket_path: &str, rule: &NewFirewallRule) -> Result<FirewallRuleData, String> {
    let body = build_body(rule);
    let value = crate::query_daemon(socket_path, "POST", "/api/v1/firewall", Some(&body))?;
    if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    let rule_val = value.get("rule").cloned().ok_or_else(|| "daemon response missing 'rule'".to_string())?;
    serde_json::from_value(rule_val).map_err(|e| format!("Failed to parse created rule: {}", e))
}

pub fn update(socket_path: &str, id: &str, rule: &NewFirewallRule) -> Result<FirewallRuleData, String> {
    let body = build_body(rule);
    let value = crate::query_daemon(socket_path, "PATCH", &format!("/api/v1/firewall/{}", id), Some(&body))?;
    if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    let rule_val = value.get("rule").cloned().ok_or_else(|| "daemon response missing 'rule'".to_string())?;
    serde_json::from_value(rule_val).map_err(|e| format!("Failed to parse updated rule: {}", e))
}

pub fn delete(socket_path: &str, id: &str) -> Result<(), String> {
    let body = serde_json::json!({ "id": id });
    let value = crate::query_daemon(socket_path, "DELETE", "/api/v1/firewall", Some(&body))?;
    if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
        return Err(err.to_string());
    }
    Ok(())
}

/// A rule's target rendered as a single display string — "203.0.113.0/24"
/// for an IP/CIDR rule, "🌍 US" for a country rule (the TUI/CLI look up the
/// display name separately via `list_countries()` when it needs the full
/// name; this stays a pure, dependency-free formatter for table rendering).
pub fn target_display(target: &FirewallTarget) -> String {
    match target {
        FirewallTarget::IpCidr(cidr) => cidr.clone(),
        FirewallTarget::Country(code) => format!("🌍 {}", code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_cidr_rule_from_daemon_response_shape() {
        let value = serde_json::json!({
            "firewall_rules": [{
                "id": "abc", "target": {"type": "IpCidr", "value": "203.0.113.0/24"},
                "direction": "inbound", "action": "DROP", "port": null,
                "scope": "global", "site": null, "reason": "test",
                "provenance": "Local", "locked": false,
                "created_at": "2026-01-01", "updated_at": "2026-01-01"
            }]
        });
        let rules_val = value.get("firewall_rules").cloned().unwrap();
        let rules: Vec<FirewallRuleData> = serde_json::from_value(rules_val).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].target, FirewallTarget::IpCidr("203.0.113.0/24".to_string()));
        assert!(!rules[0].locked);
    }

    #[test]
    fn parses_country_rule_and_locked_cloud_provenance() {
        let value = serde_json::json!({
            "id": "abc", "target": {"type": "Country", "value": "US"},
            "direction": "inbound", "action": "DROP", "port": null,
            "scope": "global", "site": null, "reason": null,
            "provenance": "Cloud", "locked": true,
            "created_at": "2026-01-01", "updated_at": "2026-01-01"
        });
        let rule: FirewallRuleData = serde_json::from_value(value).unwrap();
        assert_eq!(rule.target, FirewallTarget::Country("US".to_string()));
        assert_eq!(rule.provenance, FirewallProvenance::Cloud);
        assert!(rule.locked);
    }

    #[test]
    fn target_display_formats_ip_and_country_differently() {
        assert_eq!(target_display(&FirewallTarget::IpCidr("1.2.3.0/24".to_string())), "1.2.3.0/24");
        assert_eq!(target_display(&FirewallTarget::Country("DE".to_string())), "🌍 DE");
    }
}
