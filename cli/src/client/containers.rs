use serde::Deserialize;

/// One row of `containers list`.
#[derive(Clone, Debug)]
pub struct ContainerTarget {
    pub id: usize,
    /// Full container id, used for API calls (show/trust/untrust).
    pub container_id: String,
    pub short_id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub attached: bool,
    pub alert_count: usize,
    /// Trust baseline as last fetched from the daemon.
    pub trusted: bool,
    /// True when a trust rule exists for this image but vandamd refused to
    /// grant it because the image was rebuilt/re-pulled under the same tag
    /// since it was trusted (digest no longer matches the pin). Distinct from
    /// plain `!trusted` so the row can explain *why*, not just show untrusted.
    pub trust_stale: bool,
    /// First bind-mounted web root, if any. Empty for containers with no
    /// classified web root (e.g. a worker).
    pub web_root: String,
}

/// Real (non-mock) container list, mirroring vandamd's `/api/v1/containers`
/// response (`vandam/src/api.rs::build_containers_response`). Counterpart to
/// `servers_data.rs` — shared between the dedicated Containers-tab fetch and
/// `/api/v1/status`'s embedded `discovered_containers` (Status tab row 3).
#[derive(Deserialize, Default, Clone, Debug)]
pub struct ContainersData {
    #[serde(default)]
    pub containers: Vec<ContainerNode>,
    #[serde(default)]
    pub trusted_images: Vec<TrustedImage>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct AlertNode {
    #[serde(default)]
    pub severity: String,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct ContainerNode {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub attached: bool,
    #[serde(default)]
    pub alerts: Vec<AlertNode>,
    #[serde(default)]
    pub trusted: bool,
    /// True when a trust rule exists for this image but its pinned digest no
    /// longer matches this container's current image — it was rebuilt/
    /// re-pulled under the same tag since being trusted, so `trusted` is
    /// false and this explains why (see `vandam/src/api.rs::container_trust_state`).
    #[serde(default)]
    pub trust_stale: bool,
    #[serde(default)]
    pub web_roots: Vec<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
pub struct TrustedImage {
    #[serde(default)]
    pub image: String,
}

pub fn fetch(socket_path: &str) -> Result<ContainersData, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/containers", None)?;
    serde_json::from_value(value).map_err(|e| format!("Failed to parse /api/v1/containers response: {}", e))
}

#[derive(Deserialize, Clone, Debug)]
struct UserRule {
    id: String,
    rule_type: String,
    target: String,
}

fn find_trust_rule(socket_path: &str, image: &str) -> Result<Option<UserRule>, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/rules/user", None)?;
    let rules: Vec<UserRule> = value
        .get("user_rules")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    Ok(rules.into_iter().find(|r| r.rule_type == "ALLOW_CONTAINER_IMAGE" && r.target == image))
}

/// Trusts a container image — the daemon grants that container's PIDs full
/// trust (file, exec, network, escape-protection — see `vandam/src/trust.rs`
/// and `discovery.rs::query_single_container`). Shared by the CLI's
/// `containers trust` and the TUI's `[t]` key so they can't drift on the
/// rule shape vandamd expects.
pub fn trust(socket_path: &str, image: &str, scope: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "rule_type": "ALLOW_CONTAINER_IMAGE",
        "target": image,
        "scope": scope,
    });
    crate::query_daemon(socket_path, "POST", "/api/v1/rules/user/add", Some(&body)).map(|_| ())
}

/// Untrusts a container image: finds the matching `ALLOW_CONTAINER_IMAGE`
/// user rule and deletes it by id (vandamd's `DELETE /api/v1/rules/user`
/// only takes a rule id, not a rule_type/target filter). Shared by the CLI's
/// `containers untrust` and the TUI's `[u]` key.
pub fn untrust(socket_path: &str, image: &str) -> Result<(), String> {
    let rule = find_trust_rule(socket_path, image)?
        .ok_or_else(|| format!("Image '{}' is not currently trusted.", image))?;
    let body = serde_json::json!({ "id": rule.id });
    crate::query_daemon(socket_path, "DELETE", "/api/v1/rules/user", Some(&body)).map(|_| ())
}

/// Parses the `discovered_containers` sub-object already embedded in
/// `/api/v1/status`'s response — used by the Status tab's row 3 and the
/// TUI's initial dashboard load so they don't need a second daemon round trip.
pub fn from_status_json(value: &serde_json::Value) -> ContainersData {
    value.get("discovered_containers")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default()
}

/// Pure, unit-testable: flattens vandamd's real container list into the
/// `ContainerTarget` row shape the Containers tab table renders.
pub fn build_container_targets(data: &ContainersData) -> Vec<ContainerTarget> {
    data.containers
        .iter()
        .enumerate()
        .map(|(id, c)| {
            let short_id = if c.id.len() > 12 { c.id[..12].to_string() } else { c.id.clone() };
            let name = if c.name.is_empty() { short_id.clone() } else { c.name.clone() };
            ContainerTarget {
                id,
                container_id: c.id.clone(),
                short_id,
                name,
                image: c.image.clone(),
                status: c.status.clone(),
                attached: c.attached,
                alert_count: c.alerts.len(),
                trusted: c.trusted,
                trust_stale: c.trust_stale,
                web_root: c.web_roots.first().cloned().unwrap_or_default(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> ContainersData {
        ContainersData {
            containers: vec![
                ContainerNode {
                    id: "abcdef012345abcdef012345".to_string(),
                    name: "web-nginx".to_string(),
                    image: "nginx:1.25.4-alpine".to_string(),
                    status: "RUNNING".to_string(),
                    attached: true,
                    alerts: vec![AlertNode { severity: "HIGH".to_string() }],
                    trusted: false,
                    trust_stale: false,
                    web_roots: vec!["/var/www/web-nginx".to_string()],
                },
                ContainerNode {
                    id: "112233445566112233445566".to_string(),
                    name: String::new(),
                    image: "datadog/agent".to_string(),
                    status: "EXITED".to_string(),
                    attached: false,
                    alerts: Vec::new(),
                    trusted: true,
                    trust_stale: false,
                    web_roots: Vec::new(),
                },
            ],
            trusted_images: vec![TrustedImage { image: "datadog/agent".to_string() }],
        }
    }

    #[test]
    fn builds_one_row_per_container() {
        let targets = build_container_targets(&sample_data());
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "web-nginx");
        assert_eq!(targets[0].alert_count, 1);
        assert!(!targets[0].trusted);
    }

    #[test]
    fn falls_back_to_short_id_when_name_is_empty() {
        let targets = build_container_targets(&sample_data());
        assert_eq!(targets[1].name, "112233445566");
        assert!(targets[1].trusted);
    }

    #[test]
    fn trust_stale_flag_survives_parsing() {
        let mut data = sample_data();
        data.containers[0].trusted = false;
        data.containers[0].trust_stale = true;
        let targets = build_container_targets(&data);
        assert!(!targets[0].trusted);
        assert!(targets[0].trust_stale);
    }

    #[test]
    fn from_status_json_extracts_discovered_containers_field() {
        let value = serde_json::json!({
            "discovered_containers": { "containers": [], "trusted_images": [] },
            "other_field": "ignored"
        });
        let data = from_status_json(&value);
        assert!(data.containers.is_empty());
    }

    #[test]
    fn from_status_json_defaults_when_field_absent() {
        let data = from_status_json(&serde_json::json!({}));
        assert!(data.containers.is_empty());
        assert!(data.trusted_images.is_empty());
    }

    #[test]
    fn fetch_response_shape_parses_into_containers_data() {
        let value = serde_json::json!({
            "containers": [
                { "id": "abc123", "name": "app", "image": "app:latest", "status": "RUNNING", "attached": true, "alerts": [], "trusted": false }
            ],
            "trusted_images": []
        });
        let data: ContainersData = serde_json::from_value(value).unwrap();
        assert_eq!(data.containers.len(), 1);
        assert_eq!(data.containers[0].name, "app");
    }
}
