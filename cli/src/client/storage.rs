use serde::Deserialize;

/// Real (non-mock) storage path, mirroring vandamd's `/api/v1/storage`
/// response (`vandam/src/storage_discovery.rs::StoragePath`, serialized by
/// `get_storage()`). Counterpart to `containers_data.rs`/`servers_data.rs` —
/// shared between the CLI's `storages` command and the TUI's Configure popup
/// (`site_config.rs`) so they can't drift on what the real payload means.
#[derive(Deserialize, Clone, Debug, Default)]
pub struct StorageEntry {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub confidence: String,
    /// Whether script/code execution is permitted from this path — the one
    /// role-derived policy axis vandamd has enforced from day one (e.g.
    /// CompiledCache roles get this true, everything else false).
    #[serde(default)]
    pub allow_script_extensions: bool,
    /// Whether writes to this path are permitted. Defaults to `true` when
    /// absent from the daemon response, matching vandamd's "default policy
    /// is writable" baseline — every role predates this field and was
    /// implicitly write-allowed; only `StorageRole::LibraryPath` (and future
    /// roles) sets this false.
    #[serde(default = "default_write_allowed")]
    pub write_allowed: bool,
}

fn default_write_allowed() -> bool {
    true
}

pub fn fetch(socket_path: &str) -> Result<Vec<StorageEntry>, String> {
    let value = crate::query_daemon(socket_path, "GET", "/api/v1/storage", None)?;
    let paths = value.get("storage_paths").cloned().unwrap_or(serde_json::Value::Array(Vec::new()));
    serde_json::from_value(paths).map_err(|e| format!("Failed to parse /api/v1/storage response: {}", e))
}

/// Storage entries whose path falls under `prefix` — same substring filter
/// the CLI's `storages list --site` flag already uses, reused here so a
/// Server/Container's Configure popup can scope the global registry down to
/// just that target's own paths.
pub fn filter_by_prefix(entries: &[StorageEntry], prefix: &str) -> Vec<StorageEntry> {
    if prefix.is_empty() {
        return entries.to_vec();
    }
    entries.iter().filter(|e| e.path.contains(prefix)).cloned().collect()
}

pub fn add(socket_path: &str, path: &str, role: &str, web_root: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "path": path,
        "role": role,
        "web_root": web_root,
    });
    crate::query_daemon(socket_path, "POST", "/api/v1/storage/add", Some(&body)).map(|_| ())
}

pub fn remove(socket_path: &str, path: &str) -> Result<(), String> {
    let body = serde_json::json!({ "path": path });
    crate::query_daemon(socket_path, "POST", "/api/v1/storage/remove", Some(&body)).map(|_| ())
}

/// Triggers vandamd's full discovery-pillar rescan (framework config files,
/// process env, gitignore cross-reference, etc.) and returns the resulting
/// registry size.
pub fn discover(socket_path: &str) -> Result<u64, String> {
    let value = crate::query_daemon(socket_path, "POST", "/api/v1/storage/rescan", None)?;
    Ok(value.get("count").and_then(|c| c.as_u64()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_response_shape_parses_into_storage_entries() {
        let value = serde_json::json!({
            "storage_paths": [
                { "path": "/var/www/site/uploads", "roles": ["UploadDirectory"], "confidence": "High", "allow_script_extensions": false, "write_allowed": true }
            ]
        });
        let paths = value.get("storage_paths").cloned().unwrap();
        let entries: Vec<StorageEntry> = serde_json::from_value(paths).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/var/www/site/uploads");
        assert!(entries[0].write_allowed);
    }

    #[test]
    fn write_allowed_defaults_to_true_when_absent() {
        let value = serde_json::json!([
            { "path": "/var/www/site/cache", "roles": ["CompiledCache"], "confidence": "Medium", "allow_script_extensions": true }
        ]);
        let entries: Vec<StorageEntry> = serde_json::from_value(value).unwrap();
        assert!(entries[0].write_allowed);
    }

    #[test]
    fn filter_by_prefix_scopes_to_matching_paths_only() {
        let entries = vec![
            StorageEntry { path: "/var/www/site-a/uploads".to_string(), ..Default::default() },
            StorageEntry { path: "/var/www/site-b/uploads".to_string(), ..Default::default() },
        ];
        let filtered = filter_by_prefix(&entries, "/var/www/site-a");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].path, "/var/www/site-a/uploads");
    }

    #[test]
    fn filter_by_prefix_empty_prefix_returns_everything() {
        let entries = vec![StorageEntry { path: "/anything".to_string(), ..Default::default() }];
        assert_eq!(filter_by_prefix(&entries, "").len(), 1);
    }
}
