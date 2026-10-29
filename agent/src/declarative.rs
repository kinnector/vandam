//! declarative.rs — Declarative Configuration Loader for Vandam (`conf.d/`)
//!
//! Provides support for loading declarative YAML/JSON configuration files from
//! `/etc/vandam/conf.d/`, `/etc/kinnector/conf.d/`, and `./conf.d/`.
//! Allows sysadmins and GitOps tools (Ansible/Terraform) to declaratively define
//! site, container, storage, execution, and network overrides without calling APIs or CLI commands.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::sync::{Arc, OnceLock};
use dashmap::DashMap;
use tracing::{info, warn, error};

/// A single declarative configuration file definition.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarativeConfig {
    pub version: Option<u32>,
    pub scope: Option<String>,         // "global", "server", "container", "site"
    pub site: Option<String>,          // e.g. "example.com" or web root path
    pub process_name: Option<String>,  // e.g. "node", "python3", "java", "nginx"
    pub cwd: Option<String>,           // e.g. "/var/www/my-app"
    pub container_id: Option<String>,  // container SHA or name

    #[serde(default)]
    pub storage: Vec<DeclarativeStorageRule>,

    #[serde(default)]
    pub execution: DeclarativeExecRules,

    #[serde(default)]
    pub network: DeclarativeNetworkRules,

    #[serde(default)]
    pub toggles: DeclarativeToggles,

    pub cloud: Option<DeclarativeCloudConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarativeCloudConfig {
    pub license_key: Option<String>,
    pub auto_analyze: Option<bool>,
    pub telemetry_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarativeStorageRule {
    pub path: String,
    pub role: Option<String>, // "UploadDirectory", "TempDirectory", "CompiledCache", "AppStorage"
    pub allow_script_extensions: Option<bool>,
    pub disabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarativeExecRules {
    #[serde(default)]
    pub allow_paths: Vec<String>,
    #[serde(default)]
    pub deny_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarativeNetworkRules {
    #[serde(default)]
    pub block_inbound_ips: Vec<String>,
    #[serde(default)]
    pub block_outbound_ips: Vec<String>,
    #[serde(default)]
    pub allow_ports: Vec<u16>,
    #[serde(default)]
    pub block_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeclarativeToggles {
    pub enabled: Option<bool>,
    pub monitoring_enabled: Option<bool>,
    pub pkm_verification_enabled: Option<bool>,
    pub maintenance_mode: Option<bool>,
    pub maintenance_duration_minutes: Option<u64>,
    pub maintenance_reason: Option<String>,
}

/// Global registry of parsed declarative configurations, keyed by config filename.
static DECLARATIVE_REGISTRY: OnceLock<Arc<DashMap<String, DeclarativeConfig>>> = OnceLock::new();

pub fn get_declarative_registry() -> &'static Arc<DashMap<String, DeclarativeConfig>> {
    DECLARATIVE_REGISTRY.get_or_init(|| Arc::new(DashMap::new()))
}

/// Find all loaded declarative configurations matching a specific site domain or web root.
pub fn get_configs_for_site(site_domain_or_root: &str) -> Vec<DeclarativeConfig> {
    let registry = get_declarative_registry();
    let mut matches = Vec::new();
    for entry in registry.iter() {
        let cfg = entry.value();
        if let Some(ref s) = cfg.site {
            if s == site_domain_or_root || site_domain_or_root.starts_with(s) || s.starts_with(site_domain_or_root) {
                matches.push(cfg.clone());
                continue;
            }
        }
        if let Some(ref cwd) = cfg.cwd {
            if cwd == site_domain_or_root || site_domain_or_root.starts_with(cwd) || cwd.starts_with(site_domain_or_root) {
                matches.push(cfg.clone());
            }
        }
    }
    matches
}

/// Find all loaded declarative configurations matching a specific process basename and optional working directory.
pub fn get_configs_for_process(process_basename: &str, cwd_path: Option<&str>) -> Vec<DeclarativeConfig> {
    let registry = get_declarative_registry();
    let mut matches = Vec::new();
    for entry in registry.iter() {
        let cfg = entry.value();
        if let Some(ref proc_name) = cfg.process_name {
            if proc_name == process_basename {
                if let Some(ref target_cwd) = cfg.cwd {
                    if let Some(c) = cwd_path {
                        if c == target_cwd || c.starts_with(target_cwd) {
                            matches.push(cfg.clone());
                        }
                    }
                } else {
                    matches.push(cfg.clone());
                }
            }
        }
    }
    matches
}

/// Find all loaded declarative configurations matching a specific container ID.
pub fn get_configs_for_container(container_id: &str) -> Vec<DeclarativeConfig> {
    let registry = get_declarative_registry();
    let mut matches = Vec::new();
    for entry in registry.iter() {
        let cfg = entry.value();
        if let Some(ref c) = cfg.container_id {
            if c == container_id || container_id.starts_with(c) {
                matches.push(cfg.clone());
            }
        }
    }
    matches
}

/// Search locations for `conf.d` directories.
const CONF_D_PATHS: &[&str] = &[
    "/etc/vandam/conf.d",
];

/// Scan and load all declarative `.json` configuration files from standard `conf.d/` directories.
pub fn load_declarative_configs() -> Vec<DeclarativeConfig> {
    let registry = get_declarative_registry();
    registry.clear();
    let mut loaded = Vec::new();

    for dir_str in CONF_D_PATHS {
        let dir = Path::new(dir_str);
        if !dir.exists() || !dir.is_dir() {
            continue;
        }

        info!("[Vandam Declarative] Scanning conf.d directory: {:?}", dir);

        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("[Vandam Declarative] Failed to read directory {:?}: {}", dir, e);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let is_json = path.extension().map_or(false, |ext| ext == "json");
            if !is_json {
                continue;
            }

            match parse_config_file(&path) {
                Ok(config) => {
                    let file_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                    info!(
                        "[Vandam Declarative] Loaded config file: {} (Scope: {:?}, Site: {:?})",
                        file_name, config.scope, config.site
                    );
                    registry.insert(file_name, config.clone());
                    loaded.push(config);
                }
                Err(e) => {
                    error!("[Vandam Declarative] Error parsing {:?}: {}", path, e);
                }
            }
        }
    }

    loaded
}

/// Helper function to parse a JSON configuration file.
fn parse_config_file(path: &Path) -> Result<DeclarativeConfig, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let config: DeclarativeConfig = serde_json::from_str(&content)?;
    Ok(config)
}

/// Apply all loaded declarative configurations directly to Vandam subsystems.
pub fn apply_declarative_configs() {
    let configs = load_declarative_configs();
    if configs.is_empty() {
        info!("[Vandam Declarative] No declarative configs found in conf.d directories.");
        return;
    }

    let mut storage_count = 0;
    let mut exec_count = 0;

    for config in configs {
        // 1. Apply Storage Rules
        for storage in config.storage {
            if storage.disabled.unwrap_or(false) {
                if let Some(ref site) = config.site {
                    crate::allowlist::get_disabled_web_roots().insert(site.clone());
                }
                continue;
            }

            // Register path into allowlist if allow_script_extensions or valid storage path
            if crate::allowlist::register_inode(&storage.path) {
                storage_count += 1;
            }
            crate::allowlist::register_path_recursive(&storage.path);
        }

        // 2. Apply Execution Rules
        for path in config.execution.allow_paths {
            if crate::allowlist::register_inode(&path) {
                exec_count += 1;
            }
            crate::allowlist::register_path_recursive(&path);
        }

        // 3. Apply Toggles (Server-level PKM verification & Maintenance Mode)
        if let Some(enabled) = config.toggles.pkm_verification_enabled {
            crate::allowlist::set_pkm_verification_enabled(enabled);
        }

        if let Some(maint) = config.toggles.maintenance_mode {
            if maint {
                let duration = config.toggles.maintenance_duration_minutes.unwrap_or(60);
                let reason = config.toggles.maintenance_reason.as_deref().unwrap_or("Declarative maintenance window");
                crate::maintenance::enable_maintenance_mode(duration, reason);
            } else {
                crate::maintenance::disable_maintenance_mode();
            }
        }

        if let Some(false) = config.toggles.enabled {
            if let Some(ref site) = config.site {
                crate::allowlist::get_disabled_web_roots().insert(site.clone());
            }
        }

        // 4. Apply Cloud Settings
        if let Some(cloud) = config.cloud {
            crate::cloud::update_cloud_config(
                cloud.license_key,
                cloud.auto_analyze,
                cloud.telemetry_enabled,
            );
        }
    }

    info!(
        "[Vandam Declarative] Successfully applied declarative rules: {} storage paths, {} execution paths registered.",
        storage_count, exec_count
    );
}

/// Recursively register all files in a path if it is a directory.
fn register_path_recursive(path_str: &str) {
    let path = Path::new(path_str);
    if path.is_file() {
        crate::allowlist::register_inode(path_str);
    } else if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(p_str) = p.to_str() {
                    if p.is_file() {
                        crate::allowlist::register_inode(p_str);
                    }
                }
            }
        }
    }
}
