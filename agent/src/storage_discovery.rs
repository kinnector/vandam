use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// Fine-grained classification — one path may have multiple roles.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageRole {
    UploadDirectory,   // User-uploaded files — allow write, block exec, ELF scan
    SessionStorage,    // PHP sessions, cookie stores — allow write, block exec
    TempDirectory,     // Runtime scratch — PID-scoped inode tracking, block exec
    AppStorage,        // Framework-managed storage — allow write, block exec, no script interp
    CompiledCache,     // Compiled views / opcache output — allow write AND script interpretation
    ObjectPassthrough, // Streaming buffer to remote object store — allow write+delete, block exec
    LibraryPath, // Vendor/library code (vendor/, node_modules/-style) — block write, allow exec/interp
}

impl StorageRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageRole::UploadDirectory => "UploadDirectory",
            StorageRole::SessionStorage => "SessionStorage",
            StorageRole::TempDirectory => "TempDirectory",
            StorageRole::AppStorage => "AppStorage",
            StorageRole::CompiledCache => "CompiledCache",
            StorageRole::ObjectPassthrough => "ObjectPassthrough",
            StorageRole::LibraryPath => "LibraryPath",
        }
    }
}

/// How confidently was this path discovered?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryConfidence {
    High,     // From system config (php.ini, -Djava.io.tmpdir)
    Medium,   // From framework config file (settings.py, storage.yml)
    Low,      // From .gitignore + writable dir heuristic
    Inferred, // From eBPF behavioral signals only — requires operator review
}

impl DiscoveryConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            DiscoveryConfidence::High => "High",
            DiscoveryConfidence::Medium => "Medium",
            DiscoveryConfidence::Low => "Low",
            DiscoveryConfidence::Inferred => "Inferred",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum DiscoveryMethod {
    Env { key: String, value: String },
    Dotenv { key: String, value: String },
    Cmdline { target: String },
    ConfigFile { file: String, target: String },
    JsonConfig { file: String, target: String },
    KnownAllow { file: String, target: String },
    Gitignore { target: String },
    GitUntrackedWritable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePath {
    pub path: PathBuf,
    pub roles: Vec<StorageRole>,
    pub confidence: DiscoveryConfidence,
    pub discovered_via: Vec<DiscoveryMethod>,
    pub web_uid: u32,
    pub allow_script_extensions: bool,
    pub max_file_size_hint: Option<u64>,
    #[serde(default)]
    pub framework_name: Option<String>,
    /// Whether writes to this path are permitted. Every role predates this
    /// field and is implicitly write-allowed (matches the "default policy is
    /// writable" baseline) — only `StorageRole::LibraryPath` sets this false.
    #[serde(default = "default_write_allowed")]
    pub write_allowed: bool,
}

fn default_write_allowed() -> bool {
    true
}

/// Global thread-safe storage registry.
/// Key: canonical resolved PathBuf (symlinks resolved).
static STORAGE_REGISTRY: OnceLock<Arc<DashMap<PathBuf, StoragePath>>> = OnceLock::new();

pub fn get_registry() -> &'static Arc<DashMap<PathBuf, StoragePath>> {
    STORAGE_REGISTRY.get_or_init(|| Arc::new(DashMap::new()))
}

/// Register a path in the storage registry.
pub fn register(storage: StoragePath) {
    let registry = get_registry();
    let canonical = std::fs::canonicalize(&storage.path).unwrap_or_else(|_| storage.path.clone());

    tracing::info!(
        "[Vandam Storage] Registering path: {} as {:?} (Confidence: {:?}, Via: {:?})",
        canonical.display(),
        storage.roles,
        storage.confidence,
        storage.discovered_via
    );
    registry.insert(canonical, storage);
}

/// Remove a path from the storage registry.
pub fn remove(path: &Path) -> bool {
    let registry = get_registry();
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    registry.remove(&canonical).is_some()
}

/// Returns true if `file_path`'s parent chain contains a registered storage path.
/// Uses prefix matching.
pub fn is_in_storage(file_path: &Path) -> Option<StoragePath> {
    let registry = get_registry();
    let canonical_path =
        std::fs::canonicalize(file_path).unwrap_or_else(|_| file_path.to_path_buf());

    for entry in registry.iter() {
        if canonical_path.starts_with(entry.key()) {
            return Some(entry.value().clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Discovery Pass Implementation
// ---------------------------------------------------------------------------

/// P1: Scan process environ and cmdline for storage/temp configuration.
pub fn scan_process_env_for_storage(pid: u32) -> Vec<StoragePath> {
    let mut paths = Vec::new();
    let mut env_pairs = Vec::new();

    // 1. Read /proc/<pid>/environ
    let environ_path = format!("/proc/{}/environ", pid);
    if let Ok(environ) = std::fs::read(&environ_path) {
        for var_bytes in environ.split(|&b| b == 0) {
            if var_bytes.is_empty() {
                continue;
            }
            let var_str = String::from_utf8_lossy(var_bytes);
            if let Some((key, val)) = var_str.split_once('=') {
                if !val.is_empty() {
                    env_pairs.push((
                        key.to_string(),
                        val.to_string(),
                        DiscoveryMethod::Env {
                            key: key.to_string(),
                            value: val.to_string(),
                        },
                    ));
                }
            }
        }
    }

    // 2. Read /proc/<pid>/cwd/.env safely (if accessible)
    if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", pid)) {
        let dot_env = cwd.join(".env");
        if let Ok(content) = std::fs::read_to_string(&dot_env) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((key, val)) = trimmed.split_once('=') {
                    let clean_val = val.trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                    if !clean_val.is_empty() {
                        let path_val = if clean_val.starts_with('/') {
                            PathBuf::from(clean_val)
                        } else {
                            cwd.join(clean_val)
                        };
                        env_pairs.push((
                            key.trim().to_string(),
                            path_val.to_string_lossy().to_string(),
                            DiscoveryMethod::Dotenv {
                                key: key.trim().to_string(),
                                value: clean_val.to_string(),
                            },
                        ));
                    }
                }
            }
        }
    }

    // Process collected pairs
    for (key, val, via) in env_pairs {
        let path = PathBuf::from(&val);
        match key.as_str() {
            "TMPDIR"
            | "TEMP"
            | "TMP"
            | "UPLOAD_TMP_DIR"
            | "FILE_UPLOAD_TEMP_DIR"
            | "ASPNETCORE_TEMP"
            | "SYMFONY_VAR_DIR"
            | "runtimePath" => {
                paths.push(StoragePath {
                    path,
                    roles: vec![StorageRole::TempDirectory],
                    confidence: DiscoveryConfidence::High,
                    discovered_via: vec![via],
                    web_uid: 0,
                    allow_script_extensions: false,
                    max_file_size_hint: None,
                    framework_name: None,
                    write_allowed: true,
                });
            }
            "MEDIA_ROOT"
            | "UPLOAD_DIR"
            | "STORAGE_PATH"
            | "UPLOAD_FOLDER"
            | "file_public_path"
            | "_PS_UPLOAD_DIR_"
            | "CELERY_RESULT_BACKEND"
            | "UPLOAD_DEST"
            | "FILESYSTEM_DISK" => {
                paths.push(StoragePath {
                    path,
                    roles: vec![StorageRole::UploadDirectory],
                    confidence: DiscoveryConfidence::High,
                    discovered_via: vec![via],
                    web_uid: 0,
                    allow_script_extensions: false,
                    max_file_size_hint: None,
                    framework_name: None,
                    write_allowed: true,
                });
            }
            _ => {}
        }
    }

    // Scan cmdline for Java -D flags
    if let Ok(cmdline) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
        for arg_bytes in cmdline.split(|&b| b == 0) {
            let arg = String::from_utf8_lossy(arg_bytes);
            if let Some(path) = arg.strip_prefix("-Djava.io.tmpdir=") {
                paths.push(StoragePath {
                    path: PathBuf::from(path),
                    roles: vec![StorageRole::TempDirectory],
                    confidence: DiscoveryConfidence::High,
                    discovered_via: vec![DiscoveryMethod::Cmdline {
                        target: format!("-Djava.io.tmpdir={}", path),
                    }],
                    web_uid: 0,
                    allow_script_extensions: false,
                    max_file_size_hint: None,
                    framework_name: None,
                    write_allowed: true,
                });
            }
        }
    }

    paths
}

struct FrameworkRule {
    file_name: &'static str,
    key_regex: &'static str,
    role: StorageRole,
    confidence: DiscoveryConfidence,
}

const FRAMEWORK_RULES: &[FrameworkRule] = &[
    FrameworkRule {
        file_name: "php.ini",
        key_regex: r"upload_tmp_dir\s*=\s*(.+)",
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::High,
    },
    FrameworkRule {
        file_name: "php.ini",
        key_regex: r"session\.save_path\s*=\s*(.+)",
        role: StorageRole::SessionStorage,
        confidence: DiscoveryConfidence::High,
    },
    FrameworkRule {
        file_name: ".user.ini",
        key_regex: r"upload_tmp_dir\s*=\s*(.+)",
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    // Joomla
    FrameworkRule {
        file_name: "configuration.php",
        key_regex: r#"public\s+\$tmp_path\s*=\s*['"]([^'"]+)['"]"#,
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::High,
    },
    FrameworkRule {
        file_name: "configuration.php",
        key_regex: r#"public\s+\$cache_path\s*=\s*['"]([^'"]+)['"]"#,
        role: StorageRole::CompiledCache,
        confidence: DiscoveryConfidence::High,
    },
    FrameworkRule {
        file_name: "configuration.php",
        key_regex: r#"public\s+\$log_path\s*=\s*['"]([^'"]+)['"]"#,
        role: StorageRole::AppStorage,
        confidence: DiscoveryConfidence::High,
    },
    // Magento & Magento 2
    FrameworkRule {
        file_name: "env.php",
        key_regex: r#"'path'\s*=>\s*BP\s*\.\s*['"]/?([^'"]+)['"]"#,
        role: StorageRole::AppStorage,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: "local.xml",
        key_regex: r#"<session_save_path><!\[CDATA\[([^\]]+)\]\]></session_save_path>"#,
        role: StorageRole::SessionStorage,
        confidence: DiscoveryConfidence::High,
    },
    // CakePHP
    FrameworkRule {
        file_name: "app.php",
        key_regex: r#"'path'\s*=>\s*CACHE\s*\.\s*['"]/?([^'"]+)['"]"#,
        role: StorageRole::CompiledCache,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: "app_local.php",
        key_regex: r#"'path'\s*=>\s*LOGS"#,
        role: StorageRole::AppStorage,
        confidence: DiscoveryConfidence::Medium,
    },
    // Python Frameworks (Django, Flask, FastAPI)
    FrameworkRule {
        file_name: "settings.py",
        key_regex: r#"MEDIA_ROOT\s*=\s*['"]?([^'")\s]+)"#,
        role: StorageRole::UploadDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: "settings.py",
        key_regex: r#"FILE_UPLOAD_TEMP_DIR\s*=\s*['"]([^'"]+)['"]"#,
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: ".env",
        key_regex: r#"UPLOAD_FOLDER\s*=\s*([^\s#]+)"#,
        role: StorageRole::UploadDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: ".env",
        key_regex: r#"UPLOAD_DIR\s*=\s*([^\s#]+)"#,
        role: StorageRole::UploadDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: ".env",
        key_regex: r#"TEMP_DIR\s*=\s*([^\s#]+)"#,
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    // Java Frameworks (Spring Boot, Micronaut, Quarkus)
    FrameworkRule {
        file_name: "application.properties",
        key_regex: r#"spring\.servlet\.multipart\.location=(.+)"#,
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::High,
    },
    FrameworkRule {
        file_name: "application.yml",
        key_regex: r#"location:\s*(.+)"#,
        role: StorageRole::TempDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    // .NET and others
    FrameworkRule {
        file_name: "config/filesystems.php",
        key_regex: r#"'root'\s*=>\s*['"]([^'"]+)['"]"#,
        role: StorageRole::AppStorage,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: "config/storage.yml",
        key_regex: r#"root:\s*(.+)"#,
        role: StorageRole::AppStorage,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: "appsettings.json",
        key_regex: r#""UploadPath"\s*:\s*"([^"]+)""#,
        role: StorageRole::UploadDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
    FrameworkRule {
        file_name: "initializers/carrierwave.rb",
        key_regex: r#"config\.root\s*=\s*(.+)"#,
        role: StorageRole::UploadDirectory,
        confidence: DiscoveryConfidence::Medium,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFrameworkRule {
    pub file_name: String,
    /// Static relative path from the anchor file's parent dir — always registered when anchor found.
    pub relative_path: Option<String>,
    /// Regex with one capture group — extracts a path from the anchor file's content.
    pub key_regex: Option<String>,
    pub role: StorageRole,
    pub confidence: DiscoveryConfidence,
    /// Additional well-known public dirs relative to the anchor parent, always allowed.
    /// E.g. ["wp-content/uploads", "wp-content/plugins"] for WordPress.
    #[serde(default)]
    pub known_allow_dirs: Vec<String>,
    #[serde(default)]
    pub framework_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFramework {
    pub name: String,
    pub rules: Vec<JsonFrameworkRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonFrameworkFile {
    /// Optional description field — ignored during loading.
    #[serde(default)]
    pub description: String,
    pub frameworks: Vec<JsonFramework>,
}

/// Framework signature tables, read from the rules (`crate::rules::source`).
const FRAMEWORK_SIGNATURE_FILES: &[&str] = &[
    "php_framework_signatures.json",
    "python_framework_signatures.json",
    "nodejs_framework_signatures.json",
    "ruby_framework_signatures.json",
    "java_framework_signatures.json",
];

fn load_json_framework_rules() -> Vec<JsonFrameworkRule> {
    let src = crate::rules::source::current();
    let mut all_rules = Vec::new();
    for &sig_file in FRAMEWORK_SIGNATURE_FILES {
        let Some(content) = src.read(sig_file) else { continue };
        match serde_json::from_str::<JsonFrameworkFile>(&content) {
            Ok(file) => {
                for mut fw in file.frameworks {
                    for rule in &mut fw.rules {
                        rule.framework_name = Some(fw.name.clone());
                    }
                    all_rules.extend(fw.rules);
                }
            }
            Err(e) => {
                tracing::warn!("[Vandam Storage] Failed to parse framework signatures {}: {}", sig_file, e);
            }
        }
    }
    all_rules
}

pub fn get_framework_anchors() -> Vec<String> {
    let mut anchors = std::collections::HashSet::new();
    let rules = load_json_framework_rules();
    for rule in rules {
        anchors.insert(rule.file_name);
    }
    // Also include standard project config descriptors
    anchors.insert("composer.json".to_string());
    anchors.insert("package.json".to_string());
    anchors.insert("manage.py".to_string());
    anchors.insert("Gemfile".to_string());

    anchors.into_iter().collect()
}

/// Well-known server base directories to scan for framework apps.
/// These are searched in addition to the detected web root so apps
/// outside nginx/apache document root (e.g. behind a reverse proxy) are covered.
const KNOWN_APP_BASE_DIRS: &[&str] = &[
    "/var/www",
    "/srv/www",
    "/srv/http",
    "/srv",
    "/opt",
    "/home", // catches /home/deploy/app, /home/user/public_html, etc.
    "/app",  // Docker convention
    "/code", // some Docker/k8s patterns
    "/webroot",
];

/// Subdirectory names commonly used as web roots inside a parent base dir.
/// Used when scanning /home/* or /opt/* so we don't recurse the whole FS.
const WEB_ROOT_SUBDIRS: &[&str] = &[
    "public_html",
    "www",
    "htdocs",
    "html",
    "web",
    "public",
    "app",
];

/// P2: Framework Configuration Parser.
/// Scans `web_root` **and** all well-known server base directories so apps
/// running behind a reverse proxy or in non-standard locations are covered.
pub fn run_framework_rules(web_root: &str) -> Vec<StoragePath> {
    let mut paths = Vec::new();

    // Always scan /etc/php* for php.ini (system-wide PHP config)
    for php_dir in &["/etc/php", "/etc/php5", "/etc/php7", "/etc/php8"] {
        if Path::new(php_dir).exists() {
            walk_dir_for_rules(Path::new(php_dir), "php.ini", &mut paths);
        }
    }

    let json_rules = load_json_framework_rules();

    // Collect all directories to scan (deduplicated)
    let mut scan_dirs: Vec<PathBuf> = Vec::new();

    // 1. The directly detected web root
    let root_path = PathBuf::from(web_root);
    if root_path.exists() {
        scan_dirs.push(root_path.clone());
    }

    // The loop over KNOWN_APP_BASE_DIRS was removed. We only scan the directly detected web root.

    // 3. Apply all rules to every scan directory
    for dir in &scan_dirs {
        // Static FRAMEWORK_RULES (inline Rust rules)
        for rule in FRAMEWORK_RULES {
            if rule.file_name == "php.ini" {
                continue;
            }
            walk_dir_for_rules(dir, rule.file_name, &mut paths);
        }
        // JSON-loaded rules from all signature files
        for rule in &json_rules {
            walk_dir_for_json_rules(dir, rule, &mut paths);
        }
    }

    // Declarative conf.d rules for this site/web root
    for decl_cfg in crate::declarative::get_configs_for_site(web_root) {
        for storage_rule in decl_cfg.storage {
            let role = match storage_rule.role.as_deref() {
                Some("UploadDirectory") => StorageRole::UploadDirectory,
                Some("TempDirectory") => StorageRole::TempDirectory,
                Some("CompiledCache") => StorageRole::CompiledCache,
                _ => StorageRole::AppStorage,
            };
            let sp = StoragePath {
                path: PathBuf::from(&storage_rule.path),
                roles: vec![role],
                confidence: DiscoveryConfidence::High,
                discovered_via: vec![DiscoveryMethod::JsonConfig {
                    file: "conf.d".to_string(),
                    target: storage_rule.path.clone(),
                }],
                web_uid: resolve_web_uid(web_root),
                allow_script_extensions: storage_rule.allow_script_extensions.unwrap_or(false),
                max_file_size_hint: None,
                framework_name: Some("Declarative".to_string()),
                write_allowed: true,
            };
            paths.push(sp);
        }
    }

    paths
}

fn walk_dir_for_json_rules(dir: &Path, rule: &JsonFrameworkRule, paths: &mut Vec<StoragePath>) {
    let mut cb = |path: &Path| {
        if !path.to_string_lossy().ends_with(&rule.file_name) {
            return;
        }
        let parent = match path.parent() {
            Some(p) => p,
            None => return,
        };

        // A. Hard-coded relative_path — always register when anchor is found
        if let Some(ref rel_path) = rule.relative_path {
            let storage_dir = parent.join(rel_path);
            paths.push(StoragePath {
                path: storage_dir,
                roles: vec![rule.role.clone()],
                confidence: rule.confidence.clone(),
                discovered_via: vec![DiscoveryMethod::JsonConfig {
                    file: rule.file_name.clone(),
                    target: rel_path.clone(),
                }],
                web_uid: 0,
                allow_script_extensions: matches!(rule.role, StorageRole::CompiledCache),
                max_file_size_hint: None,
                framework_name: rule.framework_name.clone(),
                write_allowed: !matches!(rule.role, StorageRole::LibraryPath),
            });
        }

        // B. Additional publicly-known allow dirs — always registered, High confidence
        for known in &rule.known_allow_dirs {
            let storage_dir = parent.join(known);
            paths.push(StoragePath {
                path: storage_dir,
                roles: vec![rule.role.clone()],
                confidence: DiscoveryConfidence::High,
                discovered_via: vec![DiscoveryMethod::KnownAllow {
                    file: rule.file_name.clone(),
                    target: known.clone(),
                }],
                web_uid: 0,
                allow_script_extensions: matches!(rule.role, StorageRole::CompiledCache),
                max_file_size_hint: None,
                framework_name: rule.framework_name.clone(),
                write_allowed: !matches!(rule.role, StorageRole::LibraryPath),
            });
        }

        // C. key_regex — extract path from anchor file content
        if let Some(ref key_regex) = rule.key_regex {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(re) = regex::Regex::new(key_regex) {
                    for cap in re.captures_iter(&content) {
                        // Try capture group 1 first, then group 2 (some Django rules use 2 groups)
                        let val = cap.get(1).or_else(|| cap.get(2));
                        if let Some(m) = val {
                            let clean = m
                                .as_str()
                                .trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                            if clean.is_empty() {
                                continue;
                            }
                            // Absolute path → use as-is; relative → join with parent
                            let storage_dir = if clean.starts_with('/') {
                                PathBuf::from(clean)
                            } else {
                                parent.join(clean)
                            };
                            paths.push(StoragePath {
                                path: storage_dir,
                                roles: vec![rule.role.clone()],
                                confidence: rule.confidence.clone(),
                                discovered_via: vec![DiscoveryMethod::JsonConfig {
                                    file: rule.file_name.clone(),
                                    target: clean.to_string(),
                                }],
                                web_uid: 0,
                                allow_script_extensions: matches!(
                                    rule.role,
                                    StorageRole::CompiledCache
                                ),
                                max_file_size_hint: None,
                                framework_name: rule.framework_name.clone(),
                                write_allowed: !matches!(rule.role, StorageRole::LibraryPath),
                            });
                        }
                    }
                }
            }
        }
    };
    walk_dir_recursive(dir, &rule.file_name, &mut cb);
}

fn walk_dir_for_rules(dir: &Path, file_name: &str, paths: &mut Vec<StoragePath>) {
    let mut cb = |path: &Path| {
        let Ok(content) = std::fs::read_to_string(path) else {
            return;
        };
        for rule in FRAMEWORK_RULES {
            if path.to_string_lossy().ends_with(rule.file_name) {
                if let Ok(re) = regex::Regex::new(rule.key_regex) {
                    for cap in re.captures_iter(&content) {
                        if let Some(val) = cap.get(1) {
                            let clean_val = val
                                .as_str()
                                .trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                            if !clean_val.is_empty() {
                                let mut actual_path = clean_val;
                                if rule.file_name == "php.ini" || rule.file_name == "local.xml" {
                                    // Handle PHP session.save_path prefix like N;/path or N;MODE;/path
                                    let parts: Vec<&str> = actual_path.split(';').collect();
                                    if parts.len() > 1 {
                                        actual_path = parts.last().unwrap();
                                    }
                                }
                                paths.push(StoragePath {
                                    path: PathBuf::from(actual_path),
                                    roles: vec![rule.role.clone()],
                                    confidence: rule.confidence.clone(),
                                    discovered_via: vec![DiscoveryMethod::ConfigFile {
                                        file: rule.file_name.to_string(),
                                        target: actual_path.to_string(),
                                    }],
                                    web_uid: 0,
                                    allow_script_extensions: matches!(
                                        rule.role,
                                        StorageRole::CompiledCache
                                    ),
                                    max_file_size_hint: None,
                                    framework_name: None,
                                    write_allowed: !matches!(rule.role, StorageRole::LibraryPath),
                                });
                            }
                        }
                    }
                }
            }
        }
    };
    walk_dir_recursive(dir, file_name, &mut cb);
}

fn walk_dir_recursive<F>(dir: &Path, file_suffix: &str, cb: &mut F)
where
    F: FnMut(&Path),
{
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if name == "node_modules"
                    || name == ".git"
                    || name == "vendor"
                    || name == "proc"
                    || name == "sys"
                    || name == "dev"
                {
                    continue;
                }
                walk_dir_recursive(&path, file_suffix, cb);
            } else if path.is_file() {
                if path.to_string_lossy().ends_with(file_suffix) {
                    cb(&path);
                }
            }
        }
    }
}

/// Resolve the UID of the running web processes.
pub fn resolve_web_uid(_web_root: &str) -> u32 {
    let web_names = [
        "nginx",
        "apache2",
        "httpd",
        "php-fpm",
        "node",
        "gunicorn",
        "passenger",
    ];
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
                if let Ok(target) = std::fs::read_link(format!("/proc/{}/exe", pid)) {
                    let exe_name = target
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    if web_names.iter().any(|&wn| exe_name.contains(wn)) {
                        use std::os::unix::fs::MetadataExt;
                        if let Ok(meta) = std::fs::metadata(format!("/proc/{}", pid)) {
                            return meta.uid();
                        }
                    }
                }
            }
        }
    }
    33 // www-data fallback
}

use std::os::unix::fs::MetadataExt;

fn is_writable_by_uid(path: &Path, uid: u32) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    let mode = meta.mode();

    if uid == 0 {
        return true;
    }

    if meta.uid() == uid {
        return (mode & 0o200) != 0;
    }
    if (mode & 0o002) != 0 {
        return true;
    }
    if (mode & 0o020) != 0 {
        return true;
    }
    false
}

/// P3: UID-Writable + Git-Diff untracked directories
pub fn scan_uid_writable_untracked(web_root: &str, web_uid: u32) -> Vec<StoragePath> {
    let mut paths = Vec::new();
    let untracked_dirs = get_git_untracked_dirs(web_root);
    for dir in untracked_dirs {
        if is_writable_by_uid(&dir, web_uid) {
            paths.push(StoragePath {
                path: dir.clone(),
                roles: vec![StorageRole::UploadDirectory],
                confidence: DiscoveryConfidence::Low,
                discovered_via: vec![DiscoveryMethod::GitUntrackedWritable],
                web_uid,
                allow_script_extensions: false,
                max_file_size_hint: None,
                framework_name: None,
                write_allowed: true,
            });
        }
    }
    paths
}

fn get_git_untracked_dirs(web_root: &str) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    let output = std::process::Command::new("git")
        .args(&["ls-files", "--others", "--directory", "--exclude-standard"])
        .current_dir(web_root)
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    let path = Path::new(web_root).join(trimmed);
                    dirs.push(path);
                }
            }
        }
    }
    dirs
}

/// P4: gitignore cross-reference (confirmatory/qualification only)
pub fn cross_reference_gitignore(web_root: &str) {
    let gitignore_path = Path::new(web_root).join(".gitignore");
    if !gitignore_path.exists() {
        return;
    }

    let Ok(content) = std::fs::read_to_string(gitignore_path) else {
        return;
    };
    let registry = get_registry();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Match simple gitignore rules against registry paths
        for mut entry in registry.iter_mut() {
            let path_str = entry.key().to_string_lossy();
            if path_str.contains(trimmed) {
                // Confirm the confidence
                entry
                    .value_mut()
                    .discovered_via
                    .push(DiscoveryMethod::Gitignore {
                        target: trimmed.to_string(),
                    });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Upload Scan Pipeline Integration
// ---------------------------------------------------------------------------

pub fn enqueue_upload_scan(file_path: String, alert_id: String) {
    // Register inode immediately in allowlist so application doesn't get blocked
    let registered_ino = crate::allowlist::register_inode_get_ino(&file_path);

    tokio::spawn(async move {
        match crate::upload_scan::scan_uploaded_file(&file_path).await {
            crate::upload_scan::ScanResult::Elf => {
                // Retroactively quarantine ELF file
                if let Some((dev, ino)) = registered_ino {
                    crate::allowlist::deregister_inode_by_raw_ino(dev, ino);
                } else {
                    crate::allowlist::deregister_inode(&file_path);
                }
                let _ = crate::quarantine::quarantine_file(
                    &file_path,
                    &alert_id,
                    "ELF binary uploaded to storage directory",
                    "Threat.Upload.ElfBinaryDetected",
                );
            }
            crate::upload_scan::ScanResult::Suspicious(reason) => {
                // Log/alert but leave accessible (kernel will catch actual execve)
                emit_suspicious_upload_alert(&file_path, &reason, &alert_id);
            }
            crate::upload_scan::ScanResult::Clean => {}
        }
    });
}

/// Synchronous upload handler — runs inline in the heuristics event loop.
/// Performs an immediate header scan (~1-3µs) with no open window between
/// write and access control decision.
/// Returns true if a threat was detected (file was quarantined), false if clean.
pub fn handle_upload_write(file_path: &str, alert_id: &str) -> bool {
    match crate::upload_scan::scan_uploaded_file_sync(file_path) {
        crate::upload_scan::ScanResult::Elf => {
            let reason = "ELF binary uploaded to storage directory";
            let _ = crate::quarantine::quarantine_file(
                file_path,
                alert_id,
                reason,
                "Threat.Upload.ElfBinaryDetected",
            );
            emit_upload_threat_alert(
                file_path,
                reason,
                alert_id,
                "Threat.Upload.ElfBinaryDetected",
            );
            true
        }
        crate::upload_scan::ScanResult::Suspicious(reason) => {
            let _ = crate::quarantine::quarantine_file(
                file_path,
                alert_id,
                &reason,
                "Threat.Upload.SuspiciousFile",
            );
            emit_upload_threat_alert(file_path, &reason, alert_id, "Threat.Upload.SuspiciousFile");
            true
        }
        crate::upload_scan::ScanResult::Clean => {
            // File passed header scan — register inode so subsequent allowlist checks pass.
            // Optional deeper async scan (YARA, entropy) can be enqueued here as forensics-only.
            crate::allowlist::register_inode(file_path);
            false
        }
    }
}

fn emit_upload_threat_alert(file_path: &str, reason: &str, alert_id: &str, threat_type: &str) {
    let payload = crate::notifications::AlertPayload {
        alert_id: alert_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: threat_type.to_string(),
        severity: "CRITICAL".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "upload-scanner".to_string(),
            cmdline: format!("scan_uploaded_file_sync({})", file_path),
            parent_exec_path: "vandamd".to_string(),
            parent_pid: std::process::id(),
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "QUARANTINE".to_string(),
            status: format!(
                "Malicious upload detected and quarantined: {} (Reason: {})",
                file_path, reason
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

fn emit_suspicious_upload_alert(file_path: &str, reason: &str, alert_id: &str) {
    let payload = crate::notifications::AlertPayload {
        alert_id: alert_id.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Warning.Upload.SuspiciousFile".to_string(),
        severity: "HIGH".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "upload-scanner".to_string(),
            cmdline: format!("scan_uploaded_file({})", file_path),
            parent_exec_path: "vandamd".to_string(),
            parent_pid: std::process::id(),
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "AUDIT_WARNING".to_string(),
            status: format!(
                "Suspicious file upload detected: {} (Reason: {})",
                file_path, reason
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

/// Zero storage paths detected warning alert
pub fn emit_no_storage_detected_warning(web_root: &str) {
    // Check if acknowledged-none flag is set
    let ack_file = "/etc/kinnector/storage_ack.json";
    if Path::new(ack_file).exists() {
        if let Ok(content) = std::fs::read_to_string(ack_file) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if json.get("web_root").and_then(|r| r.as_str()) == Some(web_root) {
                    // Suppress warning
                    return;
                }
            }
        }
    }

    let payload = crate::notifications::AlertPayload {
        alert_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        threat_type: "Warning.Storage.NoneDetected".to_string(),
        severity: "WARNING".to_string(),
        confidence: 0.0,
        container: None,
        process: crate::notifications::ProcessInfo {
            pid: 0,
            exec_path: "vandamd".to_string(),
            cmdline: format!("storage_discovery({})", web_root),
            parent_exec_path: String::new(),
            parent_pid: 0,
            verified_package: Some(crate::allowlist::verify_system_package_binary(&String::new())),
            envs: Vec::new(),
            args: Vec::new(),
                    signature_name: None,
            service: None,
},
        remediation: crate::notifications::RemediationInfo {
            action: "OPERATOR_ACTION_REQUIRED".to_string(),
            status: format!(
                "Vandam could not auto-detect any upload, storage, or temp directories \
                 for web root '{web_root}'. If local dynamic storage is intentional, configure it manually: \
                 `vandam storage add <path> --role upload --web-root {web_root}`."
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
    eprintln!(
        "[Vandam Storage] WARNING: No storage directories detected for web root '{}'.",
        web_root
    );
}

static DISABLED_STORAGE_WEB_ROOTS: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();
static DISABLED_STORAGE_EXES: OnceLock<Arc<dashmap::DashSet<String>>> = OnceLock::new();

pub fn get_disabled_storage_web_roots() -> Arc<dashmap::DashSet<String>> {
    DISABLED_STORAGE_WEB_ROOTS
        .get_or_init(|| Arc::new(dashmap::DashSet::new()))
        .clone()
}

pub fn get_disabled_storage_exes() -> Arc<dashmap::DashSet<String>> {
    DISABLED_STORAGE_EXES
        .get_or_init(|| Arc::new(dashmap::DashSet::new()))
        .clone()
}

pub fn disable_storage_for_web_root(web_root: &str) {
    get_disabled_storage_web_roots().insert(web_root.to_string());
    tracing::warn!(
        "[Vandam Storage] Disabled all storage and FIM checks for web root: {}",
        web_root
    );
}

pub fn enable_storage_for_web_root(web_root: &str) {
    get_disabled_storage_web_roots().remove(web_root);
    tracing::info!(
        "[Vandam Storage] Enabled storage and FIM checks for web root: {}",
        web_root
    );
}

pub fn disable_storage_for_exe(exe: &str) {
    get_disabled_storage_exes().insert(exe.to_string());
    tracing::warn!(
        "[Vandam Storage] Disabled all storage and FIM checks for executable: {}",
        exe
    );
}

pub fn enable_storage_for_exe(exe: &str) {
    get_disabled_storage_exes().remove(exe);
    tracing::info!(
        "[Vandam Storage] Enabled storage and FIM checks for executable: {}",
        exe
    );
}

pub fn is_storage_disabled_for_exe(exe: &str) -> bool {
    get_disabled_storage_exes().contains(exe)
}

pub fn is_storage_disabled_for_path(path: &str, web_roots: &[String]) -> bool {
    let roots = get_disabled_storage_web_roots();
    for r in web_roots {
        if roots.contains(r) && path.starts_with(r) {
            return true;
        }
    }
    false
}
