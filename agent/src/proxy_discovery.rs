//! proxy_discovery.rs — Proxy / FastCGI backend path propagation.
//!
//! When a web server (nginx, Apache, Caddy) proxies requests to a backend
//! (php-fpm, Node.js, Gunicorn, …) via a Unix socket or TCP port, the
//! backend process needs the same storage-path allowances as the frontend.
//!
//! This module:
//!  1. Parses web server configs to extract site root → backend socket/port bindings.
//!  2. Resolves Unix sockets and TCP ports to running PIDs via /proc/net/.
//!  3. Calls allowlist::register_pid_extra_path() for every storage path that
//!     belongs to that site, so the backend process can write to them without
//!     hitting the write-block heuristic.
//!  4. For completely generic/unknown backends, sets allow_cwd so the process
//!     can write within its own working directory without false positives.
//!  5. Exposes propagate_to_new_pid() so the heuristics engine can re-run
//!     propagation whenever a new backend worker process spawns.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static WEB_ROOTS: OnceLock<Vec<String>> = OnceLock::new();

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendKind {
    PhpFpm,
    NodeJs,
    Python,   // gunicorn, uvicorn, etc.
    Ruby,     // puma, unicorn, passenger
    Java,     // via proxy_pass to Tomcat/Jetty/etc.
    Generic,  // unidentified — gets allow_cwd
}

/// One resolved web-site ↔ backend binding.
#[derive(Debug, Clone)]
pub struct SiteBinding {
    /// Nginx/Apache document root for this virtual host.
    pub web_root: PathBuf,
    /// All storage paths registered for this web root (from STORAGE_REGISTRY).
    pub allowed_paths: Vec<PathBuf>,
    /// Unix socket path or empty if TCP.
    pub socket_path: Option<PathBuf>,
    /// TCP port number (127.0.0.1:<port>) or 0.
    pub tcp_port: u16,
    /// Resolved backend PIDs at discovery time.
    pub backend_pids: Vec<u32>,
    pub kind: BackendKind,
}

// ---------------------------------------------------------------------------
// Entry point — called once at startup after storage discovery
// ---------------------------------------------------------------------------

/// Discover all proxy/fastcgi site→backend bindings, resolve backend PIDs,
/// and register allowed paths / allow_cwd flags for each.
pub fn discover_and_propagate(web_roots: &[String]) {
    if WEB_ROOTS.get().is_none() {
        let _ = WEB_ROOTS.set(web_roots.to_vec());
    }
    println!("[Vandam Proxy] Running discover_and_propagate (web_roots={:?})...", web_roots);
    // Collect allowed paths per web root from the storage registry
    let mut root_paths: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    for entry in crate::storage_discovery::get_registry().iter() {
        for root in web_roots {
            let root_pb = PathBuf::from(root);
            if entry.key().starts_with(&root_pb) || root_pb.starts_with(entry.key()) {
                root_paths
                    .entry(root_pb.clone())
                    .or_default()
                    .push(entry.key().clone());
            }
        }
        // Also include the path itself keyed by its own root prefix
        root_paths
            .entry(entry.key().clone())
            .or_default()
            .push(entry.key().clone());
    }

    let mut bindings = Vec::new();

    // Parse each web server's config
    bindings.extend(parse_nginx_bindings());
    bindings.extend(parse_apache_bindings());
    bindings.extend(parse_caddy_bindings());

    // For each binding, fill in the allowed paths from the matching web root
    for binding in &mut bindings {
        // Find the web root entry that best matches this binding's web root
        let mut best_match: Option<&PathBuf> = None;
        let mut best_len = 0usize;
        for root_key in root_paths.keys() {
            if binding.web_root.starts_with(root_key) || root_key.starts_with(&binding.web_root) {
                let len = root_key.as_os_str().len();
                if len > best_len {
                    best_len = len;
                    best_match = Some(root_key);
                }
            }
        }
        // Also scan web_roots list directly
        for root in web_roots {
            let root_pb = PathBuf::from(root);
            if root_pb == binding.web_root || binding.web_root.starts_with(&root_pb) {
                if let Some(paths) = root_paths.get(&root_pb) {
                    binding.allowed_paths.extend_from_slice(paths);
                }
            }
        }
        if let Some(bm) = best_match {
            if let Some(paths) = root_paths.get(bm) {
                for p in paths {
                    if !binding.allowed_paths.contains(p) {
                        binding.allowed_paths.push(p.clone());
                    }
                }
            }
        }

        // Resolve backend PIDs
        binding.backend_pids = resolve_pids_for_binding(binding);

        // Propagate to resolved PIDs
        propagate_binding_to_pids(binding, &binding.backend_pids.clone(), false);
    }

    // Store bindings for later re-use when new PIDs spawn
    store_bindings(bindings);
}

/// Called from the heuristics ProcessCreate handler when a new process spawns
/// that might be a backend worker. Checks if it should inherit paths from any
/// stored binding and propagates if so.
pub fn propagate_to_new_pid(pid: u32, exe: &str, parent_pid: u32) {
    let bindings = get_stored_bindings();
    let exe_kind = classify_pid_exe(pid, exe);

    for binding in bindings.iter() {
        // Does the new PID's exe kind match this binding's backend kind?
        let kind_matches = binding.kind == exe_kind
            || (binding.kind == BackendKind::Generic && exe_kind == BackendKind::Generic);
        if !kind_matches && binding.kind != BackendKind::Generic { continue; }

        // Does the new PID or its parent already appear in the binding?
        let parent_in_binding = binding.backend_pids.contains(&parent_pid);
        // Or does the new PID listen on the same socket/port?
        let pid_uses_socket = binding.socket_path.as_ref()
            .map(|s| pid_has_socket(pid, s))
            .unwrap_or(false);
        let pid_uses_port = binding.tcp_port != 0
            && pid_listens_on_port(pid, binding.tcp_port);

        if parent_in_binding || pid_uses_socket || pid_uses_port {
            propagate_binding_to_pids(binding, &[pid], true);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Nginx config parsing
// ---------------------------------------------------------------------------

fn locate_running_configs(executables: &[&str], sig_loc: &crate::generic_discovery::ConfigLocation) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else { return paths; };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };
        let exe_path = format!("/proc/{}/exe", pid);
        if let Ok(exe) = std::fs::read_link(&exe_path) {
            let basename = exe.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default();
            if executables.iter().any(|&e| basename == e) {
                // 1. Read cmdline to find config path
                let args: Vec<String> = std::fs::read(format!("/proc/{}/cmdline", pid))
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).to_string())
                    .collect();

                let flags: Vec<&str> = [
                    sig_loc.cmdline_arg.as_deref(),
                    sig_loc.alt_cmdline_arg.as_deref(),
                ]
                .into_iter()
                .flatten()
                .collect();

                for (i, arg) in args.iter().enumerate() {
                    for &flag in &flags {
                        let eq = format!("{}=", flag);
                        if let Some(val) = arg.strip_prefix(&eq) {
                            let p = PathBuf::from(val.trim());
                            if p.exists() && !paths.contains(&p) {
                                println!("[Vandam Proxy] Found config path from cmdline of PID {} (flag={}): {:?}", pid, flag, p);
                                paths.push(p);
                            }
                        }
                        if arg == flag {
                            if let Some(next) = args.get(i + 1) {
                                let p = PathBuf::from(next.trim());
                                if p.exists() && !paths.contains(&p) {
                                    println!("[Vandam Proxy] Found config path from cmdline of PID {} (flag={}): {:?}", pid, flag, p);
                                    paths.push(p);
                                }
                            }
                        }
                    }
                }

                // 2. Read environment variables to find config path
                if let Ok(env_data) = std::fs::read(format!("/proc/{}/environ", pid)) {
                    for env_var in env_data.split(|&b| b == 0) {
                        let env_str = String::from_utf8_lossy(env_var);
                        if let Some(eq_idx) = env_str.find('=') {
                            let key = &env_str[..eq_idx];
                            let val = &env_str[eq_idx+1..];
                            if (key.contains("CONF") || key.contains("CONFIG") || key.contains("FILE"))
                                && val.starts_with('/')
                            {
                                let p = PathBuf::from(val.trim());
                                if p.exists() && !paths.contains(&p) {
                                    println!("[Vandam Proxy] Found config path from env of PID {} ({}={}): {:?}", pid, key, val, p);
                                    paths.push(p);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    paths
}

fn parse_nginx_bindings() -> Vec<SiteBinding> {
    let mut bindings = Vec::new();
    let sigs = crate::generic_discovery::load_generic_signatures("linux_web_signatures.json");
    let maybe_sig = sigs.iter().find(|s| s.executables.iter().any(|e| e == "nginx"));

    let mut config_roots = Vec::new();

    // 1. Locate config files from running processes using signature metadata
    if let Some(sig) = maybe_sig {
        for p in locate_running_configs(&["nginx", "openresty"], &sig.config_location) {
            config_roots.push(p.to_string_lossy().to_string());
        }
    }

    // 2. Fall back to / merge with signature default_paths
    let defaults = maybe_sig
        .map(|s| s.config_location.default_paths.clone())
        .unwrap_or_else(|| vec![
            "/etc/nginx/nginx.conf".to_string(),
            "/etc/nginx/sites-enabled".to_string(),
            "/etc/nginx/conf.d".to_string(),
            "/usr/local/nginx/conf/nginx.conf".to_string(),
            "/opt/nginx/conf/nginx.conf".to_string(),
        ]);

    for def in defaults {
        if !config_roots.contains(&def) {
            config_roots.push(def);
        }
    }

    let mut all_content = String::new();
    for path in &config_roots {
        collect_nginx_content(Path::new(path), &mut all_content, 0);
    }

    parse_nginx_server_blocks(&all_content, &mut bindings);
    bindings
}

fn collect_nginx_content(path: &Path, out: &mut String, depth: u8) {
    if depth > 5 { return; }
    if path.is_file() {
        if let Ok(c) = std::fs::read_to_string(path) {
            // Resolve includes
            for line in c.lines() {
                let t = line.trim();
                if let Some(rest) = t.strip_prefix("include ") {
                    let pattern = rest.trim_end_matches(';').trim();
                    if let Ok(entries) = glob::glob(pattern) {
                        for e in entries.flatten() {
                            collect_nginx_content(&e, out, depth + 1);
                        }
                    }
                }
            }
            out.push_str(&c);
            out.push('\n');
        }
    } else if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for e in entries.flatten() {
                collect_nginx_content(&e.path(), out, depth + 1);
            }
        }
    }
}

fn parse_nginx_server_blocks(content: &str, bindings: &mut Vec<SiteBinding>) {
    // Simple block extractor — finds server { ... } blocks and extracts
    // root, fastcgi_pass, proxy_pass directives.
    let root_re      = regex::Regex::new(r"(?m)^\s*root\s+([^\s;]+)\s*;").unwrap();
    let fcgi_re      = regex::Regex::new(r"(?m)^\s*fastcgi_pass\s+([^\s;]+)\s*;").unwrap();
    let proxy_re     = regex::Regex::new(r"(?m)^\s*proxy_pass\s+https?://([^\s;/]+)").unwrap();
    let uwsgi_re     = regex::Regex::new(r"(?m)^\s*uwsgi_pass\s+([^\s;]+)\s*;").unwrap();

    // Split into server blocks by scanning braces
    let blocks = extract_nginx_server_blocks(content);

    for block in &blocks {
        let roots: Vec<_> = root_re.captures_iter(block)
            .filter_map(|c| c.get(1).map(|m| PathBuf::from(m.as_str())))
            .collect();

        if roots.is_empty() { continue; }

        // fastcgi_pass
        for cap in fcgi_re.captures_iter(block) {
            let target = cap.get(1).unwrap().as_str().to_string();
            for root in &roots {
                bindings.push(make_binding(root.clone(), &target, BackendKind::PhpFpm));
            }
        }

        // proxy_pass
        for cap in proxy_re.captures_iter(block) {
            let hostport = cap.get(1).unwrap().as_str().to_string();
            for root in &roots {
                bindings.push(make_binding_tcp(root.clone(), &hostport, BackendKind::Generic));
            }
        }

        // uwsgi_pass (Python)
        for cap in uwsgi_re.captures_iter(block) {
            let target = cap.get(1).unwrap().as_str().to_string();
            for root in &roots {
                bindings.push(make_binding(root.clone(), &target, BackendKind::Python));
            }
        }
    }
}

fn extract_nginx_server_blocks(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let bytes = content.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Find "server" keyword followed by optional whitespace and '{'
        if bytes[i..].starts_with(b"server") {
            let after = i + 6;
            let rest = &content[after..];
            let trimmed = rest.trim_start();
            if trimmed.starts_with('{') {
                // Find matching closing brace
                let start = after + (rest.len() - trimmed.len());
                let mut depth = 0i32;
                let mut end = start;
                for (j, &b) in bytes[start..].iter().enumerate() {
                    match b {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                end = start + j + 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                }
                if end > start {
                    blocks.push(content[start..end].to_string());
                    i = end;
                    continue;
                }
            }
        }
        i += 1;
    }
    blocks
}

// ---------------------------------------------------------------------------
// Apache config parsing
// ---------------------------------------------------------------------------

fn parse_apache_bindings() -> Vec<SiteBinding> {
    let mut bindings = Vec::new();
    let sigs = crate::generic_discovery::load_generic_signatures("linux_web_signatures.json");
    let maybe_sig = sigs.iter().find(|s| s.executables.iter().any(|e| e == "httpd" || e == "apache2"));

    let mut dirs = Vec::new();

    // 1. Locate config files from running processes using signature metadata
    if let Some(sig) = maybe_sig {
        for p in locate_running_configs(&["httpd", "apache2"], &sig.config_location) {
            // Since apache config files might be files, we can scan their parent directory or use them directly.
            // Let's add the path itself or its parent folder.
            dirs.push(p.to_string_lossy().to_string());
            if let Some(parent) = p.parent() {
                let parent_str = parent.to_string_lossy().to_string();
                if !dirs.contains(&parent_str) {
                    dirs.push(parent_str);
                }
            }
        }
    }

    // 2. Fall back to / merge with signature default_paths
    let defaults = maybe_sig
        .map(|s| s.config_location.default_paths.clone())
        .unwrap_or_else(|| vec![
            "/etc/apache2/sites-enabled".to_string(),
            "/etc/httpd/conf.d".to_string(),
            "/etc/httpd/vhosts.d".to_string(),
            "/usr/local/apache2/conf/extra".to_string(),
        ]);

    for def in defaults {
        if !dirs.contains(&def) {
            dirs.push(def);
        }
    }

    let docroot_re   = regex::Regex::new(r"(?mi)^\s*DocumentRoot\s+([^\s]+)").unwrap();
    let proxy_re     = regex::Regex::new(r"(?mi)^\s*ProxyPass\s+\S+\s+https?://([^\s/]+)").unwrap();
    let fcgi_re      = regex::Regex::new(r"(?mi)proxy:unix:([^|]+)\|").unwrap();
    let fcgi_port_re = regex::Regex::new(r#"(?mi)proxy:fcgi://([^\s"]+)"#).unwrap();

    for dir in &dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() { continue; }
        let entries: Vec<_> = if dir_path.is_file() {
            vec![dir_path.to_path_buf()]
        } else {
            std::fs::read_dir(dir_path).map(|rd| rd.flatten().map(|e| e.path()).collect())
                .unwrap_or_default()
        };

        for file in entries {
            let Ok(content) = std::fs::read_to_string(&file) else { continue; };

            let roots: Vec<_> = docroot_re.captures_iter(&content)
                .filter_map(|c| c.get(1).map(|m| PathBuf::from(m.as_str())))
                .collect();
            if roots.is_empty() { continue; }

            for cap in proxy_re.captures_iter(&content) {
                let hostport = cap.get(1).unwrap().as_str().to_string();
                for root in &roots {
                    bindings.push(make_binding_tcp(root.clone(), &hostport, BackendKind::Generic));
                }
            }
            for cap in fcgi_re.captures_iter(&content) {
                let socket = cap.get(1).unwrap().as_str().to_string();
                for root in &roots {
                    bindings.push(make_binding(root.clone(), &socket, BackendKind::PhpFpm));
                }
            }
            for cap in fcgi_port_re.captures_iter(&content) {
                let hostport = cap.get(1).unwrap().as_str().to_string();
                for root in &roots {
                    bindings.push(make_binding_tcp(root.clone(), &hostport, BackendKind::PhpFpm));
                }
            }
        }
    }
    bindings
}

// ---------------------------------------------------------------------------
// Caddy config parsing
// ---------------------------------------------------------------------------

fn parse_caddy_bindings() -> Vec<SiteBinding> {
    let mut bindings = Vec::new();
    let paths = [
        "/etc/caddy/Caddyfile",
        "/usr/local/etc/caddy/Caddyfile",
        "/opt/caddy/Caddyfile",
    ];

    let root_re       = regex::Regex::new(r"(?m)^\s*root\s+\*\s+([^\s]+)").unwrap();
    let php_fcgi_re   = regex::Regex::new(r"(?m)^\s*php_fastcgi\s+([^\s{]+)").unwrap();
    let reverse_re    = regex::Regex::new(r"(?m)^\s*reverse_proxy\s+([^\s{]+)").unwrap();

    for &p in &paths {
        let Ok(content) = std::fs::read_to_string(p) else { continue; };

        let roots: Vec<_> = root_re.captures_iter(&content)
            .filter_map(|c| c.get(1).map(|m| PathBuf::from(m.as_str())))
            .collect();
        if roots.is_empty() { continue; }

        for cap in php_fcgi_re.captures_iter(&content) {
            let target = cap.get(1).unwrap().as_str().to_string();
            for root in &roots {
                bindings.push(make_binding(root.clone(), &target, BackendKind::PhpFpm));
            }
        }
        for cap in reverse_re.captures_iter(&content) {
            let target = cap.get(1).unwrap().as_str().to_string();
            for root in &roots {
                bindings.push(make_binding_tcp(root.clone(), &target, BackendKind::Generic));
            }
        }
    }
    bindings
}

// ---------------------------------------------------------------------------
// Binding construction helpers
// ---------------------------------------------------------------------------

/// Build a SiteBinding from a fastcgi_pass / uwsgi_pass / unix socket target string.
/// Target may be:
///   unix:/var/run/php/php8.1-fpm.sock   → Unix socket
///   unix//run/php-fpm.sock              → Caddy style
///   127.0.0.1:9000                      → TCP
fn make_binding(web_root: PathBuf, target: &str, kind: BackendKind) -> SiteBinding {
    let stripped = target
        .strip_prefix("unix://").unwrap_or(target)
        .strip_prefix("unix:").unwrap_or(target)
        .strip_prefix("unix/").unwrap_or(target);

    if stripped != target || target.starts_with('/') {
        // Unix socket
        SiteBinding {
            web_root,
            allowed_paths: Vec::new(),
            socket_path: Some(PathBuf::from(stripped)),
            tcp_port: 0,
            backend_pids: Vec::new(),
            kind,
        }
    } else {
        make_binding_tcp(web_root, target, kind)
    }
}

fn make_binding_tcp(web_root: PathBuf, hostport: &str, kind: BackendKind) -> SiteBinding {
    // hostport = "127.0.0.1:3000" or "localhost:8080" or "host:port"
    let port = hostport.rsplit(':').next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(0);
    SiteBinding {
        web_root,
        allowed_paths: Vec::new(),
        socket_path: None,
        tcp_port: port,
        backend_pids: Vec::new(),
        kind,
    }
}

// ---------------------------------------------------------------------------
// PID resolution — Unix socket and TCP port
// ---------------------------------------------------------------------------

/// Resolve which PIDs own the socket or port described by this binding.
fn resolve_pids_for_binding(binding: &SiteBinding) -> Vec<u32> {
    let mut pids = Vec::new();
    if let Some(ref socket) = binding.socket_path {
        pids.extend(pids_for_unix_socket(socket));
    }
    if binding.tcp_port != 0 {
        pids.extend(pids_for_tcp_port(binding.tcp_port));
    }
    pids
}

/// Find all PIDs that have the given Unix socket path open via /proc/net/unix + /proc/<pid>/fd/.
pub fn pids_for_unix_socket(socket_path: &Path) -> Vec<u32> {
    // Step 1: find the inode of the socket from /proc/net/unix
    let socket_str = socket_path.to_string_lossy();
    let inode = find_unix_socket_inode(&socket_str);
    if inode == 0 { return Vec::new(); }
    pids_for_socket_inode(inode)
}

fn find_unix_socket_inode(socket_path: &str) -> u64 {
    let content = std::fs::read_to_string("/proc/net/unix").unwrap_or_default();
    for line in content.lines().skip(1) {
        // Format: Num RefCount Protocol Flags Type St Inode Path
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 8 && parts[7] == socket_path {
            return parts[6].parse().unwrap_or(0);
        }
    }
    0
}

fn pids_for_socket_inode(inode: u64) -> Vec<u32> {
    let target = format!("socket:[{}]", inode);
    let mut pids = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else { return pids; };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else { continue; };
        let fd_dir = format!("/proc/{}/fd", pid);
        let Ok(fds) = std::fs::read_dir(&fd_dir) else { continue; };
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if link.to_string_lossy() == target {
                    if !pids.contains(&pid) {
                        pids.push(pid);
                    }
                }
            }
        }
    }
    pids
}

/// Find all PIDs listening on a local TCP port via /proc/net/tcp.
pub fn pids_for_tcp_port(port: u16) -> Vec<u32> {
    // The local_address field is hex little-endian: "0100007F:0BB8" for 127.0.0.1:3000
    // We match on the port portion only (last 4 hex digits) for simplicity
    let port_hex = format!("{:04X}", port);
    let mut inodes = Vec::new();

    for tcp_file in &["/proc/net/tcp", "/proc/net/tcp6"] {
        let content = std::fs::read_to_string(tcp_file).unwrap_or_default();
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 10 { continue; }
            // local_address format: XXXXXXXX:PPPP
            let local = parts[1];
            if local.ends_with(&format!(":{}", port_hex)) {
                // st = 0A = LISTEN
                let st = parts[3];
                if st == "0A" {
                    if let Ok(ino) = parts[9].parse::<u64>() {
                        inodes.push(ino);
                    }
                }
            }
        }
    }

    let mut pids = Vec::new();
    for inode in inodes {
        pids.extend(pids_for_socket_inode(inode));
    }
    pids
}

// ---------------------------------------------------------------------------
// Path propagation
// ---------------------------------------------------------------------------

fn propagate_binding_to_pids(binding: &SiteBinding, pids: &[u32], is_child: bool) {
    for &pid in pids {
        // Determine the exe kind of this PID to decide if it's truly generic
        let exe = get_pid_exe(pid);
        let actual_kind = classify_pid_exe(pid, &exe);
        let is_generic = actual_kind == BackendKind::Generic;

        // Register all allowed paths for this PID
        for path in &binding.allowed_paths {
            crate::allowlist::register_pid_extra_path(pid, path.clone());
            tracing::debug!(
                "[Vandam Proxy] PID {} ({}) → inherited path {} from web root {}",
                pid, exe, path.display(), binding.web_root.display()
            );
        }

        // Also register the web root itself
        crate::allowlist::register_pid_extra_path(pid, binding.web_root.clone());

        // Generic backend — snapshot CWD to prevent false positives
        if !is_child && (is_generic || binding.kind == BackendKind::Generic) {
            let mut is_system = false;
            let mut resolved_cwd = String::new();
            if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", pid)) {
                let cwd_str = cwd.to_string_lossy().to_string();
                resolved_cwd = cwd_str.clone();
                if crate::allowlist::is_system_dir(&cwd_str) {
                    is_system = true;
                }
            }
            if !is_system && !resolved_cwd.is_empty() {
                crate::allowlist::register_pid_extra_path(pid, PathBuf::from(resolved_cwd));
                tracing::debug!(
                    "[Vandam Proxy] PID {} ({}) → snapshotted CWD as allowed path (generic backend for {})",
                    pid, exe, binding.web_root.display()
                );
            } else if is_system {
                tracing::warn!(
                    "[Vandam Proxy] PID {} ({}) → DENIED CWD snapshot because CWD is a system directory",
                    pid, exe
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Binding storage — allows re-propagation on new process spawn
// ---------------------------------------------------------------------------

static STORED_BINDINGS: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<Vec<SiteBinding>>>>
    = std::sync::OnceLock::new();

fn get_binding_store() -> &'static std::sync::Arc<std::sync::Mutex<Vec<SiteBinding>>> {
    STORED_BINDINGS.get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(Vec::new())))
}

fn store_bindings(bindings: Vec<SiteBinding>) {
    if let Ok(mut store) = get_binding_store().lock() {
        *store = bindings;
    }
}

fn get_stored_bindings() -> Vec<SiteBinding> {
    get_binding_store().lock().map(|s| s.clone()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

fn get_pid_exe(pid: u32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn get_pid_cwd(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{}/cwd", pid)).ok()
}

/// Exposed for the heuristics write handler to check allow_cwd.
pub fn read_pid_cwd(pid: u32) -> Option<PathBuf> {
    get_pid_cwd(pid)
}

/// Does this PID have the given Unix socket path open?
pub fn pid_has_socket(pid: u32, socket_path: &Path) -> bool {
    let socket_str = socket_path.to_string_lossy();
    let inode = find_unix_socket_inode(&socket_str);
    if inode == 0 { return false; }
    let target = format!("socket:[{}]", inode);
    let fd_dir = format!("/proc/{}/fd", pid);
    let Ok(fds) = std::fs::read_dir(&fd_dir) else { return false; };
    for fd in fds.flatten() {
        if let Ok(link) = std::fs::read_link(fd.path()) {
            if link.to_string_lossy() == target {
                return true;
            }
        }
    }
    false
}

/// Does this PID listen on the given TCP port?
pub fn pid_listens_on_port(pid: u32, port: u16) -> bool {
    pids_for_tcp_port(port).contains(&pid)
}

fn classify_pid_exe(pid: u32, exe: &str) -> BackendKind {
    // Stage 0: Check global signature registry from linux_web_signatures.json
    if let Some(sig_name) = crate::generic_discovery::get_signature_for_pid(pid) {
        match sig_name.as_ref() {
            "php-fpm" | "php-cli-server" | "swoole" => return BackendKind::PhpFpm,
            "node" | "bun" | "deno" => return BackendKind::NodeJs,
            "gunicorn" | "uwsgi" | "uvicorn" | "daphne" | "hypercorn" | "falcon"
            | "waitress" | "tornado" | "werkzeug-dev" | "python-wsgi" | "python-http" => return BackendKind::Python,
            "puma" | "unicorn" | "thin" | "passenger" | "ruby-rack" => return BackendKind::Ruby,
            "java-servlet" | "tomcat" | "jetty" | "wildfly" | "spring-boot" => return BackendKind::Java,
            _ => {}
        }
    }

    let base = Path::new(exe)
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if base.starts_with("php") || base.contains("php-fpm") || base.contains("php_fpm") {
        BackendKind::PhpFpm
    } else if base == "node" || base == "nodejs" || base == "deno" || base == "bun" {
        BackendKind::NodeJs
    } else if base.starts_with("python") || matches!(base.as_str(), "gunicorn" | "uvicorn" | "daphne" | "hypercorn" | "celery") {
        BackendKind::Python
    } else if base.starts_with("ruby") || matches!(base.as_str(), "puma" | "unicorn" | "passenger" | "thin") {
        BackendKind::Ruby
    } else if base.starts_with("java") || matches!(base.as_str(), "catalina" | "tomcat" | "jetty" | "wildfly") {
        BackendKind::Java
    } else {
        BackendKind::Generic
    }
}
