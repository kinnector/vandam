use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    /// Human-readable reference (e.g. "nginx:1.25") — mutable, since a tag
    /// can be repointed at a new build. Use `image_id` to detect that.
    pub image: String,
    /// Resolved local image content id (Docker inspect's top-level `Image`
    /// field, e.g. "sha256:abcd..."). Changes whenever `image` is rebuilt or
    /// re-pulled even if the tag stays the same — this is what container
    /// trust is actually pinned to, not the mutable tag in `image`.
    pub image_id: String,
    pub status: String,
    pub attached: bool,
    pub web_roots: Vec<PathBuf>,
    pub config_dirs: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredProxy {
    pub name: String,
    pub config_dirs: Vec<PathBuf>,
    pub access_logs: Vec<PathBuf>,
}

/// Returns true if a process whose argv[0] / exe symlink contains `binary_name`
/// is currently running, by scanning /proc/<pid>/exe symlinks.
/// M-16 fix: config dir existence alone is not sufficient.
fn is_process_running(binary_name: &str) -> bool {
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        // Only numeric entries (PIDs)
        if !name
            .to_str()
            .map(|s| s.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or(false)
        {
            continue;
        }
        let exe_path = entry.path().join("exe");
        if let Ok(target) = std::fs::read_link(&exe_path) {
            if target.to_string_lossy().contains(binary_name) {
                return true;
            }
        }
    }
    false
}

pub fn auto_discover_proxies() -> Vec<DiscoveredProxy> {
    let mut proxies = Vec::new();

    // 1. Nginx Check
    let mut nginx_configs = Vec::new();
    if Path::new("/etc/nginx").exists() {
        nginx_configs.push(PathBuf::from("/etc/nginx"));
    }
    let mut nginx_logs = Vec::new();
    let common_nginx_logs = ["/var/log/nginx/access.log", "/var/log/nginx/error.log"];
    for log in &common_nginx_logs {
        if Path::new(log).exists() {
            nginx_logs.push(PathBuf::from(log));
        }
    }
    // M-16: only report nginx if the binary is actually running
    if is_process_running("nginx") || (!nginx_configs.is_empty() && !nginx_logs.is_empty()) {
        if !nginx_configs.is_empty() {
            proxies.push(DiscoveredProxy {
                name: "nginx".to_string(),
                config_dirs: nginx_configs,
                access_logs: nginx_logs,
            });
        }
    }

    // 2. Apache Check
    let mut apache_configs = Vec::new();
    if Path::new("/etc/apache2").exists() {
        apache_configs.push(PathBuf::from("/etc/apache2"));
    } else if Path::new("/etc/httpd").exists() {
        apache_configs.push(PathBuf::from("/etc/httpd"));
    }
    let mut apache_logs = Vec::new();
    let common_apache_logs = ["/var/log/apache2/access.log", "/var/log/httpd/access_log"];
    for log in &common_apache_logs {
        if Path::new(log).exists() {
            apache_logs.push(PathBuf::from(log));
        }
    }
    // M-16: only report apache if the binary is actually running
    if is_process_running("apache2") || is_process_running("httpd") {
        if !apache_configs.is_empty() {
            proxies.push(DiscoveredProxy {
                name: "apache".to_string(),
                config_dirs: apache_configs,
                access_logs: apache_logs,
            });
        }
    }

    // 3. Caddy Check
    let mut caddy_configs = Vec::new();
    if Path::new("/etc/caddy").exists() {
        caddy_configs.push(PathBuf::from("/etc/caddy"));
    }
    let mut caddy_logs = Vec::new();
    let common_caddy_logs = ["/var/log/caddy/access.log"];
    for log in &common_caddy_logs {
        if Path::new(log).exists() {
            caddy_logs.push(PathBuf::from(log));
        }
    }
    // M-16: only report caddy if the binary is actually running
    if is_process_running("caddy") {
        if !caddy_configs.is_empty() {
            proxies.push(DiscoveredProxy {
                name: "caddy".to_string(),
                config_dirs: caddy_configs,
                access_logs: caddy_logs,
            });
        }
    } else if !caddy_configs.is_empty() || !caddy_logs.is_empty() {
        // Config exists but process not running — still watch configs in case of restart
        proxies.push(DiscoveredProxy {
            name: "caddy".to_string(),
            config_dirs: caddy_configs,
            access_logs: caddy_logs,
        });
    }

    proxies
}

/// Dynamically auto-detect all configured web roots from running web servers
/// and reverse proxy configurations, matching the agnostic guideline.
pub fn discover_web_roots(config: &crate::rules::ConfigManager) -> Vec<String> {
    let mut roots = std::collections::HashSet::new();

    // 1. Scan running web process cwd
    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            if !name
                .to_str()
                .map(|s| s.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(false)
            {
                continue;
            }
            let exe_path = entry.path().join("exe");
            if let Ok(target) = std::fs::read_link(&exe_path) {
                let exe_str = target.to_string_lossy();
                if config.is_web_process(&exe_str) {
                    let cwd_path = entry.path().join("cwd");
                    if let Ok(cwd_target) = std::fs::read_link(&cwd_path) {
                        let cwd_str = cwd_target.to_string_lossy().to_string();
                        // Ignore root directories / system dirs
                        if cwd_str != "/" && cwd_str != "/root" && !cwd_str.starts_with("/usr") {
                            roots.insert(cwd_str);
                        }
                    }
                }
            }
        }
    }

    // 2. Parse configuration files of reverse proxies (Nginx, Apache, Caddy)
    // Only if the corresponding proxy process is actively running!
    let config_paths = [
        ("/etc/nginx", "root", "nginx"),
        ("/etc/apache2", "DocumentRoot", "apache2"),
        ("/etc/httpd", "DocumentRoot", "httpd"),
        ("/etc/caddy", "root", "caddy"),
    ];

    for (dir_path, key, bin_name) in &config_paths {
        if Path::new(dir_path).exists() && is_process_running(bin_name) {
            scan_config_dir_for_roots(Path::new(dir_path), key, &mut roots);
        }
    }

    let mut result: Vec<String> = roots.into_iter().collect();
    adjust_web_roots_for_frameworks(&mut result);
    result
}

pub fn adjust_web_roots_for_frameworks(roots: &mut Vec<String>) {
    let mut to_add = Vec::new();
    for r in roots.iter() {
        let path = std::path::Path::new(r);
        if let Some(parent) = path.parent() {
            let markers = crate::storage_discovery::get_framework_anchors();
            for marker in &markers {
                if parent.join(marker).exists() {
                    if let Some(parent_str) = parent.to_str() {
                        to_add.push(parent_str.to_string());
                        break;
                    }
                }
            }
        }
    }
    for add in to_add {
        if !roots.contains(&add) {
            roots.push(add);
        }
    }
}

pub fn discover_listening_pids() -> std::collections::HashSet<u32> {
    let mut listening_pids = std::collections::HashSet::new();
    let mut listening_inodes = std::collections::HashSet::new();

    let files = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ];

    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 9 {
                    let state = parts[3];
                    let inode = parts[9];
                    if state == "0A" || file_path.contains("udp") {
                        if let Ok(inode_val) = inode.parse::<u64>() {
                            if inode_val > 0 {
                                listening_inodes.insert(inode_val);
                            }
                        }
                    }
                }
            }
        }
    }

    // Add Unix domain sockets
    if let Ok(content) = std::fs::read_to_string("/proc/net/unix") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let flags = parts[3];
                let inode = parts[6];
                // Flags containing 00010000 indicates a listening Unix socket (SO_ACCEPTCON)
                if flags == "00010000" || flags.contains('1') {
                    if let Ok(inode_val) = inode.parse::<u64>() {
                        if inode_val > 0 {
                            listening_inodes.insert(inode_val);
                        }
                    }
                }
            }
        }
    }

    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            let fd_path = entry.path().join("fd");
            if let Ok(fd_dir) = std::fs::read_dir(fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                            let inode_str = &link_str[8..link_str.len() - 1];
                            if let Ok(inode_val) = inode_str.parse::<u64>() {
                                if listening_inodes.contains(&inode_val) {
                                    listening_pids.insert(pid);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    listening_pids
}

pub fn discover_listening_ports() -> Vec<u16> {
    let mut ports = std::collections::HashSet::new();
    let files = ["/proc/net/tcp", "/proc/net/tcp6"];
    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 9 {
                    let state = parts[3];
                    if state == "0A" {
                        // TCP_LISTEN
                        let local_address = parts[1];
                        if let Some((_, port_hex)) = local_address.split_once(':') {
                            if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                // Ignore the proxy's own port to prevent loops
                                if port != 8443 {
                                    ports.insert(port);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ports.into_iter().collect()
}

fn scan_config_dir_for_roots(
    dir: &Path,
    pattern_key: &str,
    roots: &mut std::collections::HashSet<String>,
) {
    fn search_file(file_path: &Path, key: &str, roots: &mut std::collections::HashSet<String>) {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') {
                    continue;
                }

                if key == "DocumentRoot" {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("DocumentRoot") {
                        let path = parts[1].trim_matches('"').trim_matches('\'');
                        if path.starts_with('/') {
                            roots.insert(path.to_string());
                        }
                    }
                } else if key == "root" {
                    let clean = trimmed.trim_end_matches(';');
                    let parts: Vec<&str> = clean.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if parts[0] == "root" {
                            let path = parts[1].trim_matches('"').trim_matches('\'');
                            if path.starts_with('/') {
                                roots.insert(path.to_string());
                            }
                        }
                        if parts.len() >= 3 && parts[0] == "root" && parts[1] == "*" {
                            let path = parts[2].trim_matches('"').trim_matches('\'');
                            if path.starts_with('/') {
                                roots.insert(path.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    fn recurse(dir: &Path, key: &str, roots: &mut std::collections::HashSet<String>) {
        if let Ok(read_dir) = std::fs::read_dir(dir) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.is_dir() {
                        recurse(&path, key, roots);
                    } else if meta.is_file() {
                        search_file(&path, key, roots);
                    }
                }
            }
        }
    }
    recurse(dir, pattern_key, roots);
}

fn resolve_active_socket() -> Option<&'static str> {
    const SOCKETS: &[&str] = &[
        "/run/podman/podman.sock",
        "/var/run/podman/podman.sock",
        "/var/run/docker.sock",
        "/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
    ];
    for &path in SOCKETS {
        if std::path::Path::new(path).exists() {
            return Some(path);
        }
    }
    None
}

/// Dynamically query active container runtime socket to resolve container info,
/// config folders, and web root mounts (P6-1, P6-2, P6-3).
pub async fn discover_docker_containers() -> Vec<ContainerInfo> {
    let mut containers = Vec::new();
    let Some(socket_path) = resolve_active_socket() else {
        return containers;
    };

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(_) => return containers,
    };

    let req = "GET /containers/json HTTP/1.0\r\nHost: localhost\r\n\r\n";
    if stream.write_all(req.as_bytes()).await.is_err() {
        return containers;
    }

    let mut response = Vec::new();
    if stream.read_to_end(&mut response).await.is_err() {
        return containers;
    }

    let response_str = String::from_utf8_lossy(&response);
    let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return containers;
    }

    // Parse JSON body
    let body = parts[1];
    let Ok(json_val) = serde_json::from_str::<serde_json::Value>(body) else {
        return containers;
    };

    let Some(containers_array) = json_val.as_array() else {
        return containers;
    };

    for item in containers_array {
        let id = item
            .get("Id")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(info) = query_single_container(&id).await {
            let short_id = if info.id.len() >= 12 {
                &info.id[..12]
            } else {
                &info.id
            };
            get_active_containers().insert(
                info.id.clone(),
                crate::notifications::ContainerInfo {
                    id: info.id.clone(),
                    name: info.name.clone(),
                    image: info.image.clone(),
                    image_id: Some(info.image_id.clone()),
                    status: Some(info.status.clone()),
                    attached: info.attached,
                },
            );
            get_active_containers().insert(
                short_id.to_string(),
                crate::notifications::ContainerInfo {
                    id: info.id.clone(),
                    name: info.name.clone(),
                    image: info.image.clone(),
                    image_id: Some(info.image_id.clone()),
                    status: Some(info.status.clone()),
                    attached: info.attached,
                },
            );
            containers.push(info);
        }
    }

    containers
}

/// Spawn a background task that streams events from the active container socket.
/// Automatically detects container start/stop events in real-time (P6-4)
/// and registers their mounts without polling.
pub fn start_docker_event_listener() {
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;

        loop {
            let Some(socket_path) = resolve_active_socket() else {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            };

            let mut stream = match UnixStream::connect(socket_path).await {
                Ok(s) => s,
                Err(_) => {
                    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                    continue;
                }
            };

            let req = "GET /events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            if stream.write_all(req.as_bytes()).await.is_err() {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            let mut reader = BufReader::new(stream);
            let mut line = String::new();

            // Skip HTTP headers
            loop {
                line.clear();
                if reader.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                    break;
                }
            }

            // Read JSON events using standard HTTP chunked decoding
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        // Parse chunk size (hex)
                        let hex_str = trimmed.split(';').next().unwrap_or(trimmed).trim();
                        let chunk_size = match usize::from_str_radix(hex_str, 16) {
                            Ok(size) => size,
                            Err(_) => break,
                        };

                        if chunk_size == 0 {
                            break;
                        }

                        // Read exactly chunk_size bytes
                        let mut chunk_buf = vec![0u8; chunk_size];
                        if reader.read_exact(&mut chunk_buf).await.is_err() {
                            break;
                        }

                        // Consume trailing CRLF
                        let mut crlf = [0u8; 2];
                        if reader.read_exact(&mut crlf).await.is_err() {
                            break;
                        }

                        if let Ok(utf8_str) = String::from_utf8(chunk_buf) {
                            let trimmed_payload = utf8_str.trim();
                            if !trimmed_payload.is_empty() {
                                if let Ok(event) =
                                    serde_json::from_str::<serde_json::Value>(trimmed_payload)
                                {
                                    let action =
                                        event.get("Action").and_then(|a| a.as_str()).unwrap_or("");
                                    let id = event.get("id").and_then(|i| i.as_str()).unwrap_or("");
                                    if (action == "start" || action == "die" || action == "stop")
                                        && !id.is_empty()
                                    {
                                        trigger_container_reconfig(id, action).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
    });
}

pub(crate) async fn query_single_container(id: &str) -> Option<ContainerInfo> {
    let Some(socket_path) = resolve_active_socket() else {
        return None;
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(socket_path).await.ok()?;
    let req = format!(
        "GET /containers/{}/json HTTP/1.0\r\nHost: localhost\r\n\r\n",
        id
    );
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok()?;

    let response_str = String::from_utf8_lossy(&response);
    let body = response_str.split("\r\n\r\n").nth(1)?;
    let json_val: serde_json::Value = serde_json::from_str(body).ok()?;

    let name = json_val
        .get("Name")
        .and_then(|n| n.as_str())
        .unwrap_or("")
        .trim_start_matches('/')
        .to_string();
    let config = json_val.get("Config")?;
    let image = config
        .get("Image")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string();
    // Top-level `Image` (distinct from `Config.Image` above) is the resolved
    // local image content id — changes on rebuild/re-pull even if `image`'s
    // tag stays the same. This is what trust is actually pinned to.
    let image_id = json_val
        .get("Image")
        .and_then(|i| i.as_str())
        .unwrap_or("")
        .to_string();

    // Dynamically trust host-level container processes for Rule 4 and Rule 2 FP mitigation
    if let Some(state) = json_val.get("State") {
        if let Some(pid) = state.get("Pid").and_then(|p| p.as_u64()) {
            let pid = pid as u32;
            if pid > 0 {
                let image_lower = image.to_lowercase();
                let is_trusted_infra = [
                    "datadog/agent",
                    "datadog/cluster-agent",
                    "gcr.io/cadvisor",
                    "portainer/portainer",
                    "calico/node",
                    "flannel/flannel",
                    "weaveworks/weave-kube",
                    "kube-proxy",
                    "coredns/coredns",
                    "traefik",
                    "ingress-nginx/controller",
                ]
                .iter()
                .any(|&img| image_lower.contains(img));

                // Support Kubernetes system namespaces (prevent custom CNI/CSI driver false positives)
                let is_kube_system = config
                    .get("Labels")
                    .and_then(|l| l.get("io.kubernetes.pod.namespace"))
                    .and_then(|ns| ns.as_str())
                    == Some("kube-system");

                // Check if the container process shares the host PID namespace
                let is_host_pid_ns = if let (Ok(self_ns), Ok(peer_ns)) = (
                    std::fs::read_link("/proc/self/ns/pid"),
                    std::fs::read_link(format!("/proc/{}/ns/pid", pid)),
                ) {
                    self_ns == peer_ns
                } else {
                    false
                };

                if is_trusted_infra || is_kube_system || is_host_pid_ns {
                    tracing::info!(
                        "[Vandam Docker] Dynamically trusted system container PID {} (Image: {}, KubeSystem: {}, HostPID: {})",
                        pid, image, is_kube_system, is_host_pid_ns
                    );
                    crate::trust::grant(pid, crate::trust::TrustReason::InfraAllowlist);
                } else {
                    // User-issued trust ("vandam containers trust <image>") — full
                    // trust (see trust.rs), tracked separately so untrusting the image
                    // can revoke just this grant without touching infra-allowlist trust
                    // for other containers.
                    //
                    // Anchored to the image's content digest (image_id), not just the
                    // (mutable) tag in `image`: the first container seen running under a
                    // freshly-trusted tag pins the digest at that moment. If the tag is
                    // later repointed at a different build (rebuild/re-pull), the digest
                    // no longer matches and trust is NOT auto-renewed — it must be
                    // re-confirmed via `containers trust` again, same as any other
                    // "content changed under an old label" drift check.
                    let rules = crate::api::read_user_rules();
                    let matching_rule = rules
                        .iter()
                        .find(|r| r.rule_type == "ALLOW_CONTAINER_IMAGE" && r.target == image);
                    let is_user_trusted = match matching_rule {
                        None => false,
                        Some(rule) => match &rule.image_digest {
                            None => {
                                crate::api::pin_container_trust_digest(&image, &image_id);
                                true
                            }
                            Some(pinned) => pinned == &image_id,
                        },
                    };
                    if is_user_trusted {
                        if !crate::trust::is_trusted_by(pid, crate::trust::TrustReason::UserRule) {
                            tracing::info!(
                                "[Vandam Docker] User-trusted container PID {} (Image: {})",
                                pid,
                                image
                            );
                        }
                        crate::trust::grant(pid, crate::trust::TrustReason::UserRule);
                    } else if crate::trust::revoke_if(pid, crate::trust::TrustReason::UserRule) {
                        tracing::info!(
                            "[Vandam Docker] Revoking user trust for container PID {} (Image: {})",
                            pid,
                            image
                        );
                    }
                }
            }
        }
    }

    let mut web_roots = Vec::new();
    let mut config_dirs = Vec::new();

    if let Some(mounts) = json_val.get("Mounts").and_then(|m| m.as_array()) {
        for mount in mounts {
            let source = mount.get("Source").and_then(|s| s.as_str())?;
            let dest = mount.get("Destination").and_then(|d| d.as_str())?;
            let source_path = PathBuf::from(source);
            let dest_lower = dest.to_lowercase();
            if dest_lower.contains("html")
                || dest_lower.contains("www")
                || dest_lower.contains("public")
            {
                web_roots.push(source_path.clone());
                if let Some(parent) = source_path.parent() {
                    let markers = crate::storage_discovery::get_framework_anchors();
                    for marker in &markers {
                        if parent.join(marker).exists() {
                            let parent_buf = parent.to_path_buf();
                            if !web_roots.contains(&parent_buf) {
                                web_roots.push(parent_buf);
                            }
                            break;
                        }
                    }
                }
            } else if dest_lower.contains("conf")
                || dest_lower.contains("etc")
                || dest_lower.contains("settings")
            {
                config_dirs.push(source_path);
            }
        }
    }

    // Storage-role detection for containerized apps: a bind-mounted web root
    // is just a host-side path like any other, so the exact same
    // framework-signature scan `post_storage_rescan` already runs for host
    // web roots applies here unchanged — no container-specific heuristics
    // needed. Anchored on the mount's host source path (not `id`), so it
    // survives container recreation the same way host storage paths survive
    // a process restart.
    for web_root in &web_roots {
        let root_str = web_root.to_string_lossy();
        for sp in crate::storage_discovery::run_framework_rules(&root_str) {
            crate::storage_discovery::register(sp);
        }
    }

    let status = json_val
        .get("State")
        .and_then(|s| s.get("Status"))
        .and_then(|s| s.as_str())
        .unwrap_or("running")
        .to_uppercase();

    let attached = !web_roots.is_empty()
        || !config_dirs.is_empty()
        || get_active_container_mounts().contains_key(id);

    Some(ContainerInfo {
        id: id.to_string(),
        name,
        image,
        image_id,
        status,
        attached,
        web_roots,
        config_dirs,
    })
}

use dashmap::DashMap;
use std::sync::{Arc, OnceLock};

static ACTIVE_CONTAINER_MOUNTS: OnceLock<Arc<DashMap<String, Vec<PathBuf>>>> = OnceLock::new();
static ACTIVE_CONTAINERS: OnceLock<Arc<DashMap<String, crate::notifications::ContainerInfo>>> =
    OnceLock::new();

pub fn get_active_container_mounts() -> &'static Arc<DashMap<String, Vec<PathBuf>>> {
    ACTIVE_CONTAINER_MOUNTS.get_or_init(|| Arc::new(DashMap::new()))
}

pub fn get_active_containers() -> &'static Arc<DashMap<String, crate::notifications::ContainerInfo>>
{
    ACTIVE_CONTAINERS.get_or_init(|| Arc::new(DashMap::new()))
}

pub fn register_container_mounts(id: &str, mounts: Vec<PathBuf>) {
    get_active_container_mounts().insert(id.to_string(), mounts);
}

async fn trigger_container_reconfig(id: &str, action: &str) {
    let is_die_or_stop = action == "die" || action == "stop";
    if action == "start" {
        if let Some(c) = query_single_container(id).await {
            println!(
                "[Vandam Docker] Dynamic event: Started container {} (Image: {})",
                c.name, c.image
            );

            let short_id = if id.len() >= 12 { &id[..12] } else { id };
            get_active_containers().insert(
                id.to_string(),
                crate::notifications::ContainerInfo {
                    id: id.to_string(),
                    name: c.name.clone(),
                    image: c.image.clone(),
                    image_id: Some(c.image_id.clone()),
                    status: Some(c.status.clone()),
                    attached: c.attached,
                },
            );
            get_active_containers().insert(
                short_id.to_string(),
                crate::notifications::ContainerInfo {
                    id: id.to_string(),
                    name: c.name.clone(),
                    image: c.image.clone(),
                    image_id: Some(c.image_id.clone()),
                    status: Some(c.status.clone()),
                    attached: c.attached,
                },
            );

            let mut mounts = Vec::new();
            for wr in c.web_roots {
                println!(
                    "[Vandam Docker] Dynamically adding FIM watch and allowlist for: {}",
                    wr.display()
                );
                crate::fim::add_fim_watch_path(wr.clone());
                let wr_str = wr.to_string_lossy().to_string();
                tokio::task::block_in_place(|| {
                    crate::allowlist::register_path_recursive(&wr_str);
                });
                mounts.push(wr);
            }
            for cd in c.config_dirs {
                println!(
                    "[Vandam Docker] Dynamically adding FIM watch for config: {}",
                    cd.display()
                );
                crate::fim::add_fim_watch_path(cd.clone());
                mounts.push(cd);
            }
            register_container_mounts(id, mounts);
        }
    } else if is_die_or_stop {
        println!("[Vandam Docker] Dynamic event: Stopped container {}", id);
        let short_id = if id.len() >= 12 { &id[..12] } else { id };
        get_active_containers().remove(id);
        get_active_containers().remove(short_id);

        if let Some((_, mounts)) = get_active_container_mounts().remove(id) {
            for mount in mounts {
                println!("[Vandam Docker] Dynamically removing FIM watch and allowlist for stopped container mount: {}", mount.display());
                crate::fim::remove_fim_watch_path(mount.clone());
                let mount_str = mount.to_string_lossy();
                tokio::task::block_in_place(|| {
                    crate::allowlist::deregister_path_recursive(&mount_str);
                });
            }
        }
    }
}

fn probe_listening_port(port: u16) -> String {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let addr_str = format!("127.0.0.1:{}", port);
    let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() else {
        return "unknown".to_string();
    };

    // 1. Attempt raw HTTP probe
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(150)) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(150)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(150)));
        let req = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        if stream.write_all(req.as_bytes()).is_ok() {
            let mut buf = [0u8; 16];
            if let Ok(n) = stream.read(&mut buf) {
                if n >= 4 && &buf[..4] == b"HTTP" {
                    return "HTTP".to_string();
                }
            }
        }
    }

    // 2. Attempt HTTPS TLS detection
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(150)) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(150)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(150)));
        let client_hello = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        if stream.write_all(&client_hello).is_ok() {
            let mut buf = [0u8; 5];
            if let Ok(n) = stream.read(&mut buf) {
                if n >= 3 && (buf[0] == 0x16 || buf[0] == 0x15) && buf[1] == 0x03 {
                    return "HTTPS".to_string();
                }
            }
        }
    }

    "unknown".to_string()
}

pub fn get_listening_services() -> Vec<serde_json::Value> {
    use std::collections::{HashMap, HashSet};
    let mut inode_to_port: HashMap<u64, u16> = HashMap::new();
    let mut inode_to_unix_path: HashMap<u64, String> = HashMap::new();

    let files = [
        "/proc/net/tcp",
        "/proc/net/tcp6",
        "/proc/net/udp",
        "/proc/net/udp6",
    ];

    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 9 {
                    let local_addr = parts[1];
                    let state = parts[3];
                    let inode = parts[9];
                    if state == "0A" || file_path.contains("udp") {
                        if let Ok(inode_val) = inode.parse::<u64>() {
                            if inode_val > 0 {
                                if let Some(port_hex) = local_addr.split(':').nth(1) {
                                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                        inode_to_port.insert(inode_val, port);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if let Ok(content) = std::fs::read_to_string("/proc/net/unix") {
        for line in content.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 7 {
                let flags = parts[3];
                let inode = parts[6];
                let path = if parts.len() >= 8 {
                    parts[7].to_string()
                } else {
                    String::new()
                };
                if flags == "00010000" || flags.contains('1') {
                    if let Ok(inode_val) = inode.parse::<u64>() {
                        if inode_val > 0 {
                            inode_to_unix_path.insert(inode_val, path);
                        }
                    }
                }
            }
        }
    }

    let mut pid_to_ports: HashMap<u32, HashSet<u16>> = HashMap::new();
    let mut pid_to_unix_paths: HashMap<u32, HashSet<String>> = HashMap::new();

    if let Ok(proc_dir) = std::fs::read_dir("/proc") {
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let Ok(pid) = name_str.parse::<u32>() else {
                continue;
            };

            let fd_path = entry.path().join("fd");
            if let Ok(fd_dir) = std::fs::read_dir(fd_path) {
                for fd_entry in fd_dir.flatten() {
                    if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                            let inode_str = &link_str[8..link_str.len() - 1];
                            if let Ok(inode_val) = inode_str.parse::<u64>() {
                                if let Some(&port) = inode_to_port.get(&inode_val) {
                                    pid_to_ports.entry(pid).or_default().insert(port);
                                }
                                if let Some(path) = inode_to_unix_path.get(&inode_val) {
                                    if !path.is_empty() {
                                        pid_to_unix_paths
                                            .entry(pid)
                                            .or_default()
                                            .insert(path.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut services = Vec::new();
    let mut all_pids: HashSet<u32> = HashSet::new();
    all_pids.extend(pid_to_ports.keys());
    all_pids.extend(pid_to_unix_paths.keys());

    for pid in all_pids {
        let exe_path = format!("/proc/{}/exe", pid);
        let cwd_path = format!("/proc/{}/cwd", pid);

        let exe = std::fs::read_link(&exe_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let cwd = std::fs::read_link(&cwd_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if exe.is_empty() {
            continue;
        }

        let mut stack = detect_process_stack(pid, &exe);
        let ports = pid_to_ports.get(&pid).cloned().unwrap_or_default();
        let unix_paths = pid_to_unix_paths.get(&pid).cloned().unwrap_or_default();

        // Active TCP HTTP/HTTPS probing for unknown compiled stacks
        if (stack == "Native (C/C++)" || stack == "Rust (Compiled)" || stack == "Go (Compiled)")
            && !ports.is_empty()
        {
            for &port in &ports {
                let proto = probe_listening_port(port);
                if proto == "HTTP" || proto == "HTTPS" {
                    stack = format!("Web Service ({})", proto);
                    break;
                }
            }
        }

        let ppid = if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
            if let Some(last_paren) = stat.rfind(')') {
                let tail = &stat[last_paren + 1..];
                let parts: Vec<&str> = tail.split_whitespace().collect();
                parts
                    .get(1)
                    .and_then(|p| p.parse::<u32>().ok())
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        let manager = detect_process_manager(pid).unwrap_or_default();
        services.push(serde_json::json!({
            "pid": pid,
            "ppid": ppid,
            "exe": exe,
            "cwd": cwd,
            "stack": stack,
            "manager": manager,
            "in_container": is_container_process(pid),
            "container_name": get_process_container_name(pid),
            "ports": ports.into_iter().collect::<Vec<_>>(),
            "unix_sockets": unix_paths.into_iter().collect::<Vec<_>>(),
        }));
    }

    services
}

pub fn detect_process_manager(pid: u32) -> Option<String> {
    let mut env_str = String::new();
    if let Ok(bytes) = std::fs::read(format!("/proc/{}/environ", pid)) {
        env_str = String::from_utf8_lossy(&bytes).to_string();
        if env_str.contains("PM2_HOME=")
            || env_str.contains("pm_id=")
            || env_str.contains("PM2_USAGE=")
        {
            return Some("PM2".to_string());
        }
        if env_str.contains("SUPERVISOR_ENABLED=1") || env_str.contains("SUPERVISOR_PROCESS_NAME=")
        {
            return Some("Supervisord".to_string());
        }
        if env_str.contains("INVOCATION_ID=") || env_str.contains("SYSTEMD_EXEC_PID=") {
            return Some("systemctl".to_string());
        }
    }

    let mut cgroup_str = String::new();
    if let Ok(cg) = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)) {
        cgroup_str = cg;
        if cgroup_str.contains("/docker/")
            || cgroup_str.contains("/kubepods/")
            || cgroup_str.contains("/containerd/")
        {
            return Some("Docker".to_string());
        }
        if cgroup_str.contains(".service") || cgroup_str.contains("/system.slice/") {
            return Some("systemctl".to_string());
        }
    }

    if let Ok(cmd) = std::fs::read(format!("/proc/{}/cmdline", pid)) {
        let cmd_str = String::from_utf8_lossy(&cmd);
        if cmd_str.contains("ProcessContainer") || cmd_str.contains("ForkMode") {
            return Some("PM2".to_string());
        }
    }

    let mut cur_pid = pid;
    for _ in 0..10 {
        if let Ok(stat_str) = std::fs::read_to_string(format!("/proc/{}/stat", cur_pid)) {
            if let Some(rparen) = stat_str.rfind(')') {
                let fields: Vec<&str> = stat_str[rparen + 1..].split_whitespace().collect();
                if fields.len() >= 2 {
                    if let Ok(ppid) = fields[1].parse::<u32>() {
                        if ppid == 0 || ppid == cur_pid {
                            break;
                        }
                        if let Ok(p_cmd) = std::fs::read(format!("/proc/{}/cmdline", ppid)) {
                            let p_cmd_str = String::from_utf8_lossy(&p_cmd).to_lowercase();
                            if p_cmd_str.contains("pm2") || p_cmd_str.contains("god daemon") {
                                return Some("PM2".to_string());
                            }
                            if p_cmd_str.contains("supervisord") || p_cmd_str.contains("supervisor")
                            {
                                return Some("Supervisord".to_string());
                            }
                            if p_cmd_str.contains("containerd-shim") {
                                return Some("Docker".to_string());
                            }
                            if ppid == 1
                                && (cgroup_str.contains(".service")
                                    || cgroup_str.contains("/system.slice/"))
                            {
                                return Some("systemctl".to_string());
                            }
                            let comm = p_cmd_str.split('/').last().unwrap_or(&p_cmd_str);
                            if matches!(
                                comm.split_whitespace().next().unwrap_or(""),
                                "bash"
                                    | "zsh"
                                    | "sh"
                                    | "fish"
                                    | "screen"
                                    | "tmux"
                                    | "ssh"
                                    | "sshd"
                                    | "sudo"
                                    | "su"
                                    | "-bash"
                                    | "-zsh"
                                    | "-sh"
                            ) {
                                return Some("user spawned".to_string());
                            }
                        }
                        cur_pid = ppid;
                        continue;
                    }
                }
            }
        }
        break;
    }

    if cgroup_str.contains("session-")
        || (cgroup_str.contains("/user.slice/") && !cgroup_str.contains(".service"))
    {
        return Some("user spawned".to_string());
    }
    if env_str.contains("SSH_CONNECTION=")
        || env_str.contains("SSH_CLIENT=")
        || env_str.contains("TERM=")
    {
        return Some("user spawned".to_string());
    }

    None
}

pub fn detect_process_stack(pid: u32, exe_path: &str) -> String {
    // --- Stage 0: Check global signature registry from linux_web_signatures.json ---
    if let Some(sig_name) = crate::generic_discovery::get_signature_for_pid(pid) {
        match sig_name.as_ref() {
            "gunicorn" | "uwsgi" | "uvicorn" | "daphne" | "hypercorn" | "falcon" | "waitress"
            | "tornado" | "werkzeug-dev" | "python-wsgi" | "python-http" => {
                return "Python".to_string()
            }
            "puma" | "unicorn" | "thin" | "passenger" | "ruby-rack" => return "Ruby".to_string(),
            "php-fpm" | "php-cli-server" | "swoole" => return "PHP".to_string(),
            "node" | "bun" | "deno" => return "Node.js".to_string(),
            "java-servlet" | "tomcat" | "jetty" | "wildfly" | "spring-boot" => {
                return "Java".to_string()
            }
            "perl-fcgi" => return "Perl".to_string(),
            "lua-server" => return "Lua".to_string(),
            "dotnet-server" => return "DotNet".to_string(),
            "openresty" => return "Nginx".to_string(),
            "lighttpd" | "apache" => return "Apache".to_string(),
            "roadrunner" => return "Go (Compiled)".to_string(),
            "phoenix" => return "Erlang/Elixir".to_string(),
            _ => {}
        }
    }

    // --- Stage 1: Basename-exact matching for known scripting runtimes ---
    //
    // We match the binary filename (last path component) only — NOT a substring
    // of the full exe path.  This prevents false positives like:
    //   /usr/bin/node_exporter  → "node" substring → wrongly "Node.js"
    //   /opt/php-app/server     → "php" in dirname  → wrongly "PHP"
    //
    // Versioned binaries are handled explicitly:
    //   php8.1, php-fpm8.2, python3.11, ruby3.2, java17 …
    let basename: String = std::path::Path::new(exe_path)
        .file_name()
        .map(|f| f.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    // Node.js — exact only: "node" or "nodejs"
    // NOT: node_exporter, node_modules, nodebb, nodemon (these are app-level tools,
    // not the Node.js runtime itself, and most run through the node binary anyway)
    if basename == "node" || basename == "nodejs" {
        return "Node.js".to_string();
    }

    // PHP — "php" exact, "php-fpm", "php-cgi", "php-cgi7.4",
    //       "php8.1", "php8.2", "php-fpm8.1", "php-fpm8.2", etc.
    //       Char after "php" must be '-' or a digit to avoid matching unrelated binaries.
    if basename == "php"
        || (basename.starts_with("php")
            && basename
                .as_bytes()
                .get(3)
                .map_or(false, |&c| c == b'-' || c.is_ascii_digit()))
    {
        return "PHP".to_string();
    }

    // Python interpreter — "python", "python2", "python3", "python3.11", "python2.7"
    //   Char after "python" must be a digit or end-of-string.
    if basename == "python"
        || (basename.starts_with("python")
            && basename
                .as_bytes()
                .get(6)
                .map_or(true, |&c| c.is_ascii_digit()))
    {
        return "Python".to_string();
    }

    // Python application servers shipped as compiled binaries / installed scripts.
    // These ARE separate executables (not run through python interpreter directly
    // when installed system-wide or via pipx), so /proc/<pid>/exe points to them.
    if matches!(
        basename.as_str(),
        "uwsgi" | "gunicorn" | "uvicorn" | "daphne" | "hypercorn" | "granian"
    ) {
        return "Python".to_string();
    }

    // Java runtime — "java" exact, or "java" + digit (e.g. "java17", very rare)
    if basename == "java"
        || (basename.starts_with("java")
            && basename
                .as_bytes()
                .get(4)
                .map_or(false, |&c| c.is_ascii_digit()))
    {
        return "Java".to_string();
    }

    // JVM-language launchers that are separate binaries but run on the JVM.
    // /proc/<pid>/maps will also show libjvm.so for these (Stage 2 backup).
    if matches!(
        basename.as_str(),
        "scala" | "kotlin" | "clojure" | "lein" | "groovy"
    ) {
        return "Java".to_string();
    }

    // Ruby interpreter — "ruby", "ruby3.2", "ruby2.7", etc.
    if basename == "ruby"
        || (basename.starts_with("ruby")
            && basename
                .as_bytes()
                .get(4)
                .map_or(false, |&c| c.is_ascii_digit()))
    {
        return "Ruby".to_string();
    }

    // Ruby application servers compiled as native binaries.
    // Puma (puma 5+) ships a native launcher. Unicorn/Thin/Passenger are C extensions.
    if basename == "puma"
        || basename == "unicorn"
        || basename == "thin"
        || basename == "passenger"
        || basename.starts_with("passenger-")
        || basename == "rainbows"
    {
        return "Ruby".to_string();
    }

    // Nginx — "nginx" exact only; not "nginx-module-xyz"
    if basename == "nginx" {
        return "Nginx".to_string();
    }

    // Apache HTTPD — "httpd" or "apache2" exact
    if basename == "httpd" || basename == "apache2" {
        return "Apache".to_string();
    }

    // Caddy — "caddy" exact
    if basename == "caddy" {
        return "Caddy".to_string();
    }

    // Perl — "perl", "perl5.36", etc.
    if basename == "perl"
        || (basename.starts_with("perl")
            && basename
                .as_bytes()
                .get(4)
                .map_or(false, |&c| c.is_ascii_digit()))
    {
        return "Perl".to_string();
    }

    // Lua — "lua", "lua5.4", etc.
    if basename == "lua"
        || (basename.starts_with("lua")
            && basename
                .as_bytes()
                .get(3)
                .map_or(false, |&c| c.is_ascii_digit()))
    {
        return "Lua".to_string();
    }

    // .NET / Mono runtimes
    if matches!(
        basename.as_str(),
        "dotnet" | "mono" | "mono-sgen" | "mono-boehm"
    ) {
        return "DotNet".to_string();
    }

    // --- Stage 2: /proc/<pid>/maps shared library inspection ---
    // Only reached for binaries whose basename didn't match any known runtime.
    // This catches binaries that embed runtimes without exposing them in their name
    // (e.g. a custom compiled Python loader, a JVM embedded in a native launcher).
    if let Ok(maps) = std::fs::read_to_string(format!("/proc/{}/maps", pid)) {
        if maps.contains("libjvm.so") {
            // Any binary dynamically loading the JVM is effectively a Java app
            return "Java (JVM)".to_string();
        }
        if maps.contains("libgo.so") {
            // Go shared-lib build (rare but valid)
            return "Go (Shared)".to_string();
        }
        if maps.contains("libpython") {
            // Compiled binary embedding the Python interpreter (e.g. custom uwsgi build,
            // mod_wsgi standalone, Python C-extension launchers)
            return "Python".to_string();
        }
        if maps.contains("libruby") {
            return "Ruby".to_string();
        }
        // Dynamically-linked C++ binary — identified via libstdc++ or libc++ presence.
        // We reach here only after confirming it's not Go/Rust/Java/Python/Ruby.
        if maps.contains("libstdc++") || maps.contains("libc++.so") {
            return "Native (C/C++)".to_string();
        }
    }

    // --- Stage 3: Deep ELF byte-scan for statically-linked Go, Rust, or C/C++ ---
    // Read only the first 64 KiB — all reliable markers appear in ELF headers,
    // .note sections, and early rodata. Avoids reading 100+ MiB binaries in the
    // ProcessCreate hot-path. Uses raw byte window search (not lossy UTF-8) so
    // binary markers match exactly as they appear on disk.
    if let Ok(mut file) = std::fs::File::open(format!("/proc/{}/exe", pid)) {
        use std::io::Read;
        let mut buf = vec![0u8; 65536];
        let n = file.read(&mut buf).unwrap_or(0);
        let bytes = &buf[..n];

        // Go: statically-linked Go binaries embed a build-info header.
        // The magic prefix "\xff Go buildinf:" is written by cmd/go into the
        // .go.buildinfo ELF section (Go 1.13+). "runtime.main" is always present
        // in the symbol table of every Go binary, even stripped ones built with
        // `go build -s -w`. ".note.go.buildid" is the ELF section name.
        let go_markers: &[&[u8]] = &[
            b"\xff Go buildinf:", // go build info magic (Go 1.13+)
            b".note.go.buildid",  // ELF section name present in all Go toolchain output
            b"runtime.main",      // Go runtime symbol present in stripped binaries
            b"runtime.goexit",    // Alternative Go runtime marker
        ];
        if go_markers
            .iter()
            .any(|marker| bytes.windows(marker.len()).any(|w| w == *marker))
        {
            return "Go (Compiled)".to_string();
        }

        // Rust: "rust_begin_unwind" is the Rust panic entry point present in every
        // non-stripped Rust binary. "/rustc/" appears in DWARF debug paths embedded
        // in rodata of the standard library. "__rust_alloc" is the global allocator.
        let rust_markers: &[&[u8]] = &[
            b"rust_begin_unwind", // Rust panic entry point symbol
            b"/rustc/",           // rustc source path in rodata/DWARF
            b"core::panicking",   // core library panic path in rodata
            b"__rust_alloc",      // Rust global allocator symbol
        ];
        if rust_markers
            .iter()
            .any(|marker| bytes.windows(marker.len()).any(|w| w == *marker))
        {
            return "Rust (Compiled)".to_string();
        }
    }

    // Default: treat as native C/C++ (also covers unknown compiled binaries)
    "Native (C/C++)".to_string()
}

// ---------------------------------------------------------------------------
// Database Auto-Discovery
// ---------------------------------------------------------------------------

/// A detected host-native database server process.
#[derive(Debug, Clone)]
pub struct DiscoveredDatabase {
    /// Canonical database type string (matches DbSignature.db_type)
    pub db_type: String,
    pub pid: u32,
    /// Paths of config files extracted from cmdline arguments
    pub config_paths: Vec<PathBuf>,
    /// Common-root data/log directories to register in the BPF bypass map
    pub data_dirs: Vec<PathBuf>,
}

fn is_container_process(pid: u32) -> bool {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
        // Any of these strings in the cgroup hierarchy means containerised
        for marker in &[
            "docker",
            "containerd",
            "kubepods",
            "lxc",
            "podman",
            "libpod",
        ] {
            if content.contains(marker) {
                return true;
            }
        }
    }
    false
}

/// Returns the container ID (if any) that the process belongs to, by parsing its cgroup path.
fn get_process_container_id(pid: u32) -> Option<String> {
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    let content = std::fs::read_to_string(&cgroup_path).ok()?;

    // Look for standard container scope markers
    for line in content.lines() {
        for marker in &[
            "libpod-",
            "docker-",
            "docker/",
            "containerd-",
            "lxc-",
            "kubepods-",
        ] {
            if let Some(idx) = line.find(marker) {
                let start = idx + marker.len();
                let candidate = &line[start..];
                let id: String = candidate
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                if id.len() >= 8 {
                    return Some(id);
                }
            }
        }
    }
    None
}

/// Returns the container name mapping (if any) or fallback container ID for a pid.
pub fn get_process_container_name(pid: u32) -> Option<String> {
    let id = get_process_container_id(pid)?;
    if let Some(c) = get_active_containers().get(&id) {
        return Some(c.name.clone());
    }
    let short_id = if id.len() >= 12 { &id[..12] } else { &id };
    if let Some(c) = get_active_containers().get(short_id) {
        return Some(c.name.clone());
    }
    Some(short_id.to_string())
}

/// Returns true if `path` (a resolved /proc/<pid>/fd symlink target) should be
/// considered a database-owned data path. Filters out OS noise, shared libraries,
/// sockets, pipes, and virtual filesystems.
fn is_db_owned_path(path: &str) -> bool {
    !path.starts_with("/proc/")
        && !path.starts_with("/sys/")
        && !path.starts_with("/dev/")
        && !path.starts_with("/run/")
        && !path.starts_with("/usr/lib/")
        && !path.starts_with("/usr/share/")
        && !path.contains(".so")
        && !path.starts_with("socket:[")
        && !path.starts_with("pipe:[")
        && !path.starts_with("anon_inode:")
}

/// Given a set of paths, finds the deepest common ancestor directory.
/// Used to derive a single root inode to register in the BPF bypass map.
fn common_ancestor(paths: &[PathBuf]) -> Option<PathBuf> {
    let mut ancestor = paths.first()?.parent()?.to_path_buf();
    for path in paths.iter().skip(1) {
        while !path.starts_with(&ancestor) {
            match ancestor.parent() {
                Some(p) => ancestor = p.to_path_buf(),
                None => return None,
            }
        }
    }
    // Never bypass root or top-level system directories
    let anc_str = ancestor.to_string_lossy();
    if anc_str == "/" || anc_str.is_empty() || anc_str == "/var" || anc_str == "/etc" {
        return None;
    }
    Some(ancestor)
}

/// Method A: check /proc/<pid>/fd/ symlinks for any of the fd_signatures filenames.
fn method_a_fd_match(pid: u32, sig: &crate::rules::DbSignature) -> bool {
    if sig.fd_signatures.is_empty() {
        return false;
    }
    let fd_dir = format!("/proc/{}/fd", pid);
    if let Ok(dir) = std::fs::read_dir(&fd_dir) {
        for entry in dir.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy();
                let filename = target
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_default();
                for fs in &sig.fd_signatures {
                    if filename.contains(fs.as_str()) || target_str.contains(fs.as_str()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Method B: check /proc/<pid>/cmdline for any of the cmdline_tokens.
fn method_b_cmdline_match(pid: u32, sig: &crate::rules::DbSignature) -> bool {
    if sig.cmdline_tokens.is_empty() {
        return false;
    }
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(bytes) = std::fs::read(&cmdline_path) {
        // cmdline is NUL-delimited; convert to a single space-separated string
        let cmdline = bytes
            .iter()
            .map(|&b| if b == 0 { b' ' } else { b })
            .collect::<Vec<_>>();
        let cmdline_str = String::from_utf8_lossy(&cmdline).to_lowercase();
        for token in &sig.cmdline_tokens {
            if cmdline_str.contains(token.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Method C: scan first 100KB of binary header via /proc/<pid>/exe for embedded strings.
/// Skipped for JVM-based databases (binary_strings is empty in their signatures).
fn method_c_binary_match(pid: u32, sig: &crate::rules::DbSignature) -> bool {
    if sig.binary_strings.is_empty() {
        return false;
    }
    let exe_path = format!("/proc/{}/exe", pid);
    if let Ok(bytes) = std::fs::read(&exe_path) {
        let limit = 102_400.min(bytes.len());
        let content = String::from_utf8_lossy(&bytes[..limit]);
        for s in &sig.binary_strings {
            if content.contains(s.as_str()) {
                return true;
            }
        }
    }
    false
}

/// Collect all database-owned FD paths for `pid`, filter noise, then derive
/// common-root ancestor directories to register as BPF bypass inodes.
fn collect_data_dirs(pid: u32) -> Vec<PathBuf> {
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut owned_paths: Vec<PathBuf> = Vec::new();

    if let Ok(dir) = std::fs::read_dir(&fd_dir) {
        for entry in dir.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy();
                if is_db_owned_path(&target_str) && target.is_absolute() {
                    // Only include paths that actually exist on disk (not deleted inodes)
                    if target.exists() {
                        owned_paths.push(target);
                    }
                }
            }
        }
    }

    if owned_paths.is_empty() {
        return Vec::new();
    }

    // Group by first two path components to separate data dir from log dir
    let mut groups: std::collections::HashMap<String, Vec<PathBuf>> =
        std::collections::HashMap::new();
    for p in &owned_paths {
        let mut components = p.components();
        let _ = components.next(); // skip leading /
        let first = components
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();
        let second = components
            .next()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .unwrap_or_default();
        let group_key = format!("/{}/{}", first, second);
        groups.entry(group_key).or_default().push(p.clone());
    }

    // Find common ancestor within each group
    let mut roots: Vec<PathBuf> = Vec::new();
    for (_key, paths) in groups {
        if let Some(ancestor) = common_ancestor(&paths) {
            if !roots
                .iter()
                .any(|r| ancestor.starts_with(r) || r.starts_with(&ancestor))
            {
                roots.push(ancestor);
            }
        }
    }

    roots
}

/// Collect config file paths for `pid`, driven by the signature's `config_location` field.
/// Strategy (in order):
///  1. cmdline_arg / alt_cmdline_arg — both `--flag=value` and `--flag value` forms
///  2. datadir_from_cmdline — flag gives a data dir; look for known config filenames inside it
///  3. positional_arg — bare positional argument (e.g. redis-server <config>)
///  4. signature default_paths — well-known filesystem locations tried last
fn collect_config_paths(pid: u32, sig: &crate::rules::DbSignature) -> Vec<PathBuf> {
    fn push_candidate(config_paths: &mut Vec<PathBuf>, p: PathBuf) {
        if p.is_absolute() && p.exists() && !config_paths.contains(&p) {
            config_paths.push(p);
        }
    }

    let mut config_paths: Vec<PathBuf> = Vec::new();

    // Read and split cmdline once
    let args: Vec<String> = std::fs::read(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();

    let loc = match sig.config_location.as_ref() {
        Some(l) => l,
        None => return collect_config_paths_generic(&args),
    };

    // 1. cmdline_arg and alt_cmdline_arg (both `--flag=value` and `--flag value` forms)
    let flags_to_try: Vec<&str> = [loc.cmdline_arg.as_deref(), loc.alt_cmdline_arg.as_deref()]
        .into_iter()
        .flatten()
        .collect();

    for (i, arg) in args.iter().enumerate() {
        for &flag in &flags_to_try {
            let eq_prefix = format!("{}=", flag);
            if let Some(val) = arg.strip_prefix(&eq_prefix) {
                push_candidate(&mut config_paths, PathBuf::from(val.trim()));
            }
            if arg == flag {
                if let Some(next) = args.get(i + 1) {
                    push_candidate(&mut config_paths, PathBuf::from(next.trim()));
                }
            }
        }
    }

    // 2. datadir_from_cmdline — flag gives data directory; look for postgresql.conf etc. inside
    if let Some(ref dd_flag) = loc.datadir_from_cmdline {
        for (i, arg) in args.iter().enumerate() {
            let eq_prefix = format!("{}=", dd_flag);
            let data_dir = if let Some(val) = arg.strip_prefix(&eq_prefix) {
                Some(PathBuf::from(val.trim()))
            } else if arg == dd_flag {
                args.get(i + 1).map(|v| PathBuf::from(v.trim()))
            } else {
                None
            };
            if let Some(dd) = data_dir {
                for cfg_name in &["postgresql.conf", "pg_hba.conf", "postgresql.auto.conf"] {
                    push_candidate(&mut config_paths, dd.join(cfg_name));
                }
            }
        }
    }

    // 3. positional_arg (1-based) — e.g. redis-server /etc/redis/redis.conf is argv[1]
    if let Some(pos) = loc.positional_arg {
        if let Some(arg) = args.get(pos) {
            let p = PathBuf::from(arg.trim());
            if p.is_absolute() && !arg.starts_with('-') {
                push_candidate(&mut config_paths, p);
            }
        }
    }

    // 4. Default filesystem paths — tried if cmdline yielded nothing
    if config_paths.is_empty() {
        for default in &loc.default_paths {
            if default.contains('*') {
                if let Ok(entries) = glob::glob(default) {
                    for entry in entries.flatten() {
                        push_candidate(&mut config_paths, entry);
                    }
                }
            } else {
                push_candidate(&mut config_paths, PathBuf::from(default));
            }
        }
    }

    config_paths
}

/// Generic cmdline config path collector for signatures without config_location.
/// Catches `.conf`, `.cfg`, `.ini`, `.yaml`, `.yml`, `.toml`, `.properties`
/// and common `--config`/`-c`/`--config-file`/`--options-file` flags.
fn collect_config_paths_generic(args: &[String]) -> Vec<PathBuf> {
    fn push_candidate(config_paths: &mut Vec<PathBuf>, p: PathBuf) {
        if p.is_absolute() && p.exists() && !config_paths.contains(&p) {
            config_paths.push(p);
        }
    }
    let mut config_paths = Vec::new();
    let config_extensions = [
        ".conf",
        ".cfg",
        ".ini",
        ".yaml",
        ".yml",
        ".toml",
        ".properties",
    ];
    let config_flags = [
        "--config=",
        "--config-file=",
        "--options-file=",
        "--conf=",
        "--defaults-file=",
        "--configuration=",
    ];
    for (i, arg) in args.iter().enumerate() {
        if config_extensions.iter().any(|ext| arg.ends_with(ext)) {
            let p = PathBuf::from(arg);
            if p.is_absolute() {
                push_candidate(&mut config_paths, p);
            }
        }
        for &prefix in &config_flags {
            if let Some(val) = arg.strip_prefix(prefix) {
                push_candidate(&mut config_paths, PathBuf::from(val.trim()));
            }
            // next-arg form
            let flag = prefix.trim_end_matches('=');
            if arg == flag {
                if let Some(next) = args.get(i + 1) {
                    push_candidate(&mut config_paths, PathBuf::from(next.trim()));
                }
            }
        }
    }
    config_paths
}

/// Apply config_rules from the signature to a config file, returning paths by role.
/// Roles "data_dir" and "write_path" are returned; "outbound_ip" and "tls_cert" are ignored here.
fn extract_data_dirs_from_config(
    config_file: &Path,
    sig: &crate::rules::DbSignature,
) -> Vec<PathBuf> {
    if sig.config_rules.is_empty() {
        return Vec::new();
    }
    let Ok(content) = std::fs::read_to_string(config_file) else {
        return Vec::new();
    };

    let config_dir = config_file.parent().unwrap_or(Path::new("/"));
    let mut paths = Vec::new();

    for rule in &sig.config_rules {
        // Only extract data_dir and write_path roles for the bypass allowlist
        if rule.role != "data_dir" && rule.role != "write_path" {
            continue;
        }
        // Skip json_path-only rules (not implemented for regex path)
        if rule.regex.trim().is_empty() {
            continue;
        }
        let Ok(re) = regex::Regex::new(&rule.regex) else {
            continue;
        };

        // If a section filter is specified, extract only lines under that section header.
        let search_content: String = if let Some(ref section) = rule.section {
            extract_section(&content, section)
        } else {
            content.clone()
        };

        for cap in re.captures_iter(&search_content) {
            if let Some(m) = cap.get(1) {
                let raw = m.as_str().trim().trim_matches(|c| c == '\'' || c == '"');
                if raw.is_empty() {
                    continue;
                }
                let p = if raw.starts_with('/') {
                    PathBuf::from(raw)
                } else {
                    // Relative path — resolve against the config file's directory
                    config_dir.join(raw)
                };
                // Resolve symlinks / normalise; only add if exists
                let canonical = std::fs::canonicalize(&p).unwrap_or(p);
                if canonical.exists() && !paths.contains(&canonical) {
                    paths.push(canonical);
                }
            }
        }
    }
    paths
}

/// Extract lines that belong to a named section (e.g. `data_file_directories:` in YAML,
/// or `[log]` in INI). Very simple parser — works for the databases we support.
fn extract_section(content: &str, section: &str) -> String {
    let mut in_section = false;
    let mut result = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        // YAML/properties: match a key followed by `:` (no leading indent means new top-level key)
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // Top-level key — check if it's the target section
            in_section = trimmed.starts_with(section);
        }
        // INI-style: `[section]`
        if trimmed == format!("[{}]", section) {
            in_section = true;
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_section = false;
        }
        if in_section {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// Main entry point: scan all /proc/<pid> entries and return detected host-native
/// database server processes. Docker/container processes are automatically excluded.
///
/// Detection is entirely driven by the `DbSignature` table from `config.db_signatures()`.
/// No database-specific logic is hardcoded here.
pub fn discover_databases(config: &crate::rules::ConfigManager) -> Vec<DiscoveredDatabase> {
    let signatures = config.db_signatures();
    if signatures.is_empty() {
        tracing::warn!("[DB Discovery] No database signatures loaded — linux_database_signatures.json missing or empty");
        return Vec::new();
    }

    let mut discovered = Vec::new();

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return discovered;
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(pid) = name_str.parse::<u32>() else {
            continue;
        };

        // Skip container processes — handled by a separate container workflow
        if is_container_process(pid) {
            continue;
        }

        // Resolve executable name
        let exe_path = entry.path().join("exe");
        let exe = match std::fs::read_link(&exe_path) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let exe_basename = exe
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        // Match against each signature
        for sig in &signatures {
            // Check executable name matches first (fast path)
            let exe_matches = sig
                .executables
                .iter()
                .any(|e| exe_basename == e.to_lowercase());
            if !exe_matches {
                continue;
            }

            // Run classification: any one method is sufficient
            let matched = method_a_fd_match(pid, sig)
                || method_b_cmdline_match(pid, sig)
                || method_c_binary_match(pid, sig);

            if matched {
                let mut data_dirs = collect_data_dirs(pid);
                let config_paths = collect_config_paths(pid, sig);

                // Parse each found config file and extract data_dir / write_path entries.
                // These are merged with (and deduplicated against) the FD-scan results.
                for cfg_path in &config_paths {
                    for extracted in extract_data_dirs_from_config(cfg_path, sig) {
                        if !data_dirs.contains(&extracted) {
                            data_dirs.push(extracted);
                        }
                    }
                }

                tracing::info!(
                    "[DB Discovery] Detected {} (pid={}) | data_dirs={:?} | config_paths={:?}",
                    sig.db_type,
                    pid,
                    data_dirs,
                    config_paths
                );

                discovered.push(DiscoveredDatabase {
                    db_type: sig.db_type.clone(),
                    pid,
                    config_paths,
                    data_dirs,
                });
                break; // one PID matches at most one DB type
            }
        }
    }

    discovered
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymousMappingInfo {
    pub start: String,
    pub end: String,
    pub size_bytes: u64,
    pub permissions: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaspRichContext {
    pub language: String,
    pub framework_detected: String,
    pub allowed_dirs: Vec<String>,
    pub git_status: String,
    pub main_server_pid: u32,
    pub process_name: String,
    pub proxy_used: bool,
    pub proxy_name: String,
    pub proxy_path: String,
    pub sites: Vec<String>,
    pub stack_trace: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_so: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anonymous_mappings: Option<Vec<AnonymousMappingInfo>>,
    /// The RASP-reported operation that triggered this alert (e.g. "eval",
    /// "file_read", "exec_call") — the client-reported `function` field from
    /// the RASP protocol, not inferred.
    #[serde(default)]
    pub function_name: String,
    /// Best-known file+line context for the incident, extracted from the top
    /// frame of `stack_trace` when it's shaped as a frame list. Empty when
    /// `stack_trace` doesn't carry recognizable frame data.
    #[serde(default)]
    pub source_file: String,
    /// Dependency/vendor path pulled from the first `stack_trace` frame that
    /// looks like third-party code (vendor/, node_modules/, site-packages/).
    /// Empty when no such frame is found.
    #[serde(default)]
    pub affected_lib: String,
    /// Human-readable rendering of `stack_trace` for display without parsing
    /// raw JSON — one "file:line in function()" line per recognizable frame,
    /// or the compact JSON form as a fallback when the shape isn't a frame list.
    #[serde(default)]
    pub rasp_stack: String,
    /// Short summary derived from `git_status` — same tamper-check data,
    /// phrased for the "integrity" display slot the TUI/CLI expect.
    #[serde(default)]
    pub rasp_integrity: String,
    /// Always true today: `RaspRichContext` is only ever populated by the
    /// RASP mechanism, which by definition embeds inside interpreted-language
    /// runtimes (see CLAUDE.md's vandam-php/vandam-node/etc. RASP shims) —
    /// there is no compiled-binary source of this struct.
    #[serde(default)]
    pub is_interpreted: bool,
}

/// Parses `stack_trace` into a list of `(file, line, function)` frames when
/// it's shaped as an array of frame objects (the shape vandam-php's RASP
/// shim sends: `[{"file":..,"line":..,"function":..}, ...]`). Returns an
/// empty Vec for any other shape — callers fall back to the raw JSON.
fn parse_rasp_stack_frames(trace: &serde_json::Value) -> Vec<(String, i64, String)> {
    let Some(frames) = trace.as_array() else {
        return Vec::new();
    };
    frames
        .iter()
        .filter_map(|f| {
            let file = f.get("file").and_then(|v| v.as_str())?;
            let line = f.get("line").and_then(|v| v.as_i64()).unwrap_or(0);
            let function = f
                .get("function")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            Some((file.to_string(), line, function))
        })
        .collect()
}

fn format_rasp_stack(trace: &serde_json::Value) -> String {
    let frames = parse_rasp_stack_frames(trace);
    if frames.is_empty() {
        return trace.to_string();
    }
    frames
        .iter()
        .map(|(file, line, function)| {
            if function.is_empty() {
                format!("{}:{}", file, line)
            } else {
                format!("{}:{} in {}()", file, line, function)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn extract_source_file(trace: &serde_json::Value) -> String {
    parse_rasp_stack_frames(trace)
        .first()
        .map(|(file, line, _)| format!("{}:{}", file, line))
        .unwrap_or_default()
}

const VENDOR_PATH_MARKERS: &[&str] = &["/vendor/", "/node_modules/", "/site-packages/", "/dist-packages/"];

fn extract_affected_lib(trace: &serde_json::Value) -> String {
    parse_rasp_stack_frames(trace)
        .into_iter()
        .find(|(file, _, _)| VENDOR_PATH_MARKERS.iter().any(|m| file.contains(m)))
        .map(|(file, _, _)| file)
        .unwrap_or_default()
}

fn derive_rasp_integrity(git_status: &str) -> String {
    if git_status == "non_git_repository" {
        "unknown (not a git checkout)".to_string()
    } else if git_status.ends_with("(clean)") {
        "verified (git clean)".to_string()
    } else if git_status.ends_with("(modified/untracked)") {
        "tampered (uncommitted changes present)".to_string()
    } else {
        git_status.to_string()
    }
}

pub fn detect_framework_from_registry(root: &Path) -> (String, Vec<String>) {
    let registry = crate::storage_discovery::get_registry();
    let mut detected_framework = "generic".to_string();
    let mut allowed_dirs = vec![
        root.to_string_lossy().to_string(),
        "/tmp".to_string(),
        "/var/tmp".to_string(),
    ];

    let root_path = root.to_path_buf();

    for entry in registry.iter() {
        if entry.key().starts_with(&root_path) || root_path.starts_with(entry.key()) {
            if let Some(fw) = &entry.value().framework_name {
                detected_framework = fw.clone();
            }
            allowed_dirs.push(entry.key().to_string_lossy().to_string());
        }
    }

    allowed_dirs.sort();
    allowed_dirs.dedup();
    (detected_framework, allowed_dirs)
}

pub fn get_git_status(dir: &Path) -> String {
    let git_dir = dir.join(".git");
    if !git_dir.exists() {
        return "non_git_repository".to_string();
    }

    let head_file = git_dir.join("HEAD");
    let branch = if let Ok(head) = std::fs::read_to_string(&head_file) {
        head.trim()
            .trim_start_matches("ref: refs/heads/")
            .to_string()
    } else {
        "unknown".to_string()
    };

    let index_file = git_dir.join("index");
    let is_modified = if let Ok(meta) = std::fs::metadata(&index_file) {
        if let Ok(mtime) = meta.modified() {
            if let Ok(elapsed) = mtime.elapsed() {
                elapsed.as_secs() < 3600
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    let state = if is_modified {
        "modified/untracked"
    } else {
        "clean"
    };
    format!("branch: {} ({})", branch, state)
}

pub fn get_proxy_and_sites_info_for_root(web_root: &Path) -> (bool, String, String, Vec<String>) {
    let mut sites = Vec::new();
    let mut proxy_name = "none".to_string();
    let mut proxy_path = "".to_string();
    let mut proxy_used = false;
    let web_root_str = web_root.to_string_lossy().to_string();

    // Check Nginx
    let nginx_sites_dir = Path::new("/etc/nginx/sites-enabled");
    let nginx_conf_dir = Path::new("/etc/nginx/conf.d");

    let check_dirs = [nginx_sites_dir, nginx_conf_dir];
    for d in &check_dirs {
        if d.exists() {
            if let Ok(entries) = std::fs::read_dir(d) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() || path.is_symlink() {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let matches_root = content.contains(&web_root_str);
                            if matches_root || sites.is_empty() {
                                if matches_root {
                                    proxy_used = true;
                                    proxy_name = "nginx".to_string();
                                    proxy_path = path.to_string_lossy().to_string();
                                }
                                for line in content.lines() {
                                    let line = line.trim();
                                    if line.starts_with("server_name") {
                                        for word in line
                                            .trim_start_matches("server_name")
                                            .trim_end_matches(';')
                                            .split_whitespace()
                                        {
                                            if word != "_"
                                                && !word.starts_with('$')
                                                && !sites.contains(&word.to_string())
                                            {
                                                sites.push(word.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check Apache if Nginx wasn't found
    if !proxy_used {
        let apache_sites_dir = Path::new("/etc/apache2/sites-enabled");
        if apache_sites_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(apache_sites_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() || path.is_symlink() {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            let matches_root = content.contains(&web_root_str);
                            if matches_root || sites.is_empty() {
                                if matches_root {
                                    proxy_used = true;
                                    proxy_name = "apache2".to_string();
                                    proxy_path = path.to_string_lossy().to_string();
                                }
                                for line in content.lines() {
                                    let line = line.trim();
                                    if line.starts_with("ServerName")
                                        || line.starts_with("ServerAlias")
                                    {
                                        for word in line.split_whitespace().skip(1) {
                                            if !sites.contains(&word.to_string()) {
                                                sites.push(word.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    (proxy_used, proxy_name, proxy_path, sites)
}

pub fn get_process_topology(pid: u32) -> (String, u32) {
    let proc_name = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|c| c.trim().to_string())
        .unwrap_or_else(|_| "worker".to_string());

    let stat_content = std::fs::read_to_string(format!("/proc/{}/stat", pid)).unwrap_or_default();
    let ppid = if let Some(close_paren) = stat_content.rfind(')') {
        let rest = &stat_content[close_paren + 1..].trim();
        let fields: Vec<&str> = rest.split_whitespace().collect();
        fields
            .get(1)
            .and_then(|p| p.parse::<u32>().ok())
            .unwrap_or(0)
    } else {
        0
    };

    (proc_name, ppid)
}

pub fn get_memory_mappings_for_pid(
    pid: u32,
    language: &str,
    process_name: &str,
) -> (Option<Vec<String>>, Option<Vec<AnonymousMappingInfo>>) {
    let maps_path = format!("/proc/{}/maps", pid);
    let Ok(content) = std::fs::read_to_string(&maps_path) else {
        return (None, None);
    };

    let mut loaded_so = std::collections::HashSet::new();
    let mut anonymous_mappings = Vec::new();

    let lang_lower = language.to_lowercase();
    let proc_lower = process_name.to_lowercase();
    let is_jit = lang_lower.contains("java")
        || lang_lower.contains("node")
        || lang_lower.contains("dotnet")
        || lang_lower.contains("js")
        || proc_lower.contains("java")
        || proc_lower.contains("node")
        || proc_lower.contains("dotnet")
        || proc_lower.contains("mono");

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }

        let addr_range = parts[0];
        let permissions = parts[1];
        let inode_str = parts[4];
        let pathname = if parts.len() >= 6 { parts[5] } else { "" };

        // 1. Extract loaded shared libraries (.so)
        if !pathname.is_empty() {
            let is_so = pathname.contains(".so") || pathname.ends_with(".so");
            if is_so {
                loaded_so.insert(pathname.to_string());
            }
        }

        // 2. Extract anonymous memory mappings for non-JIT servers
        if !is_jit {
            let inode = inode_str.parse::<u64>().unwrap_or(0);
            let is_anon = inode == 0 || pathname.is_empty() || pathname.starts_with('[');

            if is_anon {
                let range_parts: Vec<&str> = addr_range.split('-').collect();
                if range_parts.len() == 2 {
                    let start_val = u64::from_str_radix(range_parts[0], 16).unwrap_or(0);
                    let end_val = u64::from_str_radix(range_parts[1], 16).unwrap_or(0);
                    let size_bytes = if end_val >= start_val {
                        end_val - start_val
                    } else {
                        0
                    };

                    if size_bytes > 0 {
                        let name = if pathname.is_empty() {
                            "[anonymous]".to_string()
                        } else {
                            pathname.to_string()
                        };

                        anonymous_mappings.push(AnonymousMappingInfo {
                            start: range_parts[0].to_string(),
                            end: range_parts[1].to_string(),
                            size_bytes,
                            permissions: permissions.to_string(),
                            name,
                        });
                    }
                }
            }
        }
    }

    let loaded_so_list: Vec<String> = loaded_so.into_iter().collect();

    (
        if !loaded_so_list.is_empty() {
            Some(loaded_so_list)
        } else {
            None
        },
        if !anonymous_mappings.is_empty() {
            Some(anonymous_mappings)
        } else {
            None
        },
    )
}

pub fn build_rich_rasp_context(
    pid: u32,
    function_name: &str,
    language_hint: &str,
    web_root_hint: &str,
    stack_trace: serde_json::Value,
) -> RaspRichContext {
    let web_root = if !web_root_hint.is_empty() {
        PathBuf::from(web_root_hint)
    } else {
        PathBuf::from("/var/www/html")
    };

    let (framework_detected, allowed_dirs) = detect_framework_from_registry(&web_root);
    let git_status = get_git_status(&web_root);
    let (proxy_used, proxy_name, proxy_path, sites) = get_proxy_and_sites_info_for_root(&web_root);
    let (process_name, main_server_pid) = get_process_topology(pid);

    let (loaded_so, anonymous_mappings) =
        get_memory_mappings_for_pid(pid, language_hint, &process_name);

    let rasp_stack = format_rasp_stack(&stack_trace);
    let source_file = extract_source_file(&stack_trace);
    let affected_lib = extract_affected_lib(&stack_trace);
    let rasp_integrity = derive_rasp_integrity(&git_status);

    RaspRichContext {
        language: if !language_hint.is_empty() {
            language_hint.to_string()
        } else {
            "unknown".to_string()
        },
        framework_detected,
        allowed_dirs,
        git_status,
        main_server_pid,
        process_name,
        proxy_used,
        proxy_name,
        proxy_path,
        sites,
        stack_trace,
        loaded_so,
        anonymous_mappings,
        function_name: function_name.to_string(),
        source_file,
        affected_lib,
        rasp_stack,
        rasp_integrity,
        is_interpreted: true,
    }
}

pub fn detect_systemd_service_for_pid(pid: u32) -> Option<String> {
    // 1. Read cgroup for systemd service slice
    let cgroup_path = format!("/proc/{}/cgroup", pid);
    if let Ok(content) = std::fs::read_to_string(&cgroup_path) {
        for line in content.lines() {
            if line.contains("/system.slice/") {
                if let Some(pos) = line.find("/system.slice/") {
                    let slice_part = &line[pos + "/system.slice/".len()..];
                    let parts: Vec<&str> = slice_part.split('/').collect();
                    for part in parts.iter().rev() {
                        if part.ends_with(".service") {
                            return Some(part.to_string());
                        }
                    }
                    if let Some(first) = parts.first() {
                        if !first.is_empty() {
                            return Some(first.to_string());
                        }
                    }
                }
            } else if line.contains("/user.slice/") {
                if let Some(pos) = line.find("/user.slice/") {
                    let user_part = &line[pos + "/user.slice/".len()..];
                    let parts: Vec<&str> = user_part.split('/').collect();
                    for part in parts.iter().rev() {
                        if part.ends_with(".scope") || part.ends_with(".service") {
                            return Some(part.to_string());
                        }
                    }
                }
            } else if line.contains(".service") {
                for part in line.split('/') {
                    if part.ends_with(".service") {
                        return Some(part.to_string());
                    }
                }
            }
        }
    }

    // 1b. PID-File lookup fallback (distro-agnostic)
    if let Some(service) = detect_service_by_pid_file(pid) {
        return Some(service);
    }

    // 2. Check parent/comm ancestry check for process managers (e.g. pm2, god, supervisor)
    let mut current_pid = pid;
    for _ in 0..5 {
        if current_pid <= 1 {
            break;
        }
        let stat_path = format!("/proc/{}/stat", current_pid);
        if let Ok(stat) = std::fs::read_to_string(&stat_path) {
            if let Some(close_paren) = stat.rfind(')') {
                let comm_start = stat.find('(').unwrap_or(0);
                let comm = &stat[comm_start + 1..close_paren];
                let comm_lower = comm.to_lowercase();

                if comm_lower.contains("pm2")
                    || comm_lower.contains("god")
                    || comm_lower.contains("supervisord")
                    || comm_lower.contains("cron")
                {
                    return Some(format!("managed-by:{}", comm));
                }

                let rest = &stat[close_paren + 1..].trim();
                let fields: Vec<&str> = rest.split_whitespace().collect();
                if let Some(ppid_str) = fields.get(1) {
                    if let Ok(ppid) = ppid_str.parse::<u32>() {
                        current_pid = ppid;
                        continue;
                    }
                }
            }
        }
        break;
    }

    None
}

pub fn detect_service_by_pid_file(target_pid: u32) -> Option<String> {
    let search_dirs = [Path::new("/run"), Path::new("/var/run")];
    for &dir in &search_dirs {
        if !dir.exists() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if path.extension().map_or(false, |ext| ext == "pid") {
                        if let Ok(content) = std::fs::read_to_string(&path) {
                            if let Ok(pid_val) = content.trim().parse::<u32>() {
                                if pid_val == target_pid {
                                    return path
                                        .file_stem()
                                        .map(|s| s.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                } else if path.is_dir() {
                    // Check one level deep inside subdirectory
                    if let Ok(sub_entries) = std::fs::read_dir(&path) {
                        for sub_entry in sub_entries.flatten() {
                            let sub_path = sub_entry.path();
                            if sub_path.is_file()
                                && sub_path.extension().map_or(false, |ext| ext == "pid")
                            {
                                if let Ok(content) = std::fs::read_to_string(&sub_path) {
                                    if let Ok(pid_val) = content.trim().parse::<u32>() {
                                        if pid_val == target_pid {
                                            // Prefer the folder name (e.g. apache2, postgresql)
                                            if let Some(folder_name) = path.file_name() {
                                                return Some(
                                                    folder_name.to_string_lossy().to_string(),
                                                );
                                            }
                                            return sub_path
                                                .file_stem()
                                                .map(|s| s.to_string_lossy().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

pub fn get_process_ports_with_probing(pid: u32) -> Vec<String> {
    use std::collections::HashMap;
    let mut inode_to_port: HashMap<u64, u16> = HashMap::new();

    let files = ["/proc/net/tcp", "/proc/net/tcp6"];
    for file_path in &files {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 9 {
                    let local_addr = parts[1];
                    let state = parts[3];
                    let inode = parts[9];
                    if state == "0A" {
                        // TCP_LISTEN
                        if let Ok(inode_val) = inode.parse::<u64>() {
                            if inode_val > 0 {
                                if let Some(port_hex) = local_addr.split(':').nth(1) {
                                    if let Ok(port) = u16::from_str_radix(port_hex, 16) {
                                        inode_to_port.insert(inode_val, port);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut ports = Vec::new();
    let fd_path = format!("/proc/{}/fd", pid);
    if let Ok(fd_dir) = std::fs::read_dir(fd_path) {
        for fd_entry in fd_dir.flatten() {
            if let Ok(link) = std::fs::read_link(fd_entry.path()) {
                let link_str = link.to_string_lossy();
                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                    let inode_str = &link_str[8..link_str.len() - 1];
                    if let Ok(inode_val) = inode_str.parse::<u64>() {
                        if let Some(&port) = inode_to_port.get(&inode_val) {
                            if !ports.contains(&port) {
                                ports.push(port);
                            }
                        }
                    }
                }
            }
        }
    }

    let mut result = Vec::new();
    for port in ports {
        let proto = probe_listening_port(port);
        result.push(format!("{}:{}", port, proto));
    }
    result
}

pub fn is_proxy_process(pid: u32, comm: &str, exe: &str) -> bool {
    // 1. Check dynamically registered signature name for PID first
    if let Some(sig_name) = crate::generic_discovery::get_signature_for_pid(pid) {
        if is_proxy_service(&sig_name) {
            return true;
        }
    }

    static PROXY_EXECUTABLES: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    let proxy_execs = PROXY_EXECUTABLES.get_or_init(|| {
        let mut set = std::collections::HashSet::new();
        // Core fallbacks in case configuration file load fails
        for fallback in &[
            "nginx",
            "apache2",
            "httpd",
            "caddy",
            "haproxy",
            "traefik",
            "envoy",
            "varnishd",
            "squid",
            "kong",
            "openresty",
            "linkerd2-proxy",
        ] {
            set.insert(fallback.to_string());
        }
        // Load dynamically from global web signatures registry
        let sigs = crate::generic_discovery::load_generic_signatures("linux_web_signatures.json");
        for sig in sigs {
            // zero-execution indicates proxies, load balancers, and pure web routing engines
            if sig.assigned_profile == "zero-execution" || sig.service_type == "varnishd" {
                for exec in sig.executables {
                    set.insert(exec.to_string());
                }
            }
        }
        set
    });

    let comm_lower = comm.to_lowercase();
    let exe_path = std::path::Path::new(exe);
    let exe_name = exe_path
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    proxy_execs.contains(&comm_lower) || proxy_execs.contains(&exe_name)
}

pub fn is_proxy_service(sig_name: &str) -> bool {
    static PROXY_SERVICES: std::sync::OnceLock<std::collections::HashSet<String>> =
        std::sync::OnceLock::new();
    let services = PROXY_SERVICES.get_or_init(|| {
        let mut set = std::collections::HashSet::new();
        for fallback in &[
            "nginx",
            "apache2",
            "httpd",
            "caddy",
            "haproxy",
            "traefik",
            "envoy",
            "varnishd",
            "squid",
            "kong",
            "openresty",
            "linkerd2-proxy",
        ] {
            set.insert(fallback.to_string());
        }
        let sigs = crate::generic_discovery::load_generic_signatures("linux_web_signatures.json");
        for sig in sigs {
            if sig.assigned_profile == "zero-execution" || sig.service_type == "varnishd" {
                set.insert(sig.service_type.clone());
            }
        }
        set
    });
    services.contains(sig_name)
}
