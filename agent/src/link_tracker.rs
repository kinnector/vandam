use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessLinkEvent {
    pub link_id: String,
    pub timestamp: String,
    pub event_type: String, // "CONNECTION_ESTABLISHED" / "CONNECTION_CLOSED"
    pub src_pid: u32,
    pub src_exec_path: String,
    pub src_comm: String,
    pub src_cgroup_id: u64,
    pub src_container_id: Option<String>,
    pub src_container_name: Option<String>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub target_type: String, // "database", "container", "local_process", "remote_server"
    pub target_service: String, // "postgresql", "mysql", "redis", "mongodb", "elasticsearch", "http", "unknown"
    pub dst_pid: Option<u32>,
}

/// Global Process Link Registry
static LINK_REGISTRY: OnceLock<Arc<DashMap<(String, u16, String, u16), ProcessLinkEvent>>> =
    OnceLock::new();

pub fn get_link_registry() -> &'static Arc<DashMap<(String, u16, String, u16), ProcessLinkEvent>> {
    LINK_REGISTRY.get_or_init(|| Arc::new(DashMap::new()))
}

pub fn get_process_network_links(pid: u32) -> Vec<crate::notifications::NetworkLinkMetadata> {
    let registry = get_link_registry();
    let mut links = Vec::new();
    for entry in registry.iter() {
        if entry.value().src_pid == pid || entry.value().dst_pid == Some(pid) {
            let dst_tree = if let Some(dst_pid) = entry.value().dst_pid {
                build_process_tree(dst_pid)
            } else {
                Vec::new()
            };

            links.push(crate::notifications::NetworkLinkMetadata {
                dst_ip: entry.value().dst_ip.clone(),
                dst_port: entry.value().dst_port,
                target_type: entry.value().target_type.clone(),
                target_service: entry.value().target_service.clone(),
                last_connect_time: entry.value().timestamp.clone(),
                dst_process_tree: dst_tree,
            });
        }
    }
    links
}

/// Classify target service by destination port
pub fn classify_target_service(port: u16) -> (String, String) {
    match port {
        5432 => ("database".to_string(), "postgresql".to_string()),
        3306 | 33060 => ("database".to_string(), "mysql".to_string()),
        6379 => ("database".to_string(), "redis".to_string()),
        27017 => ("database".to_string(), "mongodb".to_string()),
        9200 | 9300 => ("database".to_string(), "elasticsearch".to_string()),
        11211 => ("database".to_string(), "memcached".to_string()),
        5672 | 15672 => ("queue".to_string(), "rabbitmq".to_string()),
        9092 => ("queue".to_string(), "kafka".to_string()),
        80 | 443 | 8080 | 8443 => ("http_api".to_string(), "web_service".to_string()),
        _ => ("remote_server".to_string(), "unknown".to_string()),
    }
}

pub const MAX_LINK_CAPACITY: usize = 10_000;

/// Remove links when socket connection closes
pub fn remove_connection(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> bool {
    let registry = get_link_registry();
    let key = (src_ip.to_string(), src_port, dst_ip.to_string(), dst_port);
    registry.remove(&key).is_some()
}

/// Evict all network link records owned by a terminated process PID
pub fn cleanup_dead_process_links(pid: u32) -> usize {
    let registry = get_link_registry();
    let keys_to_remove: Vec<(String, u16, String, u16)> = registry
        .iter()
        .filter(|entry| entry.value().src_pid == pid || entry.value().dst_pid == Some(pid))
        .map(|entry| entry.key().clone())
        .collect();

    let count = keys_to_remove.len();
    for key in keys_to_remove {
        registry.remove(&key);
    }
    count
}

/// Record a process-to-network socket connection
pub fn record_connection(
    src_pid: u32,
    src_ip: String,
    src_port: u16,
    dst_ip: String,
    dst_port: u16,
) -> ProcessLinkEvent {
    let registry = get_link_registry();

    // Capacity Eviction Guard: If capacity limit exceeded, evict oldest entries
    if registry.len() >= MAX_LINK_CAPACITY {
        let keys_to_evict: Vec<(String, u16, String, u16)> = registry
            .iter()
            .take(500)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys_to_evict {
            registry.remove(&key);
        }
    }

    let key = (src_ip.clone(), src_port, dst_ip.clone(), dst_port);

    let (exec_path, comm, cgroup_id) = extract_process_info(src_pid);

    // Vandam self-telemetry protection
    let vandam_pid = std::process::id();
    if src_pid == vandam_pid {
        return ProcessLinkEvent {
            link_id: String::new(),
            timestamp: String::new(),
            event_type: "IGNORED_VANDAM".to_string(),
            src_pid,
            src_exec_path: exec_path,
            src_comm: comm,
            src_cgroup_id: cgroup_id,
            src_container_id: None,
            src_container_name: None,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            target_type: String::new(),
            target_service: String::new(),
            dst_pid: None,
        };
    }

    let dst_pid = find_local_listener_pid(dst_port);

    // Proxy loopback duplication filter
    let is_loopback = src_ip == "127.0.0.1"
        || dst_ip == "127.0.0.1"
        || src_ip == "::1"
        || dst_ip == "::1"
        || src_ip.starts_with('/')
        || dst_ip.starts_with('/')
        || dst_ip == "0.0.0.0";
    if is_loopback {
        let is_src_proxy = crate::discovery::is_proxy_process(src_pid, &comm, &exec_path);

        let is_dst_proxy = if let Some(d_pid) = dst_pid {
            if let Ok(d_comm) = std::fs::read_to_string(format!("/proc/{}/comm", d_pid)) {
                let d_exe = std::fs::read_link(format!("/proc/{}/exe", d_pid))
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                crate::discovery::is_proxy_process(d_pid, &d_comm.trim(), &d_exe)
            } else {
                false
            }
        } else {
            false
        };

        if is_src_proxy || is_dst_proxy {
            return ProcessLinkEvent {
                link_id: String::new(),
                timestamp: String::new(),
                event_type: "IGNORED_PROXY_LOOPBACK".to_string(),
                src_pid,
                src_exec_path: exec_path,
                src_comm: comm,
                src_cgroup_id: cgroup_id,
                src_container_id: None,
                src_container_name: None,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                target_type: String::new(),
                target_service: String::new(),
                dst_pid: None,
            };
        }
    }

    let (target_type, target_service) = classify_target_service(dst_port);
    let container_info = get_container_info(src_pid);

    let event = ProcessLinkEvent {
        link_id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        event_type: "CONNECTION_ESTABLISHED".to_string(),
        src_pid,
        src_exec_path: exec_path,
        src_comm: comm,
        src_cgroup_id: cgroup_id,
        src_container_id: container_info.as_ref().map(|c| c.0.clone()),
        src_container_name: container_info.as_ref().map(|c| c.1.clone()),
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        target_type,
        target_service,
        dst_pid,
    };

    registry.insert(key, event.clone());

    // Stream link event to cloud over gRPC
    crate::cloud::send_alert_immediate(&crate::notifications::AlertPayload {
        alert_id: event.link_id.clone(),
        timestamp: event.timestamp.clone(),
        threat_type: "Telemetry.ProcessLink".to_string(),
        severity: "INFO".to_string(),
        confidence: 1.0,
        container: container_info.map(|c| crate::notifications::ContainerInfo {
            id: c.0,
            name: c.1,
            image: c.2,
            image_id: None,
            status: None,
            attached: false,
        }),
        process: crate::notifications::ProcessInfo {
            pid: src_pid,
            exec_path: event.src_exec_path.clone(),
            cmdline: event.src_comm.clone(),
            parent_exec_path: "".to_string(),
            parent_pid: 0,
            verified_package: None,
            envs: Vec::new(),
            args: Vec::new(),
            signature_name: None,
            service: None,
        },
        remediation: crate::notifications::RemediationInfo {
            action: "LOG_ALERT".to_string(),
            status: format!(
                "Process-to-network link established: {} -> {}:{}",
                event.src_comm, event.dst_ip, event.dst_port
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
    });

    event
}

fn extract_process_info(pid: u32) -> (String, String, u64) {
    let exec_path = std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|c| c.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let cgroup_id = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .map(|cg| cg.lines().next().unwrap_or("").len() as u64)
        .unwrap_or(0);

    (exec_path, comm, cgroup_id)
}

fn find_local_listener_pid(port: u16) -> Option<u32> {
    let target_hex_port = format!("{:04X}", port);
    let mut target_inode = None;

    if let Ok(tcp_content) = std::fs::read_to_string("/proc/net/tcp") {
        for line in tcp_content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() > 9 {
                let local_address = fields[1];
                if local_address.ends_with(&target_hex_port) {
                    let state = fields[3];
                    if state == "0A" {
                        // TCP_LISTEN
                        target_inode = Some(fields[9].to_string());
                        break;
                    }
                }
            }
        }
    }

    let inode = target_inode?;

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(pid_str) = path.file_name().and_then(|f| f.to_str()) {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let fd_dir = path.join("fd");
                    if let Ok(fds) = std::fs::read_dir(fd_dir) {
                        for fd in fds.flatten() {
                            if let Ok(link) = std::fs::read_link(fd.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.contains(&inode) {
                                    return Some(pid);
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

pub fn build_process_tree(pid: u32) -> Vec<crate::notifications::ProcessTreeEntry> {
    let mut tree = Vec::new();
    let mut current_pid = pid;
    while current_pid > 1 {
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", current_pid)) {
            if let Some(close_paren) = stat.rfind(')') {
                let rest = &stat[close_paren + 1..].trim();
                let fields: Vec<&str> = rest.split_whitespace().collect();
                if let Some(ppid_str) = fields.get(1) {
                    if let Ok(ppid) = ppid_str.parse::<u32>() {
                        let exe = std::fs::read_link(format!("/proc/{}/exe", current_pid))
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_else(|_| "unknown".to_string());
                        let comm = std::fs::read_to_string(format!("/proc/{}/comm", current_pid))
                            .map(|c| c.trim().to_string())
                            .unwrap_or_else(|_| "unknown".to_string());
                        let pkg = crate::allowlist::verify_system_package_binary(&exe);
                        let service = crate::discovery::detect_systemd_service_for_pid(current_pid);
                        let ports = crate::discovery::get_process_ports_with_probing(current_pid);
                        tree.push(crate::notifications::ProcessTreeEntry {
                            pid: current_pid,
                            ppid,
                            exec_path: exe,
                            cmdline: comm,
                            verified_package: Some(pkg),
                            service,
                            ports,
                        });
                        current_pid = ppid;
                        continue;
                    }
                }
            }
        }
        break;
    }
    tree
}

fn get_container_info(pid: u32) -> Option<(String, String, String)> {
    let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;
    for line in cgroup.lines() {
        if line.contains("/docker/") {
            let id = line.split("/docker/").nth(1)?.trim();
            let short_id = if id.len() > 12 { &id[..12] } else { id };
            return Some((
                short_id.to_string(),
                format!("docker-{}", short_id),
                "docker_image".to_string(),
            ));
        } else if line.contains("/kubepods") {
            let parts: Vec<&str> = line.split('/').collect();
            if let Some(pod_part) = parts.iter().find(|p| p.starts_with("pod")) {
                return Some((
                    pod_part.to_string(),
                    pod_part.to_string(),
                    "k8s_pod".to_string(),
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_classification() {
        // Test system proxy matching against loaded configs
        assert!(crate::discovery::is_proxy_process(
            0,
            "nginx",
            "/usr/sbin/nginx"
        ));
        assert!(crate::discovery::is_proxy_process(
            0,
            "haproxy",
            "/usr/sbin/haproxy"
        ));
        assert!(crate::discovery::is_proxy_process(
            0,
            "envoy",
            "/usr/local/bin/envoy"
        ));
        assert!(crate::discovery::is_proxy_process(
            0,
            "traefik",
            "/usr/bin/traefik"
        ));
        assert!(crate::discovery::is_proxy_process(
            0,
            "varnishd",
            "/usr/sbin/varnishd"
        ));

        // Test non-proxy binaries
        assert!(!crate::discovery::is_proxy_process(
            0,
            "python3",
            "/usr/bin/python3"
        ));
        assert!(!crate::discovery::is_proxy_process(
            0,
            "node",
            "/usr/bin/node"
        ));
    }

    #[test]
    fn test_vandam_self_telemetry_exclusion() {
        // Record a connection using our own PID
        let event = record_connection(
            std::process::id(),
            "127.0.0.1".to_string(),
            9999,
            "8.8.8.8".to_string(),
            53,
        );
        assert_eq!(event.event_type, "IGNORED_VANDAM");
        assert_eq!(event.link_id, "");
    }
}
