use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, Duration};
use dashmap::DashMap;
use tokio::net::UnixListener;
use tokio::io::AsyncReadExt;
use chrono::Utc;
use regex::Regex;

#[derive(Clone, Debug)]
pub struct TlsRecord {
    pub arrival_time: Instant,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub container_id: String,
    pub direction: u8,
    pub tls_layer: u8,
    pub payload: Vec<u8>,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
struct VandamTlsHeader {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub container_id: [u8; 12],
    pub direction: u8,
    pub tls_layer: u8,
    pub payload_len: u16,
}

struct ProcessBuffer {
    records: VecDeque<TlsRecord>,
    total_bytes: usize,
}

struct TlsBufferConfig {
    pub capacity_bytes: usize,
    pub global_capacity_bytes: usize,
    pub exclude_paths: Vec<Regex>,
}

static CONFIG: OnceLock<TlsBufferConfig> = OnceLock::new();
static TLS_BUFFERS: OnceLock<DashMap<u32, Mutex<ProcessBuffer>>> = OnceLock::new();

fn get_buffers() -> &'static DashMap<u32, Mutex<ProcessBuffer>> {
    TLS_BUFFERS.get_or_init(DashMap::new)
}

fn get_total_system_ram_kb() -> usize {
    if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<usize>() {
                        return kb;
                    }
                }
            }
        }
    }
    1024 * 1024 // Fallback to 1GB if we fail to read/parse
}

static RECENT_PAYLOAD_HASHES: OnceLock<Mutex<VecDeque<u64>>> = OnceLock::new();
static HASH_SET: OnceLock<Mutex<HashSet<u64>>> = OnceLock::new();

use std::collections::HashSet;

fn is_duplicate_payload(payload: &[u8]) -> bool {
    if payload.is_empty() {
        return false;
    }
    let limit = std::cmp::min(payload.len(), 64);
    let slice = &payload[..limit];
    
    // Simple FNV-1a hash
    let mut hash = 0xcbf29ce484222325u64;
    for &byte in slice {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3u64);
    }

    let queue_lock = RECENT_PAYLOAD_HASHES.get_or_init(|| Mutex::new(VecDeque::new()));
    let set_lock = HASH_SET.get_or_init(|| Mutex::new(HashSet::new()));

    if let Ok(mut set) = set_lock.lock() {
        if set.contains(&hash) {
            return true;
        }
        
        if let Ok(mut queue) = queue_lock.lock() {
            queue.push_back(hash);
            set.insert(hash);
            
            if queue.len() > 1000 {
                if let Some(old_hash) = queue.pop_front() {
                    set.remove(&old_hash);
                }
            }
        }
    }
    false
}

fn get_config() -> &'static TlsBufferConfig {
    CONFIG.get_or_init(|| {
        let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
        
        let ram_kb = get_total_system_ram_kb();
        let total_ram_bytes = ram_kb * 1024;
        
        // Dynamic Global Cap: 3% of total RAM
        let mut global_capacity_bytes = total_ram_bytes * 3 / 100;
        
        // Dynamic Per-Process Cap:
        let mut capacity_bytes = if total_ram_bytes < 2 * 1024 * 1024 * 1024 {
            8 * 1024 * 1024       // Micro (<2GB): 8MB
        } else if total_ram_bytes < 8 * 1024 * 1024 * 1024 {
            16 * 1024 * 1024      // Standard (<8GB): 16MB
        } else if total_ram_bytes < 32 * 1024 * 1024 * 1024 {
            32 * 1024 * 1024      // Large (<32GB): 32MB
        } else if total_ram_bytes < 96 * 1024 * 1024 * 1024 {
            64 * 1024 * 1024      // High (<96GB): 64MB
        } else {
            128 * 1024 * 1024     // Enterprise (>=96GB): 128MB
        };

        let mut exclude_paths = Vec::new();

        for line in conf.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() { continue; }
            if let Some(pos) = line.find('=') {
                let key = line[..pos].trim();
                let val = line[pos+1..].trim();
                match key {
                    "tls_buffer.capacity_mb" => {
                        if let Ok(mb) = val.parse::<usize>() {
                            capacity_bytes = mb * 1024 * 1024;
                        }
                    }
                    "tls_buffer.global_capacity_mb" => {
                        if let Ok(mb) = val.parse::<usize>() {
                            // Cap global capacity at 5% of host RAM
                            let max_safe_global = total_ram_bytes * 5 / 100;
                            global_capacity_bytes = std::cmp::min(mb * 1024 * 1024, max_safe_global);
                        }
                    }

                    "tls_buffer.exclude_paths" => {
                        exclude_paths = val.split(',')
                            .map(|s| s.trim())
                            .filter(|s| !s.is_empty())
                            .filter_map(|s| Regex::new(s).ok())
                            .collect();
                    }
                    _ => {}
                }
            }
        }

        TlsBufferConfig {
            capacity_bytes,
            global_capacity_bytes,
            exclude_paths,
        }
    })
}

static IS_PAID_TIER: OnceLock<bool> = OnceLock::new();

pub fn is_paid_tier() -> bool {
    if let Some(&val) = IS_PAID_TIER.get() {
        return val;
    }
    match std::fs::read_to_string("/etc/kinnector/core.conf") {
        Ok(conf) => {
            *IS_PAID_TIER.get_or_init(|| {
                conf.lines()
                    .find(|l| l.starts_with("license_key="))
                    .map(|l| l.trim_start_matches("license_key=").trim())
                    .map(|val| !val.is_empty() && val != "free")
                    .unwrap_or(false)
            })
        }
        Err(_) => false,
    }
}

/// Plan level, coarser-grained than `is_paid_tier()`'s bool. Read from an
/// optional `plan=` line in the same `core.conf` license file; falls back to
/// `Pro`/`Free` from `is_paid_tier()` when unset, so existing installs with
/// only `license_key=` configured keep working exactly as before — `plan=`
/// is additive, not a replacement for the license-key check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseTier {
    Free,
    Pro,
    Max,
}

static LICENSE_TIER: OnceLock<LicenseTier> = OnceLock::new();

pub fn license_tier() -> LicenseTier {
    if let Some(&val) = LICENSE_TIER.get() {
        return val;
    }
    let conf = std::fs::read_to_string("/etc/kinnector/core.conf").unwrap_or_default();
    let explicit = conf
        .lines()
        .find(|l| l.starts_with("plan="))
        .map(|l| l.trim_start_matches("plan=").trim().to_lowercase())
        .and_then(|v| match v.as_str() {
            "max" => Some(LicenseTier::Max),
            "pro" => Some(LicenseTier::Pro),
            "free" => Some(LicenseTier::Free),
            _ => None,
        });
    let tier = explicit.unwrap_or(if is_paid_tier() { LicenseTier::Pro } else { LicenseTier::Free });
    *LICENSE_TIER.get_or_init(|| tier)
}

pub fn get_tls_forensics_status() -> serde_json::Value {
    let is_paid = is_paid_tier();
    serde_json::json!({
        "supported_layers": [1, 2, 3],
        "active_layers": if is_paid { vec![1, 2, 3] } else { vec![] },
        "layer_status": {
            "layer_1_uprobe": if is_paid { "active" } else { "disabled_free_tier" },
            "layer_2_jvmti": if is_paid { "active" } else { "disabled_free_tier" },
            "layer_3_ktls": if is_paid { "active" } else { "disabled_free_tier" }
        },
        "overhead_warnings": {}
    })
}

fn should_exclude_payload(payload: &[u8]) -> bool {
    let config = get_config();
    if config.exclude_paths.is_empty() {
        return false;
    }
    let text = String::from_utf8_lossy(payload);
    for re in &config.exclude_paths {
        if re.is_match(&text) {
            return true;
        }
    }
    false
}

fn try_truncate_http2(payload: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0;
    
    // Check for HTTP/2 connection preface
    let has_preface = payload.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    if has_preface {
        offset += 24; // Skip the preface
    } else {
        // Validation: verify if the first 9 bytes look like a valid HTTP/2 frame header.
        if payload.len() >= 9 {
            let frame_type = payload[3];
            let length = ((payload[0] as usize) << 16) | ((payload[1] as usize) << 8) | (payload[2] as usize);
            if frame_type > 0x09 || length + 9 > payload.len() {
                return None;
            }
        } else {
            return None;
        }
    }

    let mut truncated = Vec::with_capacity(payload.len());
    if has_preface {
        truncated.extend_from_slice(&payload[..24]);
    }

    let mut total_data_bytes = 0;
    let limit = 8192; // 8 KB limit
    let mut was_truncated = false;

    while offset + 9 <= payload.len() {
        let length = ((payload[offset] as usize) << 16) | ((payload[offset + 1] as usize) << 8) | (payload[offset + 2] as usize);
        let frame_type = payload[offset + 3];
        
        if offset + 9 + length > payload.len() {
            // Partial frame, keep it as is
            truncated.extend_from_slice(&payload[offset..]);
            break;
        }

        let frame_header = &payload[offset..offset + 9];
        let frame_payload = &payload[offset + 9..offset + 9 + length];

        if frame_type == 0x00 { // DATA frame
            total_data_bytes += length;
            if total_data_bytes > limit {
                let remaining_allowed = limit.saturating_sub(total_data_bytes - length);
                
                // Write modified frame header with the truncated length
                let mut new_header = frame_header.to_vec();
                new_header[0] = ((remaining_allowed >> 16) & 0xff) as u8;
                new_header[1] = ((remaining_allowed >> 8) & 0xff) as u8;
                new_header[2] = (remaining_allowed & 0xff) as u8;
                
                truncated.extend_from_slice(&new_header);
                if remaining_allowed > 0 {
                    truncated.extend_from_slice(&frame_payload[..remaining_allowed]);
                }
                was_truncated = true;
            } else {
                truncated.extend_from_slice(frame_header);
                truncated.extend_from_slice(frame_payload);
            }
        } else {
            // Keep HEADERS, SETTINGS, etc. in full
            truncated.extend_from_slice(frame_header);
            truncated.extend_from_slice(frame_payload);
        }

        offset += 9 + length;
    }

    if was_truncated {
        Some(truncated)
    } else {
        Some(payload.to_vec())
    }
}

fn process_and_truncate_payload(payload: &[u8]) -> Vec<u8> {
    if let Some(truncated_h2) = try_truncate_http2(payload) {
        return truncated_h2;
    }

    if payload.starts_with(b"POST ") || payload.starts_with(b"PUT ") {
        let text = String::from_utf8_lossy(payload);
        if text.contains("Content-Type: multipart/form-data") || text.contains("content-type: multipart/form-data") {
            if let Some(boundary_idx) = text.find("\r\n\r\n") {
                let header_part = &payload[..boundary_idx + 4];
                let body_part = &payload[boundary_idx + 4..];
                
                // Truncate the file upload body to the first 8 KB
                let limit = std::cmp::min(body_part.len(), 8192);
                let mut truncated = Vec::with_capacity(header_part.len() + limit + 60);
                truncated.extend_from_slice(header_part);
                truncated.extend_from_slice(&body_part[..limit]);
                if body_part.len() > limit {
                    truncated.extend_from_slice(b"\r\n... [BODY TRUNCATED BY VANDAM FILE-UPLOAD GUARD] ...\r\n");
                }
                return truncated;
            }
        }
    }
    payload.to_vec()
}

pub fn add_record(mut record: TlsRecord) {
    if crate::allowlist::get_disabled_tls_pids().contains(&record.pid) {
        return;
    }
    // Vandam self-telemetry protection
    if record.pid == std::process::id() {
        return;
    }
    // Proxy/Tunnel Payload Deduplication
    if is_duplicate_payload(&record.payload) {
        return;
    }
    if should_exclude_payload(&record.payload) {
        return;
    }

    // File Upload Body Truncation
    record.payload = process_and_truncate_payload(&record.payload);

    let pid = record.pid;
    let record_len = record.payload.len();
    let buffers = get_buffers();
    let config = get_config();
    let max_proc = config.capacity_bytes;
    let max_global = config.global_capacity_bytes;
    
    // Check global size first to prevent memory exhaustion
    let mut global_bytes = 0;
    for entry in buffers.iter() {
        if let Ok(buf) = entry.value().lock() {
            global_bytes += buf.total_bytes;
        }
    }
    
    // If global limit reached, evict oldest records across all buffers
    if global_bytes + record_len > max_global {
        let mut largest_pid = None;
        let mut largest_bytes = 0;
        for entry in buffers.iter() {
            if let Ok(buf) = entry.value().lock() {
                if buf.total_bytes > largest_bytes {
                    largest_bytes = buf.total_bytes;
                    largest_pid = Some(*entry.key());
                }
            }
        }
        if let Some(l_pid) = largest_pid {
            if let Some(entry) = buffers.get(&l_pid) {
                if let Ok(mut buf) = entry.value().lock() {
                    if let Some(old) = buf.records.pop_front() {
                        buf.total_bytes -= old.payload.len();
                    }
                }
            }
        }
    }

    let entry = buffers.entry(pid).or_insert_with(|| {
        Mutex::new(ProcessBuffer {
            records: VecDeque::new(),
            total_bytes: 0,
        })
    });

    if let Ok(mut buf) = entry.value().lock() {
        // Evict oldest from this PID until space is available
        while buf.total_bytes + record_len > max_proc && !buf.records.is_empty() {
            if let Some(old) = buf.records.pop_front() {
                buf.total_bytes -= old.payload.len();
            }
        }
        
        buf.total_bytes += record_len;
        buf.records.push_back(record);
    }
    drop(entry);
}

pub fn start_tls_telemetry_server() {
    tokio::spawn(async move {
        let socket_path = "/var/run/kinnector/tls_telemetry.sock";
        let _ = std::fs::remove_file(socket_path);
        
        if let Some(parent) = std::path::Path::new(socket_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let listener = match UnixListener::bind(socket_path) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[Vandam TLS] Failed to bind UDS socket {}: {}", socket_path, e);
                return;
            }
        };

        let _ = std::process::Command::new("chmod")
            .args(["0666", socket_path])
            .output();

        println!("[Vandam TLS] Listening for TLS plaintext telemetry on: {}", socket_path);

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let header_size = std::mem::size_of::<VandamTlsHeader>();
                        let mut header_buf = vec![0u8; header_size];

                        loop {
                            if stream.read_exact(&mut header_buf).await.is_err() {
                                break;
                            }

                            let header: VandamTlsHeader = unsafe {
                                std::ptr::read(header_buf.as_ptr() as *const VandamTlsHeader)
                            };

                            let payload_len = header.payload_len as usize;
                            if payload_len > 16384 { // cap at 16 KB as per spec
                                break;
                            }

                            let mut payload = vec![0u8; payload_len];
                            if stream.read_exact(&mut payload).await.is_err() {
                                break;
                            }

                            let container_id = String::from_utf8_lossy(&header.container_id)
                                .trim_end_matches('\0')
                                .to_string();

                            let record = TlsRecord {
                                arrival_time: Instant::now(),
                                timestamp_ns: header.timestamp_ns,
                                pid: header.pid,
                                tid: header.tid,
                                container_id,
                                direction: header.direction,
                                tls_layer: header.tls_layer,
                                payload,
                            };

                            add_record(record);
                        }
                    });
                }
                Err(_) => {}
            }
        }
    });
}

pub fn flush_on_alert(pid: u32, alert_id: &str) {
    if !is_paid_tier() {
        println!("[Vandam TLS] Free tier active: forensic ring buffer captured locally in memory but not flushed (requires paid tier license).");
        return;
    }

    let alert_id_owned = alert_id.to_string();
    let buffers = get_buffers();
    tokio::spawn(async move {
        let alert_time = Instant::now();
        println!("[Vandam TLS] Alert triggered for PID {}. Preparing forensic flush (alert: {})...", pid, alert_id_owned);

        // Wait 30 seconds for the post-event window to accumulate (as per Section 7.D)
        tokio::time::sleep(Duration::from_secs(30)).await;

        let mut collected = Vec::new();

        if let Some(entry) = buffers.get(&pid) {
            if let Ok(buf) = entry.value().lock() {
                for rec in &buf.records {
                    let time_diff = if rec.arrival_time < alert_time {
                        alert_time.duration_since(rec.arrival_time)
                    } else {
                        rec.arrival_time.duration_since(alert_time)
                    };

                    if rec.arrival_time < alert_time && time_diff <= Duration::from_secs(60) {
                        collected.push(rec.clone());
                    } else if rec.arrival_time >= alert_time && time_diff <= Duration::from_secs(30) {
                        collected.push(rec.clone());
                    }
                }
            }
        }

        if collected.is_empty() {
            println!("[Vandam TLS] Forensic flush completed: no TLS records found in time window for PID {}.", pid);
            return;
        }

        let mut json_records = Vec::new();
        
        for rec in &collected {
            let payload_str = String::from_utf8_lossy(&rec.payload).to_string();

            json_records.push(serde_json::json!({
                "timestamp_ns": rec.timestamp_ns,
                "pid": rec.pid,
                "tid": rec.tid,
                "container_id": rec.container_id,
                "direction": if rec.direction == 0 { "INBOUND" } else { "OUTBOUND" },
                "tls_layer": match rec.tls_layer {
                    1 => "uprobe",
                    2 => "jvmti",
                    3 => "ktls",
                    _ => "unknown"
                },
                "payload": payload_str,
            }));
        }

        let output_data = serde_json::json!({
            "alert_id": alert_id_owned,
            "flushed_at": Utc::now().to_rfc3339(),
            "pid": pid,
            "record_count": json_records.len(),
            "records": json_records
        });

        let json_str = serde_json::to_string(&output_data).unwrap_or_default();
        
        // Compress using zstd
        let compressed = match zstd::stream::encode_all(json_str.as_bytes(), 0) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[Vandam TLS] Failed to compress forensic payload: {}", e);
                return;
            }
        };

        let output_path = format!("/var/log/kinnector/forensic_{}.json.zst", alert_id_owned);
        let _ = std::fs::create_dir_all("/var/log/kinnector");
        if let Ok(mut file) = std::fs::File::create(&output_path) {
            use std::io::Write;
            let _ = file.write_all(&compressed);
            println!("[Vandam TLS] Forensic flush completed successfully. Saved {} compressed records to {}", collected.len(), output_path);
        }

        // Upload forensic payload to backend over cloud TLS/gRPC channel
        crate::cloud::send_forensic_payload(&alert_id_owned, compressed).await;
    });
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ram_detection() {
        let ram = get_total_system_ram_kb();
        assert!(ram > 0);
    }

    #[test]
    fn test_payload_deduplication() {
        let p1 = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let p2 = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let p3 = b"POST /api/upload HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        assert!(!is_duplicate_payload(p1));
        assert!(is_duplicate_payload(p2)); // duplicate
        assert!(!is_duplicate_payload(p3)); // unique
    }

    #[test]
    fn test_http1_upload_truncation() {
        // Small multipart upload
        let mut small_post = b"POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=boundary\r\n\r\n".to_vec();
        small_post.extend_from_slice(b"--boundary\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nsmall body");
        
        let processed_small = process_and_truncate_payload(&small_post);
        assert_eq!(processed_small, small_post);

        // Large multipart upload (exceeding 8KB)
        let header = b"POST /upload HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=boundary\r\n\r\n";
        let large_body = vec![b'A'; 10000]; // 10 KB
        let mut large_post = header.to_vec();
        large_post.extend_from_slice(&large_body);

        let processed_large = process_and_truncate_payload(&large_post);
        assert!(processed_large.len() < large_post.len());
        assert!(String::from_utf8_lossy(&processed_large).contains("BODY TRUNCATED"));
        assert!(processed_large.starts_with(header));
    }

    #[test]
    fn test_http2_truncation() {
        let mut payload = Vec::new();
        // Preface
        payload.extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        
        // HEADERS frame (Type 1, length 10)
        payload.extend_from_slice(&[0x00, 0x00, 0x0a]);
        payload.extend_from_slice(&[0x01, 0x04, 0x00, 0x00, 0x00, 0x01]);
        payload.extend_from_slice(&[0xaa; 10]);

        // DATA frame 1 (Type 0, length 4000)
        let len_1 = 4000;
        payload.extend_from_slice(&[((len_1 >> 16) & 0xff) as u8, ((len_1 >> 8) & 0xff) as u8, (len_1 & 0xff) as u8]);
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        payload.extend_from_slice(&vec![0xbb; len_1]);

        // DATA frame 2 (Type 0, length 6000) -> total DATA exceeds 8KB
        let len_2 = 6000;
        payload.extend_from_slice(&[((len_2 >> 16) & 0xff) as u8, ((len_2 >> 8) & 0xff) as u8, (len_2 & 0xff) as u8]);
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        payload.extend_from_slice(&vec![0xcc; len_2]);

        let processed = process_and_truncate_payload(&payload);
        
        // HEADERS frame intact
        assert_eq!(&processed[..43], &payload[..43]);

        // Total processed size is truncated
        assert!(processed.len() < payload.len());
        
        // DATA frame 2 header is modified to length 4192 (0x1060)
        let second_frame_offset = 24 + 9 + 10 + 9 + 4000;
        let second_len = ((processed[second_frame_offset] as usize) << 16)
            | ((processed[second_frame_offset + 1] as usize) << 8)
            | (processed[second_frame_offset + 2] as usize);
        assert_eq!(second_len, 4192);
    }
}

