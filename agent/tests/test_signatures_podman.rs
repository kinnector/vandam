use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;
use std::sync::Arc;
use std::collections::HashSet;
use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::time::{sleep, Duration};

struct TestEnvGuard {
    nginx_backup: Option<PathBuf>,
    apache_backup: Option<PathBuf>,
}

impl TestEnvGuard {
    fn setup() -> Self {
        println!("[TestPodman] Setting up config files on the host...");
        
        let nginx_backup = if Path::new("/etc/nginx").exists() {
            let backup = PathBuf::from("/etc/nginx.test_bak");
            let _ = fs::rename("/etc/nginx", &backup);
            Some(backup)
        } else {
            None
        };

        let apache_backup = if Path::new("/etc/apache2").exists() {
            let backup = PathBuf::from("/etc/apache2.test_bak");
            let _ = fs::rename("/etc/apache2", &backup);
            Some(backup)
        } else {
            None
        };

        // Create fresh directories (sites-available and sites-enabled)
        let _ = fs::create_dir_all("/etc/nginx/sites-available");
        let _ = fs::create_dir_all("/etc/nginx/sites-enabled");
        let _ = fs::create_dir_all("/etc/apache2/sites-available");
        let _ = fs::create_dir_all("/etc/apache2/sites-enabled");
        let _ = fs::create_dir_all("/tmp/var/www/site2");

        // Write Nginx site-specific config in sites-available
        let nginx_site_conf = r#"
server {
    listen 8080;
    server_name example.com;
    root /var/www/site1;
    location ~ \.php$ {
        fastcgi_pass 127.0.0.1:9000;
    }
}
"#;
        let _ = fs::write("/etc/nginx/sites-available/site1.conf", nginx_site_conf);

        // Create symlink for Nginx site config (sites-enabled -> sites-available)
        let _ = std::os::unix::fs::symlink(
            "/etc/nginx/sites-available/site1.conf",
            "/etc/nginx/sites-enabled/site1.conf"
        );

        // Write Apache site config in sites-available (with ServerName example.com)
        let apache_site_conf = r#"
<VirtualHost *:8081>
    ServerName example.com
    DocumentRoot "/var/www/site3"
    # proxy:fcgi://127.0.0.1:9000
    ProxyPassMatch ^/(.*\.php)$ fcgi://127.0.0.1:9000/var/www/site3/$1
</VirtualHost>
"#;
        let _ = fs::write("/etc/apache2/sites-available/site3.conf", apache_site_conf);

        // Create symlink for Apache site config (sites-enabled -> sites-available)
        let _ = std::os::unix::fs::symlink(
            "/etc/apache2/sites-available/site3.conf",
            "/etc/apache2/sites-enabled/site3.conf"
        );

        // Write Python app
        let python_app = r#"
def app(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b"Hello from Gunicorn"]
"#;
        let _ = fs::write("/tmp/var/www/site2/app.py", python_app);

        Self {
            nginx_backup,
            apache_backup,
        }
    }
}

impl Drop for TestEnvGuard {
    fn drop(&mut self) {
        println!("[TestPodman] Cleaning up and restoring backups...");
        
        // Remove test directories
        let _ = fs::remove_dir_all("/etc/nginx");
        let _ = fs::remove_dir_all("/etc/apache2");
        let _ = fs::remove_dir_all("/tmp/var/www/site2");

        // Restore backups
        if let Some(ref backup) = self.nginx_backup {
            let _ = fs::rename(backup, "/etc/nginx");
        }
        if let Some(ref backup) = self.apache_backup {
            let _ = fs::rename(backup, "/etc/apache2");
        }

        // Force stop and remove podman containers
        let _ = Command::new("podman")
            .args(["rm", "-f", "test-php-fpm", "test-nginx", "test-apache", "test-python"])
            .output();

        // Clean up socket file
        let _ = fs::remove_file("/var/run/kinnector/vandam.sock");
    }
}

async fn is_port_open(port: u16) -> bool {
    tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await.is_ok()
}

#[tokio::test]
async fn test_web_signatures_discovery_via_podman() {
    // 1. Skip test if not running as root
    if unsafe { libc::getuid() } != 0 {
        println!("Skipping podman test because it is not running as root/sudo.");
        return;
    }

    // 2. Setup the test environment
    let _guard = TestEnvGuard::setup();

    // 3. Start Podman containers running in the host namespaces
    println!("[TestPodman] Launching PHP-FPM container...");
    let phpfpm_status = Command::new("podman")
        .args([
            "run", "-d", "--name", "test-php-fpm",
            "--net=host", "--pid=host",
            "docker.io/library/alpine:latest",
            "sh", "-c", "apk add --no-cache php83-fpm && mkdir -p /run/php && php-fpm83 -F"
        ])
        .status()
        .expect("Failed to execute podman run php-fpm");
    assert!(phpfpm_status.success());

    println!("[TestPodman] Launching Nginx container...");
    let nginx_status = Command::new("podman")
        .args([
            "run", "-d", "--name", "test-nginx",
            "--net=host", "--pid=host",
            "-v", "/etc/nginx/sites-enabled:/etc/nginx/sites-enabled:ro",
            "-v", "/etc/nginx/sites-available:/etc/nginx/sites-available:ro",
            "docker.io/library/alpine:latest",
            "sh", "-c", "apk add --no-cache nginx && rm -f /etc/nginx/http.d/default.conf && sed -i '/http {/a \\ \\ \\ \\ include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf && nginx -g 'daemon off;'"
        ])
        .status()
        .expect("Failed to execute podman run nginx");
    assert!(nginx_status.success());

    println!("[TestPodman] Launching Apache container...");
    let apache_status = Command::new("podman")
        .args([
            "run", "-d", "--name", "test-apache",
            "--net=host", "--pid=host",
            "-v", "/etc/apache2/sites-enabled:/etc/apache2/sites-enabled:ro",
            "-v", "/etc/apache2/sites-available:/etc/apache2/sites-available:ro",
            "docker.io/library/alpine:latest",
            "sh", "-c", "apk add --no-cache apache2 apache2-proxy && sed -i 's/Listen 80/Listen 8081/g' /etc/apache2/httpd.conf && echo 'IncludeOptional /etc/apache2/sites-enabled/*.conf' >> /etc/apache2/httpd.conf && httpd -D FOREGROUND"
        ])
        .status()
        .expect("Failed to execute podman run apache");
    assert!(apache_status.success());

    println!("[TestPodman] Launching Python Gunicorn container...");
    let python_status = Command::new("podman")
        .args([
            "run", "-d", "--name", "test-python",
            "--net=host", "--pid=host",
            "-v", "/tmp/var/www/site2:/var/www/site2:ro",
            "docker.io/library/alpine:latest",
            "sh", "-c", "apk add --no-cache python3 py3-gunicorn && cd /var/www/site2 && gunicorn --bind 127.0.0.1:8000 --workers 1 app:app"
        ])
        .status()
        .expect("Failed to execute podman run python");
    assert!(python_status.success());

    // 4. Wait for package managers and services to boot up using active port polling
    println!("[TestPodman] Polling container ports for initialization...");
    let mut initialized = false;
    for i in 0..80 {
        if is_port_open(8080).await && is_port_open(8081).await && is_port_open(9000).await && is_port_open(8000).await {
            println!("[TestPodman] All containerized services verified listening after {} ms!", i * 250);
            initialized = true;
            break;
        }
        sleep(Duration::from_millis(250)).await;
    }
    assert!(initialized, "Timed out waiting for container ports to open!");

    // 5. Initialize HeuristicsEngine and start the Vandam HTTP API server
    println!("[TestPodman] Initializing Vandam Engine and API Server...");
    let config = Arc::new(vandam::rules::ConfigManager::load_defaults());
    let web_roots = vec![
        "/var/www/site1".to_string(),
        "/var/www/site2".to_string(),
        "/var/www/site3".to_string(),
    ];
    let system_shells = HashSet::new();
    let heuristics = Arc::new(vandam::heuristics::HeuristicsEngine::new(config, web_roots.clone(), system_shells, None));
    
    // Start API server on UDS socket /var/run/kinnector/vandam.sock
    vandam::api::start_api_server(heuristics.clone(), web_roots.clone(), None);
    
    // Trigger initial proxy discovery to initialize WEB_ROOTS static OnceLock
    vandam::proxy_discovery::discover_and_propagate(&web_roots);

    // Wait a brief moment for the socket to bind and start listening
    sleep(Duration::from_millis(500)).await;

    // 6. QUERY /api/v1/containers FIRST to populate global ACTIVE_CONTAINERS map
    println!("[TestPodman] Querying Vandam HTTP UDS API /api/v1/containers...");
    let mut stream2 = UnixStream::connect("/var/run/kinnector/vandam.sock")
        .await
        .expect("Failed to connect to Vandam API UDS socket");
        
    stream2.write_all(b"GET /api/v1/containers HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("Failed to send GET request to API");
    stream2.flush().await.unwrap();

    let mut response_buf2 = Vec::new();
    stream2.read_to_end(&mut response_buf2)
        .await
        .expect("Failed to read API response");
        
    let response_str2 = String::from_utf8_lossy(&response_buf2);
    let parts2: Vec<&str> = response_str2.split("\r\n\r\n").collect();
    let json_str2 = parts2.get(1).expect("API response did not contain an HTTP body");
    let containers_val: serde_json::Value = serde_json::from_str(json_str2)
        .expect("Failed to parse Vandam containers response as JSON");

    let containers = containers_val.as_array().expect("API JSON response was not a container array");

    // 7. QUERY /api/v1/status SECOND (so container_name mapping is fully resolved)
    println!("[TestPodman] Querying Vandam HTTP UDS API /api/v1/status...");
    let mut stream = UnixStream::connect("/var/run/kinnector/vandam.sock")
        .await
        .expect("Failed to connect to Vandam API UDS socket");
        
    stream.write_all(b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("Failed to send GET request to API");
    stream.flush().await.unwrap();

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf)
        .await
        .expect("Failed to read API response");
        
    let response_str = String::from_utf8_lossy(&response_buf);
    let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
    let json_str = parts.get(1).expect("API response did not contain an HTTP body");
    let json_val: serde_json::Value = serde_json::from_str(json_str)
        .expect("Failed to parse Vandam status response as JSON");

    let services = json_val.get("listening_services")
        .and_then(|s| s.as_array())
        .expect("API JSON response did not contain 'listening_services' array");

    // 7.1 QUERY AND PRINT PARSED SERVERS (SITES, STANDALONE, DAEMONS)
    println!("[TestPodman] Querying Vandam HTTP UDS API /api/v1/servers...");
    let mut stream3 = UnixStream::connect("/var/run/kinnector/vandam.sock")
        .await
        .expect("Failed to connect to Vandam API UDS socket");
        
    stream3.write_all(b"GET /api/v1/servers HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("Failed to send GET request to API");
    stream3.flush().await.unwrap();

    let mut response_buf3 = Vec::new();
    stream3.read_to_end(&mut response_buf3)
        .await
        .expect("Failed to read API response");
        
    let response_str3 = String::from_utf8_lossy(&response_buf3);
    let parts3: Vec<&str> = response_str3.split("\r\n\r\n").collect();
    let json_str3 = parts3.get(1).expect("API response did not contain an HTTP body");
    let servers_val: serde_json::Value = serde_json::from_str(json_str3)
        .expect("Failed to parse Vandam servers response as JSON");

    let sites = servers_val.get("sites").and_then(|v| v.as_array()).expect("No sites in response");
    let standalone = servers_val.get("standalone").and_then(|v| v.as_array()).expect("No standalone in response");
    let daemons = servers_val.get("daemons").and_then(|v| v.as_array()).expect("No daemons in response");

    // 8. PRINT BEAUTIFUL DISCOVERED SERVICES TABLE WITH CONTAINER NAMES
    println!("\n=================================================================================================================");
    println!("                                 VANDAM DISCOVERED LISTENING SERVICES                                            ");
    println!("=================================================================================================================");
    println!("{:<20} | {:<7} | {:<7} | {:<20} | {:<12} | {:<12} | {:<30}", "Service Binary", "PID", "PPID", "Container/Host", "Ports", "Stack", "CWD");
    println!("---------------------+---------+---------+----------------------+--------------+--------------+-----------------------------");
    for s in services {
        let exe = s.get("exe").and_then(|e| e.as_str()).unwrap_or("");
        let binary_name = std::path::Path::new(exe)
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| exe.to_string());
        let pid = s.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);
        let ppid = s.get("ppid").and_then(|p| p.as_u64()).unwrap_or(0);
        let container_name = s.get("container_name").and_then(|c| c.as_str()).unwrap_or("host");
        
        let ports_str = if let Some(ports) = s.get("ports").and_then(|p| p.as_array()) {
            ports.iter()
                .map(|p| p.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        } else {
            "-".to_string()
        };

        let stack = s.get("stack").and_then(|t| t.as_str()).unwrap_or("-");
        let cwd = s.get("cwd").and_then(|c| c.as_str()).unwrap_or("-");

        println!("{:<20} | {:<7} | {:<7} | {:<20} | {:<12} | {:<12} | {:<30}", binary_name, pid, ppid, container_name, ports_str, stack, cwd);
    }
    println!("=================================================================================================================\n");

    // 8.1 PRINT DISCOVERED MONITORED CONTAINERS TABLE
    println!("\n=================================================================================================================");
    println!("                                   VANDAM DISCOVERED MONITORED CONTAINERS                                        ");
    println!("=================================================================================================================");
    println!("{:<20} | {:<12} | {:<40} | {:<10} | {:<10}", "Container Name", "ID", "Image", "Status", "Attached");
    println!("---------------------+--------------+------------------------------------------+------------+--------------------");
    for c in containers {
        let name = c.get("name").and_then(|n| n.as_str()).unwrap_or("-");
        let id = c.get("id").and_then(|i| i.as_str()).unwrap_or("-");
        let short_id = if id.len() > 12 { &id[..12] } else { id };
        let image = c.get("image").and_then(|i| i.as_str()).unwrap_or("-");
        let status = c.get("status").and_then(|s| s.as_str()).unwrap_or("-");
        let attached = c.get("attached").and_then(|a| a.as_bool()).map(|b| if b { "YES" } else { "NO" }).unwrap_or("NO");

        println!("{:<20} | {:<12} | {:<40} | {:<10} | {:<10}", name, short_id, image, status, attached);
    }
    println!("=================================================================================================================\n");

    // 8.2 PRINT SITES, STANDALONES, AND DAEMONS
    println!("\n=================================================================================================================");
    println!("                                   VANDAM PARSED MONITORED SITES                                                 ");
    println!("=================================================================================================================");
    println!("{:<25} | {:<15} | {:<25} | {:<40}", "Site/Domain", "Stack", "Directory", "Via (Proxy chain)");
    println!("--------------------------+-----------------+---------------------------+----------------------------------------");
    for s in sites {
        let site = s.get("site").and_then(|v| v.as_str()).unwrap_or("-");
        let stack = s.get("stack").and_then(|v| v.as_str()).unwrap_or("-");
        let dir = s.get("directory").and_then(|v| v.as_str()).unwrap_or("-");
        let via = s.get("via").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{:<25} | {:<15} | {:<25} | {:<40}", site, stack, dir, via);
    }
    println!("=================================================================================================================\n");

    println!("\n=================================================================================================================");
    println!("                                   VANDAM STANDALONE SERVERS                                                     ");
    println!("=================================================================================================================");
    println!("{:<20} | {:<20} | {:<12} | {:<40}", "Process", "Stack", "Listening", "Directory");
    println!("---------------------+----------------------+--------------+-----------------------------------------------------");
    for s in standalone {
        let site = s.get("site").and_then(|v| v.as_str()).unwrap_or("-");
        let stack = s.get("stack").and_then(|v| v.as_str()).unwrap_or("-");
        let listening = s.get("listening").and_then(|v| v.as_str()).unwrap_or("-");
        let dir = s.get("directory").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{:<20} | {:<20} | {:<12} | {:<40}", site, stack, listening, dir);
    }
    println!("=================================================================================================================\n");

    println!("\n=================================================================================================================");
    println!("                                   VANDAM DETECTED DATABASE DAEMONS                                              ");
    println!("=================================================================================================================");
    println!("{:<20} | {:<15} | {:<50}", "Database", "Listening", "Directory");
    println!("---------------------+-----------------+-------------------------------------------------------------------------");
    for d in daemons {
        let process = d.get("process").and_then(|v| v.as_str()).unwrap_or("-");
        let listening = d.get("listening").and_then(|v| v.as_str()).unwrap_or("-");
        let dir = d.get("directory").and_then(|v| v.as_str()).unwrap_or("-");
        println!("{:<20} | {:<15} | {:<50}", process, listening, dir);
    }
    println!("=================================================================================================================\n");

    // 9. Assert that all 4 web services were successfully reported by the API
    let mut found_nginx = false;
    let mut found_apache = false;
    let mut found_phpfpm = false;
    let mut found_gunicorn = false;

    let mut nginx_pid = 0;
    let mut apache_pid = 0;

    for s in services {
        if let Some(stack) = s.get("stack").and_then(|t| t.as_str()) {
            match stack {
                "Nginx" => {
                    found_nginx = true;
                    nginx_pid = s.get("pid").and_then(|p| p.as_u64()).unwrap() as u32;
                }
                "Apache" => {
                    found_apache = true;
                    apache_pid = s.get("pid").and_then(|p| p.as_u64()).unwrap() as u32;
                }
                "PHP" => found_phpfpm = true,
                "Python" => found_gunicorn = true,
                _ => {}
            }
        }
    }

    assert!(found_nginx, "API status did not report Nginx service!");
    assert!(found_apache, "API status did not report Apache service!");
    assert!(found_phpfpm, "API status did not report PHP-FPM service!");
    assert!(found_gunicorn, "API status did not report Python/Gunicorn service!");

    // 10. SIMULATE AND VALIDATE TELEMETRY LISTEN EVENT INVOCATION
    println!("\n=================================================================");
    println!("[TestPodman] SIMULATING TELEMETRY-TRIGGERED LISTEN() RE-PARSING");
    println!("=================================================================");
    
    assert!(nginx_pid > 0, "No Nginx PID found to simulate telemetry event!");
    assert!(apache_pid > 0, "No Apache PID found to simulate telemetry event!");

    println!("[TestPodman] Submitting TelemetryEventRaw (Listen) for Nginx PID {}...", nginx_pid);
    let nginx_event = vandam::types::TelemetryEventRaw {
        header: vandam::types::TelemetryHeader::new(1, 1000, nginx_pid, vandam::types::EventType::Listen, vandam::types::TelemetrySource::eBPF),
        details_buffer: [0; vandam::types::DETAILS_SIZE],
    };
    heuristics.handle_raw_event(nginx_event);

    println!("[TestPodman] Submitting TelemetryEventRaw (Listen) for Apache PID {}...", apache_pid);
    let apache_event = vandam::types::TelemetryEventRaw {
        header: vandam::types::TelemetryHeader::new(2, 2000, apache_pid, vandam::types::EventType::Listen, vandam::types::TelemetrySource::eBPF),
        details_buffer: [0; vandam::types::DETAILS_SIZE],
    };
    heuristics.handle_raw_event(apache_event);

    // Yield/sleep briefly to let async task spawned by tokio::spawn run
    sleep(Duration::from_millis(500)).await;

    println!("=================================================================\n");

    println!("[TestPodman] SUCCESS: All 4 web service signatures verified via Vandam API endpoint!");
}
