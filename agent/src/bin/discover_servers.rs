use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, AsyncReadExt};

#[tokio::main]
async fn main() {
    let config = std::sync::Arc::new(vandam::rules::ConfigManager::load_defaults());
    let web_roots = vec!["/var/www/html".to_string()];
    let system_shells = std::collections::HashSet::new();
    let heuristics = std::sync::Arc::new(vandam::heuristics::HeuristicsEngine::new(config, web_roots.clone(), system_shells, None));
    
    let socket_path = "/var/run/kinnector/vandam.sock";
    let _ = std::fs::remove_file(socket_path);
    
    // Start the real Vandam API server in the background
    vandam::api::start_api_server(heuristics, web_roots, None);
    
    // Wait for the socket to initialize
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Connect to the socket and query /api/v1/servers
    let mut stream = UnixStream::connect(socket_path)
        .await
        .expect("Failed to connect to Vandam socket");
        
    stream.write_all(b"GET /api/v1/servers HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();

    let mut response_buf = Vec::new();
    stream.read_to_end(&mut response_buf).await.unwrap();
    
    let response_str = String::from_utf8_lossy(&response_buf);
    let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
    if let Some(json_str) = parts.get(1) {
        if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(json_str) {
            println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
        } else {
            println!("Failed to parse JSON body: {}", json_str);
        }
    } else {
        println!("Invalid HTTP response: {}", response_str);
    }
    
    // Clean up
    let _ = std::fs::remove_file(socket_path);
}
