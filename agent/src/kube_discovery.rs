use serde_json::Value;

pub fn is_kubernetes_detected() -> bool {
    std::path::Path::new("/var/run/secrets/kubernetes.io/serviceaccount").exists()
        || std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
}

pub fn get_kubernetes_namespace() -> Option<String> {
    std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        .map(|ns| ns.trim().to_string())
        .ok()
}

pub async fn run_kubernetes_discovery() {
    if !is_kubernetes_detected() {
        return;
    }
    
    let namespace = get_kubernetes_namespace().unwrap_or_else(|| "default".to_string());
    tracing::info!("[Vandam Kubernetes] Auto-detected execution inside Kubernetes. Namespace: {}", namespace);

    // Read the service account token
    let Ok(token) = std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token") else {
        tracing::warn!("[Vandam Kubernetes] Service account token not readable. Skipping API pod discovery.");
        return;
    };

    let host = std::env::var("KUBERNETES_SERVICE_HOST").unwrap_or_default();
    let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_default();
    if host.is_empty() || port.is_empty() {
        return;
    }

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Trust the cluster CA dynamically
        .build() 
    {
        Ok(c) => c,
        Err(_) => return,
    };

    let url = format!("https://{}:{}/api/v1/namespaces/{}/pods", host, port, namespace);
    let response = client.get(&url)
        .header("Authorization", format!("Bearer {}", token.trim()))
        .send()
        .await;

    match response {
        Ok(res) => {
            if let Ok(body) = res.json::<Value>().await {
                if let Some(items) = body.get("items").and_then(|i| i.as_array()) {
                    for pod in items {
                        let pod_name = pod.get("metadata").and_then(|m| m.get("name")).and_then(|n| n.as_str()).unwrap_or_default();
                        let labels = pod.get("metadata").and_then(|m| m.get("labels"));
                        
                        // Check if this pod is running a web workload based on labels
                        let mut is_web = false;
                        if let Some(labels_obj) = labels.and_then(|l| l.as_object()) {
                            for (k, v) in labels_obj {
                                let v_str = v.as_str().unwrap_or_default().to_lowercase();
                                if k.to_lowercase().contains("app") && (v_str.contains("web") || v_str.contains("api") || v_str.contains("server")) {
                                    is_web = true;
                                    break;
                                }
                            }
                        }

                        if is_web {
                            tracing::info!("[Vandam Kubernetes] Discovered web pod: {}", pod_name);
                            // Query container statuses to get their container IDs and trust/monitor them
                            if let Some(statuses) = pod.get("status").and_then(|s| s.get("containerStatuses")).and_then(|c| c.as_array()) {
                                for status in statuses {
                                    if let Some(container_id_full) = status.get("containerID").and_then(|c| c.as_str()) {
                                        // containerID is usually containerd://<hash> or docker://<hash>
                                        let clean_id = container_id_full.split("://").last().unwrap_or(container_id_full);
                                        tracing::info!("[Vandam Kubernetes] Pod {} container ID {} auto-registered for monitoring", pod_name, clean_id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::warn!("[Vandam Kubernetes] Failed to query Kubernetes pods API: {}", e);
        }
    }
}
