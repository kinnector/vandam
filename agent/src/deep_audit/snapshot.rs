//! snapshot.rs — Stage 1 (Static System Snapshot): installed packages,
//! services, persistence locations, SSH authorized_keys/sudoers. Runs once
//! at the start of a scan; a point-in-time inventory, not a stream.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SshKeyEntry {
    pub user: String,
    pub path: String,
    pub fingerprint: Option<String>,
    pub comment: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StaticSnapshot {
    pub process_count: usize,
    pub installed_packages: Vec<String>,
    pub services: Vec<String>,
    pub persistence_paths_present: Vec<String>,
    pub authorized_keys: Vec<SshKeyEntry>,
    pub sudoers_entries: Vec<String>,
}

fn run_lines(cmd: &str, args: &[&str]) -> Vec<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(|l| l.to_string()).collect())
        .unwrap_or_default()
}

fn installed_packages() -> Vec<String> {
    let dpkg: Vec<String> = run_lines("/usr/bin/dpkg-query", &["-W", "-f=${Package} ${Version}\n"]);
    if !dpkg.is_empty() {
        return dpkg;
    }
    run_lines("/usr/bin/rpm", &["-qa", "--qf", "%{NAME} %{VERSION}\n"])
}

fn services() -> Vec<String> {
    run_lines("/usr/bin/systemctl", &["list-units", "--type=service", "--no-legend", "--plain"])
        .into_iter()
        .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
        .collect()
}

fn sudoers_entries() -> Vec<String> {
    let mut out = Vec::new();
    let mut files = vec![std::path::PathBuf::from("/etc/sudoers")];
    if let Ok(entries) = std::fs::read_dir("/etc/sudoers.d") {
        files.extend(entries.flatten().map(|e| e.path()));
    }
    for file in files {
        if let Ok(content) = std::fs::read_to_string(&file) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    out.push(trimmed.to_string());
                }
            }
        }
    }
    out
}

fn home_dirs() -> Vec<(String, std::path::PathBuf)> {
    let mut out = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 6 {
                let user = fields[0].to_string();
                let home = std::path::PathBuf::from(fields[5]);
                out.push((user, home));
            }
        }
    }
    out
}

fn key_fingerprint(line: &str) -> Option<String> {
    // ssh-keygen needs the key on disk to fingerprint a specific line
    // reliably across formats (rsa/ed25519/ecdsa) — write it to a scratch
    // file rather than hand-parsing the base64 blob ourselves.
    let tmp = std::env::temp_dir().join(format!("kinnector-audit-key-{}", uuid::Uuid::new_v4()));
    std::fs::write(&tmp, line).ok()?;
    let out = std::process::Command::new("/usr/bin/ssh-keygen").args(["-lf", tmp.to_str()?]).output().ok();
    let _ = std::fs::remove_file(&tmp);
    let out = out.filter(|o| o.status.success())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.split_whitespace().nth(1).map(|s| s.to_string())
}

fn authorized_keys() -> Vec<SshKeyEntry> {
    let mut out = Vec::new();
    for (user, home) in home_dirs() {
        let path = home.join(".ssh").join("authorized_keys");
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let comment = trimmed.split_whitespace().last().unwrap_or_default().to_string();
            out.push(SshKeyEntry {
                user: user.clone(),
                path: path.to_string_lossy().to_string(),
                fingerprint: key_fingerprint(trimmed),
                comment,
            });
        }
    }
    out
}

pub fn collect(config: &vandam::rules::ConfigManager, process_count: usize) -> StaticSnapshot {
    let persistence_paths_present =
        config.persistence_paths().into_iter().filter(|p| std::path::Path::new(p).exists()).collect();

    StaticSnapshot {
        process_count,
        installed_packages: installed_packages(),
        services: services(),
        persistence_paths_present,
        authorized_keys: authorized_keys(),
        sudoers_entries: sudoers_entries(),
    }
}
