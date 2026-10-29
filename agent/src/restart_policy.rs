use std::path::{Path, PathBuf};
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::fs;
use notify::{Watcher, RecursiveMode, EventKind};

#[derive(Debug, Clone)]
pub enum ConfigFreshnessResult {
    Fresh,
    ConfigNewerThanProcess {
        config_path: PathBuf,
        config_mtime: SystemTime,
        process_start: SystemTime,
        delta_secs: i64,
    },
}

pub fn read_boot_epoch_from_proc_stat() -> u64 {
    if let Ok(content) = fs::read_to_string("/proc/stat") {
        for line in content.lines() {
            if line.starts_with("btime ") {
                if let Some(val_str) = line.split_whitespace().nth(1) {
                    if let Ok(val) = val_str.parse::<u64>() {
                        return val;
                    }
                }
            }
        }
    }
    0
}

pub fn get_process_starttime_jiffies(pid: u32) -> Result<u64, Box<dyn std::error::Error>> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid))?;
    let rparen_idx = stat.rfind(')').ok_or("Invalid stat format")?;
    let rest = &stat[rparen_idx + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() > 19 {
        let starttime: u64 = fields[19].parse()?;
        Ok(starttime)
    } else {
        Err("Stat does not have 22 fields".into())
    }
}

pub fn check_config_freshness(pid: u32, config_path: &Path) -> ConfigFreshnessResult {
    let starttime_jiffies = match get_process_starttime_jiffies(pid) {
        Ok(t) => t,
        Err(_) => return ConfigFreshnessResult::Fresh,
    };

    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    let boot_epoch = read_boot_epoch_from_proc_stat();
    let process_start = UNIX_EPOCH
        + Duration::from_secs(boot_epoch)
        + Duration::from_secs(starttime_jiffies / clk_tck);

    let config_mtime = fs::metadata(config_path)
        .and_then(|m| m.modified())
        .unwrap_or(UNIX_EPOCH);

    if config_mtime > process_start {
        let delta = config_mtime.duration_since(process_start)
            .unwrap_or_default().as_secs() as i64;
        ConfigFreshnessResult::ConfigNewerThanProcess {
            config_path: config_path.to_owned(),
            config_mtime,
            process_start,
            delta_secs: delta,
        }
    } else {
        ConfigFreshnessResult::Fresh
    }
}

pub fn start_config_watcher<F>(config_paths: Vec<PathBuf>, on_change: F)
where
    F: Fn(PathBuf) + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let mut watcher = match notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        }) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("[Vandam Config Watch] Failed to initialize config watcher: {}", e);
                return;
            }
        };

        for path in &config_paths {
            if path.exists() {
                let mode = if path.is_dir() { RecursiveMode::Recursive } else { RecursiveMode::NonRecursive };
                let _ = watcher.watch(path, mode);
            }
        }

        while let Some(event) = rx.recv().await {
            if matches!(event.kind, EventKind::Modify(_)) {
                for p in event.paths {
                    on_change(p);
                }
            }
        }
    });
}
