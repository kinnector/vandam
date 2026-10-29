//! quota_guard.rs — local circuit breaker for Pro/Max cloud-analysis dispatch.
//!
//! Independent per `QuotaCategory`: a sliding-window attempt counter (same
//! keyed-window shape as `vandam::heuristics`'s `ssh_attempts`, generalized
//! to a configurable window/threshold instead of a hardcoded one) that
//! auto-trips to a disabled state (with reason + cooldown) when the local
//! threshold is exceeded, plus an independent manual enable/disable
//! override — a deliberate "operator turned this off" is a different state
//! from "the failsafe tripped it," and both need to be distinguishable.
//!
//! This is the fast, self-contained local failsafe layer — not a
//! substitute for eventual cloud-side quota enforcement. Today's gRPC
//! transport (`vandam::cloud::send_forensic_payload`) is a one-way push
//! with no per-message response, so there is nowhere for the cloud to
//! report "quota exceeded" back down yet; that's separate, unscheduled work
//! (see the Cloud Auto-Audit Quota plan).
//!
//! Every Pro cloud-dispatch handler must call `get().check_and_record(category)`
//! before dispatching — see `investigate.rs` for the reference call site.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use vandam::tls_buffer::{license_tier, LicenseTier};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaCategory {
    Alerts,
    Sessions,
    Audits,
    SupplyChain,
}

impl QuotaCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            QuotaCategory::Alerts => "alerts",
            QuotaCategory::Sessions => "sessions",
            QuotaCategory::Audits => "audits",
            QuotaCategory::SupplyChain => "supply_chain",
        }
    }

    pub fn from_str(s: &str) -> Option<QuotaCategory> {
        match s {
            "alerts" => Some(QuotaCategory::Alerts),
            "sessions" => Some(QuotaCategory::Sessions),
            "audits" => Some(QuotaCategory::Audits),
            "supply_chain" => Some(QuotaCategory::SupplyChain),
            _ => None,
        }
    }

    pub fn all() -> [QuotaCategory; 4] {
        [QuotaCategory::Alerts, QuotaCategory::Sessions, QuotaCategory::Audits, QuotaCategory::SupplyChain]
    }
}

/// Sliding-window size (seconds) and attempt threshold within it, per plan.
/// Max's ceiling is much higher than Pro's, but still finite — not
/// unlimited — specifically so a large multi-server fleet under one
/// subscription can't blow past it and spam/bloat the pipeline.
fn window_and_threshold(tier: LicenseTier) -> (i64, usize) {
    match tier {
        LicenseTier::Max => (300, 200),
        LicenseTier::Pro => (300, 20),
        LicenseTier::Free => (300, 0),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CategoryState {
    pub category: QuotaCategory,
    pub manually_disabled: bool,
    pub tripped: bool,
    pub reason: Option<String>,
    pub tripped_at: Option<String>,
    pub cooldown_until: Option<i64>,
    pub window_used: usize,
    pub window_limit: usize,
}

#[derive(Debug)]
pub enum QuotaDenied {
    ManuallyDisabled,
    Tripped { reason: String, cooldown_until: i64 },
}

impl QuotaDenied {
    pub fn reason(&self) -> String {
        match self {
            QuotaDenied::ManuallyDisabled => "auto-audit manually disabled for this category".to_string(),
            QuotaDenied::Tripped { reason, .. } => reason.clone(),
        }
    }
}

#[derive(Default)]
struct CategoryInner {
    attempts: Vec<i64>,
    manually_disabled: bool,
    tripped: bool,
    reason: Option<String>,
    tripped_at: Option<String>,
    cooldown_until: Option<i64>,
}

/// Cooldown duration once tripped, before auto-recovery — separate from the
/// sliding window itself so a burst doesn't immediately re-trip on recovery.
const COOLDOWN_SECS: i64 = 600;
const LOG_PATH: &str = "/var/log/kinnector/cloud_quota.log";

pub struct QuotaGuard {
    categories: Mutex<HashMap<QuotaCategory, CategoryInner>>,
}

static QUOTA_GUARD: OnceLock<Arc<QuotaGuard>> = OnceLock::new();

pub fn get() -> Arc<QuotaGuard> {
    QUOTA_GUARD.get_or_init(|| Arc::new(QuotaGuard::new())).clone()
}

impl QuotaGuard {
    fn new() -> Self {
        Self { categories: Mutex::new(HashMap::new()) }
    }

    pub fn check_and_record(&self, category: QuotaCategory) -> Result<(), QuotaDenied> {
        let now = Utc::now().timestamp();
        let mut map = self.categories.lock().unwrap();
        let entry = map.entry(category).or_default();

        // Auto-recover from a stale trip before checking.
        if entry.tripped {
            if let Some(until) = entry.cooldown_until {
                if now >= until {
                    entry.tripped = false;
                    entry.reason = None;
                    entry.tripped_at = None;
                    entry.cooldown_until = None;
                    drop(map);
                    log_event(category, "auto_recovered", "cooldown elapsed, auto-audit re-enabled");
                    map = self.categories.lock().unwrap();
                }
            }
        }
        let entry = map.entry(category).or_default();

        if entry.manually_disabled {
            return Err(QuotaDenied::ManuallyDisabled);
        }
        if entry.tripped {
            return Err(QuotaDenied::Tripped {
                reason: entry.reason.clone().unwrap_or_default(),
                cooldown_until: entry.cooldown_until.unwrap_or(0),
            });
        }

        let (window, threshold) = window_and_threshold(license_tier());
        entry.attempts.push(now);
        entry.attempts.retain(|&t| now - t < window);
        let count = entry.attempts.len();

        if count > threshold {
            let reason = format!(
                "local failsafe: {} dispatch attempts in {}s exceeds the {:?}-plan limit of {} — auto-disabled to prevent bloat/abuse",
                count, window, license_tier(), threshold
            );
            let cooldown_until = now + COOLDOWN_SECS;
            entry.tripped = true;
            entry.reason = Some(reason.clone());
            entry.tripped_at = Some(Utc::now().to_rfc3339());
            entry.cooldown_until = Some(cooldown_until);
            drop(map);
            log_event(category, "tripped", &reason);
            return Err(QuotaDenied::Tripped { reason, cooldown_until });
        }

        Ok(())
    }

    pub fn set_manual(&self, category: QuotaCategory, enabled: bool) {
        {
            let mut map = self.categories.lock().unwrap();
            map.entry(category).or_default().manually_disabled = !enabled;
        }
        log_event(
            category,
            if enabled { "manually_enabled" } else { "manually_disabled" },
            "operator toggle via POST /api/v1/cloud/auto-audit/{category}",
        );
    }

    pub fn status(&self) -> Vec<CategoryState> {
        let map = self.categories.lock().unwrap();
        let (window, threshold) = window_and_threshold(license_tier());
        let now = Utc::now().timestamp();
        QuotaCategory::all()
            .into_iter()
            .map(|cat| {
                let used = map
                    .get(&cat)
                    .map(|e| e.attempts.iter().filter(|&&t| now - t < window).count())
                    .unwrap_or(0);
                let inner = map.get(&cat);
                CategoryState {
                    category: cat,
                    manually_disabled: inner.map(|e| e.manually_disabled).unwrap_or(false),
                    tripped: inner.map(|e| e.tripped).unwrap_or(false),
                    reason: inner.and_then(|e| e.reason.clone()),
                    tripped_at: inner.and_then(|e| e.tripped_at.clone()),
                    cooldown_until: inner.and_then(|e| e.cooldown_until),
                    window_used: used,
                    window_limit: threshold,
                }
            })
            .collect()
    }
}

fn log_event(category: QuotaCategory, event: &str, detail: &str) {
    let line = serde_json::json!({
        "ts": Utc::now().to_rfc3339(),
        "category": category.as_str(),
        "event": event,
        "detail": detail,
    })
    .to_string();
    let _ = std::fs::create_dir_all("/var/log/kinnector");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(LOG_PATH) {
        let _ = writeln!(f, "{}", line);
    }
}

/// Tail of `cloud_quota.log` for `GET /api/v1/cloud/logs`, newest-last (same
/// order as the underlying append-only file) capped to `limit` entries.
pub fn read_logs(limit: usize) -> Vec<serde_json::Value> {
    let Ok(content) = std::fs::read_to_string(LOG_PATH) else {
        return Vec::new();
    };
    let mut lines: Vec<serde_json::Value> = content.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let len = lines.len();
    if len > limit {
        lines.drain(0..len - limit);
    }
    lines
}
