//! Extension point for cloud-authored firewall rule sync — deliberately
//! left unimplemented in OSS. Structured exactly like `VandamConfig::extra_routes`
//! (see `lib.rs`): OSS defines the trait and threads an
//! `Option<Arc<dyn CloudFirewallSync>>` through, `None` by default; a real
//! implementation (bidirectional push/pull, conflict resolution) is
//! `vandam/src/firewall_sync.rs`. Unlike most other Pro capabilities
//! (e.g. `investigate.rs`, gated by `vandam::tls_buffer::is_paid_tier()`),
//! this one is **not** subscription-gated — firewall sync works for every
//! vandam install, `sub` and `nosub` alike, by product decision. Basic
//! remote block/unblock stays OSS-owned regardless (see `cloud.rs`'s
//! `block_ip`/`unblock_ip` command handlers) — this trait is specifically
//! for the richer bidirectional sync, which is Pro-build-only (not
//! Pro-subscription-only).

use crate::firewall::FirewallRule;

#[async_trait::async_trait]
pub trait CloudFirewallSync: Send + Sync {
    /// Pushes locally-authored (`FirewallProvenance::Local`) rules to the
    /// cloud console so they're visible/manageable there too.
    async fn push_local_rules(&self, rules: &[FirewallRule]) -> Result<(), String>;

    /// Pulls the cloud's current rule set — these come back tagged
    /// `FirewallProvenance::Cloud, locked: true` by the caller (see
    /// `reconcile::merge_cloud_rules`, the periodic loop's only consumer of
    /// this method), not by the implementation.
    async fn pull_cloud_rules(&self) -> Result<Vec<FirewallRule>, String>;
}
