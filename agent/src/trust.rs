//! Shared "full trust" primitive — a PID granted trust here is exempt from
//! essentially every local enforcement decision vandamd/core makes: file
//! read/write, exec, ptrace, mmap, chmod, network connect, listening-socket
//! bind, and the container-escape hooks. Confirmed against
//! `core/src/linux/ebpf/kinnector.bpf.c`: every one of those LSM hooks
//! checks the `trusted_ancestor_roots` map (`map_type` 2, "TrustedRoots")
//! as an unconditional early-return before any other check runs, and the
//! fork hook copies a trusted PID's map entry to every child it spawns —
//! so granting trust on one process covers its whole descendant tree with
//! no further work. `process_threshold_map` (`map_type` 6) is a separate,
//! independent mechanism that *imposes* exec/network restriction flags;
//! clearing it alongside the trust grant removes any ambiguity, even
//! though every threshold-gated hook already treats trust as an early-out.
//!
//! Used by both container trust (`discovery.rs`) and server/site trust
//! (`api.rs`'s `get_servers_data()` reconcile pass) so the two features
//! can't drift on what "trusted" actually does at the kernel level.

use dashmap::DashMap;
use std::sync::{Arc, OnceLock};

/// Why a PID currently holds a trust grant — lets a reconcile pass revoke
/// only the grants it itself is responsible for, without touching a grant
/// from a different source (e.g. the hardcoded infra allowlist) on the same
/// PID.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TrustReason {
    /// Hardcoded infra allowlist (datadog/agent, cadvisor, kube-system, etc.)
    /// — see `discovery.rs::query_single_container`. Permanent, never revoked.
    InfraAllowlist,
    /// A user-issued trust rule (`ALLOW_CONTAINER_IMAGE` / `ALLOW_SERVER_PATH`)
    /// — revocable when the rule is deleted or no longer matches.
    UserRule,
}

static TRUSTED_PIDS: OnceLock<Arc<DashMap<u32, TrustReason>>> = OnceLock::new();

fn trusted_pids() -> &'static Arc<DashMap<u32, TrustReason>> {
    TRUSTED_PIDS.get_or_init(|| Arc::new(DashMap::new()))
}

pub fn is_trusted_by(pid: u32, reason: TrustReason) -> bool {
    trusted_pids()
        .get(&pid)
        .map(|r| *r == reason)
        .unwrap_or(false)
}

/// Grants full trust to `pid` (idempotent — safe to call every time a
/// reconcile pass re-confirms a match). No-ops the kernel call if this PID
/// is already trusted for `reason`, since the map entries don't need
/// refreshing once set.
pub fn grant(pid: u32, reason: TrustReason) {
    if is_trusted_by(pid, reason) {
        return;
    }
    unsafe {
        crate::ffi::update_map_entry(2, pid, 0, 1); // TrustedRoots
        crate::ffi::delete_map_entry(6, pid, 0); // clear any imposed exec/network restriction flags
    }
    trusted_pids().insert(pid, reason);
}

/// Revokes trust on `pid`, but only if it was granted for `reason` — a
/// grant held for a different reason (e.g. the infra allowlist) is left
/// untouched. Returns true if a revoke actually happened.
pub fn revoke_if(pid: u32, reason: TrustReason) -> bool {
    if !is_trusted_by(pid, reason) {
        return false;
    }
    unsafe {
        crate::ffi::delete_map_entry(2, pid, 0);
    }
    trusted_pids().remove(&pid);
    true
}
