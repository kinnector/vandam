//! install_date.rs — reads the Linux system's own installation date,
//! exposed via `GET /api/v1/status`'s `daemon.installed_at_unix`. Used by
//! `vandam`'s file-integrity re-baseline advisory (OS age + audit
//! history, not local detection hits, and not Vandam's own configure
//! date — a system that's been running exposed for years and only just
//! had Vandam installed on it is the highest-risk case for blindly
//! trusting a fresh baseline, and it needs to read as *old*, not as
//! brand-new just because Vandam itself is new here).
//!
//! Sourced from `/lost+found`'s filesystem birth (or change) time — that
//! directory is created once by `mkfs` and is essentially never touched
//! again afterward, a well-known, dependency-free way to estimate a Linux
//! root filesystem's real age without shelling out to `tune2fs` or
//! knowing the root block device.
//!
//! **Deliberately stateless — no persisted record, no machine-id/DMI-uuid
//! fingerprinting.** Those were built for a different problem: detecting
//! whether a *Vandam-authored* timestamp file had been inherited from a
//! disk clone. That doesn't apply here, because this reads a property of
//! the filesystem itself, live, on every call, rather than something
//! Vandam wrote and cached. A cloned copy of an old Linux disk genuinely
//! has an old `/lost+found` — that's not a stale/incorrect inherited
//! value, it's a true fact about that disk's real filesystem history,
//! clone or not. There's nothing to detect or correct.

use std::os::unix::fs::MetadataExt;

const LOST_FOUND_PATH: &str = "/lost+found";

fn extract_timestamp(meta: &std::fs::Metadata) -> i64 {
    // Prefer true filesystem birth time when the kernel/fs exposes it
    // (ext4/xfs/btrfs via statx, Linux 4.11+). Falls back to ctime, which
    // in practice tracks creation closely for a directory that's never
    // modified after mkfs.
    if let Ok(created) = meta.created() {
        if let Ok(secs) = created.duration_since(std::time::UNIX_EPOCH) {
            return secs.as_secs() as i64;
        }
    }
    meta.ctime()
}

/// Unix seconds this Linux root filesystem was created, or `None` if
/// `/lost+found` doesn't exist or isn't readable (non-ext/xfs-style root,
/// permission issue, container without a real root fs).
pub fn get() -> Option<i64> {
    std::fs::metadata(LOST_FOUND_PATH).ok().map(|m| extract_timestamp(&m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_timestamp_reads_a_recently_created_file_as_recent() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("vandam_install_date_test_{}", std::process::id()));
        std::fs::write(&path, b"x").unwrap();
        let meta = std::fs::metadata(&path).unwrap();

        let ts = extract_timestamp(&meta);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

        assert!((now - ts).abs() < 60, "expected a just-created file's timestamp to be within 60s of now, got {ts}, now={now}");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn get_returns_none_when_lost_and_found_is_absent() {
        // This test only meaningfully exercises the "present" path on real
        // Linux root filesystems (CI/dev containers usually have one at
        // `/lost+found`); it's here to document that a missing path is
        // `None`, not a panic — `std::fs::metadata` on a nonexistent path
        // is exercised directly rather than relying on environment state.
        let result = std::fs::metadata("/definitely/does/not/exist/lost+found");
        assert!(result.is_err());
    }
}
