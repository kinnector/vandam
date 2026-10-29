//! pkg_verify.rs — binary/package attribution for the deep audit pipeline.
//!
//! Deliberately a fresh, small implementation local to `vandam` rather
//! than reusing/exposing OSS's `api.rs::resolve_version_via_package_manager`
//! (private, daemon-version-specific) — this whole feature is scoped to stay
//! out of the `vandam` crate entirely, see the Audit deep-scan design plan.
//! Same `dpkg -S`/`rpm -qf` pattern that function already established for
//! "is this binary owned by a package," extended here with a tamper check
//! (md5 comparison against the package manager's own recorded checksum).

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PackageAttribution {
    Verified { package: String, version: Option<String> },
    Unindexed,
    Tampered { package: String, expected_md5: Option<String>, actual_md5: Option<String> },
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

fn md5_of_file(path: &str) -> Option<String> {
    let out = run("/usr/bin/md5sum", &[path])?;
    out.split_whitespace().next().map(|s| s.to_string())
}

fn dpkg_attribution(path: &str) -> Option<PackageAttribution> {
    let stdout = run("/usr/bin/dpkg", &["-S", path])?;
    let package = stdout.split(':').next()?.trim().to_string();
    if package.is_empty() {
        return None;
    }

    let version = run("/usr/bin/dpkg-query", &["-W", "-f=${Version}", &package])
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    // dpkg ships the expected md5 for every file it installed at
    // /var/lib/dpkg/info/<package>.md5sums, keyed by path relative to `/`.
    let relpath = path.trim_start_matches('/');
    let expected_md5 = std::fs::read_to_string(format!("/var/lib/dpkg/info/{}.md5sums", package))
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                let mut parts = line.splitn(2, char::is_whitespace);
                let md5 = parts.next()?;
                let p = parts.next()?.trim();
                (p == relpath).then(|| md5.to_string())
            })
        });

    match expected_md5 {
        Some(expected) => {
            let actual = md5_of_file(path);
            if actual.as_deref() == Some(expected.as_str()) {
                Some(PackageAttribution::Verified { package, version })
            } else {
                Some(PackageAttribution::Tampered { package, expected_md5: Some(expected), actual_md5: actual })
            }
        }
        // Package owns the path but ships no recorded checksum for it (not
        // every dpkg package includes a .md5sums file) — attribution still
        // holds, we just can't additionally assert integrity.
        None => Some(PackageAttribution::Verified { package, version }),
    }
}

fn rpm_attribution(path: &str) -> Option<PackageAttribution> {
    let stdout = run("/usr/bin/rpm", &["-qf", "--qf", "%{NAME} %{VERSION}", path])?;
    let mut parts = stdout.split_whitespace();
    let package = parts.next()?.to_string();
    let version = parts.next().map(|s| s.to_string());

    let dump = run("/usr/bin/rpm", &["-q", "--qf", "[%{FILENAMES} %{FILEMD5S}\n]", &package]);
    let expected_md5 = dump.and_then(|content| {
        content.lines().find_map(|line| {
            let mut parts = line.splitn(2, char::is_whitespace);
            let p = parts.next()?;
            let md5 = parts.next()?.trim();
            (p == path && !md5.is_empty()).then(|| md5.to_string())
        })
    });

    match expected_md5 {
        Some(expected) => {
            let actual = md5_of_file(path);
            if actual.as_deref() == Some(expected.as_str()) {
                Some(PackageAttribution::Verified { package, version })
            } else {
                Some(PackageAttribution::Tampered { package, expected_md5: Some(expected), actual_md5: actual })
            }
        }
        None => Some(PackageAttribution::Verified { package, version }),
    }
}

/// Attributes `path` to a package (and flags tampering via md5 mismatch
/// against the package manager's own record) using whichever of dpkg/rpm is
/// present, or `Unindexed` if neither owns the path — the exact signal the
/// mock UI's "0 dpkg/rpm matches" line was gesturing at, now real.
pub fn attribute_binary(path: &str) -> PackageAttribution {
    dpkg_attribution(path).or_else(|| rpm_attribution(path)).unwrap_or(PackageAttribution::Unindexed)
}
