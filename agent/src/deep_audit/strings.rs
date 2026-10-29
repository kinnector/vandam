//! strings.rs — extracts printable strings from binaries `pkg_verify`
//! flagged `Unindexed`/`Tampered`, to help understand what an unrecognized
//! binary is actually for (config strings, hardcoded C2 addresses, library
//! names, etc.) without a full disassembler. Shells to `/usr/bin/strings`
//! at its absolute path (never resolved through `$PATH`) so a tampered
//! `strings` binary sitting earlier on PATH can't feed the audit itself
//! poisoned output.

const MAX_OUTPUT_BYTES: usize = 65_536;
const MIN_STRING_LEN: &str = "6";

/// Runs `strings -n 6 <path>`, capped to `MAX_OUTPUT_BYTES` of output
/// (truncated, not rejected — a partial extract is still useful evidence).
/// Returns `None` if the binary doesn't exist, isn't readable, or
/// `/usr/bin/strings` itself isn't present (not every minimal container
/// image ships binutils) — callers should treat that as "no strings
/// available," not an error.
pub fn extract(path: &str) -> Option<String> {
    let out = std::process::Command::new("/usr/bin/strings").args(["-n", MIN_STRING_LEN, path]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    if text.len() > MAX_OUTPUT_BYTES {
        text.truncate(MAX_OUTPUT_BYTES);
        text.push_str("\n... [truncated]");
    }
    Some(text)
}

/// Extracts strings for `path` and writes them into the finding's own
/// evidence directory (`store::evidence_dir`) as `strings.txt` — kept as raw
/// evidence separate from the structured `AuditFinding` record, same split
/// `pty_session_store.rs` uses for cast files vs. commands.jsonl. Returns
/// the written path (relative to nothing in particular — callers store it
/// in the finding's `evidence` JSON for the CLI/TUI to fetch on demand),
/// or `None` if extraction produced nothing.
pub fn extract_and_store(run_id: &str, finding_id: &str, path: &str) -> Option<std::path::PathBuf> {
    let content = extract(path)?;
    let dir = super::store::evidence_dir(run_id, finding_id);
    let dest = dir.join("strings.txt");
    std::fs::write(&dest, content).ok()?;
    Some(dest)
}
