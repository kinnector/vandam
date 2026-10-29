use std::path::Path;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanResult {
    Clean,
    Elf,
    Suspicious(String),
}

/// Synchronous header scan — runs inline in the heuristics event handler.
/// Reads exactly 4 bytes. ELF-only: no polyglot, no extension checks.
/// PHP files, WordPress plugins, and script uploads are intentionally allowed
/// through; only raw ELF binaries are quarantined at write time.
pub fn scan_uploaded_file_sync(file_path: &str) -> ScanResult {
    let path = Path::new(file_path);
    if !path.exists() {
        return ScanResult::Clean;
    }
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return ScanResult::Clean,
    };
    let mut buffer = [0u8; 4];
    match file.read(&mut buffer) {
        Ok(n) if n >= 4 => {}
        _ => return ScanResult::Clean,
    }

    // ELF magic bytes (7F 45 4C 46) — the only hard block at upload time
    if buffer == [0x7F, 0x45, 0x4C, 0x46] {
        return ScanResult::Elf;
    }

    ScanResult::Clean
}

/// Asynchronous deep scan — runs after the sync gate has already passed.
/// Currently also ELF-only. Extend here for YARA / entropy / full-hash
/// forensic passes without affecting the inline write decision.
pub async fn scan_uploaded_file(file_path: &str) -> ScanResult {
    let path = Path::new(file_path);
    if !path.exists() {
        return ScanResult::Clean;
    }
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return ScanResult::Clean,
    };
    let mut buffer = [0u8; 4];
    match file.read(&mut buffer) {
        Ok(n) if n >= 4 => {}
        _ => return ScanResult::Clean,
    }

    // ELF magic bytes (7F 45 4C 46)
    if buffer == [0x7F, 0x45, 0x4C, 0x46] {
        return ScanResult::Elf;
    }

    ScanResult::Clean
}
