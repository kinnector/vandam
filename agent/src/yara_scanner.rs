use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Lightweight OSS signature scanner for common webshell patterns.
/// Represents the community version of the YARA scanner.
pub fn scan_file_yara_oss(path: &Path) -> bool {
    // Only scan common web extensions
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    if !["php", "py", "rb", "pl", "cgi", "jsp", "aspx", "sh", "lua"].contains(&ext.as_str()) {
        return false;
    }

    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    
    // Scan up to the first 16KB to catch headers and basic shells
    let mut buf = [0u8; 16384]; 
    let bytes_read = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return false,
    };
    
    if bytes_read == 0 {
        return false;
    }

    let content = String::from_utf8_lossy(&buf[..bytes_read]);
    
    // Basic OSS YARA patterns for webshells
    let patterns = [
        "eval(base64_decode(",
        "eval(gzinflate(base64_decode(",
        "system($_GET[",
        "system($_POST[",
        "shell_exec($_GET[",
        "passthru($_POST[",
        "preg_replace('/.*/e'",
        "assert($_POST[",
        "b374k",
        "c99shell",
        "r57shell",
        "wso2",
        "wso_version",
    ];

    for pattern in &patterns {
        if content.contains(pattern) {
            return true;
        }
    }
    
    false
}
