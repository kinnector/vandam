//! Where the rules come from: one source for the whole agent, read by every loader in `rules`.
//!
//! The rules are the JSON files of the repo's `rules/` folder, by name relative to it
//! (`linux_web_signatures.json`, `linux_web_processes.json`, `policies/ssh.json`). A debug
//! build reads that folder by path (only the path string is compiled in; `VANDAM_RULES_DIR`
//! points it at another folder). A release build reads no folder at all: its rules are one signed
//! bundle from vandam-cloud, kept in memory, never on disk (the shape of antitheft's corpus), and
//! until one arrives it has none.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

/// The repo's rules folder, for debug builds and tests.
pub const REPO_RULES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../rules");

#[derive(Clone, Debug)]
pub enum Source {
    Dir(PathBuf),
    /// File name -> contents, as a vandam-cloud bundle carries them.
    Memory(Arc<BTreeMap<String, String>>),
    /// Nothing to read: a release build before its first bundle.
    Empty,
}

static CURRENT: RwLock<Option<Source>> = RwLock::new(None);

/// The source every loader reads. Unset, it is the repo folder (or `VANDAM_RULES_DIR`) in a
/// debug build, nothing in a release build.
pub fn current() -> Source {
    if let Some(src) = CURRENT.read().unwrap().as_ref() {
        return src.clone();
    }
    if !cfg!(debug_assertions) {
        return Source::Empty;
    }
    match std::env::var("VANDAM_RULES_DIR") {
        Ok(dir) => Source::Dir(PathBuf::from(dir)),
        Err(_) => Source::Dir(PathBuf::from(REPO_RULES)),
    }
}

pub fn set(source: Source) {
    *CURRENT.write().unwrap() = Some(source);
}

/// Parses a rules bundle: JSON `{"files": {"<name>": <the file's JSON>}}` (other keys ignored).
pub fn parse_bundle(bytes: &[u8]) -> Result<Source, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| format!("rules bundle is not JSON: {}", e))?;
    let files = v
        .get("files")
        .and_then(|f| f.as_object())
        .ok_or("rules bundle has no \"files\" object")?;
    let mut map = BTreeMap::new();
    for (name, content) in files {
        if !is_safe_name(name) {
            return Err(format!("rules bundle names a file outside the rules: {}", name));
        }
        map.insert(name.clone(), content.to_string());
    }
    Ok(Source::Memory(Arc::new(map)))
}

/// A relative name with no `..`, no leading `/` and no empty part.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty() && !name.starts_with('/') && name.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

impl Source {
    /// One file's text, by name relative to the rules root.
    pub fn read(&self, name: &str) -> Option<String> {
        if !is_safe_name(name) {
            return None;
        }
        match self {
            Source::Dir(root) => std::fs::read_to_string(root.join(name)).ok(),
            Source::Memory(files) => files.get(name).cloned(),
            Source::Empty => None,
        }
    }

    /// The first of `names` that exists, with its name.
    pub fn read_first(&self, names: &[&str]) -> Option<(String, String)> {
        names.iter().find_map(|n| self.read(n).map(|text| (n.to_string(), text)))
    }

    /// One file parsed as JSON.
    pub fn json(&self, name: &str) -> Option<serde_json::Value> {
        self.read(name).and_then(|t| serde_json::from_str(&t).ok())
    }

    /// The `.json` files directly in `folder` ("" = the root), sorted by name.
    pub fn json_files_in(&self, folder: &str) -> Vec<String> {
        let prefix = if folder.is_empty() { String::new() } else { format!("{}/", folder) };
        match self {
            Source::Dir(root) => {
                let mut names: Vec<String> = std::fs::read_dir(root.join(folder))
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter(|e| e.path().is_file())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| n.ends_with(".json"))
                    .map(|n| format!("{}{}", prefix, n))
                    .collect();
                names.sort();
                names
            }
            Source::Memory(files) => files
                .keys()
                .filter(|k| k.ends_with(".json"))
                .filter(|k| k.strip_prefix(&prefix).map_or(false, |rest| !rest.contains('/')))
                .cloned()
                .collect(),
            Source::Empty => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_reads_like_the_folder_it_was_made_from() {
        let bundle = br#"{"files": {"sub/a_signatures.json": {"services": []}, "b.json": {"x": 1}, "policies/p.json": {}}}"#;
        let src = parse_bundle(bundle).unwrap();
        assert_eq!(src.json("b.json").unwrap()["x"], 1);
        assert_eq!(src.json_files_in("sub"), vec!["sub/a_signatures.json"]);
        assert_eq!(src.json_files_in(""), vec!["b.json"]);
        assert_eq!(src.read_first(&["sub/b.json", "b.json"]).unwrap().0, "b.json");
    }

    #[test]
    fn a_bundle_or_a_read_never_leaves_the_rules() {
        assert!(parse_bundle(br#"{"files": {"../etc/passwd": {}}}"#).is_err());
        assert!(parse_bundle(br#"{"files": {"/etc/passwd": {}}}"#).is_err());
        assert!(Source::Dir(PathBuf::from(REPO_RULES)).read("../Cargo.toml").is_none());
    }

    #[test]
    fn the_repo_folder_holds_the_rules() {
        let src = Source::Dir(PathBuf::from(REPO_RULES));
        assert!(src.json("linux_web_signatures.json").is_some());
        assert!(src.json("linux_web_processes.json").is_some());
        assert!(!src.json_files_in("policies").is_empty());
    }
}
