pub mod cvelistv5;
pub mod epss;
pub mod kev;
pub mod exploitdb;
pub mod poc_github;
pub mod nuclei;
pub mod attack;
pub mod osv;
pub mod capec;
pub mod sigma;
pub mod ghsa;
pub mod deps_dev;

use std::path::Path;

/// Walk directory recursively, calling callback on each `.json` file.
pub fn walk_json_files(dir: &Path, callback: &mut dyn FnMut(&Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_json_files(&path, callback);
        } else if path.extension().is_some_and(|e| e == "json") {
            callback(&path);
        }
    }
}

/// Walk directory recursively, calling callback on each `.yaml`/`.yml` file.
pub fn walk_yaml_files(dir: &Path, callback: &mut dyn FnMut(&Path)) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_yaml_files(&path, callback);
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            callback(&path);
        }
    }
}

/// Get file/dir modification time as ISO 8601 string.
pub fn source_mtime(path: &Path) -> String {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| {
            let dur = t.duration_since(std::time::UNIX_EPOCH).ok()?;
            let secs = dur.as_secs();
            let days = secs / 86400;
            let mut year = 1970u64;
            let mut remaining = days;
            loop {
                let diy = if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) { 366 } else { 365 };
                if remaining < diy { break; }
                remaining -= diy;
                year += 1;
            }
            let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
            let dim: [u64; 12] = if leap {
                [31,29,31,30,31,30,31,31,30,31,30,31]
            } else {
                [31,28,31,30,31,30,31,31,30,31,30,31]
            };
            let mut month = 1u64;
            for &d in &dim {
                if remaining < d { break; }
                remaining -= d;
                month += 1;
            }
            let day = remaining + 1;
            let hh = (secs % 86400) / 3600;
            let mm = (secs % 3600) / 60;
            let ss = secs % 60;
            Some(format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z"))
        })
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get file/dir modification time as epoch seconds (0 if unavailable).
pub fn source_mtime_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Version range entry per package per CVE: (introduced, fixed).
pub type VersionRanges = std::collections::HashMap<String, std::collections::HashMap<String, Vec<(String, Option<String>)>>>;
