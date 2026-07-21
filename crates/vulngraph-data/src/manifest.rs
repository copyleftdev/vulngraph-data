use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// The semantic content of a release: files whose bytes define the graph.
/// `meta.json` and `freshness.json` are excluded — they embed build
/// timestamps, and including them would make every rebuild look like a new
/// snapshot even when nothing changed.
pub const SEMANTIC_FILES: &[&str] = &[
    "desc_index.bin",
    "desc_strings.bin",
    "edges_fwd.bin",
    "edges_rev.bin",
    "idx_extid.bin",
    "nodes.bin",
    "props_cvss.bin",
    "props_epss.bin",
    "props_epss_pct.bin",
    "props_published.bin",
    "strings.bin",
    "version_ranges.json",
];

/// Sidecar files shipped and hash-verified at install time, but excluded
/// from the snapshot identity.
pub const SIDECAR_FILES: &[&str] = &["meta.json", "freshness.json"];

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FileEntry {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DemoBlob {
    pub file: String,
    pub bytes: u64,
    pub sha256: String,
    pub vgdb_version: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Manifest {
    pub manifest_version: u32,
    /// Deterministic content identity over SEMANTIC_FILES (see snapshot_id()).
    pub snapshot_id: String,
    /// Binary format version, copied from the db's meta.json.
    pub format_version: u64,
    /// vulngraph-engine git tag the builder was compiled against.
    pub engine_rev: String,
    pub created_at: String,
    pub node_count: u64,
    pub edge_count: u64,
    /// Per-file size + hash for every shipped db file (semantic + sidecar).
    pub files: BTreeMap<String, FileEntry>,
    /// Per-source freshness, copied from the db's freshness.json.
    pub sources: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demo_blob: Option<DemoBlob>,
}

pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let bytes = std::io::copy(&mut file, &mut hasher)?;
    Ok((hex::encode(hasher.finalize()), bytes))
}

/// Compute the snapshot identity of a db directory: sha256 over
/// `filename \0 sha256(file) \n` for each SEMANTIC_FILES entry that exists,
/// in the fixed (sorted) order above. A missing semantic file changes the
/// identity because its line is absent.
pub fn snapshot_id(db_dir: &Path) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    for name in SEMANTIC_FILES {
        let path = db_dir.join(name);
        if !path.exists() {
            continue;
        }
        let (hash, _) = sha256_file(&path)?;
        hasher.update(name.as_bytes());
        hasher.update([0u8]);
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Format unix seconds as ISO 8601 UTC. Hand-computed (no chrono), same
/// algorithm as ingest::source_mtime.
pub fn iso8601_utc(secs: u64) -> String {
    let days = secs / 86400;
    let mut year = 1970u64;
    let mut remaining = days;
    loop {
        let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
        let diy = if leap { 366 } else { 365 };
        if remaining < diy {
            break;
        }
        remaining -= diy;
        year += 1;
    }
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let dim: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for &d in &dim {
        if remaining < d {
            break;
        }
        remaining -= d;
        month += 1;
    }
    let day = remaining + 1;
    let hh = (secs % 86400) / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_id_is_deterministic_and_content_sensitive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.bin"), b"abc").unwrap();
        std::fs::write(dir.path().join("strings.bin"), b"def").unwrap();
        std::fs::write(dir.path().join("meta.json"), b"{\"ts\": 1}").unwrap();

        let a = snapshot_id(dir.path()).unwrap();
        let b = snapshot_id(dir.path()).unwrap();
        assert_eq!(a, b);

        // meta.json is not semantic — changing it must not change identity
        std::fs::write(dir.path().join("meta.json"), b"{\"ts\": 2}").unwrap();
        assert_eq!(a, snapshot_id(dir.path()).unwrap());

        // semantic content change must change identity
        std::fs::write(dir.path().join("nodes.bin"), b"abd").unwrap();
        assert_ne!(a, snapshot_id(dir.path()).unwrap());
    }

    #[test]
    fn iso8601_epoch_and_leap() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(951782400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601_utc(1784538243), "2026-07-20T09:04:03Z");
    }
}
