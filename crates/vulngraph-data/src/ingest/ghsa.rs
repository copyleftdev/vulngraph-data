use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

/// Ingest GitHub Security Advisories from OSV-format JSON files.
///
/// Reads GHSA-*.json files from the OSV extracted directory (already downloaded
/// by the OSV ingest step). Creates ADVISORY nodes and links them to CVE nodes
/// via REFERENCES edges.
///
/// This is complementary to osv.rs — OSV extracts package→CVE links, while
/// GHSA creates advisory→CVE cross-references using the dormant ADVISORY type.
pub fn ingest_ghsa(
    ghsa_dir: &std::path::Path,
    builder: &mut GraphBuilder,
) -> (usize, usize) {
    let mut advisory_count = 0usize;
    let mut ref_count = 0usize;
    let mut processed = 0usize;

    let entries: Vec<_> = match std::fs::read_dir(ghsa_dir) {
        Ok(e) => e.flatten().collect(),
        Err(_) => return (0, 0),
    };

    for entry in &entries {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") { continue; }

        // Only process GHSA files (skip other OSV entries like PYSEC, RUSTSEC, etc.)
        let fname = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if !fname.starts_with("GHSA-") { continue; }

        processed += 1;
        if processed.is_multiple_of(10_000) {
            eprintln!("  ... {} GHSA files processed", processed);
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let doc: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let ghsa_id = match doc.get("id").and_then(|v| v.as_str()) {
            Some(id) if id.starts_with("GHSA-") => id,
            _ => continue,
        };

        // Collect CVE aliases
        let mut cve_ids: Vec<&str> = Vec::new();
        if let Some(aliases) = doc.get("aliases").and_then(|v| v.as_array()) {
            for alias in aliases {
                if let Some(s) = alias.as_str()
                    && s.starts_with("CVE-") {
                        cve_ids.push(s);
                    }
            }
        }

        // Only create advisory node if it references at least one known CVE
        let mut linked = false;
        let advisory_nid = builder.get_or_create_node(ghsa_id, NodeType::ADVISORY);

        for cve_id in &cve_ids {
            if let Some(cve_nid) = builder.lookup_node(cve_id) {
                builder.add_edge(advisory_nid, cve_nid, EdgeType::REFERENCES);
                ref_count += 1;
                linked = true;
            }
        }

        if linked {
            advisory_count += 1;
        }
    }

    (advisory_count, ref_count)
}
