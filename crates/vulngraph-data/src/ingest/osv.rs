use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

pub fn ingest_osv(
    osv_dir: &std::path::Path,
    builder: &mut GraphBuilder,
) -> (usize, usize, super::VersionRanges) {
    let mut vuln_count = 0usize;
    let mut link_count = 0usize;
    let mut processed = 0usize;
    let mut version_ranges: super::VersionRanges = std::collections::HashMap::new();

    let entries: Vec<_> = match std::fs::read_dir(osv_dir) {
        Ok(e) => e.flatten().collect(),
        Err(_) => return (0, 0, version_ranges),
    };

    for entry in &entries {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") { continue; }

        processed += 1;
        if processed.is_multiple_of(100_000) {
            eprintln!("  ... {} OSV files processed", processed);
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let doc: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Find CVE aliases for this vuln
        let osv_id = doc.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let aliases = doc.get("aliases").and_then(|v| v.as_array());
        let mut cve_ids: Vec<String> = Vec::new();

        if osv_id.starts_with("CVE-") {
            cve_ids.push(osv_id.to_string());
        }
        if let Some(arr) = aliases {
            for alias in arr {
                if let Some(s) = alias.as_str()
                    && s.starts_with("CVE-") && !cve_ids.contains(&s.to_string()) {
                        cve_ids.push(s.to_string());
                    }
            }
        }

        if cve_ids.is_empty() { continue; }

        // Extract affected packages
        let affected = match doc.get("affected").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => continue,
        };

        let mut linked = false;
        for a in affected {
            let pkg = match a.get("package") {
                Some(p) => p,
                None => continue,
            };
            let name = match pkg.get("name").and_then(|v| v.as_str()) {
                Some(n) => n,
                None => continue,
            };
            let ecosystem = pkg.get("ecosystem").and_then(|v| v.as_str()).unwrap_or("unknown");

            // Normalize ecosystem name
            let eco_norm = ecosystem.split(':').next().unwrap_or(ecosystem);
            let pkg_id = format!("{}:{}", eco_norm, name);
            let pkg_nid = builder.get_or_create_node(&pkg_id, NodeType::PACKAGE);

            // Extract version ranges (SEMVER or ECOSYSTEM) for this package->CVE
            let mut ranges_for_pkg: Vec<(String, Option<String>)> = Vec::new();
            if let Some(range_arr) = a.get("ranges").and_then(|v| v.as_array()) {
                for range in range_arr {
                    let rtype = range.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if rtype != "SEMVER" && rtype != "ECOSYSTEM" {
                        continue;
                    }
                    if let Some(events) = range.get("events").and_then(|v| v.as_array()) {
                        let mut introduced: Option<String> = None;
                        let range_start_len = ranges_for_pkg.len();
                        for event in events {
                            if let Some(i) = event.get("introduced").and_then(|v| v.as_str()) {
                                introduced = Some(i.to_string());
                            }
                            if let Some(f) = event.get("fixed").and_then(|v| v.as_str()) {
                                ranges_for_pkg.push((
                                    introduced.clone().unwrap_or("0".to_string()),
                                    Some(f.to_string()),
                                ));
                            }
                            // OSV `last_affected` is inclusive upper bound — vulnerable
                            // through version X, no later "fixed" event. Convert to the
                            // exclusive-fix shape by bumping the final numeric component
                            // so downstream `version_in_ranges` (strict `<`) stays correct.
                            if let Some(la) = event.get("last_affected").and_then(|v| v.as_str()) {
                                ranges_for_pkg.push((
                                    introduced.clone().unwrap_or("0".to_string()),
                                    Some(bump_last_component(la)),
                                ));
                            }
                        }
                        // If introduced but no terminal event (fixed/last_affected) -> still vulnerable
                        if let Some(intro) = introduced.clone() && ranges_for_pkg.len() == range_start_len {
                            ranges_for_pkg.push((intro, None));
                        }
                    }
                }
            }

            for cve_id in &cve_ids {
                if let Some(cve_nid) = builder.lookup_node(cve_id) {
                    builder.add_edge(cve_nid, pkg_nid, EdgeType::AFFECTS);
                    link_count += 1;
                    linked = true;
                }

                // Store version ranges if we have them
                if !ranges_for_pkg.is_empty() {
                    version_ranges
                        .entry(pkg_id.clone())
                        .or_default()
                        .entry(cve_id.clone())
                        .or_default()
                        .extend(ranges_for_pkg.iter().cloned());
                }
            }
        }

        if linked { vuln_count += 1; }
    }

    (vuln_count, link_count, version_ranges)
}

/// Increment the last numeric dot-component of a semver-ish string, preserving
/// any prerelease / build suffix semantics by stripping them first. Used to
/// translate OSV `last_affected: X` (inclusive) into an exclusive-fixed range
/// so the downstream strict-less-than comparator produces correct results.
///
/// Examples: "0.2.0" -> "0.2.1", "1.0" -> "1.1", "1.0.0-rc1" -> "1.0.1".
/// Falls back to appending ".1" if the last component isn't numeric.
fn bump_last_component(v: &str) -> String {
    let core = v.split_once('-').map(|(c, _)| c).unwrap_or(v);
    let core = core.split_once('+').map(|(c, _)| c).unwrap_or(core);
    let parts: Vec<&str> = core.split('.').collect();
    if parts.is_empty() {
        return format!("{v}.1");
    }
    let last = parts[parts.len() - 1];
    match last.parse::<u64>() {
        Ok(n) => {
            let mut out: Vec<String> = parts[..parts.len() - 1]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            out.push((n + 1).to_string());
            out.join(".")
        }
        Err(_) => format!("{core}.1"),
    }
}

#[cfg(test)]
mod tests {
    use super::bump_last_component;

    #[test]
    fn bumps_patch() {
        assert_eq!(bump_last_component("0.2.0"), "0.2.1");
        assert_eq!(bump_last_component("1.10.3"), "1.10.4");
    }

    #[test]
    fn bumps_minor_when_no_patch() {
        assert_eq!(bump_last_component("1.0"), "1.1");
    }

    #[test]
    fn strips_prerelease_and_build() {
        assert_eq!(bump_last_component("1.0.0-rc1"), "1.0.1");
        assert_eq!(bump_last_component("2.3.4+build.7"), "2.3.5");
    }

    #[test]
    fn non_numeric_last_component_falls_back() {
        assert_eq!(bump_last_component("abc"), "abc.1");
    }
}
