use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;
use super::VersionRanges;

pub fn ingest_cvelistv5(
    cve_dir: &std::path::Path,
    builder: &mut GraphBuilder,
    version_ranges: &mut VersionRanges,
) -> usize {
    let mut count: usize = 0;

    // Walk year directories
    let mut year_dirs: Vec<_> = std::fs::read_dir(cve_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();
    year_dirs.sort_by_key(|e| e.file_name());

    for year_entry in year_dirs {
        let year_path = year_entry.path();
        // Walk subdirectories (CVE ID ranges)
        super::walk_json_files(&year_path, &mut |path| {
            if let Ok(content) = std::fs::read_to_string(path)
                && let Ok(cve) = serde_json::from_str::<serde_json::Value>(&content)
                && let Some(cve_id) = cve.pointer("/cveMetadata/cveId")
                    .and_then(|v| v.as_str())
                {
                        let node_id = builder.add_node(cve_id, NodeType::CVE);

                        // Extract description (first English entry)
                        if let Some(descs) = cve.pointer("/containers/cna/descriptions")
                            .and_then(|v| v.as_array())
                        {
                            let desc_text = descs.iter()
                                .find(|d| {
                                    d.get("lang").and_then(|l| l.as_str())
                                        .map(|l| l.starts_with("en"))
                                        .unwrap_or(false)
                                })
                                .or_else(|| descs.first())
                                .and_then(|d| d.get("value"))
                                .and_then(|v| v.as_str());
                            if let Some(text) = desc_text {
                                // Cap at 512 chars to keep the blob compact
                                let truncated = if text.len() > 512 {
                                    let mut end = 512;
                                    while end > 0 && !text.is_char_boundary(end) { end -= 1; }
                                    &text[..end]
                                } else {
                                    text
                                };
                                builder.set_description(node_id, truncated);
                            }
                        }

                        // Extract publication date
                        if let Some(published) = cve.pointer("/cveMetadata/datePublished")
                            .and_then(|v| v.as_str())
                            && let Some(epoch) = parse_iso8601_to_epoch(published) {
                                builder.set_published_at(node_id, epoch);
                        }

                        // Extract CWE classifications
                        if let Some(problems) = cve.pointer("/containers/cna/problemTypes")
                            && let Some(arr) = problems.as_array() {
                                for problem in arr {
                                    if let Some(descs) = problem.get("descriptions").and_then(|d| d.as_array()) {
                                        for desc in descs {
                                            if let Some(cwe_id) = desc.get("cweId").and_then(|v| v.as_str()) {
                                                let cwe_node = builder.get_or_create_node(cwe_id, NodeType::WEAKNESS);
                                                builder.add_edge(node_id, cwe_node, EdgeType::CLASSIFIED_AS);
                                            }
                                        }
                                    }
                                }
                        }

                        // Extract CVSS score from metrics (CNA first, then ADP fallback)
                        let cvss = extract_cvss_from_metrics(cve.pointer("/containers/cna/metrics"))
                            .or_else(|| {
                                // ADP containers (e.g. NVD) often have CVSS when CNA doesn't
                                cve.pointer("/containers/adp")
                                    .and_then(|v| v.as_array())
                                    .and_then(|adps| {
                                        adps.iter().find_map(|adp| {
                                            extract_cvss_from_metrics(adp.get("metrics"))
                                        })
                                    })
                            });
                        if let Some(s) = cvss {
                            builder.set_cvss(node_id, s as f32);
                        }

                        // Extract affected products as Package nodes + version ranges
                        if let Some(affected) = cve.pointer("/containers/cna/affected")
                            && let Some(arr) = affected.as_array() {
                                for product in arr {
                                    let vendor = product.get("vendor")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");
                                    let product_name = product.get("product")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("unknown");

                                    if vendor != "n/a" && product_name != "n/a" {
                                        let pkg_id = format!("cpe:{}:{}", vendor, product_name);
                                        let pkg_node = builder.get_or_create_node(&pkg_id, NodeType::PACKAGE);
                                        builder.add_edge(node_id, pkg_node, EdgeType::AFFECTS);

                                        // Extract version ranges for remediation
                                        extract_version_ranges(
                                            product, cve_id, &pkg_id, version_ranges,
                                        );
                                    }
                                }
                            }

                        count += 1;
                        if count.is_multiple_of(50_000) {
                            eprintln!("  ... {} CVEs processed", count);
                        }
                }
        });
    }

    count
}

/// Parse ISO8601 "YYYY-MM-DDTHH:MM:SS..." to Unix epoch seconds.
fn parse_iso8601_to_epoch(s: &str) -> Option<u64> {
    if s.len() < 19 { return None; }
    let year: i64 = s.get(0..4)?.parse().ok()?;
    let month: i64 = s.get(5..7)?.parse().ok()?;
    let day: i64 = s.get(8..10)?.parse().ok()?;
    let hour: i64 = s.get(11..13)?.parse().ok()?;
    let min: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (m * 306 + 5) / 10 + (day - 1) - 719468;
    let epoch = days * 86400 + hour * 3600 + min * 60 + sec;
    if epoch > 0 { Some(epoch as u64) } else { None }
}

/// Extract version ranges from a CVE "affected" product entry.
///
/// CVEList V5 format:
///   versions: [{ version: "7.0.0", status: "affected", lessThan: "7.0.8" }, ...]
///   defaultStatus: "unaffected"  (versions outside listed ranges are safe)
///
/// We extract: (introduced=version, fixed=lessThan) for each "affected" entry.
/// For "unaffected" entries with defaultStatus="affected", we record (introduced="0", fixed=version).
fn extract_version_ranges(
    product: &serde_json::Value,
    cve_id: &str,
    pkg_id: &str,
    version_ranges: &mut VersionRanges,
) {
    let versions = match product.get("versions").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => return,
    };

    let default_status = product.get("defaultStatus")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let pkg_entry = version_ranges.entry(pkg_id.to_string()).or_default();
    let cve_entry = pkg_entry.entry(cve_id.to_string()).or_default();

    for ver in versions {
        let status = ver.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
        let version = ver.get("version").and_then(|v| v.as_str()).unwrap_or("");

        if status == "affected" {
            // lessThan or lessThanOrEqual = the fix version
            let fix = ver.get("lessThan")
                .or_else(|| ver.get("lessThanOrEqual"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let introduced = if version.is_empty() { "0".to_string() } else { version.to_string() };
            cve_entry.push((introduced, fix));
        } else if status == "unaffected" && default_status == "affected" {
            // This version is a fix — everything before it is affected
            if !version.is_empty() {
                cve_entry.push(("0".to_string(), Some(version.to_string())));
            }
        }
    }
}

pub fn extract_cvss_from_metrics(metrics: Option<&serde_json::Value>) -> Option<f64> {
    let arr = metrics?.as_array()?;
    for metric in arr {
        // Try cvssV3_1, cvssV3_0, cvssV4_0 in preference order
        let score = metric.get("cvssV3_1")
            .or_else(|| metric.get("cvssV3_0"))
            .or_else(|| metric.get("cvssV4_0"))
            .and_then(|v| v.get("baseScore"))
            .and_then(|v| v.as_f64());
        if score.is_some() { return score; }
        // CVSS v2 fallback
        let v2 = metric.get("cvssV2_0")
            .and_then(|v| v.get("baseScore"))
            .and_then(|v| v.as_f64());
        if v2.is_some() { return v2; }
    }
    None
}
