use std::path::PathBuf;
use std::time::Instant;
use crate::builder::GraphBuilder;
use crate::ingest;
use crate::BuildArgs;

pub fn cmd_build(args: &BuildArgs) {
    let sources = PathBuf::from(&args.sources);
    let output = PathBuf::from(&args.output);

    eprintln!("Building VulnGraph from: {}", sources.display());
    eprintln!("Output: {}", output.display());

    let total_start = Instant::now();
    let mut builder = GraphBuilder::new(&output);
    let mut source_freshness: std::collections::BTreeMap<String, serde_json::Value> =
        std::collections::BTreeMap::new();
    let mut version_ranges: ingest::VersionRanges = std::collections::HashMap::new();

    // Stamp every record with a source-derived timestamp so identical sources
    // produce byte-identical output (the release snapshot_id depends on it).
    let build_ts_secs = [
        sources.join("cvelistV5/cves"),
        sources.join("epss/epss_scores-current.csv"),
        sources.join("cisa-kev/known_exploited_vulnerabilities.json"),
        sources.join("exploitdb/files_exploits.csv"),
        sources.join("PoC-in-GitHub"),
        sources.join("nuclei-templates"),
        sources.join("attack-stix-data/enterprise-attack/enterprise-attack.json"),
        sources.join("sigma/rules"),
        sources.join("osv/extracted"),
        sources.join("cwe/cwec_v4.19.1.xml"),
        sources.join("capec/capec_latest.xml"),
        sources.join("deps-dev"),
    ]
    .iter()
    .map(|p| ingest::source_mtime_secs(p))
    .max()
    .unwrap_or(0);
    builder.set_build_timestamp(build_ts_secs.max(1) * 1_000_000);

    // ── Ingest cvelistV5 ────────────────────────
    let cve_dir = sources.join("cvelistV5/cves");
    if cve_dir.exists() {
        eprintln!("\n[ingest] cvelistV5...");
        let start = Instant::now();
        let count = ingest::cvelistv5::ingest_cvelistv5(&cve_dir, &mut builder, &mut version_ranges);
        eprintln!(
            "[ingest] cvelistV5: {} CVEs in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "cvelistV5".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&cve_dir) }),
        );
    } else {
        eprintln!("[skip] cvelistV5 not found at {}", cve_dir.display());
    }

    // ── Ingest EPSS ─────────────────────────────
    let epss_path = sources.join("epss/epss_scores-current.csv");
    if epss_path.exists() {
        eprintln!("\n[ingest] EPSS...");
        let start = Instant::now();
        let count = ingest::epss::ingest_epss(&epss_path, &mut builder);
        eprintln!(
            "[ingest] EPSS: {} scores in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "epss".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&epss_path) }),
        );
    } else {
        eprintln!("[skip] EPSS not found at {}", epss_path.display());
    }

    // ── Ingest CISA KEV ─────────────────────────
    let kev_path = sources.join("cisa-kev/known_exploited_vulnerabilities.json");
    if kev_path.exists() {
        eprintln!("\n[ingest] CISA KEV...");
        let start = Instant::now();
        let count = ingest::kev::ingest_cisa_kev(&kev_path, &mut builder);
        eprintln!(
            "[ingest] CISA KEV: {} entries in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "cisa_kev".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&kev_path) }),
        );
    } else {
        eprintln!("[skip] CISA KEV not found at {}", kev_path.display());
    }

    // ── Ingest ExploitDB ──────────────────────────
    let edb_path = sources.join("exploitdb/files_exploits.csv");
    if edb_path.exists() {
        eprintln!("\n[ingest] ExploitDB...");
        let start = Instant::now();
        let count = ingest::exploitdb::ingest_exploitdb(&edb_path, &mut builder);
        eprintln!(
            "[ingest] ExploitDB: {} exploit→CVE links in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "exploitdb".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&edb_path) }),
        );
    } else {
        eprintln!("[skip] ExploitDB not found at {}", edb_path.display());
    }

    // ── Ingest PoC-in-GitHub ──────────────────────
    let poc_dir = sources.join("PoC-in-GitHub");
    if poc_dir.exists() {
        eprintln!("\n[ingest] PoC-in-GitHub...");
        let start = Instant::now();
        let count = ingest::poc_github::ingest_poc_github(&poc_dir, &mut builder);
        eprintln!(
            "[ingest] PoC-in-GitHub: {} PoC→CVE links in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "poc_in_github".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&poc_dir) }),
        );
    } else {
        eprintln!("[skip] PoC-in-GitHub not found at {}", poc_dir.display());
    }

    // ── Ingest Nuclei templates ───────────────────
    let nuclei_dir = sources.join("nuclei-templates");
    if nuclei_dir.exists() {
        eprintln!("\n[ingest] Nuclei templates...");
        let start = Instant::now();
        let count = ingest::nuclei::ingest_nuclei(&nuclei_dir, &mut builder);
        eprintln!(
            "[ingest] Nuclei: {} template→CVE links in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "nuclei".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&nuclei_dir) }),
        );
    } else {
        eprintln!("[skip] Nuclei templates not found at {}", nuclei_dir.display());
    }

    // ── Ingest ATT&CK ────────────────────────────
    let attack_path = sources.join("attack-stix-data/enterprise-attack/enterprise-attack.json");
    if attack_path.exists() {
        eprintln!("\n[ingest] MITRE ATT&CK...");
        let start = Instant::now();
        let counts = ingest::attack::ingest_attack(&attack_path, &mut builder);
        eprintln!(
            "[ingest] ATT&CK: {} techniques, {} actors, {} software, {} relationships in {:.1}s",
            counts.0, counts.1, counts.2, counts.3, start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "attack".to_string(),
            serde_json::json!({
                "items": counts.0 + counts.1 + counts.2 + counts.3,
                "updated_at": ingest::source_mtime(&attack_path),
            }),
        );
    } else {
        eprintln!("[skip] ATT&CK not found at {}", attack_path.display());
    }

    // ── Ingest Sigma Rules ────────────────────────
    let sigma_dir = sources.join("sigma/rules");
    if sigma_dir.exists() {
        eprintln!("\n[ingest] Sigma detection rules...");
        let start = Instant::now();
        let count = ingest::sigma::ingest_sigma(&sigma_dir, &mut builder);
        eprintln!(
            "[ingest] Sigma: {} rule→technique/CVE links in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "sigma".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&sigma_dir) }),
        );
    } else {
        eprintln!("[skip] Sigma rules not found at {}", sigma_dir.display());
    }

    // ── Ingest OSV ────────────────────────────────
    let osv_dir = sources.join("osv/extracted");
    if osv_dir.exists() {
        eprintln!("\n[ingest] OSV...");
        let start = Instant::now();
        let (vulns, links, vr) = ingest::osv::ingest_osv(&osv_dir, &mut builder);
        // Merge OSV version ranges into the map (CVE ingest may have populated some already)
        for (pkg, cves) in vr {
            let pkg_entry = version_ranges.entry(pkg).or_default();
            for (cve_id, ranges) in cves {
                pkg_entry.entry(cve_id).or_default().extend(ranges);
            }
        }
        eprintln!(
            "[ingest] OSV: {} vulns, {} package→CVE links, {} version ranges in {:.1}s",
            vulns,
            links,
            version_ranges.values().map(|m| m.len()).sum::<usize>(),
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "osv".to_string(),
            serde_json::json!({ "items": vulns, "updated_at": ingest::source_mtime(&osv_dir) }),
        );
    } else {
        eprintln!("[skip] OSV not found at {}", osv_dir.display());
    }

    // ── Ingest GHSA advisories ─────────────────────
    // Reuses OSV extracted dir — filters for GHSA-*.json files
    let ghsa_dir = sources.join("osv/extracted");
    if ghsa_dir.exists() {
        eprintln!("\n[ingest] GHSA advisories...");
        let start = Instant::now();
        let (advisories, refs) = ingest::ghsa::ingest_ghsa(&ghsa_dir, &mut builder);
        eprintln!(
            "[ingest] GHSA: {} advisories, {} advisory→CVE references in {:.1}s",
            advisories,
            refs,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "ghsa".to_string(),
            serde_json::json!({ "items": advisories, "updated_at": ingest::source_mtime(&ghsa_dir) }),
        );
    } else {
        eprintln!("[skip] GHSA not found (requires OSV extracted data)");
    }

    // ── Bridge CWE → ATT&CK via CAPEC ─────────
    let cwe_xml = sources.join("cwe/cwec_v4.19.1.xml");
    let capec_xml = sources.join("capec/capec_latest.xml");
    if cwe_xml.exists() && capec_xml.exists() {
        eprintln!("\n[ingest] CWE→ATT&CK bridge (via CAPEC)...");
        let start = Instant::now();
        let (cwe_count, edge_count) =
            ingest::capec::ingest_capec_bridge(&cwe_xml, &capec_xml, &mut builder);
        eprintln!(
            "[ingest] CAPEC bridge: {} CWEs linked to techniques, {} edges in {:.1}s",
            cwe_count,
            edge_count,
            start.elapsed().as_secs_f64()
        );
    } else {
        if !cwe_xml.exists() {
            eprintln!("[skip] CWE XML not found at {}", cwe_xml.display());
        }
        if !capec_xml.exists() {
            eprintln!("[skip] CAPEC XML not found at {}", capec_xml.display());
        }
    }

    // ── Ingest deps.dev dependency graphs ──────────
    let deps_dir = sources.join("deps-dev");
    if deps_dir.exists() {
        eprintln!("\n[ingest] deps.dev dependency graphs...");
        let start = Instant::now();
        let count = ingest::deps_dev::ingest_deps_dev(&deps_dir, &mut builder);
        eprintln!(
            "[ingest] deps.dev: {} dependency edges in {:.1}s",
            count,
            start.elapsed().as_secs_f64()
        );
        source_freshness.insert(
            "deps_dev".to_string(),
            serde_json::json!({ "items": count, "updated_at": ingest::source_mtime(&deps_dir) }),
        );
    } else {
        eprintln!("[skip] deps.dev cache not found at {}", deps_dir.display());
    }

    // ── Build ───────────────────────────────────
    eprintln!(
        "\n[build] Flushing graph to disk...\n[build] Nodes: {}, Edges: {}",
        builder.node_count(),
        builder.edge_count()
    );
    let start = Instant::now();
    match builder.build() {
        Ok(path) => {
            if !version_ranges.is_empty() {
                let vr_path = path.join("version_ranges.json");
                // Sorted keys: HashMap iteration order must not leak into
                // on-disk output (snapshot determinism).
                let vr_sorted: std::collections::BTreeMap<_, std::collections::BTreeMap<_, _>> =
                    version_ranges
                        .iter()
                        .map(|(pkg, cves)| (pkg, cves.iter().collect()))
                        .collect();
                let vr_json = serde_json::to_string(&vr_sorted).unwrap();
                std::fs::write(&vr_path, &vr_json).unwrap();
                eprintln!(
                    "[build] writing version_ranges.json ({:.1} MB)",
                    vr_json.len() as f64 / 1_048_576.0
                );
            }

            let built_at = ingest::source_mtime(&path.join("meta.json"));
            let freshness = serde_json::json!({
                "sources": source_freshness,
                "built_at": built_at,
            });
            let freshness_json = serde_json::to_string_pretty(&freshness).unwrap();
            std::fs::write(path.join("freshness.json"), &freshness_json).unwrap();
            eprintln!(
                "[build] wrote freshness.json ({} sources)",
                source_freshness.len()
            );
            eprintln!("[build] Done in {:.1}s", start.elapsed().as_secs_f64());
            eprintln!(
                "[build] Total time: {:.1}s",
                total_start.elapsed().as_secs_f64()
            );
            eprintln!("[build] Graph at: {}", path.display());
        }
        Err(e) => {
            eprintln!("[build] FAILED: {}", e);
            std::process::exit(1);
        }
    }
}
