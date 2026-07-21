use std::path::PathBuf;
use crate::ExportDemoArgs;

pub fn cmd_export_demo(db: &str, args: &ExportDemoArgs) {
    let db_path = PathBuf::from(db);
    let out_path = PathBuf::from(&args.output);

    eprintln!("Exporting demo blob from: {}", db_path.display());

    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }

    let nodes_bin = std::fs::read(db_path.join("nodes.bin")).expect("nodes.bin");
    let edges_fwd_bin = std::fs::read(db_path.join("edges_fwd.bin")).expect("edges_fwd.bin");
    let edges_rev_bin = std::fs::read(db_path.join("edges_rev.bin")).expect("edges_rev.bin");
    let strings_bin = std::fs::read(db_path.join("strings.bin")).expect("strings.bin");
    let idx_bin = std::fs::read(db_path.join("idx_extid.bin")).expect("idx_extid.bin");
    let epss_bin = std::fs::read(db_path.join("props_epss.bin")).unwrap_or_default();
    let epss_pct_bin = std::fs::read(db_path.join("props_epss_pct.bin")).unwrap_or_default();
    let cvss_bin = std::fs::read(db_path.join("props_cvss.bin")).unwrap_or_default();
    // v3: descriptions + published dates
    let desc_index_bin = std::fs::read(db_path.join("desc_index.bin")).unwrap_or_default();
    let desc_strings_bin = std::fs::read(db_path.join("desc_strings.bin")).unwrap_or_default();
    let published_bin = std::fs::read(db_path.join("props_published.bin")).unwrap_or_default();

    let node_count = nodes_bin.len() / 48;
    let edge_count = edges_fwd_bin.len() / 32;
    let index_capacity = idx_bin.len() / 16;

    eprintln!("  Nodes: {}", node_count);
    eprintln!("  Edges: {}", edge_count);
    eprintln!("  Strings: {} bytes", strings_bin.len());
    eprintln!("  Index slots: {}", index_capacity);
    eprintln!("  CVSS scores: {} bytes", cvss_bin.len());
    eprintln!("  Descriptions: {} bytes index, {} bytes strings", desc_index_bin.len(), desc_strings_bin.len());

    let build_ts: u64 = std::fs::read_to_string(db_path.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.get("updated_at")?
                .as_str()?
                .trim_end_matches('Z')
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0);

    use std::io::Write;
    let mut out = std::io::BufWriter::new(std::fs::File::create(&out_path).unwrap());

    // v3 header: 40 bytes (was 32 in v2)
    out.write_all(b"VGDB").unwrap();                                     // 0-3: magic
    out.write_all(&3u32.to_le_bytes()).unwrap();                         // 4-7: version
    out.write_all(&(node_count as u32).to_le_bytes()).unwrap();          // 8-11: node_count
    out.write_all(&(edge_count as u32).to_le_bytes()).unwrap();          // 12-15: edge_count
    out.write_all(&(strings_bin.len() as u32).to_le_bytes()).unwrap();   // 16-19: strings_len
    out.write_all(&(index_capacity as u32).to_le_bytes()).unwrap();      // 20-23: index_capacity
    out.write_all(&build_ts.to_le_bytes()).unwrap();                     // 24-31: build_ts
    out.write_all(&(desc_strings_bin.len() as u32).to_le_bytes()).unwrap(); // 32-35: desc_strings_len
    out.write_all(&0u32.to_le_bytes()).unwrap();                         // 36-39: reserved

    // Data sections (order matters — WASM parser computes offsets sequentially)
    out.write_all(&nodes_bin).unwrap();
    out.write_all(&edges_fwd_bin).unwrap();
    out.write_all(&edges_rev_bin).unwrap();
    out.write_all(&strings_bin).unwrap();
    out.write_all(&idx_bin).unwrap();
    out.write_all(&epss_bin).unwrap();
    out.write_all(&epss_pct_bin).unwrap();
    out.write_all(&cvss_bin).unwrap();
    // v3 additions
    out.write_all(&desc_index_bin).unwrap();
    out.write_all(&desc_strings_bin).unwrap();
    out.write_all(&published_bin).unwrap();

    let freshness_json = std::fs::read(db_path.join("freshness.json")).unwrap_or_default();
    out.write_all(&freshness_json).unwrap();
    out.write_all(&(freshness_json.len() as u32).to_le_bytes())
        .unwrap();

    out.flush().unwrap();
    drop(out);

    let size = std::fs::metadata(&out_path).unwrap().len();
    eprintln!(
        "Exported: {} ({:.1} MB)",
        out_path.display(),
        size as f64 / 1_048_576.0
    );

    // Write version.json alongside the blob for cache busting.
    // app.js fetches this (no-cache) and appends ?v=<ts> to the blob URL.
    if let Some(parent) = out_path.parent() {
        let version = serde_json::json!({
            "blob": out_path.file_name().unwrap().to_str().unwrap(),
            "built_at": build_ts,
            "nodes": node_count,
            "edges": edge_count,
        });
        let vp = parent.join("version.json");
        std::fs::write(&vp, serde_json::to_string(&version).unwrap()).unwrap();
        eprintln!("Wrote: {}", vp.display());
    }
}
