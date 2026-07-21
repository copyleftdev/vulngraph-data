use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

pub fn ingest_poc_github(poc_dir: &std::path::Path, builder: &mut GraphBuilder) -> usize {
    let mut count = 0;

    // Structure: PoC-in-GitHub/{year}/{CVE-XXXX-XXXX}.json
    let entries = match std::fs::read_dir(poc_dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };

    for year_entry in entries.flatten() {
        let year_path = year_entry.path();
        if !year_path.is_dir() { continue; }

        let files = match std::fs::read_dir(&year_path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for file_entry in files.flatten() {
            let path = file_entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                // Filename is CVE-XXXX-XXXX.json
                let cve_id = path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");

                if !cve_id.starts_with("CVE-") { continue; }

                if let Some(cve_nid) = builder.lookup_node(cve_id) {
                    // Count PoC repos from JSON array
                    if let Ok(content) = std::fs::read_to_string(&path)
                        && let Ok(arr) = serde_json::from_str::<serde_json::Value>(&content) {
                            let poc_count = arr.as_array().map(|a| a.len()).unwrap_or(1);
                            // Create one exploit node per PoC repo (cap at 10 to avoid bloat)
                            let limit = poc_count.min(10);
                            for i in 0..limit {
                                let poc_id = format!("GitHub-PoC:{}:{}", cve_id, i);
                                let poc_nid = builder.get_or_create_node(&poc_id, NodeType::EXPLOIT);
                                builder.add_edge(cve_nid, poc_nid, EdgeType::HAS_POC);
                                count += 1;
                            }
                        }
                }
            }
        }
    }

    count
}
