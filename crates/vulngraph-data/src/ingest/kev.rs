use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

pub fn ingest_cisa_kev(kev_path: &std::path::Path, builder: &mut GraphBuilder) -> usize {
    let content = std::fs::read_to_string(kev_path).unwrap();
    let kev: serde_json::Value = serde_json::from_str(&content).unwrap();
    let mut count = 0;

    if let Some(vulns) = kev.get("vulnerabilities").and_then(|v| v.as_array()) {
        for vuln in vulns {
            if let Some(cve_id) = vuln.get("cveID").and_then(|v| v.as_str()) {
                // Get or create the CVE node (it should already exist from cvelistV5)
                let node_id = builder.get_or_create_node(cve_id, NodeType::CVE);

                // Create an exploit node for this KEV entry
                let kev_id = format!("KEV:{}", cve_id);
                let exploit_node = builder.get_or_create_node(&kev_id, NodeType::EXPLOIT);
                builder.add_edge(node_id, exploit_node, EdgeType::EXPLOITED_IN_WILD);

                count += 1;
            }
        }
    }

    count
}
