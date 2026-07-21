use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

pub fn ingest_nuclei(nuclei_dir: &std::path::Path, builder: &mut GraphBuilder) -> usize {
    let mut count = 0;

    // Walk all .yaml files under nuclei-templates/*/cves/
    super::walk_yaml_files(nuclei_dir, &mut |path| {
        if let Ok(content) = std::fs::read_to_string(path) {
            // Extract template ID from "id: CVE-XXXX-XXXX" line
            let mut template_cve = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(id) = trimmed.strip_prefix("id:") {
                    let id = id.trim();
                    if id.starts_with("CVE-") {
                        template_cve = Some(id.to_string());
                    }
                    break;
                }
            }

            if let Some(cve_id) = template_cve
                && let Some(cve_nid) = builder.lookup_node(&cve_id) {
                    let nuclei_id = format!("Nuclei:{}", cve_id);
                    let nuclei_nid = builder.get_or_create_node(&nuclei_id, NodeType::EXPLOIT);
                    builder.add_edge(cve_nid, nuclei_nid, EdgeType::HAS_POC);
                    count += 1;
                }
        }
    });

    count
}
