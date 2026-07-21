use crate::builder::GraphBuilder;

pub fn ingest_epss(epss_path: &std::path::Path, builder: &mut GraphBuilder) -> usize {
    let content = std::fs::read_to_string(epss_path).unwrap();
    let mut count = 0;

    for line in content.lines() {
        if line.starts_with('#') || line.starts_with("cve,") {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 3 {
            let cve_id = parts[0];
            if let (Ok(score), Ok(percentile)) = (parts[1].parse::<f32>(), parts[2].parse::<f32>()) {
                // Only set EPSS for CVEs that exist in the graph
                if let Some(node_id) = builder.lookup_node(cve_id) {
                    builder.set_epss(node_id, score, percentile);
                    count += 1;
                }
            }
        }
    }

    count
}
