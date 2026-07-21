use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

/// Ingest Sigma detection rules from the SigmaHQ repository.
///
/// Creates EXPLOIT nodes (Sigma:{uuid}) and links them to:
///   - TECHNIQUE nodes via USES_TECHNIQUE (from `tags: attack.tXXXX`)
///   - CVE nodes via HAS_POC (from `tags: cve.YYYY.NNNNN`)
///
/// Skips rules with status "deprecated" or "unsupported".
pub fn ingest_sigma(sigma_dir: &std::path::Path, builder: &mut GraphBuilder) -> usize {
    let mut count = 0;

    super::walk_yaml_files(sigma_dir, &mut |path| {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut rule_id: Option<String> = None;
        let mut status: Option<String> = None;
        let mut technique_tags: Vec<String> = Vec::new();
        let mut cve_tags: Vec<String> = Vec::new();
        let mut in_tags = false;

        for line in content.lines() {
            let trimmed = line.trim();

            // A non-indented, non-empty line ends the tags block
            if in_tags && !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
                in_tags = false;
            }

            if trimmed.starts_with("id:") && rule_id.is_none() {
                let val = trimmed[3..].trim().trim_matches('"').trim_matches('\'');
                if !val.is_empty() {
                    rule_id = Some(val.to_string());
                }
            } else if trimmed.starts_with("status:") && status.is_none() {
                status = Some(trimmed[7..].trim().to_string());
            } else if trimmed == "tags:" {
                in_tags = true;
            } else if in_tags && trimmed.starts_with("- ") {
                let tag = trimmed[2..].trim().to_lowercase();

                // ATT&CK technique: attack.t1566 or attack.t1566.001
                if let Some(rest) = tag.strip_prefix("attack.t")
                    && rest.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        technique_tags.push(format!("T{}", rest).to_uppercase());
                    }

                // CVE tag: cve.2024.4577 -> CVE-2024-4577
                if let Some(rest) = tag.strip_prefix("cve.") {
                    let cve_id = format!("CVE-{}", rest.replace('.', "-")).to_uppercase();
                    cve_tags.push(cve_id);
                }
            }
        }

        // Skip deprecated/unsupported rules
        if let Some(ref s) = status
            && (s == "deprecated" || s == "unsupported") {
                return;
            }

        let uuid = match rule_id {
            Some(id) => id,
            None => return,
        };

        // Must reference at least one technique or CVE to be useful in the graph
        if technique_tags.is_empty() && cve_tags.is_empty() {
            return;
        }

        let sigma_id = format!("Sigma:{}", uuid);
        let sigma_nid = builder.get_or_create_node(&sigma_id, NodeType::EXPLOIT);

        for tech_id in &technique_tags {
            if let Some(tech_nid) = builder.lookup_node(tech_id) {
                builder.add_edge(sigma_nid, tech_nid, EdgeType::USES_TECHNIQUE);
                count += 1;
            }
        }

        for cve_id in &cve_tags {
            if let Some(cve_nid) = builder.lookup_node(cve_id) {
                builder.add_edge(cve_nid, sigma_nid, EdgeType::HAS_POC);
                count += 1;
            }
        }
    });

    count
}
