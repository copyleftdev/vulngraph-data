use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

pub fn ingest_attack(
    attack_path: &std::path::Path,
    builder: &mut GraphBuilder,
) -> (usize, usize, usize, usize) {
    let content = std::fs::read_to_string(attack_path).unwrap();
    let bundle: serde_json::Value = serde_json::from_str(&content).unwrap();
    let objects = match bundle.get("objects").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return (0, 0, 0, 0),
    };

    let mut techniques = 0usize;
    let mut actors = 0usize;
    let mut software = 0usize;
    let mut rels = 0usize;

    // STIX ID -> our external ID mapping
    let mut stix_to_ext: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    // Pass 1: Create nodes for techniques, intrusion-sets, malware, tools
    for obj in objects {
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if obj.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false) { continue; }
        if obj.get("x_mitre_deprecated").and_then(|v| v.as_bool()).unwrap_or(false) { continue; }

        let stix_id = match obj.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };

        // Extract MITRE ATT&CK external ID (e.g., T1055, G0119, S0061)
        let ext_id = obj.get("external_references")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.iter().find(|r| {
                r.get("source_name").and_then(|v| v.as_str()) == Some("mitre-attack")
            }))
            .and_then(|r| r.get("external_id").and_then(|v| v.as_str()));

        let ext_id = match ext_id {
            Some(id) => id,
            None => continue,
        };

        match obj_type {
            "attack-pattern" => {
                builder.get_or_create_node(ext_id, NodeType::TECHNIQUE);
                stix_to_ext.insert(stix_id.to_string(), ext_id.to_string());
                techniques += 1;
            }
            "intrusion-set" => {
                builder.get_or_create_node(ext_id, NodeType::ACTOR);
                stix_to_ext.insert(stix_id.to_string(), ext_id.to_string());
                actors += 1;
            }
            "malware" | "tool" => {
                builder.get_or_create_node(ext_id, NodeType::SOFTWARE);
                stix_to_ext.insert(stix_id.to_string(), ext_id.to_string());
                software += 1;
            }
            _ => {}
        }
    }

    // Pass 2: Create edges from relationships
    for obj in objects {
        if obj.get("type").and_then(|v| v.as_str()) != Some("relationship") { continue; }
        if obj.get("revoked").and_then(|v| v.as_bool()).unwrap_or(false) { continue; }

        let rel_type = match obj.get("relationship_type").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => continue,
        };
        let source_stix = match obj.get("source_ref").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let target_stix = match obj.get("target_ref").and_then(|v| v.as_str()) {
            Some(t) => t,
            None => continue,
        };

        let source_ext = match stix_to_ext.get(source_stix) {
            Some(e) => e.clone(),
            None => continue,
        };
        let target_ext = match stix_to_ext.get(target_stix) {
            Some(e) => e.clone(),
            None => continue,
        };

        let source_nid = match builder.lookup_node(&source_ext) {
            Some(n) => n,
            None => continue,
        };
        let target_nid = match builder.lookup_node(&target_ext) {
            Some(n) => n,
            None => continue,
        };

        let edge_type = match rel_type {
            "uses" => EdgeType::USES_TECHNIQUE,
            "mitigates" => EdgeType::MITIGATES,
            "attributed-to" => EdgeType::ATTRIBUTED_TO,
            "subtechnique-of" => EdgeType::PARENT_OF,
            _ => continue,
        };

        builder.add_edge(source_nid, target_nid, edge_type);
        rels += 1;
    }

    (techniques, actors, software, rels)
}
