//! CAPEC ingest — bridges CWE weaknesses to ATT&CK techniques.
//!
//! Pipeline:
//! 1. Parse CWE XML → extract CWE→CAPEC mappings (Related_Attack_Patterns)
//! 2. Parse CAPEC XML → extract CAPEC→ATT&CK technique mappings (Taxonomy_Mappings)
//! 3. Join on CAPEC ID → create CWE→Technique edges (USES_TECHNIQUE)

use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::path::Path;

/// Parse the CWE XML file and extract CWE_ID → [CAPEC_ID] mappings.
fn parse_cwe_to_capec(cwe_xml: &Path) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    let content = match std::fs::read_to_string(cwe_xml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  WARN: could not read CWE XML: {}", e);
            return map;
        }
    };

    let mut reader = Reader::from_str(&content);
    let mut current_cwe: Option<String> = None;
    let mut in_related_attack_patterns = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"Weakness" => {
                        current_cwe = None;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"ID"
                                && let Ok(id) = std::str::from_utf8(&attr.value) {
                                    current_cwe = Some(format!("CWE-{}", id));
                                }
                        }
                    }
                    b"Related_Attack_Patterns" => {
                        in_related_attack_patterns = true;
                    }
                    b"Related_Attack_Pattern" if in_related_attack_patterns => {
                        if let Some(ref cwe_id) = current_cwe {
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"CAPEC_ID"
                                    && let Ok(capec_id) = std::str::from_utf8(&attr.value) {
                                        map.entry(cwe_id.clone())
                                            .or_default()
                                            .push(capec_id.to_string());
                                    }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) if e.name().as_ref() == b"Related_Attack_Patterns" => {
                in_related_attack_patterns = false;
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                eprintln!("  WARN: CWE XML parse error: {}", e);
                break;
            }
            _ => {}
        }
    }

    map
}

/// Parse the CAPEC XML file and extract CAPEC_ID → [ATT&CK technique ID] mappings.
fn parse_capec_to_attack(capec_xml: &Path) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    let content = match std::fs::read_to_string(capec_xml) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  WARN: could not read CAPEC XML: {}", e);
            return map;
        }
    };

    let mut reader = Reader::from_str(&content);
    let mut current_capec: Option<String> = None;
    let mut in_taxonomy_mapping = false;
    let mut is_attack_mapping = false;
    let mut in_entry_id = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"Attack_Pattern" => {
                        current_capec = None;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"ID"
                                && let Ok(id) = std::str::from_utf8(&attr.value) {
                                    current_capec = Some(id.to_string());
                                }
                        }
                    }
                    b"Taxonomy_Mapping" => {
                        is_attack_mapping = false;
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Taxonomy_Name"
                                && let Ok(val) = std::str::from_utf8(&attr.value)
                                && val == "ATTACK" {
                                    is_attack_mapping = true;
                                    in_taxonomy_mapping = true;
                                }
                        }
                    }
                    b"Entry_ID" if is_attack_mapping => {
                        in_entry_id = true;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) if in_entry_id => {
                if let (Some(capec_id), Ok(text)) = (&current_capec, e.unescape()) {
                    let technique_id = text.trim().to_string();
                    if !technique_id.is_empty() {
                        // ATT&CK IDs: "1059" → "T1059", "1574.010" → "T1574.010"
                        let full_id = format!("T{}", technique_id);
                        map.entry(capec_id.clone())
                            .or_default()
                            .push(full_id);
                    }
                }
                in_entry_id = false;
            }
            Ok(Event::End(ref e)) => {
                match e.name().as_ref() {
                    b"Taxonomy_Mapping" => {
                        in_taxonomy_mapping = false;
                        is_attack_mapping = false;
                    }
                    b"Entry_ID" => {
                        in_entry_id = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                eprintln!("  WARN: CAPEC XML parse error: {}", e);
                break;
            }
            _ => {}
        }
    }

    let _ = in_taxonomy_mapping; // suppress unused warning
    map
}

/// Ingest CWE→CAPEC→ATT&CK mappings and create CWE→Technique edges.
pub fn ingest_capec_bridge(
    cwe_xml: &Path,
    capec_xml: &Path,
    builder: &mut GraphBuilder,
) -> (usize, usize) {
    // Step 1: CWE→CAPEC from CWE XML
    let cwe_to_capec = parse_cwe_to_capec(cwe_xml);

    // Step 2: CAPEC→ATT&CK from CAPEC XML
    let capec_to_attack = parse_capec_to_attack(capec_xml);

    eprintln!(
        "  CWE→CAPEC: {} CWEs with mappings, CAPEC→ATT&CK: {} CAPECs with mappings",
        cwe_to_capec.len(),
        capec_to_attack.len()
    );

    // Step 3: Bridge — for each CWE→CAPEC→Technique chain, create CWE→Technique edge
    let mut edges_created = 0usize;
    let mut cwe_count = 0usize;
    let mut seen_edges: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for (cwe_id, capec_ids) in &cwe_to_capec {
        let mut cwe_has_technique = false;

        for capec_id in capec_ids {
            if let Some(technique_ids) = capec_to_attack.get(capec_id) {
                for tech_id in technique_ids {
                    let edge_key = (cwe_id.clone(), tech_id.clone());
                    if seen_edges.insert(edge_key) {
                        // Only create edge if both nodes exist in the graph
                        let cwe_node = builder.lookup_node(cwe_id);
                        let tech_node = builder.lookup_node(tech_id);

                        if let (Some(cwe_nid), Some(tech_nid)) = (cwe_node, tech_node) {
                            builder.add_edge(cwe_nid, tech_nid, EdgeType::USES_TECHNIQUE);
                            edges_created += 1;
                            cwe_has_technique = true;
                        }
                    }
                }
            }
        }

        if cwe_has_technique {
            cwe_count += 1;
        }
    }

    (cwe_count, edges_created)
}
