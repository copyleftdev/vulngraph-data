use crate::builder::GraphBuilder;
use vulngraph_engine::types::*;

/// Ingest dependency graphs from cached deps.dev API responses.
///
/// Reads JSON files from `deps_dir` (pre-fetched by scripts/fetch-deps-dev.sh).
/// Each file represents one package's direct dependencies. Creates DEPENDS_ON
/// edges between PACKAGE nodes.
///
/// Expected JSON format (simplified deps.dev response):
/// ```json
/// {
///   "nodes": [
///     {
///       "versionKey": { "system": "NPM", "name": "express", "version": "4.18.2" },
///       "relation": "SELF"
///     },
///     {
///       "versionKey": { "system": "NPM", "name": "accepts", "version": "1.3.8" },
///       "relation": "DIRECT"
///     }
///   ]
/// }
/// ```
pub fn ingest_deps_dev(deps_dir: &std::path::Path, builder: &mut GraphBuilder) -> usize {
    let mut count = 0;

    super::walk_json_files(deps_dir, &mut |path| {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };
        let doc: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => return,
        };

        // Find the SELF node (the package itself)
        let nodes = match doc.get("nodes").and_then(|v| v.as_array()) {
            Some(n) => n,
            None => return,
        };

        let self_node = nodes.iter().find(|n| {
            n.get("relation").and_then(|v| v.as_str()) == Some("SELF")
        });
        let self_key = match self_node.and_then(|n| n.get("versionKey")) {
            Some(k) => k,
            None => return,
        };
        let self_system = self_key.get("system").and_then(|v| v.as_str()).unwrap_or("");
        let self_name = self_key.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if self_system.is_empty() || self_name.is_empty() { return; }

        let self_eco = normalize_ecosystem(self_system);
        let self_id = format!("{}:{}", self_eco, self_name);

        // Only create edges if the package already exists in the graph
        let self_nid = match builder.lookup_node(&self_id) {
            Some(n) => n,
            None => return,
        };

        // Process direct dependencies
        for node in nodes {
            let relation = node.get("relation").and_then(|v| v.as_str()).unwrap_or("");
            if relation != "DIRECT" { continue; }

            let key = match node.get("versionKey") {
                Some(k) => k,
                None => continue,
            };
            let system = key.get("system").and_then(|v| v.as_str()).unwrap_or("");
            let name = key.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if system.is_empty() || name.is_empty() { continue; }

            let eco = normalize_ecosystem(system);
            let dep_id = format!("{}:{}", eco, name);
            let dep_nid = builder.get_or_create_node(&dep_id, NodeType::PACKAGE);
            builder.add_edge(self_nid, dep_nid, EdgeType::DEPENDS_ON);
            count += 1;
        }
    });

    count
}

/// Normalize deps.dev system names to VulnGraph ecosystem conventions.
fn normalize_ecosystem(system: &str) -> &'static str {
    match system.to_uppercase().as_str() {
        "NPM" => "npm",
        "PYPI" => "PyPI",
        "MAVEN" => "Maven",
        "GO" => "Go",
        "CARGO" => "crates.io",
        "NUGET" => "NuGet",
        _ => "unknown",
    }
}
