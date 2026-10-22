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

/// Freshness timestamp for the deps.dev cache: the mtime of the newest cached
/// response (`<ecosystem>/<name>.json`), i.e. when the cache was last topped up.
///
/// Not the mtime of `deps_dir` itself: refreshing a response rewrites a file
/// inside an ecosystem subdirectory and never touches the root, whose mtime
/// only moves when an ecosystem directory is first created. Falls back to the
/// directory's own mtime when it holds no responses. Max is order-independent,
/// so the result does not depend on directory iteration order.
pub fn cache_updated_at(deps_dir: &std::path::Path) -> String {
    let mut newest: Option<u64> = None;
    super::walk_json_files(deps_dir, &mut |path| {
        let secs = super::source_mtime_secs(path);
        if secs > 0 {
            newest = Some(newest.map_or(secs, |n| n.max(secs)));
        }
    });
    match newest {
        Some(secs) => super::format_epoch_secs(secs),
        None => super::source_mtime(deps_dir),
    }
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

#[cfg(test)]
mod tests {
    use super::cache_updated_at;
    use std::fs::File;
    use std::time::{Duration, UNIX_EPOCH};

    fn set_mtime(path: &std::path::Path, secs: u64) {
        File::open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
            .unwrap();
    }

    // 2026-07-26T05:53:01Z and 2026-10-21T05:10:00Z.
    const DIR_CREATED: u64 = 1_785_045_181;
    const LAST_FETCH: u64 = 1_792_559_400;

    /// Refreshing a cached response rewrites a file inside an ecosystem
    /// subdirectory; it never touches the cache root. The root's own mtime
    /// only moves when an ecosystem directory is first created, so it froze
    /// once every ecosystem had one. Freshness must follow the files.
    #[test]
    fn updated_at_follows_newest_cached_response_not_root_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let npm = root.join("npm");
        std::fs::create_dir(&npm).unwrap();
        std::fs::write(npm.join("old.json"), "{}").unwrap();
        std::fs::write(npm.join("express.json"), "{}").unwrap();
        set_mtime(&npm.join("old.json"), DIR_CREATED);
        set_mtime(&npm.join("express.json"), LAST_FETCH);
        set_mtime(&npm, DIR_CREATED);
        set_mtime(root, DIR_CREATED);

        assert_eq!(cache_updated_at(root), "2026-10-21T05:10:00Z");
    }

    /// An interrupted fetch leaves `*.json.tmp` behind; it is not ingested
    /// and must not count as fresh data.
    #[test]
    fn updated_at_ignores_partial_downloads() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let npm = root.join("npm");
        std::fs::create_dir(&npm).unwrap();
        std::fs::write(npm.join("express.json"), "{}").unwrap();
        std::fs::write(npm.join("left-pad.json.tmp"), "").unwrap();
        set_mtime(&npm.join("express.json"), DIR_CREATED);
        set_mtime(&npm.join("left-pad.json.tmp"), LAST_FETCH);
        set_mtime(&npm, LAST_FETCH);
        set_mtime(root, LAST_FETCH);

        assert_eq!(cache_updated_at(root), "2026-07-26T05:53:01Z");
    }
}
