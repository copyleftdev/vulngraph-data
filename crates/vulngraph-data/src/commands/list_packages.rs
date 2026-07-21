use crate::ListPackagesArgs;
use vulngraph_engine::graph::Graph;
use vulngraph_engine::types::{NodeId, NodeType};

/// Print package external IDs (ecosystem:name) one per line.
/// Consumed by scripts/fetch-deps-dev.sh to enumerate deps.dev targets.
pub fn cmd_list_packages(args: &ListPackagesArgs) {
    let graph = match Graph::open(std::path::Path::new(&args.db)) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("[list-packages] cannot open graph at {}: {}", args.db, e);
            std::process::exit(1);
        }
    };

    let eco_prefix = args
        .ecosystem
        .as_deref()
        .map(|e| format!("{}:", e.to_lowercase()));

    let mut printed = 0usize;
    for i in 0..graph.node_count() {
        if printed >= args.limit {
            break;
        }
        let nid = NodeId(i as u32);
        let Some(header) = graph.node(nid) else { continue };
        if header.node_type != NodeType::PACKAGE {
            continue;
        }
        let Some(ext_id) = graph.external_id(header) else { continue };
        if let Some(prefix) = &eco_prefix
            && !ext_id.to_lowercase().starts_with(prefix)
        {
            continue;
        }
        println!("{ext_id}");
        printed += 1;
    }
}
