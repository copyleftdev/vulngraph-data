//! Graph builder — constructs the on-disk binary files from raw data.
//!
//! The builder accumulates nodes and edges in memory, then flushes everything
//! to sorted binary files that can be mmap'd by `Graph::open()`.

use vulngraph_engine::error::{EngineError, Result};
use vulngraph_engine::graph::GraphMeta;
use vulngraph_engine::index::HashIndexBuilder;
use vulngraph_engine::storage::{ByteWriter, MappedArrayWriter};
use vulngraph_engine::types::*;
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────────
// In-memory node during construction
// ─────────────────────────────────────────────────

struct PendingNode {
    external_id: String,
    node_type: NodeType,
    created_at: u64,
    updated_at: u64,
}

// ─────────────────────────────────────────────────
// In-memory edge during construction
// ─────────────────────────────────────────────────

struct PendingEdge {
    source: u32,
    target: u32,
    edge_type: EdgeType,
    created_at: u64,
}

// ─────────────────────────────────────────────────
// Builder
// ─────────────────────────────────────────────────

pub struct GraphBuilder {
    output_path: PathBuf,
    nodes: Vec<PendingNode>,
    edges: Vec<PendingEdge>,
    id_to_node: fnv::FnvHashMap<String, u32>,
    epss_scores: Vec<(u32, f32, f32)>,  // (node_id, score, percentile)
    cvss_scores: Vec<(u32, f32)>,       // (node_id, score)
    descriptions: Vec<(u32, String)>,   // (node_id, description text)
    published_dates: Vec<(u32, u64)>,   // (node_id, epoch seconds)
    build_ts_micros: u64,
}

impl GraphBuilder {
    pub fn new(output_path: &Path) -> Self {
        Self {
            output_path: output_path.to_path_buf(),
            nodes: Vec::new(),
            edges: Vec::new(),
            id_to_node: fnv::FnvHashMap::default(),
            epss_scores: Vec::new(),
            cvss_scores: Vec::new(),
            descriptions: Vec::new(),
            published_dates: Vec::new(),
            build_ts_micros: now_micros(),
        }
    }

    /// Stamp all records with a fixed timestamp instead of wall clock.
    /// Identical sources must produce byte-identical output (the release
    /// snapshot_id depends on it), so callers pass a source-derived time.
    pub fn set_build_timestamp(&mut self, micros: u64) {
        self.build_ts_micros = micros;
    }

    /// Add a node. Returns the assigned NodeId.
    /// If the external_id already exists, returns the existing NodeId.
    pub fn add_node(&mut self, external_id: &str, node_type: NodeType) -> NodeId {
        if let Some(&existing) = self.id_to_node.get(external_id) {
            return NodeId(existing);
        }

        let id = self.nodes.len() as u32;
        let now = self.build_ts_micros;
        self.nodes.push(PendingNode {
            external_id: external_id.to_string(),
            node_type,
            created_at: now,
            updated_at: now,
        });
        self.id_to_node.insert(external_id.to_string(), id);
        NodeId(id)
    }

    /// Look up a node by external ID without creating it.
    pub fn lookup_node(&self, external_id: &str) -> Option<NodeId> {
        self.id_to_node.get(external_id).map(|&id| NodeId(id))
    }

    /// Get or create a node.
    pub fn get_or_create_node(&mut self, external_id: &str, node_type: NodeType) -> NodeId {
        self.add_node(external_id, node_type)
    }

    /// Add an edge between two nodes.
    pub fn add_edge(&mut self, source: NodeId, target: NodeId, edge_type: EdgeType) {
        self.edges.push(PendingEdge {
            source: source.0,
            target: target.0,
            edge_type,
            created_at: self.build_ts_micros,
        });
    }

    /// Set EPSS score for a node.
    pub fn set_epss(&mut self, node_id: NodeId, score: f32, percentile: f32) {
        self.epss_scores.push((node_id.0, score, percentile));
    }

    /// Set CVSS score for a node.
    pub fn set_cvss(&mut self, node_id: NodeId, score: f32) {
        self.cvss_scores.push((node_id.0, score));
    }

    /// Set a human-readable description for a node (typically CVE summary).
    pub fn set_description(&mut self, node_id: NodeId, desc: &str) {
        self.descriptions.push((node_id.0, desc.to_string()));
    }

    /// Set the publication date for a node (epoch seconds).
    pub fn set_published_at(&mut self, node_id: NodeId, epoch_secs: u64) {
        self.published_dates.push((node_id.0, epoch_secs));
    }

    /// Number of nodes added so far.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of edges added so far.
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Flush everything to disk. This is the expensive operation.
    ///
    /// Steps:
    /// 1. Sort edges by (source, edge_type, target) for forward array
    /// 2. Build node headers with edge offsets
    /// 3. Write nodes.bin, edges_fwd.bin, edges_rev.bin, strings.bin
    /// 4. Build and write hash index
    /// 5. Write property columns
    /// 6. Write meta.json
    pub fn build(mut self) -> Result<PathBuf> {
        std::fs::create_dir_all(&self.output_path)
            .map_err(|e| EngineError::Io(format!("{}: {}", self.output_path.display(), e)))?;

        let node_count = self.nodes.len();
        let edge_count = self.edges.len();

        eprintln!("[build] {} nodes, {} edges", node_count, edge_count);

        // ── Step 1: Sort edges ──────────────────
        eprintln!("[build] sorting forward edges...");
        self.edges.sort_unstable_by(|a, b| {
            a.source.cmp(&b.source)
                .then(a.edge_type.0.cmp(&b.edge_type.0))
                .then(a.target.cmp(&b.target))
        });

        // ── Step 2: Compute edge offsets per node ──
        let mut edge_offsets: Vec<(u32, u16)> = vec![(0, 0); node_count]; // (offset, count)
        {
            let mut current_source: u32 = u32::MAX;
            let mut current_start: u32 = 0;
            let mut current_count: u16 = 0;

            for (i, edge) in self.edges.iter().enumerate() {
                if edge.source != current_source {
                    if current_source != u32::MAX
                        && let Some(slot) = edge_offsets.get_mut(current_source as usize) {
                            *slot = (current_start, current_count);
                        }
                    current_source = edge.source;
                    current_start = i as u32;
                    current_count = 1;
                } else {
                    current_count = current_count.saturating_add(1);
                }
            }
            // Flush last node
            if current_source != u32::MAX
                && let Some(slot) = edge_offsets.get_mut(current_source as usize) {
                    *slot = (current_start, current_count);
                }
        }

        // ── Step 3: Write strings.bin and build node headers ──
        eprintln!("[build] writing strings.bin...");
        let mut string_writer = ByteWriter::create(&self.output_path.join("strings.bin"))?;
        let mut node_headers: Vec<NodeHeader> = Vec::with_capacity(node_count);
        let mut index_builder = HashIndexBuilder::with_capacity(node_count);

        for (i, pending) in self.nodes.iter().enumerate() {
            let ext_id_bytes = pending.external_id.as_bytes();
            let offset = string_writer.append(ext_id_bytes)? as u32;
            let hash = fnv1a_hash(ext_id_bytes);

            let (edge_offset, edge_count) = edge_offsets.get(i)
                .copied()
                .unwrap_or((0, 0));

            let header = NodeHeader {
                node_id: i as u32,
                node_type: pending.node_type,
                _pad0: [0; 3],
                external_id_hash: hash,
                external_id_offset: offset,
                external_id_len: ext_id_bytes.len() as u16,
                _pad1: [0; 2],
                edge_list_offset: edge_offset,
                edge_count,
                _pad2: [0; 2],
                created_at: pending.created_at,
                updated_at: pending.updated_at,
            };
            node_headers.push(header);

            // Build index (ignore collisions — log them)
            if let Err(e) = index_builder.insert(&pending.external_id, NodeId(i as u32)) {
                eprintln!("[build] WARNING: index insert failed: {}", e);
            }
        }
        string_writer.finish()?;

        // ── Step 4: Write nodes.bin ──
        eprintln!("[build] writing nodes.bin...");
        let mut node_writer = MappedArrayWriter::<NodeHeader>::create(
            &self.output_path.join("nodes.bin")
        )?;
        node_writer.extend(&node_headers)?;
        node_writer.finish()?;

        // ── Step 5: Write edges_fwd.bin ──
        eprintln!("[build] writing edges_fwd.bin...");
        let fwd_records: Vec<EdgeRecord> = self.edges.iter().map(|e| EdgeRecord {
            source: e.source,
            target: e.target,
            edge_type: e.edge_type,
            _pad0: [0; 3],
            properties_offset: 0,
            created_at: e.created_at,
            _reserved: 0,
        }).collect();

        let mut fwd_writer = MappedArrayWriter::<EdgeRecord>::create(
            &self.output_path.join("edges_fwd.bin")
        )?;
        fwd_writer.extend(&fwd_records)?;
        fwd_writer.finish()?;

        // ── Step 6: Write edges_rev.bin (sorted by target) ──
        eprintln!("[build] sorting and writing edges_rev.bin...");
        let mut rev_records = fwd_records;
        rev_records.sort_unstable_by(|a, b| {
            a.target.cmp(&b.target)
                .then(a.edge_type.0.cmp(&b.edge_type.0))
                .then(a.source.cmp(&b.source))
        });

        let mut rev_writer = MappedArrayWriter::<EdgeRecord>::create(
            &self.output_path.join("edges_rev.bin")
        )?;
        rev_writer.extend(&rev_records)?;
        rev_writer.finish()?;

        // ── Step 7: Write hash index ──
        eprintln!("[build] writing idx_extid.bin ({} entries)...", index_builder.len());
        index_builder.write_to(&self.output_path.join("idx_extid.bin"))?;

        // ── Step 8: Write property columns ──
        self.write_property_columns(node_count)?;

        // ── Step 9: Write meta.json ──
        let meta = GraphMeta {
            version: 1,
            node_count: node_count as u32,
            edge_count: edge_count as u64,
            created_at: chrono_now(),
            updated_at: chrono_now(),
        };
        let meta_json = serde_json::to_string_pretty(&meta)
            .map_err(|e| EngineError::Io(format!("meta serialization: {}", e)))?;
        std::fs::write(self.output_path.join("meta.json"), meta_json)
            .map_err(|e| EngineError::Io(format!("meta.json write: {}", e)))?;

        eprintln!("[build] done. Graph at {}", self.output_path.display());
        Ok(self.output_path)
    }

    fn write_property_columns(&self, node_count: usize) -> Result<()> {
        // EPSS scores — f32 array indexed by node_id
        if !self.epss_scores.is_empty() {
            eprintln!("[build] writing props_epss.bin ({} scores)...", self.epss_scores.len());
            let mut scores = vec![0.0f32; node_count];
            let mut percentiles = vec![0.0f32; node_count];
            for &(nid, score, pct) in &self.epss_scores {
                if (nid as usize) < node_count {
                    scores[nid as usize] = score;
                    percentiles[nid as usize] = pct;
                }
            }
            write_f32_column(&self.output_path.join("props_epss.bin"), &scores)?;
            write_f32_column(&self.output_path.join("props_epss_pct.bin"), &percentiles)?;
        }

        // CVSS scores
        if !self.cvss_scores.is_empty() {
            eprintln!("[build] writing props_cvss.bin ({} scores)...", self.cvss_scores.len());
            let mut scores = vec![0.0f32; node_count];
            for &(nid, score) in &self.cvss_scores {
                if (nid as usize) < node_count {
                    scores[nid as usize] = score;
                }
            }
            write_f32_column(&self.output_path.join("props_cvss.bin"), &scores)?;
        }

        // Descriptions — variable-length strings with index
        if !self.descriptions.is_empty() {
            eprintln!("[build] writing descriptions ({} entries)...", self.descriptions.len());
            let mut desc_strings = ByteWriter::create(&self.output_path.join("desc_strings.bin"))?;
            let mut desc_index = vec![DescSlot { offset: 0, len: 0 }; node_count];
            for (nid, desc) in &self.descriptions {
                if (*nid as usize) < node_count {
                    let offset = desc_strings.append(desc.as_bytes())? as u32;
                    desc_index[*nid as usize] = DescSlot {
                        offset,
                        len: desc.len() as u32,
                    };
                }
            }
            desc_strings.finish()?;
            let mut idx_writer = MappedArrayWriter::<DescSlot>::create(
                &self.output_path.join("desc_index.bin"),
            )?;
            idx_writer.extend(&desc_index)?;
            idx_writer.finish()?;
        }

        // Published dates — u64 epoch seconds indexed by node_id
        if !self.published_dates.is_empty() {
            eprintln!("[build] writing published dates ({} entries)...", self.published_dates.len());
            let mut dates = vec![0u64; node_count];
            for &(nid, epoch) in &self.published_dates {
                if (nid as usize) < node_count {
                    dates[nid as usize] = epoch;
                }
            }
            write_u64_column(&self.output_path.join("props_published.bin"), &dates)?;
        }

        Ok(())
    }
}

fn write_f32_column(path: &Path, data: &[f32]) -> Result<()> {
    let mut writer = MappedArrayWriter::<f32>::create(path)?;
    writer.extend(data)?;
    writer.finish()?;
    Ok(())
}

fn write_u64_column(path: &Path, data: &[u64]) -> Result<()> {
    let mut writer = MappedArrayWriter::<u64>::create(path)?;
    writer.extend(data)?;
    writer.finish()?;
    Ok(())
}

fn chrono_now() -> String {
    // Simple UTC timestamp without pulling in chrono crate
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Good enough for a timestamp string
    format!("{}Z", secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vulngraph_engine::graph::Graph;
    use tempfile::TempDir;

    #[test]
    fn build_and_query_small_graph() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("testdb");

        // Build
        let mut builder = GraphBuilder::new(&db_path);

        let cve1 = builder.add_node("CVE-2024-4577", NodeType::CVE);
        let cve2 = builder.add_node("CVE-2024-1234", NodeType::CVE);
        let pkg = builder.add_node("npm:lodash", NodeType::PACKAGE);
        let cwe = builder.add_node("CWE-79", NodeType::WEAKNESS);

        builder.add_edge(cve1, pkg, EdgeType::AFFECTS);
        builder.add_edge(cve2, pkg, EdgeType::AFFECTS);
        builder.add_edge(cve1, cwe, EdgeType::CLASSIFIED_AS);

        builder.set_epss(cve1, 0.95, 0.999);
        builder.set_epss(cve2, 0.01, 0.30);

        let path = builder.build().unwrap();

        // Open and query
        let graph = Graph::open(&path).unwrap();
        assert_eq!(graph.node_count(), 4);
        assert_eq!(graph.edge_count(), 3);

        // P0: CVE lookup
        let result = graph.cve_lookup("CVE-2024-4577").unwrap();
        assert_eq!(result.node_type, NodeType::CVE);
        assert_eq!(result.edges_out.len(), 2); // affects + classified_as
        assert!((result.epss_score.unwrap() - 0.95).abs() < 0.001);

        // Lookup by package
        let cves = graph.cves_for_package("npm:lodash");
        assert_eq!(cves.len(), 2);

        // External ID resolution
        let (_, header) = graph.node_by_id("CVE-2024-4577").unwrap();
        assert_eq!(graph.external_id(header).unwrap(), "CVE-2024-4577");

        // Miss returns None
        assert!(graph.cve_lookup("CVE-9999-0000").is_none());
    }

    #[test]
    fn dedup_nodes() {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("testdb2");

        let mut builder = GraphBuilder::new(&db_path);
        let id1 = builder.add_node("CVE-2024-4577", NodeType::CVE);
        let id2 = builder.add_node("CVE-2024-4577", NodeType::CVE); // duplicate
        assert_eq!(id1, id2);
        assert_eq!(builder.node_count(), 1);
    }
}
