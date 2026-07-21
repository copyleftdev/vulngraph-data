# VulnGraph Custom Graph Database Design

Based on structure analysis of 9 downloaded data sources (2026-03-14).

---

## 1. Measured Data Profile

### Node Counts (from real data)

| Node Type | Count | Source | Avg Record Size |
|-----------|-------|--------|-----------------|
| CVE | 338,014 | cvelistV5 | 3,665 B |
| OSV Vulnerability | 727,752 | OSV all.zip | varies |
| Package (estimated) | 500K–2M | OSV affected[] | — |
| Exploit (ExploitDB) | 46,968 | ExploitDB CSV | — |
| Exploit (PoC) | ~8,457 CVEs w/ PoCs | PoC-in-GitHub | — |
| Exploit (Nuclei) | 12,760 templates | nuclei-templates | — |
| ATT&CK Technique | 835 | attack-stix-data | — |
| ATT&CK Group | 187 | attack-stix-data | — |
| ATT&CK Software | 787 | attack-stix-data | — |
| CWE Weakness | 969 | CWE XML | — |
| **TOTAL nodes** | **~1.5–3.5M** | | |

### Edge Counts (estimated)

| Edge Type | Estimated Count | Source |
|-----------|----------------|--------|
| CVE → affects Package@Version | 2–10M | OSV (multiple affected per vuln) |
| CVE → fixed_by Version | 500K–2M | OSV ranges.fixed |
| CVE → classified_as CWE | ~300K | cvelistV5 problemTypes |
| CVE → exploited_in_wild | 1,542 | CISA KEV |
| CVE → has_poc Exploit | ~80K | ExploitDB(25K) + PoC(8K) + Nuclei |
| Technique → uses Software | 17,270 | ATT&CK relationships |
| Technique → mitigated_by | 1,445 | ATT&CK relationships |
| CWE → parent_of CWE | ~2K | CWE hierarchy |
| **TOTAL edges** | **~5–15M** | |

### Property Volumes

| Property | Cardinality | Update Freq |
|----------|-------------|-------------|
| EPSS score (per CVE) | 320,502 float pairs | Daily |
| CVSS score (per CVE) | ~200K (NVD-enriched) | On NVD update |
| KEV status (per CVE) | 1,542 booleans | As CISA adds |
| Ransomware flag | 312 (Known) of 1,542 KEV | As CISA adds |

---

## 2. Access Patterns (what the MCP server must answer fast)

These are the queries that must be sub-millisecond:

### P0 — Must be <1ms

1. **CVE lookup by ID** → full CVE record + EPSS + KEV status + CVSS
2. **Package vulnerability query** → given (ecosystem, package, version), return all affecting CVEs
3. **Is this CVE exploited?** → KEV status + PoC existence + EPSS score

### P1 — Must be <10ms

4. **Dependency tree scan** → given list of (ecosystem, package, version), return all CVEs + risk scores
5. **Top-N risky CVEs** → by EPSS score, filtered by ecosystem/date
6. **CVE → full context** → CWE, ATT&CK techniques, exploits, patches, timeline

### P2 — Can be <100ms

7. **Attack surface query** → given a set of packages, find all CVEs with active exploits
8. **Trending vulnerabilities** → CVEs with recent KEV additions or EPSS score jumps
9. **Flight Recorder timeline** → for a CVE, show disclosure → PoC → exploit → patch dates

---

## 3. Storage Engine Design

### 3.1 Core Principle: Adjacency List with Typed Edges + Columnar Properties

Traditional graph DBs (Neo4j, etc.) optimize for generic traversal. We don't need that.
VulnGraph's access patterns are:

- **Point lookups** (CVE ID → node) — hash map, O(1)
- **Typed edge traversal** (CVE → all affects edges) — pre-grouped adjacency, O(degree)
- **Range scans** (EPSS > 0.5, date > X) — sorted indexes, O(log n + k)
- **Set intersection** (packages ∩ affected CVEs) — bitmap indexes or sorted merge

This means: **not a general graph DB**. More like a **typed adjacency store with
columnar indexes** — think TigerBeetle's philosophy applied to graph data.

### 3.2 Node Storage

```
Node Layout (fixed-size header + variable payload):

┌──────────────────────────────────────────────┐
│ node_id: u64 (internal, monotonic)           │
│ node_type: u8 (CVE=0, Package=1, Exploit=2, │
│                CWE=3, Technique=4, Actor=5)  │
│ external_id_hash: u64 (FNV-1a of string ID) │
│ external_id_offset: u32 (into string table)  │
│ external_id_len: u16                         │
│ properties_offset: u32 (into property store) │
│ edge_list_offset: u32 (into edge store)      │
│ edge_count: u16                              │
│ created_at: u64 (unix micros)                │
│ updated_at: u64 (unix micros)                │
├──────────────────────────────────────────────┤
│ Total header: 48 bytes                       │
└──────────────────────────────────────────────┘

For 3M nodes: 3M × 48B = 144 MB (fits in L3 cache on modern server)
```

### 3.3 Edge Storage

```
Edge Layout (fixed-size, grouped by source node + edge type):

┌──────────────────────────────────────────────┐
│ source_node_id: u64                          │
│ target_node_id: u64                          │
│ edge_type: u8 (affects=0, fixed_by=1,        │
│               exploited=2, has_poc=3,         │
│               classified_as=4, uses=5, ...)   │
│ properties_offset: u32 (optional, 0 = none)  │
│ created_at: u64 (unix micros)                │
├──────────────────────────────────────────────┤
│ Total: 29 bytes (pad to 32 for alignment)    │
└──────────────────────────────────────────────┘

For 10M edges: 10M × 32B = 320 MB
Sorted by (source_node_id, edge_type) for grouped traversal.
Reverse index: sorted by (target_node_id, edge_type) for incoming edges.
```

### 3.4 Index Structures

```
Primary Indexes (always in memory):

1. external_id → node_id
   Hash map: FNV-1a(external_id) → node_id
   Size: 3M × 16B = 48 MB
   Lookup: O(1) amortized

2. (ecosystem, package_name) → node_id
   Hash map for Package nodes
   Size: ~1M × 24B = 24 MB

3. edge_type adjacency
   Per source node: offset + count into sorted edge array
   Lookup: O(1) to find edge list, O(degree) to scan

Secondary Indexes (for range/filter queries):

4. EPSS score index
   Sorted array of (epss_score, cve_node_id)
   Size: 320K × 12B = 3.8 MB
   Range query: binary search, O(log n + k)

5. Date index (created_at, updated_at)
   Sorted array of (timestamp, node_id)
   Size: 3M × 12B = 36 MB

6. KEV bitmap
   Bitset of node_ids that are in CISA KEV
   Size: 3M / 8 = 375 KB
```

### 3.5 Property Storage

```
Two-tier property storage:

Hot properties (columnar, always in memory):
- EPSS score: f32 array indexed by node_id → 3M × 4B = 12 MB
- EPSS percentile: f32 array → 12 MB
- CVSS score: f32 array → 12 MB
- KEV status: bitset → 375 KB
- Ransomware flag: bitset → 375 KB

Cold properties (memory-mapped, loaded on demand):
- Full CVE description text
- OSV affected version ranges (variable-length)
- ATT&CK technique descriptions
- Exploit code references
```

### 3.6 Total Memory Budget

```
Component                    Size
─────────────────────────────────────
Node headers                 144 MB
Edge arrays (fwd + rev)      640 MB
Primary indexes               72 MB
Secondary indexes              40 MB
Hot properties                 37 MB
String table                 ~200 MB
─────────────────────────────────────
TOTAL (in-memory)           ~1.1 GB

Cold storage (mmap):        ~5-10 GB
```

This entire graph fits in memory on a single server with 4 GB RAM.

---

## 4. Freshness Pipeline Architecture

### 4.1 Tier Design

```
                    ┌─────────────┐
                    │  Graph DB   │
                    │  (in-mem)   │
                    └──────▲──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────▼──┐  ┌──────▼───┐  ┌────▼────────┐
     │  Tier 1   │  │  Tier 2  │  │   Tier 3    │
     │  HOT      │  │  WARM    │  │   COLD      │
     │  ≤15 min  │  │  1-24hr  │  │   daily+    │
     └───────────┘  └──────────┘  └─────────────┘
          │              │              │
     CVE.org git    NVD API 2.0    ExploitDB git
     CISA KEV json  EPSS CSV       Nuclei git
     OSV modified   CPE/CVSS       PoC-in-GitHub
     VulnCheck API                 ATT&CK git
                                   CWE download
```

### 4.2 Ingest Pipeline (per source)

```
Source → Fetcher → Normalizer → Differ → Graph Writer → Index Updater
                                  │
                              Changelog
                            (Flight Recorder)
```

Each stage:

1. **Fetcher**: Source-specific (git pull, HTTP GET, API call)
2. **Normalizer**: Transforms source format → internal node/edge format
3. **Differ**: Compares against current graph state, produces delta
4. **Graph Writer**: Applies delta atomically (insert/update/delete nodes+edges)
5. **Index Updater**: Rebuilds affected indexes incrementally
6. **Changelog**: Appends to Flight Recorder timeline

### 4.3 Update Strategy

```
Hot path (Tier 1): poll → diff → atomic swap

  - CVE.org: git fetch --depth=1, diff HEAD~1..HEAD, process changed files
  - CISA KEV: HTTP ETag/Last-Modified, diff JSON array
  - OSV: download modified_id.csv, fetch only changed records
  - VulnCheck: API poll with since= parameter

  Target: full cycle in <60 seconds

Warm path (Tier 2): poll → batch normalize → bulk update

  - NVD: API with lastModStartDate, paginate, batch insert/update
  - EPSS: download daily CSV, columnar overwrite of EPSS score array

  Target: full cycle in <5 minutes

Cold path (Tier 3): scheduled pull → full re-index

  - Git repos: pull, re-scan changed files
  - CWE: download, full replace (tiny dataset)

  Target: once per day, <30 minutes
```

### 4.4 Atomic Updates

The graph must remain queryable during updates. Strategy:

- **Double-buffer for hot properties**: write to shadow array, atomic pointer swap
- **Edge list append**: new edges appended, periodic compaction
- **Node updates**: copy-on-write for modified nodes
- **Consistency**: version counter per update batch; queries see consistent snapshot

---

## 5. Query Performance Analysis

### 5.1 CVE Lookup by ID

```
Steps:
  1. Hash "CVE-2024-4577" → u64                    O(1)     ~10ns
  2. Hash map lookup → node_id                      O(1)     ~50ns
  3. Read node header (48B, in L1/L2 cache)         O(1)     ~10ns
  4. Read hot properties (EPSS, CVSS, KEV)          O(1)     ~20ns
  5. Read edge list offset, scan edges              O(deg)   ~100ns (avg degree ~15)
  ──────────────────────────────────────────────
  Total: ~200ns = 0.0002ms
```

### 5.2 Package Vulnerability Query

```
Steps:
  1. Hash (ecosystem, package_name) → node_id       O(1)     ~60ns
  2. Scan reverse edges of type "affects"            O(deg)   ~500ns (avg ~10 CVEs)
  3. For each CVE: read hot props (EPSS, KEV)        O(k)    ~200ns
  ──────────────────────────────────────────────
  Total: ~760ns = 0.0008ms
```

### 5.3 Dependency Tree Scan (100 packages)

```
Steps:
  1. Hash 100 package lookups                        100×60ns = 6µs
  2. Scan reverse edges (avg 10 CVEs each)           1000×50ns = 50µs
  3. Deduplicate CVE set                             O(n log n) = ~10µs
  4. Read hot props for unique CVEs                  ~500×20ns = 10µs
  ──────────────────────────────────────────────
  Total: ~76µs = 0.076ms
```

All P0 queries are well under 1ms. P1 queries under 10ms even for large scans.

---

## 6. File Format (On-Disk Persistence)

```
vulngraph.db/
├── meta.json              # version, node/edge counts, timestamps
├── nodes.bin              # fixed-size node headers, sorted by node_id
├── edges_fwd.bin          # edges sorted by (source, type)
├── edges_rev.bin          # edges sorted by (target, type)
├── strings.bin            # string table (external IDs, descriptions)
├── props_epss.bin         # columnar f32 array
├── props_cvss.bin         # columnar f32 array
├── props_kev.bin          # bitset
├── idx_extid.bin          # hash map: external_id_hash → node_id
├── idx_package.bin        # hash map: (eco, pkg) → node_id
├── idx_epss_sorted.bin    # sorted (score, node_id) pairs
├── idx_date.bin           # sorted (timestamp, node_id) pairs
├── changelog/             # Flight Recorder append-only log
│   ├── 2026-03-14.jsonl
│   └── ...
└── snapshots/             # periodic full snapshots for recovery
    └── 2026-03-14T00:00:00Z/
```

Startup: mmap all .bin files → ready to serve in <1 second.

---

## 7. Technology Choice

For building this custom engine, the options are:

| Language | Pros | Cons |
|----------|------|------|
| **Rust** | Zero-cost abstractions, memory safety, mmap ergonomics, excellent for data-oriented design | Steeper dev curve |
| **Go** | Fast iteration, good concurrency, simple deployment | GC pauses could affect sub-ms tail latency |
| **C** | Maximum control, proven for DB engines | Memory safety burden, slower iteration |
| **Zig** | Low-level control like C, better ergonomics | Smaller ecosystem |

**Recommendation**: Rust. The memory safety guarantees are critical for a database
engine, and the zero-cost abstractions align perfectly with the sub-ms latency
requirement. The mmap and unsafe escape hatch give full control when needed.

---

## 8. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| OSV version range parsing complexity | High | Medium | Use semver libs; test against all 44 ecosystems |
| NVD enrichment delays (hours-days) | High | Medium | CVE.org as primary; NVD as best-effort enrichment |
| Memory pressure from OSV growth | Medium | Medium | Cap cold properties to mmap; page-level eviction |
| Update atomicity bugs | Medium | High | WAL (write-ahead log) for all mutations; snapshot recovery |
| EPSS model version changes (v4→v5) | Low | Low | Version field in changelog; re-score on model change |
| VulnCheck API terms change | Medium | Medium | Abstract exploit intelligence behind interface; fallback to CISA KEV only |

---

## 9. Next Steps

1. Write per-source normalizer scripts (Python) to validate the normalization logic
2. Prototype the core graph engine (Rust) with node/edge storage + primary index
3. Build the first ingest pipeline for cvelistV5 → graph
4. Add EPSS + KEV enrichment
5. Add OSV package mapping
6. Benchmark P0 queries against real data
7. Build the MCP server interface on top
