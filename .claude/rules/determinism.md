---
paths:
  - "crates/vulngraph-data/src/builder.rs"
  - "crates/vulngraph-data/src/ingest/**"
  - "crates/vulngraph-data/src/commands/build.rs"
---

# Build Determinism

## Law 3: Edge Sort Invariant

The graph database has two edge arrays containing the SAME edges in different sort orders:

| Array | Sort Key | File | Used For |
|-------|----------|------|----------|
| Forward | `(source, edge_type, target)` | `edges_fwd.bin` | Outgoing edge traversal via `NodeHeader.edge_list_offset` |
| Reverse | `(target, edge_type, source)` | `edges_rev.bin` | Incoming edge lookup via `partition_point()` binary search |

Both arrays must contain the exact same edge set. The sort orders are enforced in `GraphBuilder::build()`:

```rust
// Forward sort
edges.sort_unstable_by(|a, b| {
    a.source.cmp(&b.source)
        .then(a.edge_type.0.cmp(&b.edge_type.0))
        .then(a.target.cmp(&b.target))
});

// Reverse sort (separate pass on cloned array)
rev_edges.sort_unstable_by(|a, b| {
    a.target.cmp(&b.target)
        .then(a.edge_type.0.cmp(&b.edge_type.0))
        .then(a.source.cmp(&b.source))
});
```

## Determinism Requirements

1. **All sorts use `sort_unstable_by` with explicit comparators** — never rely on `PartialOrd` defaults (especially not for `f32` which has NaN issues)
2. **Node IDs are assigned in insertion order** — `GraphBuilder::add_node()` assigns monotonic u32 IDs
3. **Deduplication via `id_to_node` map** — `add_node()` returns existing NodeId if external_id already seen
4. **Hash function is pure** — FNV-1a with fixed constants, no randomized seeding
5. **Source freshness uses BTreeMap** — `commands/build.rs` uses `BTreeMap` for deterministic JSON output
6. **No wall-clock in on-disk records** — node/edge `created_at` comes from `GraphBuilder::set_build_timestamp()` (source-mtime-derived), never `now_micros()` per record. Identical sources must produce byte-identical semantic files; the release `snapshot_id` and skip-publish logic depend on it. Verify with a double build.

## HashMap Iteration Rules

`HashMap` (including `FnvHashMap`) has non-deterministic iteration order. Rules:

- **Allowed**: When filling a position-indexed output (e.g., `HashIndexBuilder` places entries at computed positions — iteration order doesn't affect the result)
- **Allowed**: When collecting into a `HashSet` for dedup, followed by sorting
- **NOT allowed**: When iteration order feeds directly into a sorted output or binary file
- **Prefer `BTreeMap`**: When output needs to be deterministic AND human-readable (e.g., JSON metadata)

## Ingest Module Conventions

Each ingest module (`cvelistv5.rs`, `epss.rs`, `kev.rs`, etc.) follows:

1. Walk source files via `walk_json_files()` or `walk_yaml_files()` or read a single file
2. For each record: `builder.add_node()` (idempotent via dedup) + `builder.add_edge()`
3. Track source freshness via `source_mtime()`
4. Errors during parsing are logged and skipped — one bad record doesn't poison the build
5. The ingest order doesn't matter — the builder sorts edges during `build()`

## What NOT to Do

- Do not use `sort()` or `sort_by()` (stable sorts are slower; `sort_unstable_by` is correct here since edge equality is defined by all fields)
- Do not use `rand` or any randomized data structure in the build pipeline
- Do not assume HashMap iteration order in any code that writes to disk
- Do not modify `GraphBuilder::add_node()` dedup behavior — it prevents duplicate external IDs
