---
name: ingest-verify
description: "Validate data ingest correctness after a graph build. Run tests and verify graph database consistency including node/edge counts, file sizes, and release packaging."
version: 0.2.0
user-invocable: true
allowed-tools: "Bash(cargo *) Bash(./target/*) Read Grep Glob"
argument-hint: "[--db path/to/vulngraph.db]"
---

# Graph Ingest Verification

Validate the integrity of a built graph database.

## Procedure

### Step 1: Run Unit Tests

```bash
cargo test
```

All tests must pass (builder, osv ingest, manifest). Report any failures.

### Step 2: File Size Consistency

If a built graph exists (default: `builds/vulngraph.db/`), read `meta.json`
for `node_count` / `edge_count` and verify:

- `nodes.bin` size == node_count * 48
- `edges_fwd.bin` size == edge_count * 32
- `edges_rev.bin` size == edge_count * 32
- `props_epss.bin`, `props_epss_pct.bin`, `props_cvss.bin` size == node_count * 4
- `props_published.bin`, `desc_index.bin` size == node_count * 8
- `idx_extid.bin` size is a multiple of 16 (IndexSlot) and a power-of-2 slot count
- `version_ranges.json` and `freshness.json` exist and parse as JSON

### Step 3: Sample Lookups

Verify index and string table integrity via the read API:

```bash
./target/release/vulngraph-data list-packages --db builds/vulngraph.db --ecosystem npm --limit 5
```

Should print five `npm:` package IDs.

### Step 4: Determinism Spot-Check

If a second build from the same sources is available, its semantic files must
be byte-identical (compare `sha256sum` of the 11 `.bin` files +
`version_ranges.json`). Equivalent: `package` both and compare `snapshot_id`.

### Step 5: Packaging Round-Trip

```bash
./target/release/vulngraph-data package --db builds/vulngraph.db --demo-blob builds/vulngraph.bin --out dist
./target/release/vulngraph-data verify --dist dist
```

`verify` must PASS (asset checksums, per-file hashes, snapshot identity).

## Output

```
Ingest Verification Report
==========================

Tests:      {n}/{n} passed
Nodes:      {count}   Edges: {count}
File sizes: {OK/mismatches}
Lookups:    npm packages {found/not found}
Snapshot:   {snapshot_id}
Packaging:  {PASS/FAIL}

Verdict: {PASS/FAIL}
{failure details if any}
```
