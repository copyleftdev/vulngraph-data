# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

VulnGraph Data is the data pipeline for VulnGraph (github.com/copyleftdev/vulngraph). It ingests 10+ vulnerability-intelligence sources (CVEList V5, EPSS, CISA KEV, ExploitDB, PoC-in-GitHub, Nuclei, MITRE ATT&CK, Sigma, OSV/GHSA, CAPEC, deps.dev), builds the binary graph database, and publishes checksummed `data-YYYYMMDD` GitHub Releases. It contains no query engine and no MCP server — the serve side lives in the vulngraph repo and installs published releases via its `scripts/update.sh`.

## Format Contract (Non-Negotiable)

The on-disk binary format (NodeHeader=48B, EdgeRecord=32B, IndexSlot=16B, FNV-1a hash contract, edge sort invariant) is defined **once** in the `vulngraph-engine` crate, consumed here as a git dependency pinned to an `engine-v*` tag in `crates/vulngraph-data/Cargo.toml`. The `ENGINE_REV` const in `src/main.rs` must match that tag — bump both together, and only deliberately: every published manifest records `engine_rev` and `format_version`, which the serve side checks at install time.

The workspace root `Cargo.toml` has a `[patch]` section pointing at `../vulngraph/engine` for local development against an uncommitted engine checkout. Comment it out to build against the pinned tag.

## Build Determinism

Same rules as the engine (this is where they're enforced, since the builder lives here):

- All edge sorts use `sort_unstable_by` with explicit comparators: forward `(source, edge_type, target)`, reverse `(target, edge_type, source)` — in `src/builder.rs`.
- Node IDs assigned in insertion order; dedup via `id_to_node` map in `GraphBuilder::add_node()`.
- No `rand`, no HashMap-iteration-order dependence in anything written to disk. `BTreeMap` for human-readable JSON output (freshness).
- Ingest errors are logged and skipped — one bad record doesn't poison the build.
- The determinism check: build twice from the same sources → identical `snapshot_id`.

## Commands

```bash
cargo build --release
cargo test
cargo run --release -- build --sources research/downloads --output builds/vulngraph.db
cargo run --release -- export-demo --db builds/vulngraph.db --output builds/vulngraph.bin
cargo run --release -- package --db builds/vulngraph.db --demo-blob builds/vulngraph.bin --out dist
cargo run --release -- verify --dist dist
./scripts/refresh.sh [--rebuild-only] [--publish] [--cron]   # full pipeline
```

## Layout

- `crates/vulngraph-data/src/builder.rs` — `GraphBuilder` (moved from engine; uses engine's public writer primitives)
- `crates/vulngraph-data/src/ingest/` — one module per source
- `crates/vulngraph-data/src/manifest.rs` — manifest schema, `snapshot_id`, `SEMANTIC_FILES`
- `crates/vulngraph-data/src/commands/` — build, export_demo, package, verify, list_packages
- `scripts/refresh.sh` — pull sources → build → export → package → verify → promote → publish
- `scripts/publish.sh` — `gh release create data-YYYYMMDD`, skip when snapshot unchanged
- `scripts/fetch-deps-dev.sh` — deps.dev API cache, enumerates packages via `list-packages`
- `docs/data-releases.md` — the release/install contract (authoritative)
- `research/downloads/` — raw sources (~17 GB, gitignored)
- `builds/`, `dist/`, `logs/` — pipeline outputs (gitignored)

## Conventions

- Commit prefixes: `feat:`, `fix:`, `refactor:`, `chore:`, scoped like `fix(ingest/osv):`.
- Changing `SEMANTIC_FILES`, the manifest schema, or asset names is a contract change — update `docs/data-releases.md` and coordinate with vulngraph's `scripts/update.sh` in the same change.
- The `export-demo` VGDB blob layout must stay in sync with `demo/wasm/src/lib.rs` in the vulngraph repo (`vgdb_version` in the manifest tracks it).
