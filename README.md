# VulnGraph Data

**The deterministic data pipeline behind [VulnGraph](https://github.com/copyleftdev/vulngraph).**

[![Tip my tokens](https://tokentip.to/badge/copyleftdev.svg?logo=1)](https://tokentip.to/@copyleftdev)
<!-- badges:auto -->
[![release](https://img.shields.io/badge/release-data--20260809-0969da)](https://github.com/copyleftdev/vulngraph-data/releases/latest)
[![snapshot](https://img.shields.io/badge/snapshot-2e081a39-8250df)](https://github.com/copyleftdev/vulngraph-data/releases/latest)
[![graph](https://img.shields.io/badge/graph-563%2C831_nodes_%2F_813%2C998_edges-1f6feb)](https://github.com/copyleftdev/vulngraph-data/releases/latest)
[![sources](https://img.shields.io/badge/sources-11-2ea44f)](docs/data-releases.md)
<!-- /badges:auto -->
[![reproducible](https://img.shields.io/badge/builds-byte--identical-2ea44f)](.claude/rules/determinism.md)
[![engine pin](https://img.shields.io/badge/engine-engine--v0.1.0-b7410e)](crates/vulngraph-data/Cargo.toml)

VulnGraph Data retrieves bulk publications from original vulnerability
sources, ingests and normalizes them into the VulnGraph binary graph
database, and publishes reproducible, checksummed release artifacts. It does
not contain the query engine or the MCP server and never serves per-CVE
lookups — the release artifact, not this repository, is the product.

Badges inside the `badges:auto` markers are stamped from the published
`manifest.json` by `scripts/update-badges.sh` at publish time — the numbers
are the release, not marketing.

## Dataset coverage

| Source | What it contributes |
|---|---|
| CVE List V5 | 359k+ CVE records, CVSS extraction, version ranges |
| EPSS | Exploit-probability scores + percentiles |
| CISA KEV | Known-exploited flags |
| ExploitDB · PoC-in-GitHub · Nuclei | Public exploit / PoC / template links |
| MITRE ATT&CK · CAPEC · CWE | Techniques, actors, software; CWE→ATT&CK bridge |
| Sigma | Detection-rule links |
| OSV · GHSA | Advisories, package ecosystems, version ranges |
| deps.dev | Package dependency edges (incremental, 7-day cache) |

## Pipeline

```text
raw bulk sources (research/downloads/, ~17 GB, gitignored)
        ↓
vulngraph-data build          → builds/vulngraph.db   (mmap binary graph)
        ↓
vulngraph-data export-demo    → builds/vulngraph.bin  (VGDB blob, WASM demo)
        ↓
vulngraph-data package        → dist/   (tarballs + sha256 + manifest.json)
        ↓
vulngraph-data verify         → re-verification under the client install rules
        ↓
scripts/publish.sh            → immutable data-YYYYMMDD GitHub Release
```

Consumers install releases with vulngraph's `scripts/update.sh`: checksum →
per-file hash verify → `snapshot_id` recompute → engine sanity-open → atomic
swap. A failed update never replaces a verified snapshot.

## Determinism is the contract

Identical sources produce **byte-identical** semantic files. That is what
makes the manifest's `snapshot_id` a real content identity, "no change → no
release" enforceable, and any consumer able to re-derive and audit exactly
what it installed. Enforced by:

- explicit sort comparators for both edge orderings
- no HashMap iteration order in anything written to disk (key-sorted JSON)
- no wall-clock in on-disk records — a single source-mtime-derived build
  timestamp, injected via `GraphBuilder::set_build_timestamp()`
- verified with double builds ([rules](.claude/rules/determinism.md))

## Commands

```bash
cargo run --release -- build --sources research/downloads --output builds/vulngraph.db
cargo run --release -- export-demo --db builds/vulngraph.db --output builds/vulngraph.bin
cargo run --release -- package --db builds/vulngraph.db --demo-blob builds/vulngraph.bin --out dist
cargo run --release -- verify --dist dist
cargo run --release -- list-packages --db builds/vulngraph.db --ecosystem npm

# Full pipeline
./scripts/refresh.sh                # pull sources + build + package + verify
./scripts/refresh.sh --publish      # + publish a GitHub Release (skips if unchanged)
```

## The artifacts are the product

Consumers should use the **published releases**, not build from source. The
[vulngraph CLI](https://github.com/copyleftdev/vulngraph-cli) installs them
with `vulngraph update`; the hosted MCP server installs them with its
`update.sh`. Building this pipeline from source additionally requires access
to the private `vulngraph` engine repository (a git dependency); that is only
needed to *produce* releases, never to consume them.

## Format contract

The on-disk binary format is defined once, in the `vulngraph-engine` crate,
consumed here as a git dependency pinned to an `engine-v*` tag. Every
published manifest records `engine_rev` and `format_version`; consumers
reject mismatches, so the repos cannot drift silently. The public
[vulngraph-cli](https://github.com/copyleftdev/vulngraph-cli) mirrors the
`snapshot_id` algorithm and `SEMANTIC_FILES` from `manifest.rs` — changing
either is a cross-repo contract change gated by `manifest_version` /
`format_version`. Bumping the engine pin is a deliberate format-sync act.

MIT licensed.

Release cadence, asset names, manifest schema, and the client install
contract: [docs/data-releases.md](docs/data-releases.md).
