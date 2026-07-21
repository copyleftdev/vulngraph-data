# VulnGraph Data

VulnGraph Data is the deterministic vulnerability-intelligence data pipeline
for [VulnGraph](https://github.com/copyleftdev/vulngraph). It retrieves bulk
publications from original sources, ingests and normalizes them into the
VulnGraph binary graph database, and publishes reproducible, checksummed
release artifacts. It does not contain the query engine or the MCP server and
never serves per-CVE lookups.

## Dataset coverage

- CVE List V5 records with CVSS extraction
- EPSS exploit-probability scores, CISA Known Exploited Vulnerabilities
- ExploitDB, PoC-in-GitHub, and Nuclei template exploit intelligence
- MITRE ATT&CK techniques/actors/software, Sigma detection rules,
  CWE→ATT&CK bridging via CAPEC
- OSV advisories with version ranges, GHSA advisories, deps.dev dependency
  graphs

## Data workflow

```text
raw bulk sources (research/downloads/, ~17 GB)
        ↓
vulngraph-data build          → builds/vulngraph.db (mmap binary graph)
        ↓
vulngraph-data export-demo    → builds/vulngraph.bin (VGDB blob for WASM demo)
        ↓
vulngraph-data package        → dist/ (tarballs + sha256 + manifest.json)
        ↓
vulngraph-data verify         → client-rule re-verification
        ↓
scripts/publish.sh            → immutable data-YYYYMMDD GitHub Release
```

## Commands

```bash
cargo run --release -p vulngraph-data -- build --sources research/downloads --output builds/vulngraph.db
cargo run --release -p vulngraph-data -- export-demo --db builds/vulngraph.db --output builds/vulngraph.bin
cargo run --release -p vulngraph-data -- package --db builds/vulngraph.db --demo-blob builds/vulngraph.bin --out dist
cargo run --release -p vulngraph-data -- verify --dist dist
cargo run --release -p vulngraph-data -- list-packages --db builds/vulngraph.db --ecosystem npm

# Full pipeline
./scripts/refresh.sh                # pull sources + build + package
./scripts/refresh.sh --publish      # + publish GitHub Release
```

## Format contract

The on-disk binary format is defined once, in the `vulngraph-engine` crate,
which this repo consumes as a git dependency pinned to an `engine-v*` tag.
Bumping that pin is a deliberate format-sync act. The release cadence, asset
names, manifest schema, and client install rules are documented in
[docs/data-releases.md](docs/data-releases.md).
