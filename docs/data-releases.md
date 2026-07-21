# Dataset cadence and release policy

VulnGraph Data publishes a single release channel. All upstream sources are
daily-cadence or slower, so there is no fast/edge overlay.

## Source cadence

| Source | Upstream behavior | Schedule |
| --- | --- | --- |
| CVE List V5 | Continuous git updates | Daily build |
| EPSS scores | Published daily | Daily build |
| CISA KEV | Updated on new exploitation evidence | Daily build |
| ExploitDB, PoC-in-GitHub, Nuclei templates | Continuous git updates | Daily build |
| MITRE ATT&CK, CAPEC, CWE | Updated on framework releases | Checked daily |
| Sigma rules | Continuous git updates | Daily build |
| OSV (full database zip) | Rebuilt continuously | Daily build |
| deps.dev | Per-package API, 7-day cache | Incremental during daily build |

The daily pipeline runs at 02:00 UTC (`scripts/refresh.sh --cron --publish`).

## Release channel

The pipeline creates an immutable release tagged `data-YYYYMMDD` only when the
semantic snapshot changed, and marks it the repository's latest release.

Assets (fixed names):

```text
vulngraph-db.tar.gz          # graph database directory contents, archive root
vulngraph-db.tar.gz.sha256
vulngraph-demo.tar.gz        # vulngraph.bin, vulngraph.bin.gz, version.json
vulngraph-demo.tar.gz.sha256
manifest.json
```

## Manifest

```json
{
  "manifest_version": 1,
  "snapshot_id": "sha256:…",
  "format_version": 1,
  "engine_rev": "engine-v0.1.0",
  "created_at": "2026-07-20T09:04:03Z",
  "node_count": 541550,
  "edge_count": 751324,
  "files": { "nodes.bin": { "bytes": 25994400, "sha256": "…" } },
  "sources": { "cvelistV5": { "items": 359258, "updated_at": "…" } },
  "demo_blob": { "file": "vulngraph.bin", "bytes": 0, "sha256": "…", "vgdb_version": 3 }
}
```

- `snapshot_id` is the deterministic content identity: sha256 over
  `filename \0 sha256(file) \n` lines for the semantic files (the eleven
  `.bin` files plus `version_ranges.json`), in sorted filename order.
  `meta.json` and `freshness.json` are excluded because they embed build
  timestamps; they are still hash-listed in `files` for install verification.
- `format_version` mirrors the database `meta.json` version. `engine_rev` is
  the `vulngraph-engine` git tag the builder was compiled against. Together
  they guard the cross-repo binary-format contract.

## Client install contract

A client (vulngraph `scripts/update.sh`, or any other consumer):

1. Resolves the latest release (or an explicit `data-YYYYMMDD` tag).
2. Skips installation when the manifest `snapshot_id` matches the installed
   `installed-manifest.json`.
3. Downloads assets and verifies each tarball against its `.sha256`.
4. Unpacks to a staging directory, verifies every file against
   `manifest.files`, and recomputes `snapshot_id`.
5. Rejects: `format_version` mismatch, future-dated `created_at`
   (> now + 5 minutes), malformed manifest. Warns when the release is older
   than 14 days.
6. Sanity-opens the staged database with the engine before promotion.
7. Installs atomically. A failed update never replaces the last verified
   local snapshot.

## Failure and freshness rules

- A build whose `snapshot_id` equals the latest published release does not
  publish (no semantic change → no release).
- Release tags are immutable; a same-day re-publish is an error.
- Source download failures are non-fatal to the build — the previous local
  copy of that source is used and per-source `updated_at` reflects it.
- The release artifact — not this git repository — is the distribution
  boundary. Raw sources (~17 GB) and built databases are never committed.
