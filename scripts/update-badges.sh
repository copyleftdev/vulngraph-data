#!/usr/bin/env bash
# Stamp README badge values from a release manifest so the badges always
# reflect the actual published data. Rewrites the block between the
# `badges:auto` markers in README.md.
#
# Usage: ./scripts/update-badges.sh [--dist DIR] [--tag data-YYYYMMDD]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"
TAG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dist) DIST_DIR="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

MANIFEST="$DIST_DIR/manifest.json"
README="$PROJECT_DIR/README.md"
[ -f "$MANIFEST" ] || { echo "ERROR: $MANIFEST not found"; exit 1; }
[ -z "$TAG" ] && TAG="data-$(date -u +%Y%m%d)"

python3 - "$MANIFEST" "$README" "$TAG" <<'PYEOF'
import json, re, sys

manifest, readme_path, tag = sys.argv[1], sys.argv[2], sys.argv[3]
m = json.load(open(manifest))

snap = m["snapshot_id"].removeprefix("sha256:")[:8]
nodes = f"{m['node_count']:,}".replace(",", "%2C")
edges = f"{m['edge_count']:,}".replace(",", "%2C")
sources = len(m.get("sources") or {})
tag_badge = tag.replace("-", "--")

block = f"""<!-- badges:auto -->
[![release](https://img.shields.io/badge/release-{tag_badge}-0969da)](https://github.com/copyleftdev/vulngraph-data/releases/latest)
[![snapshot](https://img.shields.io/badge/snapshot-{snap}-8250df)](https://github.com/copyleftdev/vulngraph-data/releases/latest)
[![graph](https://img.shields.io/badge/graph-{nodes}_nodes_%2F_{edges}_edges-1f6feb)](https://github.com/copyleftdev/vulngraph-data/releases/latest)
[![sources](https://img.shields.io/badge/sources-{sources}-2ea44f)](docs/data-releases.md)
<!-- /badges:auto -->"""

text = open(readme_path).read()
new = re.sub(r"<!-- badges:auto -->.*?<!-- /badges:auto -->", block, text, flags=re.S)
if new == text:
    print("badges: unchanged")
else:
    open(readme_path, "w").write(new)
    print(f"badges: stamped {tag} / {snap} / {m['node_count']:,} nodes")
PYEOF
