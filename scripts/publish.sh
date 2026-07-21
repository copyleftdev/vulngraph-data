#!/usr/bin/env bash
# Publish dist/ as an immutable data-YYYYMMDD GitHub Release.
# Skips publishing when the snapshot_id matches the latest published release
# (no semantic change → no release).
#
# Usage: ./scripts/publish.sh [--dist DIR] [--repo owner/name]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"
REPO="copyleftdev/vulngraph-data"

while [ $# -gt 0 ]; do
    case "$1" in
        --dist) DIST_DIR="$2"; shift 2 ;;
        --repo) REPO="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

MANIFEST="$DIST_DIR/manifest.json"
[ -f "$MANIFEST" ] || { echo "ERROR: $MANIFEST not found"; exit 1; }

SNAPSHOT_ID="$(python3 -c "import json; print(json.load(open('$MANIFEST'))['snapshot_id'])")"
echo "Local snapshot: $SNAPSHOT_ID"

# Compare against the latest published release's manifest
LATEST_MANIFEST="$(mktemp -d)/manifest.json"
if gh release download --repo "$REPO" --pattern manifest.json \
    --output "$LATEST_MANIFEST" 2>/dev/null; then
    LATEST_ID="$(python3 -c "import json; print(json.load(open('$LATEST_MANIFEST'))['snapshot_id'])" 2>/dev/null || echo "")"
    if [ "$LATEST_ID" = "$SNAPSHOT_ID" ]; then
        echo "Snapshot unchanged from latest release — not publishing."
        exit 0
    fi
    echo "Latest published: ${LATEST_ID:-<none>}"
else
    echo "No previous release found."
fi

TAG="data-$(date -u +%Y%m%d)"

if gh release view "$TAG" --repo "$REPO" > /dev/null 2>&1; then
    echo "ERROR: release $TAG already exists (releases are immutable; rerun tomorrow or delete manually)."
    exit 1
fi

echo "Creating release $TAG..."
gh release create "$TAG" \
    --repo "$REPO" \
    --title "VulnGraph data $TAG" \
    --notes "Snapshot \`$SNAPSHOT_ID\`. See manifest.json for per-source freshness and file hashes." \
    --latest \
    "$DIST_DIR"/vulngraph-db.tar.gz \
    "$DIST_DIR"/vulngraph-db.tar.gz.sha256 \
    "$DIST_DIR"/vulngraph-demo.tar.gz \
    "$DIST_DIR"/vulngraph-demo.tar.gz.sha256 \
    "$DIST_DIR"/manifest.json

echo "Published $TAG."

# Stamp README badges from the manifest and push, so the badge numbers
# always describe the release that is actually latest.
"$SCRIPT_DIR/update-badges.sh" --dist "$DIST_DIR" --tag "$TAG"
if ! git -C "$PROJECT_DIR" diff --quiet -- README.md; then
    git -C "$PROJECT_DIR" add README.md
    git -C "$PROJECT_DIR" commit -q -m "chore: stamp README badges for $TAG"
    git -C "$PROJECT_DIR" push -q origin HEAD || echo "WARN: badge push failed (non-fatal)"
    echo "README badges updated for $TAG."
fi
