#!/usr/bin/env bash
# Fetch dependency data from deps.dev API for packages in the graph.
#
# Usage: ./scripts/fetch-deps-dev.sh <cache_dir> <db_dir>
#
# Reads the graph's string table to find package IDs, then queries the
# deps.dev API for each one. Caches responses as JSON files so the engine
# can read them offline during graph builds.
#
# Rate limiting: 100ms delay between requests (deps.dev has rate limits).
# Only fetches packages not already cached (incremental).

set -euo pipefail

CACHE_DIR="${1:?Usage: $0 <cache_dir> <db_dir>}"
DB_DIR="${2:?Usage: $0 <cache_dir> <db_dir>}"

API_BASE="https://api.deps.dev/v3alpha"
DELAY=0.1  # 100ms between requests
MAX_PACKAGES=20000  # cap to avoid excessive API calls

# Map VulnGraph ecosystem prefixes to deps.dev system names
ecosystem_to_system() {
    case "$1" in
        npm)       echo "npm" ;;
        PyPI)      echo "pypi" ;;
        Maven)     echo "maven" ;;
        Go)        echo "go" ;;
        crates.io) echo "cargo" ;;
        NuGet)     echo "nuget" ;;
        *)         echo "" ;;
    esac
}

# Enumerate package nodes from the previous build via the pipeline CLI.
# strings.bin stores entries back-to-back and references them by
# (offset, length) from NodeHeader, so it is not parseable with `strings`.
DATA_BIN="$(dirname "$0")/../target/release/vulngraph-data"
if [ ! -x "$DATA_BIN" ]; then
    echo "Pipeline binary not found at $DATA_BIN — skipping deps.dev fetch"
    exit 0
fi
if [ ! -d "$DB_DIR" ]; then
    echo "Graph db not found at $DB_DIR — skipping deps.dev fetch"
    exit 0
fi

PACKAGES=""
for eco in npm PyPI Maven Go crates.io NuGet; do
    ids=$("$DATA_BIN" list-packages --db "$DB_DIR" --ecosystem "$eco" \
        --limit "$MAX_PACKAGES" 2>/dev/null) || ids=""
    if [ -n "$ids" ]; then
        PACKAGES="${PACKAGES}${ids}
"
    fi
done
PACKAGES=$(printf '%s' "$PACKAGES" | sed '/^$/d' | sort -u | head -n "$MAX_PACKAGES")

TOTAL=$(printf '%s\n' "$PACKAGES" | grep -c . || true)
echo "Found $TOTAL packages to check"

FETCHED=0
SKIPPED=0
ERRORS=0

while IFS= read -r pkg_id; do
    [ -z "$pkg_id" ] && continue

    # Split ecosystem:name
    ECO="${pkg_id%%:*}"
    NAME="${pkg_id#*:}"
    SYSTEM=$(ecosystem_to_system "$ECO")

    [ -z "$SYSTEM" ] && continue

    # Cache path: cache_dir/ecosystem/urlencoded_name.json
    SAFE_NAME=$(echo "$NAME" | sed 's|/|__|g; s| |_|g')
    CACHE_FILE="$CACHE_DIR/$ECO/$SAFE_NAME.json"

    # Skip if already cached and < 7 days old
    if [ -f "$CACHE_FILE" ]; then
        AGE=$(( $(date +%s) - $(stat -c %Y "$CACHE_FILE" 2>/dev/null || echo 0) ))
        if [ "$AGE" -lt 604800 ]; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi
    fi

    mkdir -p "$CACHE_DIR/$ECO"

    # URL-encode the package name for the API
    ENCODED_NAME=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$NAME', safe=''))" 2>/dev/null || echo "$NAME")

    # Fetch from deps.dev API (get latest version's dependencies)
    URL="$API_BASE/systems/$SYSTEM/packages/$ENCODED_NAME"

    # First get the default version
    RESP=$(curl -sS -w "\n%{http_code}" "$URL" 2>/dev/null) || { ERRORS=$((ERRORS+1)); continue; }
    HTTP_CODE=$(echo "$RESP" | tail -1)
    BODY=$(echo "$RESP" | head -n -1)

    if [ "$HTTP_CODE" != "200" ]; then
        ERRORS=$((ERRORS + 1))
        sleep "$DELAY"
        continue
    fi

    # Extract default version
    DEFAULT_VERSION=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('versions',[])[0].get('versionKey',{}).get('version',''))" 2>/dev/null || echo "")

    if [ -z "$DEFAULT_VERSION" ]; then
        ERRORS=$((ERRORS + 1))
        sleep "$DELAY"
        continue
    fi

    ENCODED_VERSION=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$DEFAULT_VERSION', safe=''))" 2>/dev/null || echo "$DEFAULT_VERSION")

    # Fetch dependencies for this version
    DEP_URL="$API_BASE/systems/$SYSTEM/packages/$ENCODED_NAME/versions/$ENCODED_VERSION:dependencies"
    if curl -sS -o "$CACHE_FILE.tmp" "$DEP_URL" 2>/dev/null && [ -s "$CACHE_FILE.tmp" ]; then
        mv "$CACHE_FILE.tmp" "$CACHE_FILE"
        FETCHED=$((FETCHED + 1))
    else
        rm -f "$CACHE_FILE.tmp"
        ERRORS=$((ERRORS + 1))
    fi

    sleep "$DELAY"

    # Progress every 100
    DONE=$((FETCHED + SKIPPED + ERRORS))
    if [ $((DONE % 100)) -eq 0 ]; then
        echo "  progress: $DONE/$TOTAL (fetched=$FETCHED, cached=$SKIPPED, errors=$ERRORS)"
    fi
done <<< "$PACKAGES"

echo "deps.dev fetch complete: fetched=$FETCHED, cached=$SKIPPED, errors=$ERRORS"
