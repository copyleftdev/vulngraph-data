#!/usr/bin/env bash
# VulnGraph data pipeline refresh.
# Pulls raw sources, rebuilds the graph, exports the demo blob, packages a
# release dist/, and optionally publishes it as a GitHub Release.
#
# This script never touches a serving MCP instance. Consumers install
# published releases with vulngraph's scripts/update.sh.
#
# Usage:
#   ./scripts/refresh.sh                    # pull + build + package
#   ./scripts/refresh.sh --rebuild-only     # skip source pulls
#   ./scripts/refresh.sh --publish          # also publish a data-YYYYMMDD release
#   ./scripts/refresh.sh --cron             # cron-friendly: logs to file
#
# Crontab example (daily at 02:00 UTC):
#   0 2 * * * /home/ops/Project/vulngraph-data/scripts/refresh.sh --cron --publish

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DOWNLOADS_DIR="$PROJECT_DIR/research/downloads"
DATA_BIN="$PROJECT_DIR/target/release/vulngraph-data"
BUILDS_DIR="$PROJECT_DIR/builds"
DB_DIR="$BUILDS_DIR/vulngraph.db"
DB_NEW="$BUILDS_DIR/vulngraph.db.new"
DEMO_BLOB="$BUILDS_DIR/vulngraph.bin"
DIST_DIR="$PROJECT_DIR/dist"
LOG_FILE="$PROJECT_DIR/logs/refresh.log"

REBUILD_ONLY=false
CRON_MODE=false
PUBLISH=false

for arg in "$@"; do
    case "$arg" in
        --rebuild-only) REBUILD_ONLY=true ;;
        --cron) CRON_MODE=true ;;
        --publish) PUBLISH=true ;;
    esac
done

log() {
    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    if $CRON_MODE; then
        echo "[$ts] $*" >> "$LOG_FILE"
    else
        echo "[$ts] $*"
    fi
}

mkdir -p "$PROJECT_DIR/logs" "$BUILDS_DIR"

log "=== vulngraph-data refresh started ==="

# ─────────────────────────────────────────────────
# Step 1: Update data sources
# ─────────────────────────────────────────────────

if ! $REBUILD_ONLY; then
    log "Updating data sources..."

    update_repo() {
        local name="$1" dir="$2"
        if [ -d "$dir/.git" ]; then
            log "  pulling $name..."
            git -C "$dir" pull --ff-only --quiet 2>/dev/null || log "  WARN: $name pull failed (non-fatal)"
        else
            log "  SKIP: $name (not a git repo)"
        fi
    }

    update_repo "cvelistV5"        "$DOWNLOADS_DIR/cvelistV5"
    update_repo "exploitdb"        "$DOWNLOADS_DIR/exploitdb"
    update_repo "PoC-in-GitHub"    "$DOWNLOADS_DIR/PoC-in-GitHub"
    update_repo "nuclei-templates" "$DOWNLOADS_DIR/nuclei-templates"
    update_repo "attack-stix-data" "$DOWNLOADS_DIR/attack-stix-data"

    # Sigma rules: clone or pull SigmaHQ repo
    if [ -d "$DOWNLOADS_DIR/sigma/.git" ]; then
        update_repo "sigma" "$DOWNLOADS_DIR/sigma"
    else
        log "  cloning SigmaHQ/sigma..."
        git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$DOWNLOADS_DIR/sigma" 2>/dev/null || \
            log "  WARN: sigma clone failed (non-fatal)"
    fi

    # EPSS: re-download latest CSV
    # Note: cyentia.com 301-redirects to empiricalsecurity.com — need -L to follow
    log "  downloading latest EPSS scores..."
    mkdir -p "$DOWNLOADS_DIR/epss"
    if curl -sSL -o "$DOWNLOADS_DIR/epss/epss_scores-current.csv.gz" \
        "https://epss.cyentia.com/epss_scores-current.csv.gz" 2>/dev/null && \
        [ -s "$DOWNLOADS_DIR/epss/epss_scores-current.csv.gz" ]; then
        gunzip -f "$DOWNLOADS_DIR/epss/epss_scores-current.csv.gz" 2>/dev/null || true
        log "  EPSS updated"
    else
        log "  WARN: EPSS download failed (non-fatal)"
    fi

    # CISA KEV: re-download latest JSON
    log "  downloading latest CISA KEV..."
    mkdir -p "$DOWNLOADS_DIR/cisa-kev"
    if curl -sSL -o "$DOWNLOADS_DIR/cisa-kev/known_exploited_vulnerabilities.json" \
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" 2>/dev/null; then
        log "  KEV updated"
    else
        log "  WARN: KEV download failed (non-fatal)"
    fi

    # CAPEC: re-download latest XML (CWE→ATT&CK bridge)
    log "  downloading latest CAPEC data..."
    mkdir -p "$DOWNLOADS_DIR/capec"
    if curl -sSL -o "$DOWNLOADS_DIR/capec/capec_latest.xml" \
        "https://capec.mitre.org/data/xml/capec_latest.xml" 2>/dev/null && \
        [ -s "$DOWNLOADS_DIR/capec/capec_latest.xml" ]; then
        log "  CAPEC updated"
    else
        log "  WARN: CAPEC download failed (non-fatal)"
    fi

    # OSV: re-download full database (~1.1 GB zip)
    log "  downloading latest OSV database..."
    mkdir -p "$DOWNLOADS_DIR/osv"
    if curl -sSL -o "$DOWNLOADS_DIR/osv/all.zip.tmp" \
        "https://storage.googleapis.com/osv-vulnerabilities/all.zip" 2>/dev/null && \
        [ -s "$DOWNLOADS_DIR/osv/all.zip.tmp" ]; then
        mv "$DOWNLOADS_DIR/osv/all.zip.tmp" "$DOWNLOADS_DIR/osv/all.zip"
        log "  OSV download done ($(du -sh "$DOWNLOADS_DIR/osv/all.zip" | cut -f1))"
        log "  extracting OSV advisories..."
        rm -rf "$DOWNLOADS_DIR/osv/extracted"
        mkdir -p "$DOWNLOADS_DIR/osv/extracted"
        unzip -q -o "$DOWNLOADS_DIR/osv/all.zip" -d "$DOWNLOADS_DIR/osv/extracted" 2>/dev/null || true
        log "  OSV extracted"
    else
        rm -f "$DOWNLOADS_DIR/osv/all.zip.tmp"
        log "  WARN: OSV download failed (non-fatal)"
    fi

    # deps.dev: fetch dependency data for packages in the previous build
    FETCH_DEPS_SCRIPT="$SCRIPT_DIR/fetch-deps-dev.sh"
    if [ -x "$FETCH_DEPS_SCRIPT" ] && [ -d "$DB_DIR" ]; then
        log "  fetching deps.dev dependency data..."
        mkdir -p "$DOWNLOADS_DIR/deps-dev"
        "$FETCH_DEPS_SCRIPT" "$DOWNLOADS_DIR/deps-dev" "$DB_DIR" 2>&1 | \
            while IFS= read -r line; do log "  $line"; done || \
            log "  WARN: deps.dev fetch failed (non-fatal)"
    else
        log "  [skip] deps.dev fetch (no script or no previous build)"
    fi

    log "Data source update complete."
fi

# ─────────────────────────────────────────────────
# Step 2: Build the pipeline binary if missing
# ─────────────────────────────────────────────────

if [ ! -x "$DATA_BIN" ]; then
    log "Pipeline binary not found, building..."
    (cd "$PROJECT_DIR" && cargo build --release 2>&1 | tail -2) || {
        log "ERROR: cargo build failed"
        exit 1
    }
fi

# ─────────────────────────────────────────────────
# Step 3: Build graph to a fresh directory
# ─────────────────────────────────────────────────

log "Building graph..."
rm -rf "$DB_NEW"
mkdir -p "$DB_NEW"

if "$DATA_BIN" build --sources "$DOWNLOADS_DIR" --output "$DB_NEW" 2>&1 | \
    while IFS= read -r line; do log "  $line"; done; then
    log "Graph build succeeded."
else
    log "ERROR: Graph build failed."
    rm -rf "$DB_NEW"
    exit 1
fi

# ─────────────────────────────────────────────────
# Step 4: Export demo blob + package dist/
# ─────────────────────────────────────────────────

log "Exporting demo blob..."
"$DATA_BIN" export-demo --db "$DB_NEW" --output "$DEMO_BLOB" 2>&1 | \
    while IFS= read -r line; do log "  $line"; done

log "Packaging release dist..."
rm -rf "$DIST_DIR"
"$DATA_BIN" package --db "$DB_NEW" --demo-blob "$DEMO_BLOB" --out "$DIST_DIR" 2>&1 | \
    while IFS= read -r line; do log "  $line"; done

log "Verifying dist..."
if "$DATA_BIN" verify --dist "$DIST_DIR" 2>&1 | \
    while IFS= read -r line; do log "  $line"; done; then
    log "Dist verified."
else
    log "ERROR: dist verification failed — not promoting build."
    exit 1
fi

# Promote: new build becomes the "previous build" for the next deps.dev fetch
rm -rf "$DB_DIR"
mv "$DB_NEW" "$DB_DIR"
log "Build promoted to $DB_DIR"

# ─────────────────────────────────────────────────
# Step 5: Publish (optional)
# ─────────────────────────────────────────────────

if $PUBLISH; then
    log "Publishing release..."
    if $CRON_MODE; then
        "$SCRIPT_DIR/publish.sh" --dist "$DIST_DIR" >> "$LOG_FILE" 2>&1 || {
            log "ERROR: publish failed"
            exit 1
        }
    else
        "$SCRIPT_DIR/publish.sh" --dist "$DIST_DIR" || {
            log "ERROR: publish failed"
            exit 1
        }
    fi
fi

log "=== vulngraph-data refresh complete ==="
