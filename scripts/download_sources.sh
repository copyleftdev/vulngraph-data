#!/usr/bin/env bash
set -euo pipefail

# VulnGraph Data Source Downloader
# Downloads all freely available vulnerability data sources for structure analysis.
# Run from: anywhere (paths resolve relative to this script).
# Output:   research/downloads/<source>/

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOWNLOADS_DIR="${SCRIPT_DIR}/../research/downloads"
LOG_FILE="${DOWNLOADS_DIR}/download.log"

mkdir -p "${DOWNLOADS_DIR}"

log() {
    local msg="[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] $1"
    echo "${msg}"
    echo "${msg}" >> "${LOG_FILE}"
}

fail() {
    log "FAIL: $1"
    # Continue to next source, don't abort
}

download_duration() {
    local start=$1
    local end=$(date +%s)
    echo "$(( end - start ))s"
}

# ─────────────────────────────────────────────────
# 1. CISA KEV (tiny, fast — good smoke test)
# ─────────────────────────────────────────────────
download_cisa_kev() {
    local dir="${DOWNLOADS_DIR}/cisa-kev"
    mkdir -p "${dir}"
    log "Downloading CISA KEV catalog..."
    local start=$(date +%s)
    curl -sL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
        -o "${dir}/known_exploited_vulnerabilities.json" || { fail "CISA KEV download"; return; }
    log "CISA KEV done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 2. EPSS scores (current day + historical sample)
# ─────────────────────────────────────────────────
download_epss() {
    local dir="${DOWNLOADS_DIR}/epss"
    mkdir -p "${dir}"
    log "Downloading EPSS current scores..."
    local start=$(date +%s)
    curl -sL "https://epss.cyentia.com/epss_scores-current.csv.gz" \
        -o "${dir}/epss_scores-current.csv.gz" || { fail "EPSS current"; return; }
    # Decompress for analysis
    gunzip -kf "${dir}/epss_scores-current.csv.gz" 2>/dev/null || true
    log "EPSS done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 3. OSV — full database download (all ecosystems)
# ─────────────────────────────────────────────────
download_osv() {
    local dir="${DOWNLOADS_DIR}/osv"
    mkdir -p "${dir}"
    log "Downloading OSV full database (all.zip)... this may take a few minutes"
    local start=$(date +%s)
    curl -sL "https://storage.googleapis.com/osv-vulnerabilities/all.zip" \
        -o "${dir}/all.zip" || { fail "OSV all.zip"; return; }
    log "OSV download done ($(download_duration ${start}), $(du -sh "${dir}/all.zip" | cut -f1))"
    # Extract a sample for analysis (full extract is huge)
    log "Extracting OSV sample (first 1000 files)..."
    mkdir -p "${dir}/sample"
    unzip -q -o "${dir}/all.zip" -d "${dir}/extracted" 2>/dev/null &
    local unzip_pid=$!
    # Let it run; we'll also grab the ecosystems list
    curl -sL "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt" \
        -o "${dir}/ecosystems.txt" || true
    # Also grab the modified_id.csv for freshness analysis
    curl -sL "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv" \
        -o "${dir}/modified_id.csv" || true
    wait ${unzip_pid} 2>/dev/null || log "OSV extract may have had issues (non-fatal)"
    log "OSV fully done ($(download_duration ${start}))"
}

# ─────────────────────────────────────────────────
# 4. CVE.org cvelistV5 (git shallow clone)
# ─────────────────────────────────────────────────
download_cvelistv5() {
    local dir="${DOWNLOADS_DIR}/cvelistV5"
    log "Cloning CVE.org cvelistV5 (shallow)..."
    local start=$(date +%s)
    if [ -d "${dir}/.git" ]; then
        log "cvelistV5 already cloned, pulling latest..."
        git -C "${dir}" pull --depth=1 2>/dev/null || fail "cvelistV5 pull"
    else
        git clone --depth=1 "https://github.com/CVEProject/cvelistV5.git" "${dir}" || { fail "cvelistV5 clone"; return; }
    fi
    log "cvelistV5 done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 5. MITRE ATT&CK STIX data
# ─────────────────────────────────────────────────
download_attack() {
    local dir="${DOWNLOADS_DIR}/attack-stix-data"
    log "Cloning MITRE ATT&CK STIX data (shallow)..."
    local start=$(date +%s)
    if [ -d "${dir}/.git" ]; then
        log "ATT&CK already cloned, pulling latest..."
        git -C "${dir}" pull --depth=1 2>/dev/null || fail "ATT&CK pull"
    else
        git clone --depth=1 "https://github.com/mitre-attack/attack-stix-data.git" "${dir}" || { fail "ATT&CK clone"; return; }
    fi
    log "ATT&CK done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 6. Nuclei templates
# ─────────────────────────────────────────────────
download_nuclei() {
    local dir="${DOWNLOADS_DIR}/nuclei-templates"
    log "Cloning Nuclei templates (shallow)..."
    local start=$(date +%s)
    if [ -d "${dir}/.git" ]; then
        log "Nuclei already cloned, pulling latest..."
        git -C "${dir}" pull --depth=1 2>/dev/null || fail "Nuclei pull"
    else
        git clone --depth=1 "https://github.com/projectdiscovery/nuclei-templates.git" "${dir}" || { fail "Nuclei clone"; return; }
    fi
    log "Nuclei done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 7. ExploitDB
# ─────────────────────────────────────────────────
download_exploitdb() {
    local dir="${DOWNLOADS_DIR}/exploitdb"
    log "Cloning ExploitDB (shallow)..."
    local start=$(date +%s)
    if [ -d "${dir}/.git" ]; then
        log "ExploitDB already cloned, pulling latest..."
        git -C "${dir}" pull --depth=1 2>/dev/null || fail "ExploitDB pull"
    else
        git clone --depth=1 "https://gitlab.com/exploit-database/exploitdb.git" "${dir}" || { fail "ExploitDB clone"; return; }
    fi
    log "ExploitDB done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 8. PoC-in-GitHub
# ─────────────────────────────────────────────────
download_poc_github() {
    local dir="${DOWNLOADS_DIR}/PoC-in-GitHub"
    log "Cloning PoC-in-GitHub (shallow)..."
    local start=$(date +%s)
    if [ -d "${dir}/.git" ]; then
        log "PoC-in-GitHub already cloned, pulling latest..."
        git -C "${dir}" pull --depth=1 2>/dev/null || fail "PoC-in-GitHub pull"
    else
        git clone --depth=1 "https://github.com/nomi-sec/PoC-in-GitHub.git" "${dir}" || { fail "PoC-in-GitHub clone"; return; }
    fi
    log "PoC-in-GitHub done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 9. CWE (Common Weakness Enumeration)
# ─────────────────────────────────────────────────
download_cwe() {
    local dir="${DOWNLOADS_DIR}/cwe"
    mkdir -p "${dir}"
    log "Downloading CWE data..."
    local start=$(date +%s)
    curl -sL "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip" \
        -o "${dir}/cwec_latest.xml.zip" || { fail "CWE XML"; return; }
    unzip -q -o "${dir}/cwec_latest.xml.zip" -d "${dir}" 2>/dev/null || true
    # Also try JSON
    curl -sL "https://cwe.mitre.org/data/json/weakness-catalog.json" \
        -o "${dir}/weakness-catalog.json" 2>/dev/null || true
    log "CWE done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 10. Sigma detection rules
# ─────────────────────────────────────────────────
download_sigma() {
    local dir="${DOWNLOADS_DIR}/sigma"
    log "Downloading Sigma rules..."
    local start=$(date +%s)
    if [ -d "${dir}/.git" ]; then
        log "Sigma already cloned, pulling latest..."
        git -C "${dir}" pull --depth=1 2>/dev/null || fail "Sigma pull"
    else
        git clone --depth=1 "https://github.com/SigmaHQ/sigma.git" "${dir}" || { fail "Sigma clone"; return; }
    fi
    log "Sigma done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# 11. CAPEC (CWE→ATT&CK bridge)
# ─────────────────────────────────────────────────
download_capec() {
    local dir="${DOWNLOADS_DIR}/capec"
    mkdir -p "${dir}"
    log "Downloading CAPEC data..."
    local start=$(date +%s)
    curl -sL "https://capec.mitre.org/data/xml/capec_latest.xml" \
        -o "${dir}/capec_latest.xml" || { fail "CAPEC XML"; return; }
    log "CAPEC done ($(download_duration ${start}), $(du -sh "${dir}" | cut -f1))"
}

# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────
log "=========================================="
log "VulnGraph Data Source Download — START"
log "Target: ${DOWNLOADS_DIR}"
log "=========================================="

# Parse args: allow selective download
SOURCES="${1:-all}"

if [ "${SOURCES}" = "all" ]; then
    # Order: small/fast first, large last
    download_cisa_kev
    download_epss
    download_cwe
    download_capec
    download_sigma
    download_attack
    download_nuclei
    download_poc_github
    download_exploitdb
    download_cvelistv5
    download_osv
else
    # Download specific source(s), comma-separated
    IFS=',' read -ra REQUESTED <<< "${SOURCES}"
    for src in "${REQUESTED[@]}"; do
        case "${src}" in
            kev|cisa-kev)    download_cisa_kev ;;
            epss)            download_epss ;;
            cwe)             download_cwe ;;
            capec)           download_capec ;;
            sigma)           download_sigma ;;
            attack|attck)    download_attack ;;
            nuclei)          download_nuclei ;;
            exploitdb)       download_exploitdb ;;
            poc|poc-github)  download_poc_github ;;
            cve|cvelistv5)   download_cvelistv5 ;;
            osv)             download_osv ;;
            *) log "Unknown source: ${src}" ;;
        esac
    done
fi

log "=========================================="
log "Download complete. Disk usage:"
du -sh "${DOWNLOADS_DIR}"/* 2>/dev/null || true
log "=========================================="
