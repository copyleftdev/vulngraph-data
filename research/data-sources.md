# VulnGraph Data Source Inventory

Status: DRAFT — validating sources before pipeline design

This document catalogs every candidate data source for the VulnGraph intelligence
graph, organized by the graph node/edge types they feed. Each source is assessed on:

- **Format** — wire format and schema
- **Access** — API, bulk download, git clone, etc.
- **Freshness** — how often the upstream updates
- **Latency** — lag between real-world event and data availability
- **Rate limits** — throttling, auth requirements
- **License** — redistribution constraints
- **Quality** — known gaps, caveats
- **Priority** — how critical this source is to VulnGraph MVP

---

## 1. CVE / Base Vulnerability Records

These feed the **CVE** node and provide the canonical vulnerability identifiers.

### 1.1 NVD (NIST National Vulnerability Database) — CVE API 2.0

| Field          | Value |
|----------------|-------|
| **URL**        | https://nvd.nist.gov/developers/vulnerabilities |
| **Format**     | JSON (NVD CVE 2.0 schema) |
| **Access**     | REST API (HTTP GET), paginated |
| **Auth**       | API key (free, raises rate limit) |
| **Rate limit** | Without key: 5 req / 30s. With key: 50 req / 30s |
| **Freshness**  | CVEs added/modified continuously; recommended poll interval ≥ 2 hours using `lastModStartDate`/`lastModEndDate` |
| **Latency**    | Hours to days after CNA publishes (NVD enrichment adds delay) |
| **Data**       | CVE ID, descriptions, CVSS v2/v3/v4, CWE, CPE matches, references |
| **License**    | Public domain (US government work). Must display: "This product uses data from the NVD API but is not endorsed or certified by the NVD." |
| **Quality**    | Gold standard for CVSS/CPE. Known enrichment backlog (NVD has had multi-month delays in analysis). |
| **Priority**   | **CRITICAL** — primary CVE + CVSS + CPE source |

**Freshness concern**: NVD has experienced significant enrichment delays (2024 backlog
incident). Cannot be sole source for time-sensitive CVE data.

### 1.2 CVE.org / CVEList V5 (MITRE CVE Program)

| Field          | Value |
|----------------|-------|
| **URL**        | https://github.com/CVEProject/cvelistV5 |
| **Format**     | JSON (CVE Record Format 5.x) |
| **Access**     | Git clone (bulk), CVE Services REST API |
| **Auth**       | None for git; API requires CNA credentials for write |
| **Rate limit** | Git: none. API: undocumented |
| **Freshness**  | Near-real-time — CNAs publish directly |
| **Latency**    | Minutes after CNA submission |
| **Data**       | CVE ID, descriptions, affected products (vendor-supplied), references |
| **License**    | Public domain |
| **Quality**    | Faster than NVD but less enriched — no CVSS, no CPE normalization |
| **Priority**   | **HIGH** — fills the NVD enrichment gap for early CVE awareness |

**Key insight**: Use CVE.org for fast CVE ingestion, NVD for enrichment. Together they
cover the freshness gap.

---

## 2. Package / Dependency Vulnerability Mapping

These feed the **software package**, **software version**, and **dependency** nodes and
the **affects** / **depends_on** edges.

### 2.1 OSV (Open Source Vulnerabilities) — Google

| Field          | Value |
|----------------|-------|
| **URL**        | https://osv.dev / https://google.github.io/osv.dev/api/ |
| **Format**     | OpenSSF OSV format (JSON) |
| **Access**     | REST API, GCS bulk download (`gs://osv-vulnerabilities/`) |
| **Auth**       | None |
| **Rate limit** | Currently no limits on API. Response max 32 MiB. |
| **Freshness**  | Continuously aggregated from upstream sources |
| **Latency**    | Minutes to hours (depends on upstream source) |
| **Ecosystems** | npm, PyPI, Go, crates.io, Maven, NuGet, RubyGems, Packagist, Pub, Hex, Alpine, Debian, Ubuntu, Rocky, Alma, Android, Linux kernel, Haskell, R, Swift, OCaml, Git/C/C++ |
| **Data**       | Vuln ID, affected packages, affected version ranges (precise), references, severity, credits |
| **License**    | Varies by source (CC-BY 4.0, CC0, Apache 2.0, MIT, BSD) — all permissive |
| **Quality**    | Excellent version range precision. Aggregates 16+ upstream databases. |
| **Bulk sync**  | `modified_id.csv` files enable efficient incremental sync (reverse chronological) |
| **Priority**   | **CRITICAL** — single best source for open-source package→vulnerability mapping |

**Key insight**: OSV is the aggregator. It already ingests GHSA, PyPI advisories, Go
vulndb, RustSec, etc. For most ecosystems, OSV is sufficient and avoids needing to
integrate each ecosystem DB individually.

### 2.2 GitHub Advisory Database (GHSA)

| Field          | Value |
|----------------|-------|
| **URL**        | https://github.com/advisories / https://docs.github.com/en/rest/security-advisories |
| **Format**     | OSV JSON (in advisory-database repo), also GraphQL/REST API |
| **Access**     | Git clone (`github/advisory-database`), REST API, GraphQL API |
| **Auth**       | Git: none. API: GitHub token |
| **Rate limit** | 5,000 req/hr (authenticated REST), GraphQL point-based |
| **Freshness**  | Continuously updated; GitHub-reviewed advisories curated by security team |
| **Data**       | GHSA ID, CVE cross-ref, affected packages (ecosystem-specific), severity, patches |
| **License**    | CC-BY 4.0 |
| **Quality**    | High — GitHub-reviewed subset is human-curated |
| **Priority**   | **MEDIUM** — already aggregated by OSV, but direct access useful for GHSA-specific IDs and GitHub ecosystem integration |

---

## 3. Exploit Intelligence

These feed the **exploit** node and the **exploited_by** edge.

### 3.1 CISA KEV (Known Exploited Vulnerabilities Catalog)

| Field          | Value |
|----------------|-------|
| **URL**        | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **Format**     | JSON, CSV |
| **Access**     | Direct download (JSON/CSV), no API needed |
| **Auth**       | None |
| **Rate limit** | None (static file) |
| **Freshness**  | Updated as CISA adds entries (typically within days of confirmed exploitation) |
| **Latency**    | Days to weeks after exploitation begins (CISA validation process) |
| **Data**       | CVE, vendor, product, vuln name, date added, due date, required action, ransomware use flag |
| **License**    | Public domain (US government) |
| **Quality**    | High confidence — CISA-validated exploitation. Conservative (under-counts). ~1,200+ entries. |
| **Priority**   | **CRITICAL** — authoritative "exploited in the wild" signal |

### 3.2 VulnCheck KEV (Community)

| Field          | Value |
|----------------|-------|
| **URL**        | https://vulncheck.com/kev / https://api.vulncheck.com/v3/backup/vulncheck-kev |
| **Format**     | JSON |
| **Access**     | REST API |
| **Auth**       | Bearer token (free community tier) |
| **Rate limit** | Community tier limits (undocumented specifics) |
| **Freshness**  | Continuously updated |
| **Latency**    | Hours — significantly faster than CISA KEV |
| **Data**       | CVE, vendor, product, CWEs, exploit references (xdb links, GitHub PoCs), reported exploitation sources with dates, ransomware campaign flag, CISA cross-reference |
| **License**    | Community access (free tier), commercial terms for full API |
| **Quality**    | ~80% more CVEs than CISA KEV. Includes exploit DB cross-references and canary data. |
| **Priority**   | **HIGH** — best available "exploited in the wild" enrichment beyond CISA |

### 3.3 EPSS (Exploit Prediction Scoring System) — FIRST.org

| Field          | Value |
|----------------|-------|
| **URL**        | https://www.first.org/epss/ / https://api.first.org/data/v1/epss |
| **Format**     | CSV (bulk), JSON (API) |
| **Access**     | REST API, CSV download |
| **Auth**       | None |
| **Rate limit** | Undocumented (public API) |
| **Freshness**  | **Daily** — scores recalculated every day |
| **Latency**    | ~24 hours |
| **Data**       | CVE ID, EPSS probability (0–1), percentile |
| **Historical** | All daily scores since 2021-04-14 via https://github.com/empiricalsec/epss_scores |
| **Version**    | Currently v4 (v2025.03.14), started publishing 2025-03-17 |
| **License**    | Free, open data |
| **Quality**    | Empirically validated. Predicts probability of exploitation in next 30 days. |
| **Priority**   | **CRITICAL** — core input for risk scoring and the "AI Risk Insights" premium feature |

### 3.4 ExploitDB / Exploit Database

| Field          | Value |
|----------------|-------|
| **URL**        | https://gitlab.com/exploit-database/exploitdb |
| **Format**     | CSV index + raw exploit files |
| **Access**     | Git clone (GitLab repo) |
| **Auth**       | None |
| **Rate limit** | None (git clone) |
| **Freshness**  | Updated as exploits are submitted and reviewed |
| **Data**       | Exploit ID, CVE cross-ref, exploit type, platform, exploit code |
| **License**    | GPL v2 |
| **Quality**    | Curated by OffSec. Established, but aging. Not all entries have CVE mappings. |
| **Priority**   | **MEDIUM** — useful for exploit code linkage, but VulnCheck xdb provides better coverage |

### 3.5 Nuclei Templates (ProjectDiscovery)

| Field          | Value |
|----------------|-------|
| **URL**        | https://github.com/projectdiscovery/nuclei-templates |
| **Format**     | YAML templates |
| **Access**     | Git clone |
| **Auth**       | None |
| **Rate limit** | None (git) |
| **Freshness**  | Community-driven, very active (~daily commits) |
| **Data**       | Template ID, CVE cross-ref, severity, detection logic, tags (incl. `kev` tag for ~1,496 KEV-mapped templates) |
| **License**    | MIT |
| **Quality**    | Large, active community. Templates are detection-oriented (confirms exploitability). |
| **Priority**   | **MEDIUM** — signals "scannable/exploitable" and provides detection metadata |

### 3.6 PoC-in-GitHub (nomi-sec)

| Field          | Value |
|----------------|-------|
| **URL**        | https://github.com/nomi-sec/PoC-in-GitHub |
| **Format**     | JSON (per-year directories, per-CVE files) |
| **Access**     | Git clone |
| **Auth**       | None |
| **Rate limit** | None (git) |
| **Freshness**  | Auto-collected from GitHub, updated regularly |
| **Data**       | CVE ID → list of GitHub repos with PoC code (repo URL, stars, forks, description, dates) |
| **License**    | Not explicitly stated |
| **Quality**    | Automated collection — includes malicious/fake PoCs. Needs quality filtering. |
| **Priority**   | **LOW** — VulnCheck xdb is a better curated alternative, but useful as supplementary signal |

---

## 4. Threat Actor Intelligence

These feed the **threat actor** node and **observed_in** edges.

### 4.1 MITRE ATT&CK

| Field          | Value |
|----------------|-------|
| **URL**        | https://attack.mitre.org/ / https://github.com/mitre-attack/attack-stix-data |
| **Format**     | STIX 2.1 JSON bundles |
| **Access**     | Git clone, TAXII 2.1 server |
| **Auth**       | None |
| **Rate limit** | None |
| **Freshness**  | Updated with ATT&CK releases (roughly quarterly major, with interim updates) |
| **Latency**    | Weeks to months (curated framework) |
| **Data**       | Techniques, tactics, groups, software, mitigations, data sources |
| **License**    | Apache 2.0 |
| **Quality**    | Gold standard for adversary TTPs. Not CVE-granular — maps techniques, not individual vulns. |
| **Priority**   | **MEDIUM** — enriches threat context but requires CVE→technique mapping (not 1:1) |

**Integration note**: ATT&CK maps at the technique level, not CVE level. Linking
CVEs to ATT&CK techniques requires a mapping layer (e.g., via CWE→ATT&CK or
exploit-type tagging).

---

## 5. Patch / Fix Tracking

These feed the **patched_by** edge and the "Vulnerability Flight Recorder" timeline.

### 5.1 NVD References

| Field          | Value |
|----------------|-------|
| **Data**       | CVE references include vendor advisories, patch URLs, commit links |
| **Quality**    | Variable — some CVEs have precise patch commit links, many don't |
| **Priority**   | **HIGH** — already ingested with NVD data; parse reference tags for patch signals |

### 5.2 OSV Fix Data

| Field          | Value |
|----------------|-------|
| **Data**       | OSV records include `fixed` version ranges per ecosystem |
| **Quality**    | Precise — ecosystem-native version ranges |
| **Priority**   | **HIGH** — best source for "which version fixes this" |

### 5.3 GitHub Commits / PRs (via Advisory References)

| Field          | Value |
|----------------|-------|
| **Access**     | GitHub API (REST/GraphQL) |
| **Auth**       | GitHub token required |
| **Rate limit** | 5,000 req/hr authenticated |
| **Data**       | Commit SHAs, PR metadata, timestamps |
| **Quality**    | Requires CVE→commit mapping (partially available via GHSA and NVD references) |
| **Priority**   | **MEDIUM** — needed for "Flight Recorder" feature timeline precision |

---

## 6. Supplementary / Enrichment Sources

### 6.1 CPE Dictionary (NVD)

| Field          | Value |
|----------------|-------|
| **URL**        | https://nvd.nist.gov/developers/products |
| **Data**       | CPE names → vendor/product/version mappings |
| **Priority**   | **HIGH** — needed for CVE→product mapping when ingesting NVD |

### 6.2 CWE (Common Weakness Enumeration)

| Field          | Value |
|----------------|-------|
| **URL**        | https://cwe.mitre.org/data/downloads.html |
| **Format**     | XML, JSON |
| **Data**       | Weakness taxonomy, hierarchy, descriptions |
| **Priority**   | **MEDIUM** — enriches CVE classification, enables CWE→ATT&CK bridging |

---

## 7. Sources Explicitly NOT Recommended for MVP

| Source | Reason |
|--------|--------|
| **Shodan/Censys** | Infrastructure scanning data — useful but out of scope for vuln intelligence MVP |
| **VirusTotal** | Malware-focused, not vuln-focused. Commercial API. |
| **Full MITRE CVE Services API** | Write-oriented (for CNAs). Read via cvelistV5 git instead. |
| **Commercial feeds (Recorded Future, Mandiant, etc.)** | Cost-prohibitive for MVP. Revisit for Enterprise tier. |

---

## 8. Freshness Lifecycle Matrix

This matrix summarizes the data freshness characteristics across all sources.

| Source | Update Frequency | Typical Latency | Sync Method | Pipeline Tier |
|--------|-----------------|-----------------|-------------|---------------|
| CVE.org (cvelistV5) | Real-time | Minutes | Git poll (15 min) | **Tier 1 — Hot** |
| CISA KEV | As-needed | Days | HTTP download (1 hr) | **Tier 1 — Hot** |
| EPSS | Daily | ~24 hours | CSV download (daily) | **Tier 2 — Warm** |
| NVD API | Continuous (enrichment delayed) | Hours–days | API poll (2 hr) | **Tier 2 — Warm** |
| OSV | Continuous | Minutes–hours | GCS sync / `modified_id.csv` (1 hr) | **Tier 1 — Hot** |
| VulnCheck KEV | Continuous | Hours | API poll (1 hr) | **Tier 1 — Hot** |
| GHSA | Continuous | Hours | Git poll (1 hr) or via OSV | **Tier 2 — Warm** (via OSV) |
| ExploitDB | As-needed | Days | Git pull (daily) | **Tier 3 — Cold** |
| Nuclei Templates | Daily+ | Days | Git pull (daily) | **Tier 3 — Cold** |
| PoC-in-GitHub | Regular | Days | Git pull (daily) | **Tier 3 — Cold** |
| ATT&CK | Quarterly | Weeks | Git pull (weekly) | **Tier 3 — Cold** |
| CWE | Infrequent | N/A | Download (weekly) | **Tier 3 — Cold** |
| CPE Dictionary | Continuous | Hours | API (2 hr, with NVD) | **Tier 2 — Warm** |

### Pipeline Tiers

- **Tier 1 — Hot (≤1 hr)**: Sources where freshness is critical to VulnGraph's value proposition. These drive real-time exploit awareness and fast CVE ingestion.
- **Tier 2 — Warm (1–24 hr)**: Sources providing enrichment (scores, CPE mapping, detailed analysis). Slight delay is acceptable.
- **Tier 3 — Cold (daily+)**: Reference data and supplementary signals. Updated on a relaxed schedule.

---

## 9. Open Questions

- [ ] **NVD reliability**: Given the 2024 enrichment backlog, should we treat NVD as enrichment-only and use CVE.org + OSV as primary?
- [ ] **VulnCheck Community tier limits**: Need to validate rate limits and terms of service for production use.
- [ ] **OSV as single aggregator**: Can we skip individual ecosystem DBs entirely and rely on OSV? Need to verify coverage gaps.
- [ ] **License compliance**: OSV sources have mixed licenses. Need legal review for redistribution in a commercial product.
- [ ] **CVE→ATT&CK mapping**: No authoritative mapping exists. Build our own via CWE bridging or manual curation?
- [ ] **Flight Recorder data**: Which sources provide the timestamps needed for the disclosure→exploit→patch timeline?

---

## 10. Recommended MVP Source Stack

For the initial VulnGraph intelligence graph, the minimum viable source set is:

| Role | Primary Source | Enrichment Source |
|------|---------------|-------------------|
| **CVE records** | CVE.org (cvelistV5) | NVD API 2.0 |
| **Package mapping** | OSV | (subsumes GHSA, Go, Rust, PyPI, etc.) |
| **Exploit status** | CISA KEV + VulnCheck KEV | — |
| **Exploit likelihood** | EPSS | — |
| **Risk scoring** | CVSS (via NVD) + EPSS | — |
| **Patch status** | OSV (fixed versions) | NVD references |

This gives us **6 primary integrations** covering all core graph nodes and edges.
