# VulnGraph Data Structure Analysis Summary

Generated: 2026-03-14T04:37:27Z

## Source Status

| Source | Status | Records | CVE Cross-refs | Key Insight |
|--------|--------|---------|----------------|-------------|
| cisa_kev | analyzed | 1542 | 1542 | Authoritative exploitation signal |
| epss | analyzed | 320502 | 320502 | Daily scores, p99=0.78254 |
| osv | analyzed | 727752 | 14 | 44 ecosystems |
| cvelistV5 | analyzed | 338014 | 338014 | Avg record: 3665B |
| attack_stix | analyzed | 24772 | 0 | 835 techniques, 187 groups |
| nuclei | analyzed | 12760 | 23 | Detection templates with CVE mapping |
| exploitdb | analyzed | 46968 | 24936 | Exploit code + CVE mapping |
| poc_github | analyzed | 8457 | 300 | Avg 2.0 PoCs/CVE |
| cwe | analyzed | 969 | N/A (taxonomy) | Weakness hierarchy for classification |

## Graph Design Implications

**Primary join key**: CVE ID (CVE-YYYY-NNNNN)

### Required Indexes (for sub-ms queries)

- CVE ID → all connected nodes (primary lookup)
- Package + Ecosystem → affected CVEs (dependency query)
- EPSS score range → CVEs (risk-based query)
- Date ranges → CVEs (freshness/timeline query)

### Node Types (from all sources)

- **CVE** — central hub (linked by every source)
- **Package** — secondary hub (ecosystem + name + version)
- **Exploit** — PoC, ExploitDB entry, Nuclei template
- **Weakness** — CWE taxonomy node
- **Technique** — ATT&CK technique/tactic
- **Actor** — ATT&CK group/intrusion-set

### Edge Types

- **affects** — CVE → Package@Version (from OSV)
- **fixed_by** — CVE → Package@FixVersion (from OSV)
- **exploited_in_wild** — CVE → ExploitStatus (from KEV)
- **has_poc** — CVE → Exploit (from ExploitDB, PoC-in-GitHub, Nuclei)
- **classified_as** — CVE → CWE (from NVD/cvelistV5)
- **uses_technique** — Exploit → ATT&CK Technique
- **attributed_to** — Technique → Actor (from ATT&CK)
- **scored** — CVE → EPSS score (daily property, not edge)

---

See `structure_report.json` for full field-level details.