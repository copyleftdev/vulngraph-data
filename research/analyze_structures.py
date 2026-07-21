#!/usr/bin/env python3
"""
VulnGraph Data Structure Analyzer

Inspects each downloaded data source and produces a structured report:
- Schema discovery (field names, types, nesting depth)
- Record counts
- Field cardinality (unique values per field)
- Cross-reference key analysis (CVE IDs, package names, CWEs)
- Size characteristics (avg record size, total size)
- Relationship density (how sources connect to each other)

Output: research/analysis/structure_report.json + human-readable summary
"""

import json
import csv
import os
import sys
import glob
import time
import statistics
import collections
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).parent
DOWNLOADS_DIR = SCRIPT_DIR.parent / "downloads"
ANALYSIS_DIR = SCRIPT_DIR.parent / "analysis"
ANALYSIS_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────
# Utility functions
# ─────────────────────────────────────────────────

def discover_json_schema(obj: Any, max_depth: int = 10, _depth: int = 0) -> dict:
    """Recursively discover the schema of a JSON object."""
    if _depth >= max_depth:
        return {"type": "truncated_at_max_depth"}

    if obj is None:
        return {"type": "null"}
    elif isinstance(obj, bool):
        return {"type": "boolean"}
    elif isinstance(obj, int):
        return {"type": "integer"}
    elif isinstance(obj, float):
        return {"type": "float"}
    elif isinstance(obj, str):
        return {"type": "string", "sample_length": len(obj)}
    elif isinstance(obj, list):
        if len(obj) == 0:
            return {"type": "array", "items": {"type": "unknown"}, "length": 0}
        # Sample first few items
        item_schemas = [discover_json_schema(item, max_depth, _depth + 1)
                        for item in obj[:3]]
        return {
            "type": "array",
            "items": item_schemas[0],  # representative
            "length": len(obj),
        }
    elif isinstance(obj, dict):
        fields = {}
        for key, value in obj.items():
            fields[key] = discover_json_schema(value, max_depth, _depth + 1)
        return {"type": "object", "fields": fields, "field_count": len(fields)}
    else:
        return {"type": str(type(obj).__name__)}


def count_json_files(directory: Path, pattern: str = "**/*.json") -> int:
    """Count JSON files in a directory tree."""
    return sum(1 for _ in directory.glob(pattern))


def sample_json_files(directory: Path, pattern: str = "**/*.json",
                      max_samples: int = 100) -> list[dict]:
    """Load a sample of JSON files from a directory."""
    files = sorted(directory.glob(pattern))
    if len(files) > max_samples:
        step = len(files) // max_samples
        files = files[::step][:max_samples]

    samples = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
                samples.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return samples


def extract_cve_ids(obj: Any, _found: set | None = None) -> set:
    """Recursively extract CVE IDs from any JSON structure."""
    if _found is None:
        _found = set()

    if isinstance(obj, str):
        if obj.startswith("CVE-"):
            _found.add(obj)
    elif isinstance(obj, list):
        for item in obj:
            extract_cve_ids(item, _found)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            extract_cve_ids(value, _found)
    return _found


def field_value_stats(samples: list[dict], field_path: str) -> dict:
    """Get statistics on a specific field across samples."""
    values = []
    for sample in samples:
        obj = sample
        for part in field_path.split("."):
            if isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                obj = None
                break
        if obj is not None:
            values.append(obj)

    if not values:
        return {"present": 0, "missing": len(samples)}

    result = {
        "present": len(values),
        "missing": len(samples) - len(values),
        "type": type(values[0]).__name__,
    }

    if all(isinstance(v, str) for v in values):
        lengths = [len(v) for v in values]
        unique = len(set(values))
        result.update({
            "unique_values": unique,
            "cardinality_ratio": round(unique / len(values), 4),
            "avg_length": round(statistics.mean(lengths), 1),
            "max_length": max(lengths),
        })
    elif all(isinstance(v, (int, float)) for v in values):
        result.update({
            "min": min(values),
            "max": max(values),
            "mean": round(statistics.mean(values), 4),
            "median": round(statistics.median(values), 4),
        })
    elif all(isinstance(v, list) for v in values):
        lengths = [len(v) for v in values]
        result.update({
            "avg_list_length": round(statistics.mean(lengths), 1),
            "max_list_length": max(lengths),
        })

    return result


# ─────────────────────────────────────────────────
# Source-specific analyzers
# ─────────────────────────────────────────────────

def analyze_cisa_kev() -> dict:
    """Analyze CISA KEV catalog."""
    path = DOWNLOADS_DIR / "cisa-kev" / "known_exploited_vulnerabilities.json"
    if not path.exists():
        return {"status": "not_downloaded"}

    with open(path, "r") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    schema = discover_json_schema(vulns[0] if vulns else {})
    cve_ids = set()
    vendors = set()
    products = set()

    for v in vulns:
        cve_ids.add(v.get("cveID", ""))
        vendors.add(v.get("vendorProject", ""))
        products.add(v.get("product", ""))

    return {
        "status": "analyzed",
        "file_size_bytes": path.stat().st_size,
        "catalog_version": data.get("catalogVersion", "unknown"),
        "total_records": len(vulns),
        "unique_cve_ids": len(cve_ids),
        "unique_vendors": len(vendors),
        "unique_products": len(products),
        "record_schema": schema,
        "sample_record": vulns[0] if vulns else None,
        "date_range": {
            "earliest": min((v.get("dateAdded", "") for v in vulns), default=""),
            "latest": max((v.get("dateAdded", "") for v in vulns), default=""),
        },
        "ransomware_use_breakdown": dict(collections.Counter(
            v.get("knownRansomwareCampaignUse", "Unknown") for v in vulns
        )),
        "cross_reference_keys": ["cveID"],
        "graph_relevance": {
            "node_types": ["CVE", "vendor", "product"],
            "edge_types": ["exploited_in_wild", "ransomware_campaign"],
            "freshness_signal": "date_added field tracks when exploitation was confirmed",
        },
    }


def analyze_epss() -> dict:
    """Analyze EPSS scores."""
    csv_path = DOWNLOADS_DIR / "epss" / "epss_scores-current.csv"
    gz_path = DOWNLOADS_DIR / "epss" / "epss_scores-current.csv.gz"

    if not csv_path.exists() and not gz_path.exists():
        return {"status": "not_downloaded"}

    if not csv_path.exists() and gz_path.exists():
        import gzip
        with gzip.open(gz_path, "rt") as f:
            content = f.read()
        with open(csv_path, "w") as f:
            f.write(content)

    scores = []
    header = None
    comment_lines = []

    with open(csv_path, "r") as f:
        for line in f:
            if line.startswith("#"):
                comment_lines.append(line.strip())
                continue
            if header is None:
                header = line.strip().split(",")
                continue
            parts = line.strip().split(",")
            if len(parts) >= 3:
                try:
                    scores.append({
                        "cve": parts[0],
                        "epss": float(parts[1]),
                        "percentile": float(parts[2]),
                    })
                except ValueError:
                    continue

    epss_values = [s["epss"] for s in scores]
    percentiles = [s["percentile"] for s in scores]

    # Distribution analysis
    high_risk = sum(1 for v in epss_values if v >= 0.5)
    medium_risk = sum(1 for v in epss_values if 0.1 <= v < 0.5)
    low_risk = sum(1 for v in epss_values if v < 0.1)

    return {
        "status": "analyzed",
        "file_size_bytes": csv_path.stat().st_size,
        "metadata_comments": comment_lines,
        "columns": header,
        "total_records": len(scores),
        "unique_cves": len(set(s["cve"] for s in scores)),
        "epss_distribution": {
            "min": min(epss_values) if epss_values else 0,
            "max": max(epss_values) if epss_values else 0,
            "mean": round(statistics.mean(epss_values), 6) if epss_values else 0,
            "median": round(statistics.median(epss_values), 6) if epss_values else 0,
            "stdev": round(statistics.stdev(epss_values), 6) if len(epss_values) > 1 else 0,
            "p95": round(sorted(epss_values)[int(len(epss_values) * 0.95)], 6) if epss_values else 0,
            "p99": round(sorted(epss_values)[int(len(epss_values) * 0.99)], 6) if epss_values else 0,
        },
        "risk_buckets": {
            "high_risk_gte_0.5": high_risk,
            "medium_risk_0.1_to_0.5": medium_risk,
            "low_risk_lt_0.1": low_risk,
        },
        "cross_reference_keys": ["cve"],
        "graph_relevance": {
            "node_enrichment": "CVE node gets epss_score and epss_percentile properties",
            "update_frequency": "daily",
            "storage_note": "~200K+ float pairs, trivial storage, but need daily delta tracking",
        },
    }


def analyze_osv() -> dict:
    """Analyze OSV database."""
    osv_dir = DOWNLOADS_DIR / "osv"
    ecosystems_path = osv_dir / "ecosystems.txt"
    extracted_dir = osv_dir / "extracted"

    if not osv_dir.exists():
        return {"status": "not_downloaded"}

    result = {
        "status": "analyzing",
        "zip_size_bytes": 0,
    }

    zip_path = osv_dir / "all.zip"
    if zip_path.exists():
        result["zip_size_bytes"] = zip_path.stat().st_size

    # Ecosystems
    if ecosystems_path.exists():
        with open(ecosystems_path) as f:
            ecosystems = [l.strip() for l in f if l.strip()]
        result["ecosystems"] = ecosystems
        result["ecosystem_count"] = len(ecosystems)

    # Modified ID CSV analysis
    mod_path = osv_dir / "modified_id.csv"
    if mod_path.exists():
        lines = []
        with open(mod_path, "r") as f:
            for i, line in enumerate(f):
                if i >= 1000:
                    break
                lines.append(line.strip())
        result["modified_id_sample_count"] = len(lines)
        if lines:
            result["most_recent_modification"] = lines[0]

    # Analyze extracted files if available
    if extracted_dir.exists():
        json_files = list(extracted_dir.glob("**/*.json"))
        result["total_json_files"] = len(json_files)

        # Sample analysis
        samples = sample_json_files(extracted_dir, max_samples=200)
        if samples:
            result["sample_schema"] = discover_json_schema(samples[0])
            result["sample_count"] = len(samples)

            # Cross-reference analysis
            all_cves = set()
            ecosystems_seen = set()
            severity_types = set()
            id_prefixes = collections.Counter()

            for s in samples:
                # Extract CVE aliases
                for alias in s.get("aliases", []):
                    if alias.startswith("CVE-"):
                        all_cves.add(alias)

                # Ecosystem from affected
                for affected in s.get("affected", []):
                    pkg = affected.get("package", {})
                    eco = pkg.get("ecosystem", "")
                    if eco:
                        ecosystems_seen.add(eco)

                # Severity
                for sev in s.get("severity", []):
                    severity_types.add(sev.get("type", ""))

                # ID prefix
                vuln_id = s.get("id", "")
                if "-" in vuln_id:
                    id_prefixes[vuln_id.split("-")[0]] += 1

            result.update({
                "sample_cve_cross_refs": len(all_cves),
                "sample_ecosystems_seen": sorted(ecosystems_seen),
                "severity_types": sorted(severity_types),
                "id_prefix_distribution": dict(id_prefixes.most_common(20)),
                "sample_record": samples[0],
            })

            # Field completeness analysis
            field_presence = collections.Counter()
            for s in samples:
                for key in s.keys():
                    field_presence[key] += 1

            result["field_presence_pct"] = {
                k: round(v / len(samples) * 100, 1)
                for k, v in field_presence.most_common()
            }

    result["status"] = "analyzed"
    result["cross_reference_keys"] = ["id", "aliases (CVE-*)", "affected.package.name"]
    result["graph_relevance"] = {
        "node_types": ["CVE", "package", "version", "ecosystem"],
        "edge_types": ["affects", "fixed_by"],
        "key_insight": "OSV provides precise version ranges — critical for affects edges",
    }
    return result


def analyze_cvelistv5() -> dict:
    """Analyze CVE.org cvelistV5 repository."""
    cve_dir = DOWNLOADS_DIR / "cvelistV5"

    if not cve_dir.exists():
        return {"status": "not_downloaded"}

    # Count CVE files by year
    cves_dir = cve_dir / "cves"
    if not cves_dir.exists():
        return {"status": "downloaded_but_no_cves_dir"}

    year_counts = {}
    total_files = 0
    for year_dir in sorted(cves_dir.iterdir()):
        if year_dir.is_dir() and year_dir.name.isdigit():
            count = sum(1 for _ in year_dir.glob("**/*.json"))
            year_counts[year_dir.name] = count
            total_files += count

    # Sample analysis
    samples = sample_json_files(cves_dir, max_samples=200)
    schema = discover_json_schema(samples[0]) if samples else {}

    # Analyze structure patterns
    states = collections.Counter()
    data_types = collections.Counter()
    cna_names = collections.Counter()

    for s in samples:
        state = s.get("cveMetadata", {}).get("state", "unknown")
        states[state] += 1
        dtype = s.get("dataType", "unknown")
        data_types[dtype] += 1
        cna = s.get("cveMetadata", {}).get("assignerShortName", "unknown")
        cna_names[cna] += 1

    # Record size analysis
    sizes = []
    for s in samples:
        sizes.append(len(json.dumps(s)))

    return {
        "status": "analyzed",
        "total_cve_files": total_files,
        "cves_by_year": year_counts,
        "sample_schema": schema,
        "sample_count": len(samples),
        "state_distribution": dict(states),
        "data_type_distribution": dict(data_types),
        "top_cnas": dict(cna_names.most_common(15)),
        "record_size_bytes": {
            "min": min(sizes) if sizes else 0,
            "max": max(sizes) if sizes else 0,
            "mean": round(statistics.mean(sizes)) if sizes else 0,
            "median": round(statistics.median(sizes)) if sizes else 0,
        },
        "sample_record_keys": list(samples[0].keys()) if samples else [],
        "cross_reference_keys": ["cveMetadata.cveId"],
        "graph_relevance": {
            "node_types": ["CVE"],
            "edge_types": ["affects (from containers.cna.affected)"],
            "key_insight": "Fastest CVE source. No CVSS — pair with NVD for scoring.",
            "freshness": "Near real-time via git pull",
        },
    }


def analyze_attack_stix() -> dict:
    """Analyze MITRE ATT&CK STIX data."""
    attack_dir = DOWNLOADS_DIR / "attack-stix-data"

    if not attack_dir.exists():
        return {"status": "not_downloaded"}

    # Find STIX bundle files
    bundles = list(attack_dir.glob("**/*-attack.json"))
    if not bundles:
        bundles = list(attack_dir.glob("**/*.json"))

    result = {
        "status": "analyzed",
        "bundle_files": [str(b.relative_to(attack_dir)) for b in bundles[:20]],
        "bundle_count": len(bundles),
    }

    # Analyze the enterprise ATT&CK bundle (most relevant)
    enterprise_bundles = [b for b in bundles if "enterprise" in b.name.lower()]
    if enterprise_bundles:
        bundle_path = sorted(enterprise_bundles)[-1]  # latest version
        with open(bundle_path, "r") as f:
            bundle = json.load(f)

        objects = bundle.get("objects", [])
        type_counts = collections.Counter(obj.get("type", "unknown") for obj in objects)

        # Analyze techniques specifically
        techniques = [o for o in objects if o.get("type") == "attack-pattern"]
        groups = [o for o in objects if o.get("type") == "intrusion-set"]
        software = [o for o in objects if o.get("type") in ("malware", "tool")]
        relationships = [o for o in objects if o.get("type") == "relationship"]

        # Relationship types
        rel_types = collections.Counter(r.get("relationship_type", "") for r in relationships)

        # External references with CVE
        cve_refs = set()
        for obj in objects:
            for ref in obj.get("external_references", []):
                ext_id = ref.get("external_id", "")
                if ext_id.startswith("CVE-"):
                    cve_refs.add(ext_id)

        result.update({
            "enterprise_bundle": str(bundle_path.relative_to(attack_dir)),
            "total_objects": len(objects),
            "object_type_counts": dict(type_counts.most_common()),
            "techniques_count": len(techniques),
            "groups_count": len(groups),
            "software_count": len(software),
            "relationships_count": len(relationships),
            "relationship_types": dict(rel_types.most_common()),
            "cve_cross_references": len(cve_refs),
            "cve_cross_reference_sample": sorted(cve_refs)[:10],
            "sample_technique": discover_json_schema(techniques[0]) if techniques else {},
        })

    result["cross_reference_keys"] = ["external_references[].external_id (CVE-*, T*)"]
    result["graph_relevance"] = {
        "node_types": ["technique", "tactic", "group", "software"],
        "edge_types": ["uses", "mitigates", "attributed_to"],
        "key_insight": "Sparse CVE linkage — most value is technique taxonomy, not direct CVE mapping",
    }
    return result


def analyze_nuclei() -> dict:
    """Analyze Nuclei templates."""
    nuclei_dir = DOWNLOADS_DIR / "nuclei-templates"

    if not nuclei_dir.exists():
        return {"status": "not_downloaded"}

    # Find YAML templates
    yaml_files = list(nuclei_dir.glob("**/*.yaml"))
    result = {
        "status": "analyzed",
        "total_templates": len(yaml_files),
    }

    # Categorize by directory
    dir_counts = collections.Counter()
    for f in yaml_files:
        parts = f.relative_to(nuclei_dir).parts
        if len(parts) > 0:
            dir_counts[parts[0]] += 1

    result["templates_by_category"] = dict(dir_counts.most_common())

    # Sample YAML files for structure (parse as text to extract key fields)
    import re
    cve_ids = set()
    severities = collections.Counter()
    tags_counter = collections.Counter()
    sample_count = 0

    for yf in yaml_files[:500]:
        try:
            content = yf.read_text(encoding="utf-8", errors="replace")
            sample_count += 1

            # Extract CVE references
            for match in re.findall(r"CVE-\d{4}-\d{4,}", content):
                cve_ids.add(match)

            # Extract severity
            sev_match = re.search(r"severity:\s*(\w+)", content)
            if sev_match:
                severities[sev_match.group(1).lower()] += 1

            # Extract tags
            tags_match = re.search(r"tags:\s*(.+)", content)
            if tags_match:
                for tag in tags_match.group(1).split(","):
                    tags_counter[tag.strip().lower()] += 1
        except OSError:
            continue

    result.update({
        "samples_analyzed": sample_count,
        "unique_cve_references": len(cve_ids),
        "severity_distribution": dict(severities.most_common()),
        "top_tags": dict(tags_counter.most_common(30)),
        "cve_sample": sorted(cve_ids)[:10],
        "cross_reference_keys": ["CVE IDs in template metadata", "tags"],
        "graph_relevance": {
            "node_types": ["exploit_template"],
            "edge_types": ["detects (CVE)", "tagged_with"],
            "key_insight": "Signals 'scannable/exploitable' — enriches exploit node confidence",
        },
    })
    return result


def analyze_exploitdb() -> dict:
    """Analyze ExploitDB repository."""
    edb_dir = DOWNLOADS_DIR / "exploitdb"

    if not edb_dir.exists():
        return {"status": "not_downloaded"}

    # Look for CSV index files
    csv_files = list(edb_dir.glob("files_*.csv")) + list(edb_dir.glob("**/files_*.csv"))
    result = {"status": "analyzed"}

    # Main index
    main_csv = edb_dir / "files_exploits.csv"
    if not main_csv.exists():
        main_csv_candidates = list(edb_dir.glob("**/files_exploits.csv"))
        if main_csv_candidates:
            main_csv = main_csv_candidates[0]

    if main_csv.exists():
        exploits = []
        with open(main_csv, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            columns = reader.fieldnames or []
            for row in reader:
                exploits.append(row)

        platforms = collections.Counter(e.get("platform", "") for e in exploits)
        types = collections.Counter(e.get("type", "") for e in exploits)

        # CVE cross-references
        cve_ids = set()
        for e in exploits:
            codes = e.get("codes", "")
            for part in codes.split(";"):
                part = part.strip()
                if part.startswith("CVE-"):
                    cve_ids.add(part)

        result.update({
            "index_columns": columns,
            "total_exploits": len(exploits),
            "unique_cve_cross_refs": len(cve_ids),
            "platform_distribution": dict(platforms.most_common(15)),
            "type_distribution": dict(types.most_common()),
            "sample_record": exploits[0] if exploits else None,
        })
    else:
        result["index_note"] = "files_exploits.csv not found"

    # Shellcodes index
    shellcode_csv = edb_dir / "files_shellcodes.csv"
    if not shellcode_csv.exists():
        candidates = list(edb_dir.glob("**/files_shellcodes.csv"))
        if candidates:
            shellcode_csv = candidates[0]

    if shellcode_csv.exists():
        count = sum(1 for _ in open(shellcode_csv)) - 1
        result["total_shellcodes"] = count

    result["cross_reference_keys"] = ["codes (CVE-*)", "id"]
    result["graph_relevance"] = {
        "node_types": ["exploit"],
        "edge_types": ["exploits (CVE)"],
        "key_insight": "Provides actual exploit code linkage. CVE mapping is incomplete.",
    }
    return result


def analyze_poc_github() -> dict:
    """Analyze PoC-in-GitHub repository."""
    poc_dir = DOWNLOADS_DIR / "PoC-in-GitHub"

    if not poc_dir.exists():
        return {"status": "not_downloaded"}

    # Structure: year directories with CVE JSON files
    json_files = list(poc_dir.glob("**/*.json"))
    year_counts = collections.Counter()
    total_pocs = 0
    total_cves = 0
    stars_distribution = []

    sample_count = 0
    for jf in json_files[:300]:
        try:
            parts = jf.relative_to(poc_dir).parts
            if len(parts) > 0 and parts[0].isdigit():
                year_counts[parts[0]] += 1

            with open(jf, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)

            total_cves += 1
            if isinstance(data, list):
                total_pocs += len(data)
                for poc in data:
                    stars = poc.get("stargazers_count", 0)
                    if isinstance(stars, int):
                        stars_distribution.append(stars)
            sample_count += 1
        except (json.JSONDecodeError, OSError):
            continue

    return {
        "status": "analyzed",
        "total_json_files": len(json_files),
        "samples_analyzed": sample_count,
        "cves_in_sample": total_cves,
        "pocs_in_sample": total_pocs,
        "avg_pocs_per_cve": round(total_pocs / max(total_cves, 1), 1),
        "year_distribution": dict(year_counts.most_common()),
        "stars_distribution": {
            "min": min(stars_distribution) if stars_distribution else 0,
            "max": max(stars_distribution) if stars_distribution else 0,
            "mean": round(statistics.mean(stars_distribution), 1) if stars_distribution else 0,
            "median": statistics.median(stars_distribution) if stars_distribution else 0,
        },
        "cross_reference_keys": ["CVE ID (from filename)", "html_url (GitHub repo)"],
        "graph_relevance": {
            "node_types": ["exploit_poc"],
            "edge_types": ["poc_for (CVE)"],
            "key_insight": "Automated collection — quality varies. Stars can signal legitimacy.",
        },
    }


def analyze_cwe() -> dict:
    """Analyze CWE data."""
    cwe_dir = DOWNLOADS_DIR / "cwe"

    if not cwe_dir.exists():
        return {"status": "not_downloaded"}

    result = {"status": "analyzed"}

    # Try JSON first
    json_path = cwe_dir / "weakness-catalog.json"
    if json_path.exists() and json_path.stat().st_size > 0:
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            result["format"] = "json"
            result["schema"] = discover_json_schema(data, max_depth=3)
            result["file_size_bytes"] = json_path.stat().st_size
        except json.JSONDecodeError:
            result["json_note"] = "JSON parse failed"

    # Try XML
    xml_files = list(cwe_dir.glob("cwec_*.xml"))
    if xml_files:
        xml_path = xml_files[0]
        result["xml_file"] = xml_path.name
        result["xml_size_bytes"] = xml_path.stat().st_size
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            # Count weaknesses
            ns = {"cwe": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
            if ns:
                weaknesses = root.findall(f".//{{{ns['cwe']}}}Weakness")
            else:
                weaknesses = root.findall(".//Weakness")

            result["total_weaknesses"] = len(weaknesses)

            if weaknesses:
                # Sample attributes
                sample_attrs = dict(weaknesses[0].attrib)
                result["sample_weakness_attributes"] = sample_attrs
                # Count child elements
                child_tags = collections.Counter()
                for w in weaknesses[:50]:
                    for child in w:
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        child_tags[tag] += 1
                result["weakness_child_elements"] = dict(child_tags.most_common())
        except ET.ParseError:
            result["xml_note"] = "XML parse failed"

    result["cross_reference_keys"] = ["CWE-ID"]
    result["graph_relevance"] = {
        "node_types": ["weakness_type"],
        "edge_types": ["classified_as (CVE→CWE)", "parent_of (CWE hierarchy)"],
        "key_insight": "Taxonomy — static enrichment. Bridge for CVE→ATT&CK mapping.",
    }
    return result


# ─────────────────────────────────────────────────
# Cross-reference analysis
# ─────────────────────────────────────────────────

def analyze_cross_references(source_results: dict) -> dict:
    """Analyze how sources connect to each other via shared keys."""
    # This will be filled in after individual analyses
    # For now, document the expected linkage
    return {
        "primary_join_key": "CVE ID (CVE-YYYY-NNNNN)",
        "linkage_map": {
            "cvelistV5 → NVD": "CVE ID",
            "cvelistV5 → EPSS": "CVE ID",
            "cvelistV5 → CISA KEV": "CVE ID",
            "cvelistV5 → OSV": "CVE ID (via aliases field)",
            "cvelistV5 → ExploitDB": "CVE ID (via codes field)",
            "cvelistV5 → Nuclei": "CVE ID (in template metadata)",
            "cvelistV5 → PoC-in-GitHub": "CVE ID (filename)",
            "cvelistV5 → CWE": "CWE ID (from problemTypes)",
            "OSV → packages": "package name + ecosystem",
            "ATT&CK → CVE": "sparse — external_references only",
        },
        "secondary_join_keys": [
            "CWE ID (bridges CVE → weakness taxonomy → ATT&CK technique)",
            "Package name + version (bridges OSV → dependency analysis)",
            "Vendor + Product (bridges KEV → CPE → NVD)",
        ],
        "graph_design_implications": {
            "cveid_is_hub": "CVE ID is the central hub node — all sources radiate from it",
            "package_is_secondary_hub": "Package nodes connect ecosystems, versions, and vulns",
            "indexes_needed": [
                "CVE ID → all connected nodes (primary lookup)",
                "Package + Ecosystem → affected CVEs (dependency query)",
                "EPSS score range → CVEs (risk-based query)",
                "Date ranges → CVEs (freshness/timeline query)",
            ],
        },
    }


# ─────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("VulnGraph Structure Analysis")
    print("=" * 60)

    results = {}

    analyzers = [
        ("cisa_kev", "CISA KEV", analyze_cisa_kev),
        ("epss", "EPSS", analyze_epss),
        ("osv", "OSV", analyze_osv),
        ("cvelistV5", "CVE.org cvelistV5", analyze_cvelistv5),
        ("attack_stix", "MITRE ATT&CK", analyze_attack_stix),
        ("nuclei", "Nuclei Templates", analyze_nuclei),
        ("exploitdb", "ExploitDB", analyze_exploitdb),
        ("poc_github", "PoC-in-GitHub", analyze_poc_github),
        ("cwe", "CWE", analyze_cwe),
    ]

    for key, name, analyzer in analyzers:
        print(f"\n{'─' * 40}")
        print(f"Analyzing: {name}")
        start = time.time()
        try:
            results[key] = analyzer()
            elapsed = time.time() - start
            status = results[key].get("status", "unknown")
            print(f"  Status: {status} ({elapsed:.1f}s)")
        except Exception as e:
            results[key] = {"status": "error", "error": str(e)}
            print(f"  ERROR: {e}")

    # Cross-reference analysis
    print(f"\n{'─' * 40}")
    print("Analyzing cross-references...")
    results["cross_references"] = analyze_cross_references(results)

    # Write full JSON report
    report_path = ANALYSIS_DIR / "structure_report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nFull report: {report_path}")

    # Write human-readable summary
    summary_path = ANALYSIS_DIR / "structure_summary.md"
    write_summary(results, summary_path)
    print(f"Summary:     {summary_path}")

    print(f"\n{'=' * 60}")
    print("Analysis complete.")


def write_summary(results: dict, path: Path):
    """Write a human-readable markdown summary."""
    lines = [
        "# VulnGraph Data Structure Analysis Summary",
        "",
        f"Generated: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        "",
        "## Source Status",
        "",
        "| Source | Status | Records | CVE Cross-refs | Key Insight |",
        "|--------|--------|---------|----------------|-------------|",
    ]

    source_summaries = {
        "cisa_kev": lambda r: (
            r.get("total_records", "?"),
            r.get("unique_cve_ids", "?"),
            "Authoritative exploitation signal"
        ),
        "epss": lambda r: (
            r.get("total_records", "?"),
            r.get("unique_cves", "?"),
            f"Daily scores, p99={r.get('epss_distribution', {}).get('p99', '?')}"
        ),
        "osv": lambda r: (
            r.get("total_json_files", "?"),
            r.get("sample_cve_cross_refs", "?"),
            f"{r.get('ecosystem_count', '?')} ecosystems"
        ),
        "cvelistV5": lambda r: (
            r.get("total_cve_files", "?"),
            r.get("total_cve_files", "?"),
            f"Avg record: {r.get('record_size_bytes', {}).get('mean', '?')}B"
        ),
        "attack_stix": lambda r: (
            r.get("total_objects", "?"),
            r.get("cve_cross_references", "?"),
            f"{r.get('techniques_count', '?')} techniques, {r.get('groups_count', '?')} groups"
        ),
        "nuclei": lambda r: (
            r.get("total_templates", "?"),
            r.get("unique_cve_references", "?"),
            "Detection templates with CVE mapping"
        ),
        "exploitdb": lambda r: (
            r.get("total_exploits", "?"),
            r.get("unique_cve_cross_refs", "?"),
            "Exploit code + CVE mapping"
        ),
        "poc_github": lambda r: (
            r.get("total_json_files", "?"),
            r.get("cves_in_sample", "?"),
            f"Avg {r.get('avg_pocs_per_cve', '?')} PoCs/CVE"
        ),
        "cwe": lambda r: (
            r.get("total_weaknesses", "?"),
            "N/A (taxonomy)",
            "Weakness hierarchy for classification"
        ),
    }

    for key, summarizer in source_summaries.items():
        r = results.get(key, {})
        status = r.get("status", "unknown")
        if status == "analyzed":
            records, xrefs, insight = summarizer(r)
            lines.append(f"| {key} | {status} | {records} | {xrefs} | {insight} |")
        else:
            lines.append(f"| {key} | {status} | — | — | — |")

    # Cross-reference summary
    xref = results.get("cross_references", {})
    lines.extend([
        "",
        "## Graph Design Implications",
        "",
        f"**Primary join key**: {xref.get('primary_join_key', '?')}",
        "",
        "### Required Indexes (for sub-ms queries)",
        "",
    ])

    for idx in xref.get("graph_design_implications", {}).get("indexes_needed", []):
        lines.append(f"- {idx}")

    lines.extend([
        "",
        "### Node Types (from all sources)",
        "",
        "- **CVE** — central hub (linked by every source)",
        "- **Package** — secondary hub (ecosystem + name + version)",
        "- **Exploit** — PoC, ExploitDB entry, Nuclei template",
        "- **Weakness** — CWE taxonomy node",
        "- **Technique** — ATT&CK technique/tactic",
        "- **Actor** — ATT&CK group/intrusion-set",
        "",
        "### Edge Types",
        "",
        "- **affects** — CVE → Package@Version (from OSV)",
        "- **fixed_by** — CVE → Package@FixVersion (from OSV)",
        "- **exploited_in_wild** — CVE → ExploitStatus (from KEV)",
        "- **has_poc** — CVE → Exploit (from ExploitDB, PoC-in-GitHub, Nuclei)",
        "- **classified_as** — CVE → CWE (from NVD/cvelistV5)",
        "- **uses_technique** — Exploit → ATT&CK Technique",
        "- **attributed_to** — Technique → Actor (from ATT&CK)",
        "- **scored** — CVE → EPSS score (daily property, not edge)",
        "",
        "---",
        "",
        "See `structure_report.json` for full field-level details.",
    ])

    with open(path, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
