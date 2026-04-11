#!/usr/bin/env python3
"""
Consistency validator for the metaeffekt-cryptography repository.

Checks YAML registry data against README claims, enforces schema invariants,
and detects duplicates, bad OIDs, and status violations.

Usage:
    python3 validate_consistency.py [BASE_DIR]

BASE_DIR defaults to the repository root (one level above scripts/).
Exit code 0 if all checks pass, 1 if any fail.
"""

import os
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML is required.  pip install pyyaml")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_yaml_files(registry_dir: Path) -> list[tuple[str, dict]]:
    """Return [(filename, parsed_dict), ...] for every cr-*.yaml file."""
    results = []
    for p in sorted(registry_dir.glob("cr-*.yaml")):
        with open(p) as f:
            results.append((p.name, yaml.safe_load(f)))
    return results


def extract_families(yaml_files: list[tuple[str, dict]]) -> list[dict]:
    """Flatten all family entries from all files."""
    families = []
    for _name, doc in yaml_files:
        families.extend(doc.get("families") or [])
    return families


def collect_oids(families: list[dict]) -> set[str]:
    """Collect every unique OID from family, oidMap, implicitParameters, and parameter values."""
    oids: set[str] = set()
    for fam in families:
        if fam.get("oid"):
            oids.add(fam["oid"])
        for v in (fam.get("oidMap") or {}).values():
            oids.add(v)
        for ip in fam.get("implicitParameters") or []:
            if ip.get("oid"):
                oids.add(ip["oid"])
        for param in fam.get("parameters") or []:
            for val in param.get("values") or []:
                if isinstance(val, dict) and val.get("oid"):
                    oids.add(val["oid"])
    return oids


OID_RE = re.compile(r"^\d+(\.\d+)+$")
VALID_STATUSES = {"approved", "deprecated", "disallowed", "broken"}


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_family_count(families: list[dict], base: Path) -> bool:
    """Check 1: YAML family count vs README claims."""
    ok = True
    count = len(families)

    targets = {
        "registry README": base / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "README.md",
        "top-level README": base / "README.md",
        "validator-test-report": base / "management" / "validator-test-report.md",
    }

    for label, path in targets.items():
        if not path.exists():
            print(f"  SKIP  {label}: file not found ({path})")
            continue
        text = path.read_text()
        # Look for patterns like "324 families" or "324 algorithm families" or "324 registered algorithm families"
        # Use a tight pattern: number immediately followed by optional adjectives then "famil..."
        m = re.search(r"\b(\d+)\s+(?:\w+\s+){0,3}famil(?:ies|y)", text)
        if m:
            claimed = int(m.group(1))
            if claimed == count:
                print(f"  OK    {label}: {claimed} families matches YAML")
            else:
                print(f"  FAIL  {label}: claims {claimed} families, YAML has {count}")
                ok = False
        else:
            print(f"  SKIP  {label}: no family count found")

    return ok


def check_oid_count(families: list[dict], base: Path) -> bool:
    """Check 2: unique OID count vs README claims."""
    oids = collect_oids(families)
    count = len(oids)

    readme = base / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "README.md"
    if not readme.exists():
        print(f"  SKIP  registry README not found")
        return True

    text = readme.read_text()
    m = re.search(r"\b(\d+)\s+unique\s+OID", text)
    if not m:
        print(f"  SKIP  no OID count found in registry README")
        return True

    claimed = int(m.group(1))
    if claimed == count:
        print(f"  OK    {claimed} unique OIDs matches YAML")
        return True
    else:
        print(f"  FAIL  registry README claims {claimed} unique OIDs, YAML has {count}")
        return False


def check_parameter_name_coverage(families: list[dict], base: Path) -> bool:
    """Check 3: informational comparison of YAML parameter names vs cryptographic-parameters.md placeholders."""
    # Extract parameter names from YAML
    yaml_names: set[str] = set()
    for fam in families:
        for param in fam.get("parameters") or []:
            if param.get("name"):
                yaml_names.add(param["name"])

    # Extract {placeholder} section headings from cryptographic-parameters.md
    params_file = base / "cryptographic-parameters.md"
    if not params_file.exists():
        print(f"  SKIP  cryptographic-parameters.md not found")
        return True

    text = params_file.read_text()
    # Match ### or #### `{name}` headings
    md_names = set(re.findall(r"^#{3,4} `\{([^}]+)\}`", text, re.MULTILINE))

    in_yaml_only = yaml_names - md_names
    in_md_only = md_names - yaml_names

    if in_yaml_only:
        print(f"  INFO  parameter names in YAML but not in cryptographic-parameters.md ({len(in_yaml_only)}):")
        for n in sorted(in_yaml_only):
            print(f"          {n}")
    if in_md_only:
        print(f"  INFO  placeholders in cryptographic-parameters.md but not in YAML ({len(in_md_only)}):")
        for n in sorted(in_md_only):
            print(f"          {n}")
    if not in_yaml_only and not in_md_only:
        print(f"  OK    all {len(yaml_names)} parameter names match between YAML and cryptographic-parameters.md")

    # Informational only — always passes
    return True


def check_deprecated_preferred_invariant(families: list[dict]) -> bool:
    """Check 4: patternStatus='deprecated' requires preferredPattern, and vice versa."""
    ok = True
    for fam in families:
        name = fam.get("family", "<unknown>")
        has_deprecated = fam.get("patternStatus") == "deprecated"
        has_preferred = bool(fam.get("preferredPattern"))

        if has_deprecated and not has_preferred:
            print(f"  FAIL  {name}: patternStatus=deprecated but no preferredPattern")
            ok = False
        if has_preferred and not has_deprecated:
            print(f"  FAIL  {name}: has preferredPattern but patternStatus is not 'deprecated'")
            ok = False

    if ok:
        print(f"  OK    patternStatus/preferredPattern invariant holds for all families")
    return ok


def check_status_values(families: list[dict]) -> bool:
    """Check 5: all status fields contain only valid values."""
    ok = True
    for fam in families:
        name = fam.get("family", "<unknown>")

        # Family-level status (defaults to approved if absent)
        status = fam.get("status")
        if status and status not in VALID_STATUSES:
            print(f"  FAIL  {name}: invalid family status '{status}'")
            ok = False

        # Parameter-value statuses
        for param in fam.get("parameters") or []:
            for val in param.get("values") or []:
                if isinstance(val, dict):
                    vs = val.get("status")
                    if vs and vs not in VALID_STATUSES:
                        print(f"  FAIL  {name}.{param.get('name')}.{val.get('value')}: invalid status '{vs}'")
                        ok = False

        # Implicit parameter statuses
        for ip in fam.get("implicitParameters") or []:
            ips = ip.get("status")
            if ips and ips not in VALID_STATUSES:
                print(f"  FAIL  {name} implicitParam {ip.get('name')}: invalid status '{ips}'")
                ok = False

    if ok:
        print(f"  OK    all status values are valid ({', '.join(sorted(VALID_STATUSES))})")
    return ok


def check_duplicate_families(families: list[dict]) -> bool:
    """Check 6: no duplicate family names across all YAML files."""
    names = [f.get("family", "<unknown>") for f in families]
    counts = Counter(names)
    dupes = {n: c for n, c in counts.items() if c > 1}
    if dupes:
        for n, c in sorted(dupes.items()):
            print(f"  FAIL  duplicate family '{n}' appears {c} times")
        return False
    print(f"  OK    all {len(names)} family names are unique")
    return True


def check_oid_format(families: list[dict]) -> bool:
    """Check 7: all OIDs match dotted-decimal format."""
    ok = True
    for fam in families:
        name = fam.get("family", "<unknown>")

        def validate_oid(oid_str: str, context: str):
            nonlocal ok
            if not OID_RE.match(oid_str):
                print(f"  FAIL  {name}: invalid OID format '{oid_str}' ({context})")
                ok = False

        if fam.get("oid"):
            validate_oid(fam["oid"], "family oid")
        for key, val in (fam.get("oidMap") or {}).items():
            validate_oid(val, f"oidMap[{key}]")
        for ip in fam.get("implicitParameters") or []:
            if ip.get("oid"):
                validate_oid(ip["oid"], f"implicitParam {ip.get('name')}")
        for param in fam.get("parameters") or []:
            for val_entry in param.get("values") or []:
                if isinstance(val_entry, dict) and val_entry.get("oid"):
                    validate_oid(val_entry["oid"], f"param {param.get('name')}.{val_entry.get('value')}")

    if ok:
        print(f"  OK    all OIDs match dotted-decimal format")
    return ok


# Status severity ladder. Lower index = more permissive; higher = more restrictive.
# Maps the leading symbol (or normalized phrase) to a tier.
STATUS_TIER = {
    "✅": 0,  # Recommended
    "✓": 1,   # Approved
    "⚠": 2,   # Conditional
    "🔜": 3,  # Transitional
    "❌": 4,  # Deprecated
    "🚫": 5,  # Disallowed / Not recommended
}

# Words used as fallback when no symbol is present.
STATUS_WORD_TIER = {
    "recommended": 0,
    "approved": 1,
    "acceptable": 1,
    "conditional": 2,
    "transitional": 3,
    "until": 3,           # "Until 2031", "Until 2035" — time-bounded approval
    "deprecated": 4,
    "removed": 4,
    "not listed": 4,
    "disallowed": 5,
    "not recommended": 5,
    "broken": 5,
}


def normalize_status(cell: str) -> int | None:
    """Map a status cell (with emoji + words) to a severity tier 0-5, or None if unknown."""
    s = cell.strip()
    if not s or s == "—" or s == "-":
        return None
    # Try leading symbol first
    for sym, tier in STATUS_TIER.items():
        if sym in s:
            return tier
    # Fallback: word match (case-insensitive)
    sl = s.lower()
    for word, tier in STATUS_WORD_TIER.items():
        if word in sl:
            return tier
    return None


def check_authority_divergence(base: Path) -> bool:
    """Check 9: detect rows in algorithm-status.md where NIST and BSI columns disagree."""
    md_file = base / "cryptographic-algorithm-status.md"
    if not md_file.exists():
        print(f"  SKIP  cryptographic-algorithm-status.md not found")
        return True

    text = md_file.read_text()
    lines = text.splitlines()

    divergences: list[tuple[int, str, str, str, str]] = []  # (line, pattern, nist, bsi, severity)
    same_tier = 0
    total_rows = 0

    nist_idx = None
    bsi_idx = None
    in_table = False
    pattern_idx = 0  # first column is pattern/algorithm

    for i, line in enumerate(lines, 1):
        if not line.startswith("|"):
            in_table = False
            nist_idx = None
            bsi_idx = None
            continue

        cells = [c.strip() for c in line.split("|")]
        # cells[0] is empty (leading |); cells[-1] is empty (trailing |)
        # Detect header row by presence of "NIST" and "BSI"
        if "NIST" in cells and "BSI" in cells:
            nist_idx = cells.index("NIST")
            bsi_idx = cells.index("BSI")
            in_table = True
            continue

        # Skip alignment row (e.g., |:---|:---|...)
        if in_table and re.match(r"^\|[:\-\s|]+\|\s*$", line):
            continue

        # Data row
        if in_table and nist_idx is not None and bsi_idx is not None:
            if nist_idx >= len(cells) or bsi_idx >= len(cells):
                continue
            pattern = cells[1] if len(cells) > 1 else ""
            nist_cell = cells[nist_idx]
            bsi_cell = cells[bsi_idx]
            nist_tier = normalize_status(nist_cell)
            bsi_tier = normalize_status(bsi_cell)
            if nist_tier is None or bsi_tier is None:
                continue
            total_rows += 1
            if nist_tier == bsi_tier:
                same_tier += 1
            else:
                # Mark severity by tier difference
                diff = abs(nist_tier - bsi_tier)
                if diff >= 3:
                    severity = "MAJOR"
                elif diff == 2:
                    severity = "MEDIUM"
                else:
                    severity = "minor"
                divergences.append((i, pattern, nist_cell, bsi_cell, severity))

    if total_rows == 0:
        print(f"  SKIP  no NIST/BSI tables found")
        return True

    print(f"  OK    {same_tier}/{total_rows} rows with matching NIST/BSI tier")
    if divergences:
        print(f"  INFO  {len(divergences)} rows with diverging guidance:")
        # Group by severity for readability
        for sev in ("MAJOR", "MEDIUM", "minor"):
            group = [d for d in divergences if d[4] == sev]
            if not group:
                continue
            print(f"    [{sev}] {len(group)} row(s):")
            for line_no, pattern, nist, bsi, _ in group[:20]:
                # Truncate long status strings for readability
                n = (nist[:32] + "…") if len(nist) > 33 else nist
                b = (bsi[:32] + "…") if len(bsi) > 33 else bsi
                p = pattern if len(pattern) <= 60 else pattern[:57] + "…"
                print(f"      L{line_no}  {p}")
                print(f"             NIST: {n}")
                print(f"             BSI:  {b}")
            if len(group) > 20:
                print(f"      ... and {len(group) - 20} more")
    # Informational only
    return True


def check_test_count(base: Path) -> bool:
    """Check 8: total test count in validator-test-report.md vs sum of per-class counts."""
    report = base / "management" / "validator-test-report.md"
    if not report.exists():
        print(f"  SKIP  management/validator-test-report.md not found")
        return True

    text = report.read_text()

    # Find the test summary table — rows like "| `ClassName` | 42 | ... |"
    # and the total row "| **Total** | **769** | |"
    # Only parse lines between "## Test Summary" and the next "---" or "##" heading.
    per_class = []
    claimed_total = None
    in_summary = False

    for line in text.splitlines():
        if re.match(r"^##\s+Test Summary", line):
            in_summary = True
            continue
        if in_summary and (re.match(r"^---\s*$", line) or re.match(r"^##\s", line)):
            if per_class or claimed_total is not None:
                break  # end of the summary table
            continue  # skip the "---" right after the heading

        if not in_summary:
            continue

        # Total row
        m_total = re.match(r"\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*", line)
        if m_total:
            claimed_total = int(m_total.group(1))
            continue

        # Per-class row: | `ClassName` | 42 | ... |
        m_row = re.match(r"\|\s*`[^`]+`\s*\|\s*(\d+)\s*\|", line)
        if m_row:
            per_class.append(int(m_row.group(1)))

    if claimed_total is None:
        print(f"  SKIP  no total test count found in validator-test-report.md")
        return True

    computed = sum(per_class)
    if computed == claimed_total:
        print(f"  OK    test total {claimed_total} matches sum of {len(per_class)} per-class counts")
        return True
    else:
        print(f"  FAIL  claimed total {claimed_total}, but sum of per-class counts is {computed} ({len(per_class)} classes)")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) > 1:
        base = Path(sys.argv[1]).resolve()
    else:
        # Default: one level up from scripts/ -> repo root
        base = Path(__file__).resolve().parent.parent

    registry_dir = base / "ae-pattern-validator" / "src" / "main" / "resources" / "registry"
    if not registry_dir.is_dir():
        sys.exit(f"ERROR: registry directory not found: {registry_dir}")

    print(f"Base directory: {base}")
    print(f"Registry:       {registry_dir}")
    print()

    yaml_files = load_yaml_files(registry_dir)
    print(f"Loaded {len(yaml_files)} YAML files: {', '.join(n for n, _ in yaml_files)}")
    families = extract_families(yaml_files)
    print(f"Total families: {len(families)}")
    oids = collect_oids(families)
    print(f"Unique OIDs:    {len(oids)}")
    print()

    all_ok = True

    checks = [
        ("1. Family count vs READMEs",               lambda: check_family_count(families, base)),
        ("2. OID count vs README",                    lambda: check_oid_count(families, base)),
        ("3. Parameter name coverage (informational)",lambda: check_parameter_name_coverage(families, base)),
        ("4. patternStatus/preferredPattern invariant",lambda: check_deprecated_preferred_invariant(families)),
        ("5. Status values",                          lambda: check_status_values(families)),
        ("6. Duplicate family names",                 lambda: check_duplicate_families(families)),
        ("7. OID format",                             lambda: check_oid_format(families)),
        ("8. Test count vs report",                   lambda: check_test_count(base)),
        ("9. NIST/BSI authority divergence",          lambda: check_authority_divergence(base)),
    ]

    for title, fn in checks:
        print(f"--- {title} ---")
        if not fn():
            all_ok = False
        print()

    if all_ok:
        print("ALL CHECKS PASSED")
        sys.exit(0)
    else:
        print("SOME CHECKS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
