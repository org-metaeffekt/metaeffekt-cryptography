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
# Tier interpretation:
#   0 = ✅ Recommended / MUST / REQUIRED
#   1 = ✓  Approved / SHOULD / Permitted
#   2 = ⚠ / ◯  Conditional / MAY / MUST-
#   3 = 🔜 Transitional / Until <year>
#   4 = ❌ Deprecated / SHOULD NOT / NOT RECOMMENDED / Removed
#   5 = 🚫 Disallowed / MUST NOT / Broken
STATUS_TIER = {
    "✅": 0,  # Recommended / MUST
    "✓": 1,   # Approved / SHOULD
    "⚠": 2,   # Conditional / MUST-
    "◯": 2,   # MAY (IETF "permitted but no preference")
    "🔜": 3,  # Transitional
    "❌": 4,  # Deprecated / SHOULD NOT / NOT RECOMMENDED
    "🚫": 5,  # Disallowed / MUST NOT
}

# Words used as fallback when no symbol is present.
STATUS_WORD_TIER = {
    "must not":         5,  # check before "must" so longer prefix wins
    "should not":       4,
    "not recommended":  4,
    "must":             0,
    "should":           1,
    "may":              2,
    "permitted":        1,
    "recommended":      0,
    "approved":         1,
    "acceptable":       1,
    "conditional":      2,
    "transitional":     3,
    "until":            3,  # "Until 2031", "Until 2035" — time-bounded approval
    "deprecated":       4,
    "removed":          4,
    "not listed":       4,
    "disallowed":       5,
    "broken":           5,
}


def normalize_status(cell: str) -> int | None:
    """Map a status cell (with emoji + words) to a severity tier 0-5, or None if unknown.

    Textual cues that override the leading symbol:
    - "Until <year>" → tier 3 (transitional/time-bounded), even if cell starts with ✅
      (BSI commonly writes "✅ Until 2031" meaning "approved only through 2031")
    - "Conditional" → tier 2, even if cell starts with ✓ or ✅
    """
    s = cell.strip()
    if not s or s == "—" or s == "-":
        return None
    sl = s.lower()

    # Override cues — these take precedence over the leading symbol
    if "until" in sl:
        return 3
    if "conditional" in sl:
        return 2
    if "transitional" in sl:
        return 3

    # Try leading symbol first
    for sym, tier in STATUS_TIER.items():
        if sym in s:
            return tier
    # Fallback: word match (case-insensitive, longest-prefix-first via insertion order)
    for word, tier in STATUS_WORD_TIER.items():
        if word in sl:
            return tier
    return None


# Authority columns recognised in status tables.
AUTHORITY_NAMES = ("IETF", "NIST", "BSI", "CABF", "CNSA")


def _split_table_row(line: str) -> list[str]:
    """Split a markdown table row by '|', preserving escaped pipes (\\|) inside cells."""
    # Replace escaped pipe with a sentinel that cannot appear in markdown
    PIPE_SENTINEL = "\x00PIPE\x00"
    safe = line.replace("\\|", PIPE_SENTINEL)
    cells = [c.strip().replace(PIPE_SENTINEL, "\\|") for c in safe.split("|")]
    return cells


def parse_authority_tables(text: str) -> list[tuple[int, str, dict]]:
    """Parse markdown tables and return data rows that contain at least 2 authority columns.

    Returns list of (line_number, pattern, {authority_name: cell_text}).
    """
    rows: list[tuple[int, str, dict]] = []
    lines = text.splitlines()

    auth_indices: dict[str, int] = {}
    in_table = False

    for i, line in enumerate(lines, 1):
        if not line.startswith("|"):
            in_table = False
            auth_indices = {}
            continue

        cells = _split_table_row(line)

        # Header row detection: contains at least one authority name as exact cell
        header_authorities = {n: cells.index(n) for n in AUTHORITY_NAMES if n in cells}
        if header_authorities:
            auth_indices = header_authorities
            in_table = True
            continue

        # Skip alignment row
        if in_table and re.match(r"^\|[:\-\s|]+\|\s*$", line):
            continue

        # Data row — only consider rows where we have at least 2 authority columns
        if in_table and len(auth_indices) >= 2:
            # Pattern is in the first column (cells[1] since cells[0] is leading empty)
            pattern = cells[1] if len(cells) > 1 else ""
            auths = {}
            for name, idx in auth_indices.items():
                if idx < len(cells):
                    auths[name] = cells[idx]
            rows.append((i, pattern, auths))

    return rows


def check_authority_divergence(base: Path) -> bool:
    """Check 9: detect rows where authority columns (IETF/NIST/BSI/CABF) disagree."""
    files_to_check = [
        ("cryptographic-algorithm-status.md", "algo"),
        ("cryptographic-protocol-status.md", "proto"),
    ]

    total_rows = 0
    same_tier_rows = 0
    divergences: list[tuple[str, int, str, dict, int]] = []
    # (file_label, line_number, pattern, {authority: cell}, max_diff)

    for filename, label in files_to_check:
        md_file = base / filename
        if not md_file.exists():
            continue
        text = md_file.read_text()
        for line_no, pattern, auths in parse_authority_tables(text):
            # Compute tier for each cell that has a known status
            tiers = {}
            for name, cell in auths.items():
                t = normalize_status(cell)
                if t is not None:
                    tiers[name] = t
            if len(tiers) < 2:
                continue
            total_rows += 1
            tier_values = list(tiers.values())
            max_diff = max(tier_values) - min(tier_values)
            if max_diff == 0:
                same_tier_rows += 1
            else:
                divergences.append((label, line_no, pattern, auths, max_diff))

    if total_rows == 0:
        print(f"  SKIP  no authority-comparison tables found")
        return True

    print(f"  OK    {same_tier_rows}/{total_rows} rows with all authorities agreeing on tier")
    if divergences:
        print(f"  INFO  {len(divergences)} rows with diverging guidance:")
        # Group by severity for readability
        groups = {"MAJOR": [], "MEDIUM": [], "minor": []}
        for d in divergences:
            diff = d[4]
            if diff >= 3:
                groups["MAJOR"].append(d)
            elif diff == 2:
                groups["MEDIUM"].append(d)
            else:
                groups["minor"].append(d)

        for sev in ("MAJOR", "MEDIUM", "minor"):
            group = groups[sev]
            if not group:
                continue
            print(f"    [{sev}] {len(group)} row(s):")
            for label, line_no, pattern, auths, _ in group[:25]:
                p = pattern if len(pattern) <= 56 else pattern[:53] + "…"
                print(f"      [{label}] L{line_no}  {p}")
                for name in AUTHORITY_NAMES:
                    if name in auths and auths[name] not in ("—", "-", ""):
                        cell = auths[name]
                        c = (cell[:38] + "…") if len(cell) > 39 else cell
                        print(f"             {name:5s}: {c}")
            if len(group) > 25:
                print(f"      ... and {len(group) - 25} more")
    # Informational only
    return True


# ---------------------------------------------------------------------------
# Check 10: heading style (noun-only rule, em-dashes, bracket case)
# ---------------------------------------------------------------------------

# Words that should be lowercase in headings (unless first content word).
# Covers verbs, modals, articles, conjunctions, prepositions, determiners,
# pronouns, adverbs, and common adjectives.  Nouns, gerunds, acronyms, and
# proper nouns are NOT in this set.
_SHOULD_BE_LOWERCASE = frozenset({
    # articles
    "a", "an", "the",
    # conjunctions
    "and", "but", "or", "nor", "yet", "so", "than",
    # prepositions
    "at", "by", "for", "in", "of", "on", "to", "up", "via", "with", "from",
    "per", "across", "around", "between", "during", "through", "into", "onto",
    "about", "after", "before", "over", "under", "until",
    # determiners / pronouns
    "this", "that", "these", "those", "each", "every", "all", "some", "any",
    "it", "its", "they", "them", "their", "we", "us", "our", "you", "your",
    "who", "whom", "whose", "which",
    # verbs / modals / auxiliaries
    "is", "are", "was", "were", "be", "been", "being", "am",
    "has", "have", "had", "having",
    "do", "does", "did", "doing",
    "will", "would", "shall", "should", "can", "could", "may", "might", "must",
    "makes", "made", "enables", "exists", "appears", "provides", "requires",
    "retains", "excludes", "grants", "disallows", "disagree", "disagrees",
    "allows", "used", "compared", "phased",
    # adverbs
    "always", "never", "mostly", "sometimes", "often", "now", "then",
    "more", "most", "less", "very", "too", "also", "only", "even", "just",
    "still", "already", "not", "no",
    # common adjectives (non-noun words that appear in crypto headings)
    "specific", "general", "common", "special",
    "simple", "complex", "good", "bad",
    "historical", "classical", "modern", "legacy",
    "symmetric", "asymmetric", "digital", "quantum", "cryptographic",
    "elliptic", "prime", "composite", "hybrid", "pure",
    "national", "international", "commercial",
    "internal", "external", "additional", "notable",
    "minor", "major", "medium",
    "permissive", "restrictive", "strict",
    "urgent", "critical", "important",
    "invisible", "visible",
    "random", "lightweight",
    "weak", "strong",
    "consolidated", "comparable",
    "miscellaneous",
})


def check_heading_style(base: Path) -> bool:
    """Check 10: heading style — noun-only capitalisation, no em-dashes, bracket case."""
    md_globs = ["*.md", "inventory/*.md", "management/*.md",
                "ae-pattern-validator/*.md", "ae-pattern-validator/src/main/resources/registry/*.md"]
    md_files: list[Path] = []
    for g in md_globs:
        md_files.extend(sorted(base.glob(g)))

    em_dash_issues: list[tuple[str, int, str]] = []
    cap_issues: list[tuple[str, int, str, str]] = []

    for fpath in md_files:
        try:
            lines = fpath.read_text().splitlines()
        except (IOError, UnicodeDecodeError):
            continue
        rel = str(fpath.relative_to(base))
        for i, line in enumerate(lines, 1):
            m = re.match(r"^#{1,6}\s+(.*)", line)
            if not m:
                continue
            heading = m.group(1)

            # ── em-dash check ──
            if "—" in heading:
                em_dash_issues.append((rel, i, heading))

            # ── capitalised-lowercase-word check ──
            # Strip code spans and section-number prefix
            stripped = re.sub(r"`[^`]*`", "", heading)
            stripped = re.sub(r"^\d+(\.\d+)*\.?\s*", "", stripped)
            # Tokenise into word-like sequences with their position in stripped text
            tokens = list(re.finditer(r"[A-Za-z][A-Za-z']*", stripped))
            if not tokens:
                continue

            for j, tok in enumerate(tokens):
                word = tok.group()
                # Skip first content word (always capitalised)
                if j == 0:
                    continue
                # Skip all-uppercase (acronyms)
                if word.isupper():
                    continue
                # Skip words that start lowercase (already OK)
                if word[0].islower():
                    continue
                # Word starts uppercase — check if it should be lowercase
                if word.lower() in _SHOULD_BE_LOWERCASE:
                    cap_issues.append((rel, i, heading, word))

    ok = True

    if em_dash_issues:
        print(f"  WARN  {len(em_dash_issues)} heading(s) contain em-dash (avoid per §9.2):")
        for rel, ln, h in em_dash_issues[:10]:
            print(f"    {rel}:{ln}  {h}")
        if len(em_dash_issues) > 10:
            print(f"    ... and {len(em_dash_issues) - 10} more")
        ok = False

    if cap_issues:
        print(f"  INFO  {len(cap_issues)} heading word(s) may need lowercase (review per §9.1):")
        for rel, ln, h, w in cap_issues[:15]:
            print(f"    {rel}:{ln}  '{w}' in: {h}")
        if len(cap_issues) > 15:
            print(f"    ... and {len(cap_issues) - 15} more")

    if not em_dash_issues and not cap_issues:
        print(f"  OK    no heading style issues detected ({sum(1 for f in md_files for l in f.read_text().splitlines() if l.startswith('#'))} headings scanned)")

    return ok  # em-dash is WARN (fails check); capitalisation is INFO only


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
        ("10. Heading style (noun-only rule)",         lambda: check_heading_style(base)),
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
