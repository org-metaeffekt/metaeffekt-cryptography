#!/usr/bin/env python3
"""
Generate status-comparison tables in the status markdown files from the
authoritative cr-*.yaml registry data.

Reads:
  - ae-pattern-validator/src/main/resources/registry/cr-tls.yaml
  - ae-pattern-validator/src/main/resources/registry/cr-ssh.yaml
  - ae-pattern-validator/src/main/resources/registry/cr-ipsec.yaml

Writes back into:
  - cryptographic-protocol-status.md       (SSH §1.x, IPsec §2.x)
  - cryptographic-tls-cipher-suites.md     (BSI §12, NIST §13, comparison §14)

Replaces content between AUTOGEN markers, e.g.

    <!-- AUTOGEN:BEGIN ssh-kex -->
    ... auto-generated table ...
    <!-- AUTOGEN:END ssh-kex -->

Hand-written content outside marker pairs is preserved verbatim.

Usage:
    python3 scripts/generate_status_tables_from_yaml.py [--check]
"""

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML required.  pip install pyyaml")


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
REGISTRY_DIR = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry"

TLS_YAML = REGISTRY_DIR / "cr-tls.yaml"
SSH_YAML = REGISTRY_DIR / "cr-ssh.yaml"
IPSEC_YAML = REGISTRY_DIR / "cr-ipsec.yaml"
KERBEROS_YAML = REGISTRY_DIR / "cr-kerberos.yaml"
DNSSEC_YAML = REGISTRY_DIR / "cr-dnssec.yaml"

PROTOCOL_STATUS_MD = REPO_ROOT / "cryptographic-protocol-status.md"
TLS_CIPHER_SUITES_MD = REPO_ROOT / "cryptographic-tls-cipher-suites.md"
REGISTRY_README_MD = REGISTRY_DIR / "README.md"


# ── Status rendering ──────────────────────────────────────────────────────────

# Mapping from YAML status value to display glyph + label.
BSI_STATUS_DISPLAY = {
    "recommended":  "✅ Recommended",
    "approved":     "✓ Approved",
    "conditional":  "⚠ Conditional",
    "transitional": "🔜 Transitional",
    "deprecated":   "❌ Deprecated",
    "disallowed":   "🚫 Disallowed",
    "broken":       "💥 Broken",
}

NIST_STATUS_DISPLAY = {
    "recommended":  "✅ Recommended",
    "approved":     "✓ Approved",
    "conditional":  "⚠ Conditional",
    "transitional": "🔜 Transitional",
    "deprecated":   "❌ Deprecated",
    "disallowed":   "🚫 Disallowed",
    "broken":       "💥 Broken",
}

IETF_LEVEL_DISPLAY = {
    "MUST":       "✅ MUST",
    "MUST-":      "⚠ MUST-",
    "SHOULD":     "✓ SHOULD",
    "MAY":        "◯ MAY",
    "SHOULD-NOT": "❌ SHOULD NOT",
    "MUST-NOT":   "🚫 MUST NOT",
}


_CURRENT_YEAR = __import__("datetime").date.today().year
_URGENCY_HORIZON_YEARS = 1   # bold if deadline is within current_year + this many years


def _format_use_up_to(value: str) -> str:
    """Bold the year when the deadline is at most _URGENCY_HORIZON_YEARS away
    (already expired, expires this year, or expires next year). The "+" suffix
    on durable horizons (e.g. "2032+") strips before integer parsing and is
    preserved verbatim in the output."""
    s = str(value)
    bare = s.rstrip("+")
    try:
        year = int(bare)
    except ValueError:
        return s
    if year <= _CURRENT_YEAR + _URGENCY_HORIZON_YEARS:
        return f"**{s}**"
    return s


def render_bsi(entry: dict) -> str:
    bsi = entry.get("bsi")
    if not bsi:
        return "—"
    glyph = BSI_STATUS_DISPLAY.get(bsi["status"], bsi["status"])
    parts = [glyph]
    if "useUpTo" in bsi:
        parts.append(f"(use up to {_format_use_up_to(bsi['useUpTo'])})")
    requires = bsi.get("requires") or []
    if requires:
        parts.append(f"— requires {'; '.join(requires)}")
    return " ".join(parts)


def render_nist(entry: dict) -> str:
    nist = entry.get("nist")
    if not nist:
        return "—"
    glyph = NIST_STATUS_DISPLAY.get(nist["status"], nist["status"])
    return glyph


def render_ietf(entry: dict) -> str:
    """Render the IETF column. For IPsec entries with both an `ietf:` block (ESP
    data plane, RFC 8221) and an `ietfIkev2:` block (IKEv2 control plane,
    RFC 8247), render both levels side-by-side."""
    ietf = entry.get("ietf")
    ikev2 = entry.get("ietfIkev2")
    if not ietf and not ikev2:
        return "—"

    def _one(block: dict) -> str:
        level = block.get("level")
        src = short_ietf_source(block["source"])
        if level:
            return f"{IETF_LEVEL_DISPLAY.get(level, level)} ({src})"
        return f"({src})"

    if ietf and ikev2:
        return f"ESP: {_one(ietf)}<br>IKEv2: {_one(ikev2)}"
    if ietf:
        return _one(ietf)
    return _one(ikev2)


def short_ietf_source(source: str) -> str:
    # "RFC 9142 §3.1.1" -> "§3.1.1" if leading RFC matches default; else full string.
    return source


def cite_bsi_source(entry: dict) -> str:
    bsi = entry.get("bsi")
    return bsi["source"] if bsi else ""


def cite_nist_source(entry: dict) -> str:
    nist = entry.get("nist")
    return nist["source"] if nist else ""


# ── YAML loading ──────────────────────────────────────────────────────────────

def load_entries(path: Path) -> list:
    with path.open() as f:
        data = yaml.safe_load(f)
    return data.get("entries", [])


# ── Table builders ────────────────────────────────────────────────────────────

def by_subtype(entries: list, subtype: str) -> list:
    return [e for e in entries if e.get("subType") == subtype]


def render_ssh_table(entries: list, subtype: str) -> str:
    rows = by_subtype(entries, subtype)
    lines = ["| Algorithm | IETF | NIST | BSI | Notes |",
             "|:---|:---|:---|:---|:---|"]
    for e in rows:
        notes_str = "; ".join(e.get("remarks", []))
        lines.append(
            f"| `{e['id']}` | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} | {notes_str} |"
        )
    return "\n".join(lines)


def render_ipsec_dh_table(entries: list) -> str:
    rows = by_subtype(entries, "ipsecDhGroup")
    lines = ["| Group | Description | IETF | NIST | BSI |",
             "|:---|:---|:---|:---|:---|"]
    for e in rows:
        description = entry_description(e) or ", ".join(e.get("components", []))
        lines.append(
            f"| `{e['id']}` | {description} | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} |"
        )
    return "\n".join(lines)


def render_ipsec_esp_table(entries: list) -> str:
    rows = by_subtype(entries, "espTransform")
    lines = ["| Transform | IETF (ESP / IKEv2) | NIST | BSI | Notes |",
             "|:---|:---|:---|:---|:---|"]
    for e in rows:
        notes_str = "; ".join(e.get("remarks", []))
        lines.append(
            f"| `{e['id']}` | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} | {notes_str} |"
        )
    return "\n".join(lines)


def render_ipsec_auth_table(entries: list) -> str:
    rows = by_subtype(entries, "ipsecIntegrity")
    lines = ["| Algorithm | IETF | NIST | BSI | Notes |",
             "|:---|:---|:---|:---|:---|"]
    for e in rows:
        notes_str = "; ".join(e.get("remarks", []))
        lines.append(
            f"| `{e['id']}` | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} | {notes_str} |"
        )
    return "\n".join(lines)


def render_kerberos_table(entries: list) -> str:
    """Single Kerberos table covering enc-types, integrity, and PKINIT KEX —
    a Mechanism column distinguishes the three sub-types."""
    sub_label = {
        "krbEncType":   "Encryption",
        "krbIntegrity": "Integrity (MAC)",
        "krbKex":       "Key exchange (PKINIT)",
    }
    lines = ["| Mechanism | Algorithm | IETF | NIST | BSI | Notes |",
             "|:---|:---|:---|:---|:---|:---|"]
    for e in entries:
        mech = sub_label.get(e.get("subType"), e.get("subType", ""))
        notes_str = entry_description(e)
        if e.get("remarks"):
            extras = "; ".join(e["remarks"])
            notes_str = f"{notes_str}; {extras}" if notes_str else extras
        lines.append(
            f"| {mech} | `{e['id']}` | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} | {notes_str} |"
        )
    return "\n".join(lines)


def render_dnssec_zone_table(entries: list) -> str:
    rows = by_subtype(entries, "dnssecAlgorithm")
    lines = ["| Algorithm | Description | IETF | NIST | BSI | Notes |",
             "|:---|:---|:---|:---|:---|:---|"]
    for e in rows:
        notes_str = "; ".join(e.get("remarks", []))
        lines.append(
            f"| `{e['id']}` | {entry_description(e)} | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} | {notes_str} |"
        )
    return "\n".join(lines)


def render_dnssec_tsig_table(entries: list) -> str:
    rows = by_subtype(entries, "dnssecTsig")
    lines = ["| Algorithm | IETF | NIST | BSI | Notes |",
             "|:---|:---|:---|:---|:---|"]
    for e in rows:
        notes_str = "; ".join(e.get("remarks", []))
        lines.append(
            f"| `{e['id']}` | {render_ietf(e)} | {render_nist(e)} | {render_bsi(e)} | {notes_str} |"
        )
    return "\n".join(lines)


# ── TLS overlay tables (replicates §12, §13 in cryptographic-tls-cipher-suites.md) ──

def has_pfs(suite_id: str) -> bool:
    """Derive Perfect Forward Secrecy from a TLS cipher suite ID.
    Suites carrying ephemeral DH (DHE / ECDHE) provide PFS; static DH/ECDH and
    RSA key transport do not. Convention is reliable for the standard
    `TLS_<KEX>_<AUTH>_WITH_...` naming.
    """
    # Drop the leading "TLS_" and inspect the kex/auth fragment up to "_WITH_"
    # Examples that have PFS: ECDHE_*, DHE_*, ECDHE_PSK, DHE_PSK
    # Examples that don't:    RSA, RSA_PSK, ECDH_*, DH_*, PSK
    return "ECDHE" in suite_id or "DHE" in suite_id


def first_reference(entry: dict) -> str:
    """Return the primary IANA reference (first in the list), or empty string."""
    refs = entry.get("iana", {}).get("references", [])
    return refs[0]["ref"] if refs else ""


def entry_description(entry: dict) -> str:
    """Return the human-readable description for an entry.

    Priority:
      1. explicit `description:` field
      2. first remark (fallback for entries that haven't been backfilled)
      3. empty string
    """
    if entry.get("description"):
        return entry["description"]
    remarks = entry.get("remarks") or []
    if remarks:
        return remarks[0]
    return ""


def entry_short_label(entry: dict) -> str:
    """Strip the registry prefix from the entry's id for column rendering.
    e.g. `tls-group:secp256r1` → `secp256r1`, `ipsec-dh:group19` → `group19`,
    bare ids passed through unchanged.
    """
    raw = entry["id"]
    for prefix in ("tls-group:", "tls-sig:", "ipsec-dh:", "ipsec-esp:", "ipsec-auth:"):
        if raw.startswith(prefix):
            return raw[len(prefix):]
    return raw


def render_tls_bsi_cipher_suite_group(entries: list, table_label: str,
                                      pfs_column: bool = False) -> str:
    """Render a BSI cipher-suite table for entries whose bsi.source contains
    the table_label. The Spec column is populated from iana.references[0].ref.
    Set pfs_column=True for §12.4 (PSK) where Perfect Forward Secrecy varies
    per row.
    """
    rows = []
    for e in entries:
        if e.get("subType") != "cipherSuite":
            continue
        bsi = e.get("bsi")
        if not bsi:
            continue
        if table_label not in bsi.get("source", ""):
            continue
        rows.append(e)
    rows.sort(key=lambda e: e["iana"]["value"])

    if pfs_column:
        header = "| Cipher suite | IANA | Spec | Use up to | PFS |"
        sep    = "|:---|:---|:---|:---|:---:|"
    else:
        header = "| Cipher suite | IANA | Spec | Use up to |"
        sep    = "|:---|:---|:---|:---|"
    lines = [header, sep]
    for e in rows:
        spec = first_reference(e)
        use = _format_use_up_to(e["bsi"].get("useUpTo", ""))
        if pfs_column:
            pfs = "✓" if has_pfs(e["id"]) else "✗"
            lines.append(f"| `{e['id']}` | `{e['iana']['value']}` | {spec} | {use} | {pfs} |")
        else:
            lines.append(f"| `{e['id']}` | `{e['iana']['value']}` | {spec} | {use} |")
    return "\n".join(lines)


def render_tls_bsi_groups_table(entries: list, table_label: str | None = None) -> str:
    """Render BSI groups table; optionally filter by a substring of bsi.source
    (e.g., "Table 6" for TLS 1.2 groups, "Table 10" for TLS 1.3 groups). Groups
    listed in both tables are emitted in either filter."""
    rows = []
    for e in entries:
        if e.get("subType") != "supportedGroup":
            continue
        bsi = e.get("bsi")
        if not bsi:
            continue
        if table_label and table_label not in bsi.get("source", ""):
            continue
        rows.append(e)
    rows.sort(key=lambda e: int(e["iana"]["value"]))
    lines = ["| Group | Description | IANA | Spec | Use up to |",
             "|:---|:---|:---|:---|:---|"]
    for e in rows:
        name = entry_short_label(e)
        description = entry_description(e)
        spec = first_reference(e)
        use = _format_use_up_to(e["bsi"].get("useUpTo", ""))
        lines.append(f"| `{name}` | {description} | {e['iana']['value']} | {spec} | {use} |")
    return "\n".join(lines)


def render_tls_bsi_sigs_table(entries: list, sigalg_cert: bool = False) -> str:
    """Render BSI signature-scheme table.
    sigalg_cert=True  -> filter to entries from Table 12 (PKCS#1 v1.5 set);
    sigalg_cert=False -> filter to entries from Table 11.
    """
    rows = []
    for e in entries:
        if e.get("subType") != "signatureScheme":
            continue
        bsi = e.get("bsi")
        if not bsi:
            continue
        is_cert = "Table 12" in bsi.get("source", "")
        if sigalg_cert != is_cert:
            continue
        rows.append(e)
    rows.sort(key=lambda e: e["iana"]["value"])
    lines = ["| Signature algorithm | IANA | Spec | Use up to |",
             "|:---|:---|:---|:---|"]
    for e in rows:
        name = e["id"].replace("tls-sig:", "")
        spec = first_reference(e)
        use = _format_use_up_to(e["bsi"].get("useUpTo", ""))
        lines.append(f"| `{name}` | `{e['iana']['value']}` | {spec} | {use} |")
    return "\n".join(lines)


def render_tls_nist_cipher_suites_section(entries: list, section: str) -> str:
    """Render NIST cipher-suite table for entries whose nist.source contains section."""
    rows = []
    for e in entries:
        if e.get("subType") != "cipherSuite":
            continue
        nist = e.get("nist")
        if not nist:
            continue
        if section not in nist.get("source", ""):
            continue
        rows.append(e)
    rows.sort(key=lambda e: e["iana"]["value"])
    lines = ["| Cipher suite | IANA | Spec | Available in |",
             "|:---|:---|:---|:---|"]
    for e in rows:
        spec = first_reference(e)
        # Available-in column comes from protocolVersions plus the “interop only” trailing note
        pv = " / ".join(f"TLS {v}" for v in e.get("protocolVersions", []))
        if "interop only" in e["nist"].get("source", ""):
            pv = "TLS 1.0 / 1.1 / 1.2 (interop only)"
        lines.append(f"| `{e['id']}` | `{e['iana']['value']}` | {spec} | {pv} |")
    return "\n".join(lines)


def render_tls13_cipher_suites_simple(entries: list) -> str:
    """Render the small TLS 1.3 cipher-suite table (BSI §12.11 / NIST §13.3)."""
    rows = [e for e in entries if e.get("subType") == "cipherSuite" and "1.3" in e.get("protocolVersions", [])]
    rows.sort(key=lambda e: e["iana"]["value"])
    lines = ["| Cipher suite | IANA | NIST | BSI |",
             "|:---|:---|:---|:---|"]
    for e in rows:
        lines.append(
            f"| `{e['id']}` | `{e['iana']['value']}` | {render_nist(e)} | {render_bsi(e)} |"
        )
    return "\n".join(lines)


# ── Registry category distribution ──────────────────────────────────────────

ALGORITHM_YAML_FILES = [
    "cr-symmetric-ciphers.yaml",
    "cr-hash-functions.yaml",
    "cr-macs.yaml",
    "cr-asymmetric.yaml",
    "cr-pqc.yaml",
    "cr-kdfs.yaml",
    "cr-rngs.yaml",
    "cr-cdx.yaml",
    "cr-spdx.yaml",
]


def render_category_distribution() -> str:
    """Build a markdown table summarising YAML algorithm entries by category.

    Counts entries (not markdown rows) per `category:` value and aggregates
    by top-level branch. Unannotated entries (when annotation is incomplete)
    are reported as a separate `(unannotated)` row.
    """
    from collections import Counter
    counts: Counter = Counter()
    total_algorithms = 0
    unannotated = 0
    for fname in ALGORITHM_YAML_FILES:
        for entry in load_entries(REGISTRY_DIR / fname):
            if entry.get("type") != "algorithm":
                continue
            total_algorithms += 1
            cat = entry.get("category")
            if cat is None:
                unannotated += 1
            else:
                counts[cat] += 1

    # Group by top-level branch, preserving spec order. The "list" sentinel
    # appears as its own pseudo-branch at the end (entries that span multiple
    # categories or have no clear single mapping).
    BRANCH_ORDER = [
        "symmetric", "hash", "mac", "asymmetric", "hpke",
        "curve", "kdf", "framework", "rng", "padding", "composite",
        "list",
    ]
    grouped: dict[str, list[tuple[str, int]]] = {b: [] for b in BRANCH_ORDER}
    for cat, n in counts.items():
        top = cat.split("/", 1)[0]
        grouped.setdefault(top, []).append((cat, n))

    lines = [
        "| Category | Count |",
        "|:---|---:|",
    ]
    annotated_total = 0
    for branch in BRANCH_ORDER:
        rows = sorted(grouped.get(branch, []), key=lambda t: t[0])
        if not rows:
            continue
        for cat, n in rows:
            lines.append(f"| `{cat}` | {n} |")
            annotated_total += n
    # Surface any unexpected branch values (would indicate vocabulary drift)
    for branch in sorted(set(grouped) - set(BRANCH_ORDER)):
        for cat, n in sorted(grouped[branch], key=lambda t: t[0]):
            lines.append(f"| `{cat}` _(unknown branch)_ | {n} |")
            annotated_total += n
    if unannotated:
        lines.append(f"| _(unannotated)_ | {unannotated} |")
    lines.append(f"| **Total** | **{total_algorithms}** |")
    lines.append("")
    lines.append(
        f"_Computed from `cr-*.yaml` algorithm entries. "
        f"{annotated_total}/{total_algorithms} annotated "
        f"({grouped.get('list', []) and sum(n for _, n in grouped['list']) or 0} use the `\"list\"` sentinel); "
        f"see [`management/registry-category-taxonomy.md`](../../../../../management/registry-category-taxonomy.md) for the controlled vocabulary._"
    )
    return "\n".join(lines)


# ── Marker substitution ───────────────────────────────────────────────────────

MARKER_RE = re.compile(
    r"(<!-- AUTOGEN:BEGIN (?P<name>[a-z0-9-]+) -->)(?:\n.*?)?\n(<!-- AUTOGEN:END (?P=name) -->)",
    re.DOTALL,
)


def substitute(text: str, sections: dict) -> tuple[str, list, list]:
    """Replace AUTOGEN sections with new content. Returns (new_text, replaced, missing)."""
    replaced = []
    found_names = set()

    def _sub(m: re.Match) -> str:
        name = m.group("name")
        found_names.add(name)
        if name not in sections:
            return m.group(0)
        replaced.append(name)
        return f"{m.group(1)}\n{sections[name]}\n{m.group(3)}"

    new_text = MARKER_RE.sub(_sub, text)
    missing = [name for name in sections if name not in found_names]
    return new_text, replaced, missing


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Regenerate status-table autogen sections from cr-*.yaml")
    parser.add_argument("--check", action="store_true",
                        help="Compare generated output with existing markdown; exit non-zero on differences")
    args = parser.parse_args()

    tls = load_entries(TLS_YAML)
    ssh = load_entries(SSH_YAML)
    ipsec = load_entries(IPSEC_YAML)
    kerberos = load_entries(KERBEROS_YAML)
    dnssec = load_entries(DNSSEC_YAML)

    sections_protocol = {
        "ssh-kex":                   render_ssh_table(ssh, "sshKex"),
        "ssh-host-auth":             render_ssh_table(ssh, "sshHostAuth"),
        "ssh-symmetric-encryption":  render_ssh_table(ssh, "sshCipher"),
        "ssh-mac":                   render_ssh_table(ssh, "sshMac"),
        "ipsec-dh-groups":           render_ipsec_dh_table(ipsec),
        "ipsec-esp-encryption":      render_ipsec_esp_table(ipsec),
        "ipsec-integrity":           render_ipsec_auth_table(ipsec),
        "kerberos":                  render_kerberos_table(kerberos),
        "dnssec-zone-signing":       render_dnssec_zone_table(dnssec),
        "dnssec-tsig":               render_dnssec_tsig_table(dnssec),
    }

    sections_tls = {
        "tls-bsi-12-2":      render_tls_bsi_cipher_suite_group(tls, "Table 3"),
        "tls-bsi-12-3":      render_tls_bsi_cipher_suite_group(tls, "Table 4"),
        "tls-bsi-12-4":      render_tls_bsi_cipher_suite_group(tls, "Table 5", pfs_column=True),
        "tls-bsi-12-5":      render_tls_bsi_groups_table(tls, "Table 6"),
        "tls-bsi-12-8":      render_tls_bsi_groups_table(tls, "Table 10"),
        "tls-bsi-12-9":      render_tls_bsi_sigs_table(tls, sigalg_cert=False),
        "tls-bsi-12-10":     render_tls_bsi_sigs_table(tls, sigalg_cert=True),
        "tls-bsi-12-11":     render_tls13_cipher_suites_simple(tls),
        "tls-nist-13-2-1":   render_tls_nist_cipher_suites_section(tls, "§3.3.1.1.1"),
        "tls-nist-13-2-2":   render_tls_nist_cipher_suites_section(tls, "§3.3.1.1.2"),
        "tls-nist-13-2-3":   render_tls_nist_cipher_suites_section(tls, "§3.3.1.1.3"),
        "tls-nist-13-2-4":   render_tls_nist_cipher_suites_section(tls, "§3.3.1.1.4"),
        "tls-nist-13-2-5":   render_tls_nist_cipher_suites_section(tls, "§3.3.1.1.5"),
        "tls-nist-13-3":     render_tls_nist_cipher_suites_section(tls, "§3.3.1.2"),
    }

    sections_registry = {
        "registry-category-distribution": render_category_distribution(),
    }

    overall_ok = True
    for path, sections in [(PROTOCOL_STATUS_MD, sections_protocol),
                           (TLS_CIPHER_SUITES_MD, sections_tls),
                           (REGISTRY_README_MD, sections_registry)]:
        original = path.read_text()
        new_text, replaced, missing = substitute(original, sections)

        if missing:
            print(f"  WARN  {path.name}: {len(missing)} sections produced but no marker found:", file=sys.stderr)
            for name in missing:
                print(f"    - {name}", file=sys.stderr)

        if args.check:
            if new_text == original:
                print(f"  {path.name} is up to date ({len(replaced)} autogen sections checked).")
            else:
                print(f"  ERROR: {path.name} is out of date! Re-run without --check.", file=sys.stderr)
                overall_ok = False
        else:
            if new_text != original:
                path.write_text(new_text)
                print(f"  {path.name}: updated ({len(replaced)} autogen sections).")
            else:
                print(f"  {path.name}: no changes ({len(replaced)} autogen sections checked).")

    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
