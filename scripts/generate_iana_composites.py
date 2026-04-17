#!/usr/bin/env python3
"""
Generate cr-tls.yaml from IANA TLS parameter registries.

Fetches (or reads from local cache) IANA CSVs for:
  - Cipher Suites (tls-parameters-4.csv)
  - Supported Groups (tls-parameters-8.csv)
  - Signature Schemes (tls-signaturescheme.csv)

Decomposes each entry into component algorithm patterns and writes
a v2 registry YAML file for use by ae-pattern-validator.

Usage:
    python generate_iana_composites.py [--check] [--cache-dir DIR]

Options:
    --check       Compare generated output with existing cr-tls.yaml;
                  exit non-zero on differences.
    --cache-dir   Directory for cached CSV files (default: scripts/.iana-cache)
"""

import argparse
import csv
import io
import os
import re
import sys
import textwrap
from pathlib import Path
from typing import Optional

# ── Paths ──────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
OUTPUT_PATH = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "cr-tls.yaml"
DEFAULT_CACHE_DIR = SCRIPT_DIR / ".iana-cache"

# ── IANA CSV URLs ──────────────────────────────────────────────────────────────

CSV_URLS = {
    "cipher-suites": "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv",
    "supported-groups": "https://www.iana.org/assignments/tls-parameters/tls-parameters-8.csv",
    "signature-schemes": "https://www.iana.org/assignments/tls-parameters/tls-signaturescheme.csv",
}

# ── Lookup tables: IANA names -> registry patterns ─────────────────────────────

CIPHER_MAP = {
    "AES_128_GCM": "AES-128-GCM",
    "AES_256_GCM": "AES-256-GCM",
    "AES_128_CCM": "AES-128-CCM",
    "AES_256_CCM": "AES-256-CCM",
    "AES_128_CCM_8": "AES-128-CCM",
    "AES_128_CBC": "AES-128-CBC",
    "AES_256_CBC": "AES-256-CBC",
    "3DES_EDE_CBC": "3DES-CBC",
    "CHACHA20_POLY1305": "ChaCha20-Poly1305",
    "NULL": "NULL",
}

KEX_MAP = {
    "ECDHE": "ECDH",
    "ECDH": "ECDH",
    "DHE": "FFDH",
    "DH": "FFDH",
    "RSA": "RSAES-PKCS1",  # RSA key transport
    "PSK": "PSK",
    "ECDHE_PSK": "ECDH",
    "DHE_PSK": "FFDH",
    "RSA_PSK": "RSAES-PKCS1",
    "PSK_DHE": "FFDH",
}

AUTH_MAP = {
    "ECDSA": "ECDSA",
    "RSA": "RSASSA-PSS",
    "PSK": "PSK",
    "DSS": "DSA",
    "anon": "NULL",
}

HASH_MAP = {
    "SHA256": "HKDF-SHA-256",
    "SHA384": "HKDF-SHA-384",
    "SHA512": "HKDF-SHA-512",
    "SHA": "SHA-1",  # legacy
}

GROUP_MAP = {
    "secp256r1": "ECDH-P-256",
    "secp384r1": "ECDH-P-384",
    "secp521r1": "ECDH-P-521",
    "x25519": "ECDH-Curve25519",
    "x448": "ECDH-Curve448",
    "ffdhe2048": "FFDH-ffdhe2048",
    "ffdhe3072": "FFDH-ffdhe3072",
    "ffdhe4096": "FFDH-ffdhe4096",
    "ffdhe6144": "FFDH-ffdhe6144",
    "ffdhe8192": "FFDH-ffdhe8192",
    "X25519MLKEM768": ["ECDH-Curve25519", "ML-KEM-768"],
    "SecP256r1MLKEM768": ["ECDH-P-256", "ML-KEM-768"],
    "SecP384r1MLKEM1024": ["ECDH-P-384", "ML-KEM-1024"],
    "MLKEM512": "ML-KEM-512",
    "MLKEM768": "ML-KEM-768",
    "MLKEM1024": "ML-KEM-1024",
}

SIG_MAP = {
    "ecdsa_secp256r1_sha256": "ECDSA-P-256-SHA-256",
    "ecdsa_secp384r1_sha384": "ECDSA-P-384-SHA-384",
    "ecdsa_secp521r1_sha512": "ECDSA-P-521-SHA-512",
    "rsa_pss_rsae_sha256": "RSASSA-PSS-SHA-256",
    "rsa_pss_rsae_sha384": "RSASSA-PSS-SHA-384",
    "rsa_pss_rsae_sha512": "RSASSA-PSS-SHA-512",
    "rsa_pss_pss_sha256": "RSASSA-PSS-SHA-256",
    "rsa_pss_pss_sha384": "RSASSA-PSS-SHA-384",
    "rsa_pss_pss_sha512": "RSASSA-PSS-SHA-512",
    "rsa_pkcs1_sha256": "RSASSA-PKCS1-v1_5-SHA-256",
    "rsa_pkcs1_sha384": "RSASSA-PKCS1-v1_5-SHA-384",
    "rsa_pkcs1_sha512": "RSASSA-PKCS1-v1_5-SHA-512",
    "rsa_pkcs1_sha1": "RSASSA-PKCS1-v1_5-SHA-1",
    "ecdsa_sha1": "ECDSA-SHA-1",
    "ed25519": "EdDSA-Ed25519",
    "ed448": "EdDSA-Ed448",
    "mldsa44": "ML-DSA-44",
    "mldsa65": "ML-DSA-65",
    "mldsa87": "ML-DSA-87",
}


# ── CSV fetching / caching ─────────────────────────────────────────────────────

def fetch_csv(name: str, cache_dir: Path) -> str:
    """Fetch a CSV from IANA, or return cached version if available."""
    cache_file = cache_dir / f"{name}.csv"
    if cache_file.exists():
        print(f"  Using cached {cache_file.name}")
        return cache_file.read_text(encoding="utf-8")

    url = CSV_URLS[name]
    print(f"  Fetching {url} ...")
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = resp.read().decode("utf-8")
    except Exception as e:
        print(f"  ERROR: Failed to fetch {url}: {e}", file=sys.stderr)
        print(f"  Place cached CSV at {cache_file}", file=sys.stderr)
        sys.exit(1)

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(data, encoding="utf-8")
    return data


def parse_csv(text: str) -> list[dict]:
    """Parse CSV text into a list of dicts, stripping markdown/whitespace."""
    # Remove any leading markdown fences
    lines = text.strip().splitlines()
    clean_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("#"):
            continue
        clean_lines.append(line)
    return list(csv.DictReader(clean_lines))


# ── Cipher suite decomposition ─────────────────────────────────────────────────

# TLS 1.3 pattern: TLS_<CIPHER>_<HASH>
TLS13_RE = re.compile(r"^TLS_([A-Za-z0-9_]+?)_(SHA\d*|SM3|ASCONHASH256)$")

# TLS 1.2 pattern: TLS_<KEX>_<AUTH>_WITH_<CIPHER>_<HASH>
# Also handles TLS_<KEX>_WITH_<CIPHER>_<HASH> (PSK without separate auth)
TLS12_WITH_RE = re.compile(r"^TLS_(.+?)_WITH_(.+?)_(SHA\d*|MD5|SM3)$")


def decompose_tls13(name: str) -> Optional[dict]:
    """Decompose a TLS 1.3 cipher suite name into components."""
    m = TLS13_RE.match(name)
    if not m:
        return None
    cipher_raw, hash_raw = m.group(1), m.group(2)
    cipher = CIPHER_MAP.get(cipher_raw)
    hash_alg = HASH_MAP.get(hash_raw)
    if cipher is None or hash_alg is None:
        return None
    return {
        "protocolVersions": ["1.3"],
        "components": [cipher, hash_alg],
    }


def decompose_tls12(name: str) -> Optional[dict]:
    """Decompose a TLS 1.2 (or earlier) cipher suite name into components."""
    m = TLS12_WITH_RE.match(name)
    if not m:
        return None

    kex_auth_raw, cipher_raw, hash_raw = m.group(1), m.group(2), m.group(3)

    # Map cipher
    cipher = CIPHER_MAP.get(cipher_raw)
    if cipher is None:
        return None

    # Map hash (TLS 1.2 uses raw hash, not HKDF)
    hash_map_12 = {
        "SHA256": "SHA-256",
        "SHA384": "SHA-384",
        "SHA512": "SHA-512",
        "SHA": "SHA-1",
        "MD5": "MD5",
    }
    hash_alg = hash_map_12.get(hash_raw)
    if hash_alg is None:
        return None

    # Split kex and auth
    # Patterns: "ECDHE_ECDSA", "ECDHE_RSA", "DHE_RSA", "DHE_DSS",
    #           "RSA" (kex=RSA, auth=RSA), "PSK", "DHE_PSK", "ECDHE_PSK",
    #           "RSA_PSK", "DH_RSA", "DH_DSS", "DH_anon", "ECDH_ECDSA",
    #           "ECDH_RSA", "ECDH_anon", "PSK_DHE"
    components = []

    if "_" in kex_auth_raw:
        parts = kex_auth_raw.split("_", 1)
        kex_raw = parts[0]
        auth_raw = parts[1]

        # Compound KEX like ECDHE_PSK: the full thing is the kex, auth is PSK
        if kex_auth_raw in KEX_MAP:
            kex = KEX_MAP[kex_auth_raw]
            # auth is implied by the compound
            auth_part = kex_auth_raw.split("_")[-1]
            auth = AUTH_MAP.get(auth_part)
            if auth is None:
                return None
            components = [kex, auth, cipher, hash_alg]
        else:
            kex = KEX_MAP.get(kex_raw)
            auth = AUTH_MAP.get(auth_raw)
            if kex is None or auth is None:
                return None
            components = [kex, auth, cipher, hash_alg]
    else:
        # Single token: "RSA" or "PSK"
        kex = KEX_MAP.get(kex_auth_raw)
        auth = AUTH_MAP.get(kex_auth_raw)
        if kex is None or auth is None:
            return None
        components = [kex, auth, cipher, hash_alg]

    return {
        "protocolVersions": ["1.2"],
        "components": components,
    }


def decompose_cipher_suite(name: str) -> Optional[dict]:
    """Try to decompose a cipher suite name into components."""
    # Skip non-cipher-suite names
    if not name.startswith("TLS_"):
        return None

    # TLS 1.3 suites have no _WITH_
    if "_WITH_" not in name:
        return decompose_tls13(name)
    else:
        return decompose_tls12(name)


# ── YAML generation ────────────────────────────────────────────────────────────

def yaml_str(s: str) -> str:
    """Quote a string for YAML if needed."""
    if any(c in s for c in ":#{}[]|>&*!%@`"):
        return f'"{s}"'
    if s in ("true", "false", "null", "yes", "no", "on", "off"):
        return f'"{s}"'
    if s.startswith("0x") or s.startswith("0X"):
        return f'"{s}"'
    return f'"{s}"'


def format_entry(entry: dict) -> str:
    """Format a single registry entry as YAML text."""
    lines = []
    lines.append(f'  - id: {yaml_str(entry["id"])}')
    lines.append(f'    type: "composite"')
    lines.append(f'    subType: {yaml_str(entry["subType"])}')
    lines.append(f'    protocol: "TLS"')

    # protocolVersions
    pvs = entry.get("protocolVersions", [])
    pv_str = ", ".join(yaml_str(v) for v in pvs)
    lines.append(f'    protocolVersions: [{pv_str}]')

    # iana block
    iana = entry.get("iana", {})
    lines.append(f'    iana:')
    lines.append(f'      registry: {yaml_str(iana["registry"])}')
    lines.append(f'      value: {yaml_str(iana["value"])}')
    rec = iana.get("recommended", False)
    lines.append(f'      recommended: {"true" if rec else "false"}')

    # components
    components = entry.get("components", [])
    comp_str = ", ".join(yaml_str(c) for c in components)
    lines.append(f'    components: [{comp_str}]')

    return "\n".join(lines)


def generate_yaml(entries: list[dict]) -> str:
    """Generate the full YAML document."""
    parts = []
    parts.append("# TLS protocol composites: cipher suites, supported groups, and signature schemes")
    parts.append("#")
    parts.append("# Auto-generated from IANA TLS parameter registries.")
    parts.append("# Do not edit manually; regenerate with:")
    parts.append("#   python scripts/generate_iana_composites.py")
    parts.append("#")
    parts.append("# Part of the ae-pattern-validator validation registry.")
    parts.append("# See README.md in this directory for schema documentation.")
    parts.append('version: "2.0"')
    parts.append("")
    parts.append("entries:")

    for entry in entries:
        parts.append("")
        parts.append(format_entry(entry))

    return "\n".join(parts) + "\n"


# ── Main processing ────────────────────────────────────────────────────────────

def is_actionable(row: dict) -> bool:
    """Check if a CSV row is an actionable (non-reserved, non-unassigned) entry."""
    desc = row.get("Description", "").strip()
    if not desc:
        return False
    desc_lower = desc.lower()
    if "unassigned" in desc_lower:
        return False
    if "reserved" in desc_lower:
        return False
    return True


def is_recommended_or_named(row: dict) -> bool:
    """Check if the Recommended column is Y, N, or D (not empty)."""
    rec = row.get("Recommended", "").strip()
    return rec in ("Y", "N", "D")


def process_cipher_suites(csv_text: str) -> tuple[list[dict], list[str]]:
    """Process cipher suites CSV and return (entries, failures)."""
    rows = parse_csv(csv_text)
    entries = []
    failures = []
    seen_ids = set()

    for row in rows:
        if not is_actionable(row):
            continue
        if not is_recommended_or_named(row):
            continue

        desc = row["Description"].strip()
        value = row.get("Value", "").strip()
        recommended = row.get("Recommended", "").strip()

        # Skip non-cipher-suite entries (signaling, SCSV, etc.)
        if not desc.startswith("TLS_"):
            continue
        if "SCSV" in desc:
            continue

        result = decompose_cipher_suite(desc)
        if result is None:
            failures.append(desc)
            continue

        # Deduplicate (some suites appear with multiple code points)
        if desc in seen_ids:
            continue
        seen_ids.add(desc)

        entry = {
            "id": desc,
            "subType": "cipherSuite",
            "protocolVersions": result["protocolVersions"],
            "iana": {
                "registry": "tls-cipher-suites",
                "value": value,
                "recommended": recommended == "Y",
            },
            "components": result["components"],
        }
        entries.append(entry)

    return entries, failures


def process_supported_groups(csv_text: str) -> tuple[list[dict], list[str]]:
    """Process supported groups CSV and return (entries, failures)."""
    rows = parse_csv(csv_text)
    entries = []
    failures = []

    for row in rows:
        if not is_actionable(row):
            continue
        if not is_recommended_or_named(row):
            continue

        desc = row["Description"].strip()
        value = row.get("Value", "").strip()
        recommended = row.get("Recommended", "").strip()

        # Skip obsolete entries
        if "(OBSOLETE)" in desc:
            continue

        mapping = GROUP_MAP.get(desc)
        if mapping is None:
            failures.append(desc)
            continue

        if isinstance(mapping, list):
            components = mapping
        else:
            components = [mapping]

        entry = {
            "id": f"tls-group:{desc}",
            "subType": "supportedGroup",
            "protocolVersions": ["1.2", "1.3"],
            "iana": {
                "registry": "tls-supported-groups",
                "value": value,
                "recommended": recommended == "Y",
            },
            "components": components,
        }
        entries.append(entry)

    return entries, failures


def process_signature_schemes(csv_text: str) -> tuple[list[dict], list[str]]:
    """Process signature schemes CSV and return (entries, failures)."""
    rows = parse_csv(csv_text)
    entries = []
    failures = []

    for row in rows:
        if not is_actionable(row):
            continue
        if not is_recommended_or_named(row):
            continue

        desc = row["Description"].strip()
        value = row.get("Value", "").strip()
        recommended = row.get("Recommended", "").strip()

        mapping = SIG_MAP.get(desc)
        if mapping is None:
            failures.append(desc)
            continue

        entry = {
            "id": f"tls-sig:{desc}",
            "subType": "signatureScheme",
            "protocolVersions": ["1.2", "1.3"],
            "iana": {
                "registry": "tls-signature-schemes",
                "value": value,
                "recommended": recommended == "Y",
            },
            "components": [mapping],
        }
        entries.append(entry)

    return entries, failures


def main():
    parser = argparse.ArgumentParser(description="Generate cr-tls.yaml from IANA TLS registries")
    parser.add_argument("--check", action="store_true",
                        help="Compare generated output with existing file; exit non-zero on differences")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
                        help="Directory for cached CSV files")
    args = parser.parse_args()

    print("=== IANA TLS Composite Generator ===\n")
    print("Fetching IANA CSV data...")

    cs_csv = fetch_csv("cipher-suites", args.cache_dir)
    sg_csv = fetch_csv("supported-groups", args.cache_dir)
    ss_csv = fetch_csv("signature-schemes", args.cache_dir)

    print("\nProcessing cipher suites...")
    cs_entries, cs_failures = process_cipher_suites(cs_csv)
    print(f"  Generated: {len(cs_entries)} entries")
    if cs_failures:
        print(f"  Unmapped:  {len(cs_failures)} entries")
        for f in cs_failures:
            print(f"    - {f}")

    print("\nProcessing supported groups...")
    sg_entries, sg_failures = process_supported_groups(sg_csv)
    print(f"  Generated: {len(sg_entries)} entries")
    if sg_failures:
        print(f"  Unmapped:  {len(sg_failures)} entries")
        for f in sg_failures:
            print(f"    - {f}")

    print("\nProcessing signature schemes...")
    ss_entries, ss_failures = process_signature_schemes(ss_csv)
    print(f"  Generated: {len(ss_entries)} entries")
    if ss_failures:
        print(f"  Unmapped:  {len(ss_failures)} entries")
        for f in ss_failures:
            print(f"    - {f}")

    all_entries = cs_entries + sg_entries + ss_entries
    yaml_text = generate_yaml(all_entries)

    print(f"\n=== Summary ===")
    print(f"  Cipher suites:    {len(cs_entries)}")
    print(f"  Supported groups: {len(sg_entries)}")
    print(f"  Signature schemes:{len(ss_entries)}")
    print(f"  Total entries:    {len(all_entries)}")
    print(f"  Decomp failures:  {len(cs_failures) + len(sg_failures) + len(ss_failures)}")

    if args.check:
        if not OUTPUT_PATH.exists():
            print(f"\nERROR: {OUTPUT_PATH} does not exist for comparison", file=sys.stderr)
            sys.exit(1)
        existing = OUTPUT_PATH.read_text(encoding="utf-8")
        if existing == yaml_text:
            print(f"\n  cr-tls.yaml is up to date.")
            sys.exit(0)
        else:
            print(f"\n  ERROR: cr-tls.yaml is out of date! Re-run without --check to regenerate.",
                  file=sys.stderr)
            sys.exit(1)
    else:
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_PATH.write_text(yaml_text, encoding="utf-8")
        print(f"\n  Written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
