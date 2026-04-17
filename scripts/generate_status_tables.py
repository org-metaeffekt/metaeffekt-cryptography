#!/usr/bin/env python3
"""
Cross-check and generation script for cryptographic-algorithm-status.md.

Modes:
  --check     Compare algorithm status data between the markdown tables and
              the YAML registry files.  Reports all discrepancies.
  --generate  Patch the existing markdown: for each table row in §1-§10 that
              has NIST / BSI / CNSA columns, replace those cells with values
              resolved from the YAML registry.  All other columns, header
              content, blockquotes, and §11-§14 are preserved verbatim.
              Output goes to stdout (or to a file with --output <path>).
  --apply     Same as --generate but writes back to the source markdown file
              in-place.

Usage:
    python3 scripts/generate_status_tables.py --check
    python3 scripts/generate_status_tables.py --generate > /tmp/out.md
    python3 scripts/generate_status_tables.py --generate --output /tmp/out.md
    python3 scripts/generate_status_tables.py --apply

Exit code 0 on success, 1 on failure.
"""

import argparse
import re
import sys
from collections import OrderedDict
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("ERROR: PyYAML is required.  pip install pyyaml")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
REGISTRY_DIR = BASE_DIR / "ae-pattern-validator" / "src" / "main" / "resources" / "registry"
MD_FILE = BASE_DIR / "cryptographic-algorithm-status.md"

# YAML files to load (algorithm registries, NOT protocol registries)
YAML_PREFIXES_EXCLUDE = {"cr-cdx", "cr-spdx", "cr-tls", "cr-ssh", "cr-x509", "cr-ipsec"}


# ---------------------------------------------------------------------------
# Markdown cell splitter (handles escaped pipes \|)
# ---------------------------------------------------------------------------

def split_md_row(line: str) -> list[str]:
    """Split a markdown table row into cells, respecting escaped pipes (\\|).

    The input looks like:
      | `AES-[128\\|192\\|256]-GCM` | 128-256 bit | ... |

    We replace \\| with a placeholder, split on |, then restore.
    """
    placeholder = "\x00PIPE\x00"
    protected = line.replace("\\|", placeholder)
    parts = protected.split("|")
    # Restore and strip
    cells = [p.replace(placeholder, "\\|").strip() for p in parts]
    # Remove empty first and last (from leading/trailing |)
    if cells and cells[0] == "":
        cells = cells[1:]
    if cells and cells[-1] == "":
        cells = cells[:-1]
    return cells


# ---------------------------------------------------------------------------
# Status mapping: markdown symbol -> normalised status
# ---------------------------------------------------------------------------

def normalise_md_status(text: str) -> dict:
    """Parse a markdown status cell into a normalised dict with keys:
       status, qualifier, until, raw
    """
    text = text.strip()
    result = {"raw": text, "status": None, "qualifier": None, "until": None}

    if not text or text == "—" or text.startswith("—"):
        result["status"] = "not_addressed"
        return result

    # Mandatory
    if "Mandatory" in text and "✅" in text:
        result["status"] = "mandatory"
    # Recommended
    elif text.startswith("✅ Recommended"):
        result["status"] = "recommended"
    # Until (transitional)
    elif text.startswith("✅ Until") or text.startswith("🔜 Until"):
        result["status"] = "transitional"
        m = re.search(r'Until\s+(\d{4})', text)
        if m:
            result["until"] = m.group(1)
    # Approved
    elif text.startswith("✓ Approved") or text.startswith("✓ AES-256"):
        result["status"] = "approved"
        if "AES-256" in text:
            result["qualifier"] = "AES-256 only"
    # ML-DSA-87 only
    elif text.startswith("✓ ML-DSA-87"):
        result["status"] = "approved"
        result["qualifier"] = "ML-DSA-87 only"
    # Conditional
    elif text.startswith("⚠ Conditional") or text.startswith("⚠ AES-256"):
        result["status"] = "conditional"
        if "AES-256" in text:
            result["qualifier"] = "AES-256 only"
    # Transitional
    elif "🔜" in text:
        result["status"] = "transitional"
    # Deprecated (various forms)
    elif "❌" in text:
        result["status"] = "deprecated"
    # Disallowed / Not recommended / Not in CNSA
    elif "🚫" in text:
        result["status"] = "disallowed"
    # "Not yet evaluated"
    elif "Not yet evaluated" in text:
        result["status"] = "not_addressed"
    else:
        result["status"] = "unknown"
        result["qualifier"] = text

    return result


# ---------------------------------------------------------------------------
# Parse markdown tables
# ---------------------------------------------------------------------------

def parse_md_tables(md_path: Path) -> list[dict]:
    """Parse all tables from the markdown file.
    Returns a list of dicts, each with:
      section, subsection, pattern, nist_raw, bsi_raw, cnsa_raw (where present)
    """
    content = md_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    rows = []
    current_section = ""
    current_subsection = ""
    header_cols = []
    in_table = False

    for line in lines:
        # Track sections
        sec_match = re.match(r'^##\s+(\d+)\.\s+(.*)', line)
        if sec_match:
            current_section = f"{sec_match.group(1)}. {sec_match.group(2)}"
            current_subsection = ""
            in_table = False
            continue

        subsec_match = re.match(r'^###\s+(\d+\.\d+)\s+(.*)', line)
        if subsec_match:
            current_subsection = f"{subsec_match.group(1)} {subsec_match.group(2)}"
            in_table = False
            continue

        # Also track #### sub-subsections
        sub4_match = re.match(r'^####\s+(.*)', line)
        if sub4_match:
            current_subsection = sub4_match.group(1).strip()
            in_table = False
            continue

        # Skip non-algorithm sections (Notation, Status Legend, Comparing Authorities)
        if current_section and not re.match(r'\d+\.', current_section):
            continue

        # Detect table header: must be a row where the FIRST cell (after |)
        # contains a known column name (not just a substring match in any cell).
        if line.startswith("|") and not in_table:
            candidate_cells = split_md_row(line)
            first_cell = candidate_cells[0].strip("*").strip() if candidate_cells else ""
            if first_cell in (
                "Pattern", "Algorithm", "Curve", "Curve family", "Version",
                "Class", "Group", "Scheme", "Hash function", "Security strength (bits)",
                "Security strength", "Key type", "Algorithm family",
            ):
                header_cols = candidate_cells
                in_table = True
                continue

        # Skip separator line (|:---|:---|...)
        if line.startswith("|") and re.match(r'^\|[\s:|-]+\|$', line):
            continue

        # Parse data row
        if in_table and line.startswith("|"):
            cells = split_md_row(line)

            if len(cells) < 2:
                continue

            # Build column map
            col_map = {}
            for j, hdr in enumerate(header_cols):
                if j < len(cells):
                    col_map[hdr] = cells[j]

            pattern = col_map.get("Pattern", col_map.get("Algorithm",
                      col_map.get("Curve", col_map.get("Version",
                      col_map.get("Group", col_map.get("Scheme", ""))))))
            # Clean pattern: remove backticks
            pattern = pattern.replace("`", "").strip()

            if not pattern:
                continue

            row = {
                "section": current_section,
                "subsection": current_subsection,
                "pattern": pattern,
                "nist_raw": col_map.get("NIST", ""),
                "bsi_raw": col_map.get("BSI", ""),
                "cnsa_raw": col_map.get("CNSA", ""),
            }
            rows.append(row)
        elif in_table and not line.startswith("|") and not line.startswith(">"):
            # Blank line or non-table line ends the table (but not blockquotes)
            if line.strip() == "" or line.startswith("#"):
                pass  # table might continue after blank line (between notes)
            else:
                in_table = False

    return rows


# ---------------------------------------------------------------------------
# Load YAML registry
# ---------------------------------------------------------------------------

def load_yaml_entries(registry_dir: Path) -> dict:
    """Load all cr-*.yaml files (excluding protocol registries).
    Returns dict keyed by entry id -> entry data.
    """
    entries = {}
    for p in sorted(registry_dir.glob("cr-*.yaml")):
        stem = p.stem
        if stem in YAML_PREFIXES_EXCLUDE:
            continue
        with open(p) as f:
            doc = yaml.safe_load(f)
        if not doc:
            continue
        for entry in doc.get("entries", []):
            eid = entry.get("id", "")
            if eid:
                entries[eid] = entry
                entries[eid]["_source_file"] = p.name
    return entries


def get_yaml_authority_status(entry: dict, authority: str) -> dict:
    """Extract authority status from a YAML entry at the top level.
    Returns dict with: status, source, until, note
    """
    result = {"status": None, "source": None, "until": None, "note": None}
    auths = entry.get("authorities", {})
    if auths and authority in auths:
        auth_data = auths[authority]
        result["status"] = auth_data.get("status")
        result["source"] = auth_data.get("source")
        result["until"] = str(auth_data.get("until", "")) if auth_data.get("until") else None
        result["note"] = auth_data.get("note")
    return result


def get_yaml_param_status(entry: dict, authority: str, param_value: str,
                          param_name: str = None) -> dict:
    """Extract authority status from a specific parameter value.
    Searches parameters and implicitParameters for the given value.
    Returns dict with: status, source, until, note (or all-None if not found).
    """
    result = {"status": None, "source": None, "until": None, "note": None}

    # Search parameters
    for param in entry.get("parameters", []):
        if param_name and param.get("name") != param_name:
            continue
        for val in param.get("values", []):
            if val.get("value") == param_value:
                auths = val.get("authorities", {})
                if authority in auths:
                    auth_data = auths[authority]
                    result["status"] = auth_data.get("status")
                    result["source"] = auth_data.get("source")
                    result["until"] = str(auth_data.get("until", "")) if auth_data.get("until") else None
                    result["note"] = auth_data.get("note")
                    return result

    # Search implicitParameters
    for param in entry.get("implicitParameters", []):
        if param.get("value") == param_value:
            auths = param.get("authorities", {})
            if authority in auths:
                auth_data = auths[authority]
                result["status"] = auth_data.get("status")
                result["source"] = auth_data.get("source")
                return result

    return result


# ---------------------------------------------------------------------------
# Pattern-to-YAML matching
# ---------------------------------------------------------------------------

# Static mapping: markdown pattern -> (yaml_id, optional context for parameter lookup)
PATTERN_MAP = {
    # Section 1: Symmetric
    "AES-256-*": ("AES", {"keyLength": "256"}),
    "AES-[128\\|192]-*": ("AES", {"keyLength": "128"}),
    "CAMELLIA-[128\\|256]-*": ("Camellia", None),
    "3DES-*": ("3DES", None),
    "DES-*": ("DES", None),
    "RC2-*": ("RC2", None),
    "RC4-*": ("RC4", None),
    "IDEA-*": ("IDEA", None),
    "Blowfish-*": ("Blowfish", None),
    # Modes
    "AES-[128\\|192\\|256]-GCM": ("AES", {"mode": "GCM"}),
    "AES-[128\\|192\\|256]-CCM": ("AES", {"mode": "CCM"}),
    "AES-[128\\|192\\|256]-GCM-SIV": ("AES", {"mode": "GCM-SIV"}),
    "AES-[128\\|192\\|256]-CTR": ("AES", {"mode": "CTR"}),
    "AES-[128\\|192\\|256]-CBC": ("AES", {"mode": "CBC"}),
    "AES-[128\\|192\\|256]-CFB[128]": ("AES", {"mode": "CFB128"}),
    "AES-[128\\|192\\|256]-OFB": ("AES", {"mode": "OFB"}),
    "AES-[128\\|192\\|256]-XTS": ("AES", {"mode": "XTS"}),
    "AES-[128\\|192\\|256]-ECB": ("AES", {"mode": "ECB"}),
    "AES-KW-[128\\|192\\|256]": ("AES-KW", None),
    "ChaCha20-Poly1305": ("ChaCha20", {"mode": "Poly1305"}),
    # Tag length
    "AES-*-GCM[-128]": ("AES", {"mode": "GCM"}),
    "AES-*-GCM-96": ("AES", {"mode": "GCM"}),
    "AES-*-GCM-[32\\|64]": ("AES", {"mode": "GCM"}),
    # Section 2: Hash
    "SHA-384": ("SHA", {"variant": "384"}),
    "SHA-512": ("SHA", {"variant": "512"}),
    "SHA-256": ("SHA", {"variant": "256"}),
    "SHA-512/256": ("SHA", {"variant": "512-256"}),
    "SHA3-[256\\|384\\|512]": ("SHA3", {"outputLength": "256"}),
    "SHAKE128": ("SHAKE128", None),
    "SHAKE256": ("SHAKE256", None),
    "BLAKE2b-[256\\|384\\|512]": ("BLAKE2b", None),
    "BLAKE3": ("BLAKE3", None),
    "SHA-224": ("SHA", {"variant": "224"}),
    "SHA-1": ("SHA", {"variant": "1"}),
    "MD5": ("MD5", None),
    "MD4": ("MD4", None),
    # Section 3: MACs
    "HMAC-[SHA-384\\|SHA-512]": ("HMAC", {"hashAlgorithm": "SHA-384"}),
    "HMAC-SHA-256": ("HMAC", {"hashAlgorithm": "SHA-256"}),
    "HMAC-[SHA3-256\\|SHA3-384\\|SHA3-512]": ("HMAC", {"hashAlgorithm": "SHA3-256"}),
    "HMAC-SHA-256[-128]": ("HMAC", {"hashAlgorithm": "SHA-256"}),
    "AES-[128\\|192\\|256]-CMAC": ("AES-CMAC", None),
    "KMAC128": ("KMAC128", None),
    "KMAC256": ("KMAC256", None),
    "Poly1305": ("Poly1305", None),
    "HMAC-SHA-1": ("HMAC", {"hashAlgorithm": "SHA-1"}),
    "HMAC-MD5": ("HMAC", {"hashAlgorithm": "MD5"}),
    "CBC-MAC-*": ("CBC-MAC", None),
    "AES-*-GMAC": ("GMAC", None),
    # Section 4: Key Encapsulation
    "RSAES-OAEP-[3072\\|4096]-SHA-384-MGF1": ("RSAES-OAEP", {"keyLength": "3072"}),
    "RSAES-OAEP-[3072\\|4096]-[SHA-256\\|SHA-512]-MGF1": ("RSAES-OAEP", {"keyLength": "3072"}),
    "RSAES-OAEP-2048-*": ("RSAES-OAEP", {"keyLength": "2048"}),
    "RSAES-PKCS1-[2048\\|3072\\|4096]": ("RSAES-PKCS1", None),
    "ECIES-[P-256\\|P-384\\|P-521]-*": ("ECIES", None),
    # ML-KEM
    "ML-KEM-512": ("ML-KEM", {"parameterSet": "512"}),
    "ML-KEM-768": ("ML-KEM", {"parameterSet": "768"}),
    "ML-KEM-1024": ("ML-KEM", {"parameterSet": "1024"}),
    # Section 5: Key Agreement
    "ECDH-P-384": ("ECDH", {"ellipticCurve": "P-384"}),
    "ECDH-[P-256\\|P-521]": ("ECDH", {"ellipticCurve": "P-256"}),
    "ECDH-[brainpoolP256r1\\|brainpoolP384r1\\|brainpoolP512r1]": ("ECDH", {"ellipticCurve": "brainpoolP256r1"}),
    "ECDH-[Curve25519\\|X25519]": ("ECDH", {"ellipticCurve": "Curve25519"}),
    "ECDH-[Curve448\\|X448]": ("ECDH", {"ellipticCurve": "Curve448"}),
    "FFDH-[ffdhe3072\\|ffdhe4096\\|ffdhe6144\\|ffdhe8192]": ("FFDH", {"group": "ffdhe3072"}),
    "FFDH-ffdhe2048": ("FFDH", {"group": "ffdhe2048"}),
    "FFDH-[1024\\|1536]": ("FFDH", None),
    "ECDH-secp256k1": ("ECDH", None),
    # Section 6: Signatures
    "ECDSA-P-384-SHA-384": ("ECDSA", {"ellipticCurve": "P-384", "hashAlgorithm": "SHA-384"}),
    "ECDSA-[P-256\\|P-521]-[SHA-256\\|SHA-384\\|SHA-512]": ("ECDSA", {"ellipticCurve": "P-256"}),
    "ECDSA-P-384-[SHA-256\\|SHA-512]": ("ECDSA", {"ellipticCurve": "P-384"}),
    "ECDSA-[brainpoolP256r1\\|brainpoolP384r1\\|brainpoolP512r1]-*": ("ECDSA", {"ellipticCurve": "brainpoolP256r1"}),
    "EdDSA-[Ed25519\\|Ed448]": ("EdDSA", None),
    "RSASSA-PSS-[3072\\|4096\\|7680\\|15360]-SHA-384-*": ("RSASSA-PSS", {"keyLength": "3072"}),
    "RSASSA-PSS-[3072\\|4096\\|7680\\|15360]-[SHA-256\\|SHA-512]-*": ("RSASSA-PSS", {"keyLength": "3072"}),
    "RSASSA-PSS-2048-[SHA-256\\|SHA-384\\|SHA-512]-*": ("RSASSA-PSS", {"keyLength": "2048"}),
    "RSASSA-PKCS1-[3072\\|4096]-[SHA-256\\|SHA-384\\|SHA-512]": ("RSASSA-PKCS1", {"keyLength": "3072"}),
    "RSASSA-PKCS1-2048-*": ("RSASSA-PKCS1", {"keyLength": "2048"}),
    "DSA-[2048\\|3072]-[SHA-256\\|SHA-384\\|SHA-512]": ("DSA", {"keyLength": "2048"}),
    "ECDSA-[P-192\\|secp192r1]": ("ECDSA", {"ellipticCurve": "P-192"}),
    "DSA-1024-*": ("DSA", {"keyLength": "1024"}),
    "RSASSA-*-1024-*": ("RSASSA-PKCS1", {"keyLength": "1024"}),
    # ML-DSA
    "ML-DSA-44": ("ML-DSA", {"parameterSet": "44"}),
    "ML-DSA-65": ("ML-DSA", {"parameterSet": "65"}),
    "ML-DSA-87": ("ML-DSA", {"parameterSet": "87"}),
    "ML-DSA-[44\\|65\\|87]-(deterministic)": ("ML-DSA", {"signingMode": "deterministic"}),
    "ML-DSA-[44\\|65\\|87]-(hedged)": ("ML-DSA", {"signingMode": "hedged"}),
    # SLH-DSA
    "SLH-DSA-SHA2-128s": ("SLH-DSA", {"parameterSet": "128s"}),
    "SLH-DSA-SHA2-128f": ("SLH-DSA", {"parameterSet": "128f"}),
    "SLH-DSA-SHA2-[192s\\|192f]": ("SLH-DSA", {"parameterSet": "192s"}),
    "SLH-DSA-SHA2-[256s\\|256f]": ("SLH-DSA", {"parameterSet": "256s"}),
    "SLH-DSA-SHAKE-[128s\\|128f\\|192s\\|192f\\|256s\\|256f]": ("SLH-DSA", {"hashFamily": "SHAKE"}),
    # FN-DSA
    "FN-DSA-512": ("FN-DSA", {"parameterSet": "512"}),
    "FN-DSA-1024": ("FN-DSA", {"parameterSet": "1024"}),
    # Section 7: Stateful signatures
    "LMS_SHA256_M32_H{5\\|10\\|15\\|20\\|25}": ("LMS", None),
    "LMS_SHA256_M24_H{5\\|10\\|15\\|20\\|25}": ("LMS", None),
    "LMS_SHAKE_M32_H{5\\|10\\|15\\|20\\|25}": ("LMS", None),
    "LMS_SHAKE_M24_H{5\\|10\\|15\\|20\\|25}": ("LMS", None),
    "HSS-*": ("LMS", None),
    "XMSS-SHA2_[10\\|16\\|20]_[256\\|512]": ("XMSS", None),
    "XMSS-SHAKE_[10\\|16\\|20]_[256\\|512]": ("XMSS", None),
    "XMSS-SHA2_[10\\|16\\|20]_192": ("XMSS", None),
    "XMSS-SHAKE256_[10\\|16\\|20]_192": ("XMSS", None),
    "XMSSMT-*": ("XMSSMT", None),
    # Section 8: KDFs
    "HKDF-[SHA-256\\|SHA-384\\|SHA-512]": ("HKDF", None),
    "SP800-108-[HMAC-SHA256\\|HMAC-SHA384\\|HMAC-SHA512\\|AES-CMAC]": ("SP800-108", None),
    "SP800-56C-*": ("SP800-56C", None),
    "TLS13-PRF-[SHA-256\\|SHA-384]": ("TLS13-HKDF", None),
    "TLS12-PRF-SHA-256": ("TLS12-PRF", None),
    "ANSI-KDF-[X9.42\\|X9.63]-[SHA-256\\|SHA-384\\|SHA-512]": ("ANSI-KDF-X9.42", None),
    "TLS10-PRF-*": (None, None),
    "SSL30-PRF-*": (None, None),
    # Section 9: Password
    "Argon2id-*-[19456\\|65536\\|262144\\|1048576]-[2\\|3]-1": ("Argon2id", None),
    "scrypt-[32768\\|65536\\|1048576]-8-1-*": ("scrypt", None),
    "bcrypt-[12\\|13\\|14]-*": ("bcrypt", None),
    "PBKDF2-HMAC-[SHA-256\\|SHA-384\\|SHA-512]-[600000\\|1000000]-*-[32\\|48\\|64]": ("PBKDF2", None),
    "PBKDF2-HMAC-SHA-1-*": ("PBKDF2", {"hashAlgorithm": "SHA-1"}),
    "PBKDF1-*": ("PBKDF1", None),
    # Section 10: RNGs
    "HMAC_DRBG-[SHA-256\\|SHA-384\\|SHA-512]": ("HMAC_DRBG", None),
    "Hash_DRBG-[SHA-256\\|SHA-384\\|SHA-512]": ("Hash_DRBG", None),
    "CTR_DRBG-[AES-128\\|AES-192\\|AES-256]": ("CTR_DRBG", None),
    "CTR_DRBG-AES-256": ("CTR_DRBG", None),
    "CTR_DRBG-AES-[128\\|192\\|256]-noDF": ("CTR_DRBG", {"option": "noDF"}),
    "Hash_DRBG-[SHA-1\\|SHA-224]": ("Hash_DRBG", {"hashAlgorithm": "SHA-1"}),
    "CTR_DRBG-3DES": ("CTR_DRBG", {"cipher": "3DES"}),
    "Dual_EC_DRBG": ("Dual_EC_DRBG", None),
    "Fortuna-AES-256-SHA-256": ("Fortuna", None),
    "Fortuna-*": ("Fortuna", None),
    "Yarrow-*": ("Yarrow", None),
}


def match_pattern_to_yaml(pattern: str, yaml_entries: dict) -> tuple:
    """Try to find the best matching YAML entry for a markdown pattern.
    Returns (yaml_id, yaml_entry, param_context) or (None, None, None).
    """
    # Try exact pattern map first
    if pattern in PATTERN_MAP:
        yaml_id, ctx = PATTERN_MAP[pattern]
        if yaml_id and yaml_id in yaml_entries:
            return yaml_id, yaml_entries[yaml_id], ctx
        if yaml_id is None:
            return None, None, None

    # Fallback: extract base algorithm name
    p = pattern.strip()

    # Multi-segment prefixes
    multi_prefixes = [
        ("RSAES-OAEP", "RSAES-OAEP"), ("RSAES-PKCS1", "RSAES-PKCS1"),
        ("RSASSA-PSS", "RSASSA-PSS"), ("RSASSA-PKCS1", "RSASSA-PKCS1"),
        ("ML-KEM-", "ML-KEM"), ("ML-DSA-", "ML-DSA"),
        ("SLH-DSA-", "SLH-DSA"), ("FN-DSA-", "FN-DSA"),
        ("AES-KW", "AES-KW"), ("AES-CMAC", "AES-CMAC"),
        ("ChaCha20-Poly1305", "ChaCha20"),
        ("HMAC-", "HMAC"),
        ("ECDH-", "ECDH"), ("ECDSA-", "ECDSA"), ("EdDSA-", "EdDSA"),
        ("ECIES-", "ECIES"), ("FFDH-", "FFDH"), ("DSA-", "DSA"),
        ("Hash_DRBG", "Hash_DRBG"), ("HMAC_DRBG", "HMAC_DRBG"),
        ("CTR_DRBG", "CTR_DRBG"), ("Dual_EC_DRBG", "Dual_EC_DRBG"),
        ("HKDF-", "HKDF"), ("SP800-108", "SP800-108"), ("SP800-56C", "SP800-56C"),
        ("LMS_", "LMS"), ("HSS-", "LMS"), ("XMSS-", "XMSS"), ("XMSSMT-", "XMSSMT"),
        ("Fortuna-", "Fortuna"), ("Yarrow-", "Yarrow"),
        ("BLAKE2b", "BLAKE2b"), ("BLAKE3", "BLAKE3"),
        ("SHA3-", "SHA3"), ("SHA-", "SHA"),
        ("SHAKE128", "SHAKE128"), ("SHAKE256", "SHAKE256"),
        ("AES-", "AES"),
        ("Argon2id", "Argon2id"), ("PBKDF2", "PBKDF2"), ("PBKDF1", "PBKDF1"),
        ("scrypt", "scrypt"), ("bcrypt", "bcrypt"),
    ]

    for prefix, yaml_id in multi_prefixes:
        if p.startswith(prefix):
            if yaml_id in yaml_entries:
                return yaml_id, yaml_entries[yaml_id], None

    # Try direct/case-insensitive
    if p in yaml_entries:
        return p, yaml_entries[p], None
    for eid in yaml_entries:
        if eid.lower() == p.lower():
            return eid, yaml_entries[eid], None

    return None, None, None


# ---------------------------------------------------------------------------
# Get effective YAML status (entry-level + parameter-level)
# ---------------------------------------------------------------------------

def get_effective_yaml_status(entry: dict, authority: str, param_ctx: dict = None) -> dict:
    """Get the effective status for an authority, considering both entry-level
    and parameter-level authorities.

    If param_ctx is provided (e.g. {"mode": "ECB"}), look up the parameter
    value's authority status. If the parameter value has a MORE RESTRICTIVE
    status than the entry level, use the parameter status. Otherwise keep the
    entry-level status. This ensures AES entry=recommended + mode=ECB=disallowed
    resolves to disallowed.
    """
    # Start with entry-level
    entry_auth = get_yaml_authority_status(entry, authority)

    if not param_ctx:
        return entry_auth

    # Check each parameter value; take the most restrictive
    effective = dict(entry_auth)
    for param_name, param_value in param_ctx.items():
        param_auth = get_yaml_param_status(entry, authority, param_value, param_name)
        if param_auth["status"] is not None:
            if effective["status"] is None:
                effective = dict(param_auth)
            else:
                # Use the more restrictive of entry vs param
                combined = _more_restrictive(effective["status"], param_auth["status"])
                if combined == param_auth["status"]:
                    # Parameter is more restrictive — use its full record
                    effective = dict(param_auth)

    return effective


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------

def compare_status(md_normalised: dict, yaml_auth: dict, authority: str) -> tuple:
    """Compare normalised markdown status with YAML authority data.
    Returns (match: bool, detail: str)
    """
    md_status = md_normalised["status"]
    yaml_status = yaml_auth.get("status")
    yaml_note = yaml_auth.get("note")
    yaml_until = yaml_auth.get("until")

    # If markdown says not_addressed
    if md_status == "not_addressed":
        if yaml_status is None:
            return True, "both not addressed"
        else:
            return False, f"md=not_addressed yaml={yaml_status}"

    # If YAML has no status
    if yaml_status is None:
        if yaml_note:
            if md_status == "not_addressed":
                return True, "note-only, not addressed"
            elif md_status == "disallowed" and ("Not in CNSA" in (yaml_note or "") or "Not" in (yaml_note or "")):
                return True, "note-only disallowed/not-in-CNSA"
            elif md_status == "deprecated" and "Not" in (yaml_note or ""):
                return True, "note-only deprecated/not-listed"
            elif md_status == "approved" and ("recommended" in (yaml_note or "").lower() or "approved" in (yaml_note or "").lower()):
                return True, "note-only approved"
            else:
                return False, f"md={md_status} yaml=note-only({yaml_note})"
        else:
            return False, f"md={md_status} yaml=absent"

    # Map YAML statuses
    yaml_norm = yaml_status

    # Direct comparisons
    if md_status == yaml_norm:
        return True, f"match ({md_status})"

    # broken is a sub-category of disallowed
    if md_status == "disallowed" and yaml_norm == "broken":
        return True, "disallowed~broken"

    # approved vs mandatory (mandatory is stricter positive)
    if md_status == "approved" and yaml_norm == "mandatory":
        return True, "approved~mandatory"
    if md_status == "recommended" and yaml_norm == "mandatory":
        return True, "recommended~mandatory"

    # Transitional with until
    if md_status == "transitional" and yaml_norm == "transitional":
        return True, "match (transitional)"
    if md_status == "transitional" and yaml_norm == "approved" and yaml_until:
        return True, f"transitional~approved-until-{yaml_until}"
    if md_status == "transitional" and yaml_norm == "approved":
        return False, f"md=transitional yaml=approved (no until)"

    # Conditional
    if md_status == "conditional" and yaml_norm == "conditional":
        return True, "match (conditional)"
    if md_status == "conditional" and yaml_norm == "approved":
        return True, "conditional~approved"

    # deprecated vs disallowed (genuine semantic gap)
    if md_status == "deprecated" and yaml_norm == "disallowed":
        return False, f"md=deprecated yaml=disallowed"
    if md_status == "deprecated" and yaml_norm == "deprecated":
        return True, "match (deprecated)"

    # disallowed in MD vs deprecated in YAML
    if md_status == "disallowed" and yaml_norm == "deprecated":
        return False, f"md=disallowed yaml=deprecated"

    return False, f"md={md_status} yaml={yaml_norm}"


# ---------------------------------------------------------------------------
# Status restrictiveness ordering (for parameter-combination resolution)
# ---------------------------------------------------------------------------

# Lower number = more permissive, higher = more restrictive
_RESTRICTIVENESS = {
    "mandatory": 0,
    "recommended": 1,
    "approved": 2,
    "conditional": 3,
    "transitional": 4,
    "deprecated": 5,
    "disallowed": 6,
    "broken": 7,
}


def _more_restrictive(status_a: str | None, status_b: str | None) -> str | None:
    """Return whichever status is MORE restrictive (higher rank).
    None means 'no data' and is treated as transparent (the other wins).
    """
    if status_a is None:
        return status_b
    if status_b is None:
        return status_a
    ra = _RESTRICTIVENESS.get(status_a, 99)
    rb = _RESTRICTIVENESS.get(status_b, 99)
    return status_a if ra >= rb else status_b


def _less_restrictive(status_a: str | None, status_b: str | None) -> str | None:
    """Return whichever status is LESS restrictive (lower rank).
    None means 'no data' and is treated as transparent (the other wins).
    """
    if status_a is None:
        return status_b
    if status_b is None:
        return status_a
    ra = _RESTRICTIVENESS.get(status_a, 99)
    rb = _RESTRICTIVENESS.get(status_b, 99)
    return status_a if ra <= rb else status_b


# ---------------------------------------------------------------------------
# Format a YAML authority dict into a markdown cell string
# ---------------------------------------------------------------------------

def format_authority_cell(auth_data: dict) -> str:
    """Render a YAML authority record as a human-readable markdown cell.

    auth_data has keys: status, source, until, note  (any may be None).
    Returns a string such as '✅ Recommended' or '🚫 Not in CNSA'.
    """
    if auth_data is None:
        return "—"

    status = auth_data.get("status")
    note = auth_data.get("note") or ""
    source = auth_data.get("source") or ""
    until = auth_data.get("until")

    # No explicit status — use the note if informative
    if status is None:
        if note:
            return f"— {note}"
        return "—"

    symbols = {
        "mandatory": "✅",
        "approved": "✓",
        "recommended": "✅",
        "conditional": "⚠",
        "transitional": "🔜",
        "deprecated": "❌",
        "disallowed": "🚫",
        "broken": "🚫",
    }
    labels = {
        "mandatory": "Mandatory",
        "approved": "Approved",
        "recommended": "Recommended",
        "conditional": "Conditional",
        "transitional": "Transitional",
        "deprecated": "Deprecated",
        "disallowed": "Disallowed",
        "broken": "Broken",
    }

    sym = symbols.get(status, "?")
    label = labels.get(status, status)

    parts = [sym]

    if status == "transitional" and until:
        parts.append(f"Until {until}")
    else:
        parts.append(label)

    # Add source reference for BSI (compact form)
    if source:
        parts.append(f"({source})")
    # Add note only if no source (avoid double qualifier)
    elif note:
        parts.append(f"({note})")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Resolve effective authority status for a pattern (entry + params)
# ---------------------------------------------------------------------------

def resolve_authority_for_pattern(
    pattern: str, yaml_entries: dict, authority: str
) -> dict:
    """Resolve the effective authority status for *pattern* against the YAML
    registry for a single *authority* ('nist', 'bsi', or 'cnsa').

    Returns a dict with keys: status, source, until, note  (all may be None).
    """
    yaml_id, yaml_entry, param_ctx = match_pattern_to_yaml(pattern, yaml_entries)

    if yaml_entry is None:
        return {"status": None, "source": None, "until": None, "note": None}

    return get_effective_yaml_status(yaml_entry, authority, param_ctx)


# ---------------------------------------------------------------------------
# Generate / patch mode
# ---------------------------------------------------------------------------

def _is_in_patchable_section(current_section_num: int | None) -> bool:
    """Sections 1 through 10 are patchable; 11+ are not."""
    if current_section_num is None:
        return False
    return 1 <= current_section_num <= 10


def run_generate(md_path: Path, yaml_entries: dict) -> str:
    """Read the existing markdown, patch authority cells in §1-§10 tables from
    YAML data, and return the full patched markdown as a string.
    """
    content = md_path.read_text(encoding="utf-8")
    lines = content.split("\n")

    out_lines: list[str] = []
    current_section_num: int | None = None
    header_cols: list[str] = []
    in_table = False
    after_separator = False  # True once we have seen the |---| line

    # Column indices for the authority columns we want to patch
    nist_col: int | None = None
    bsi_col: int | None = None
    cnsa_col: int | None = None

    for line in lines:
        # Detect ## section headers and extract the section number
        sec_match = re.match(r'^##\s+(\d+)\.\s+', line)
        if sec_match:
            current_section_num = int(sec_match.group(1))
            in_table = False
            after_separator = False

        # Detect ### / #### subsection headers (reset table state)
        if re.match(r'^###\s+', line) or re.match(r'^####\s+', line):
            in_table = False
            after_separator = False

        # Are we in a section that should be patched?
        patchable = _is_in_patchable_section(current_section_num)

        # Detect table header row
        if patchable and line.startswith("|") and not in_table:
            candidate_cells = split_md_row(line)
            first_cell = candidate_cells[0].strip("*").strip() if candidate_cells else ""
            if first_cell in (
                "Pattern", "Algorithm", "Curve", "Curve family", "Version",
                "Class", "Group", "Scheme", "Hash function",
                "Security strength (bits)", "Security strength",
                "Key type", "Algorithm family",
            ):
                header_cols = candidate_cells
                in_table = True
                after_separator = False

                # Find authority column indices
                nist_col = None
                bsi_col = None
                cnsa_col = None
                for j, hdr in enumerate(header_cols):
                    h = hdr.strip("*").strip()
                    if h == "NIST":
                        nist_col = j
                    elif h == "BSI":
                        bsi_col = j
                    elif h == "CNSA":
                        cnsa_col = j

                # If we found no authority column at all, this table is not
                # patchable (e.g. the curves taxonomy tables).
                if nist_col is None and bsi_col is None and cnsa_col is None:
                    in_table = False

                out_lines.append(line)
                continue

        # Detect separator line (must come right after header)
        if in_table and line.startswith("|") and re.match(r'^\|[\s:|-]+\|$', line):
            after_separator = True
            out_lines.append(line)
            continue

        # Process data rows
        if in_table and after_separator and line.startswith("|"):
            cells = split_md_row(line)
            if len(cells) < 2:
                out_lines.append(line)
                continue

            # Build column map to find the pattern
            col_map = {}
            for j, hdr in enumerate(header_cols):
                if j < len(cells):
                    col_map[hdr] = cells[j]

            # Extract the pattern text
            pattern = col_map.get("Pattern", col_map.get("Algorithm",
                      col_map.get("Curve", col_map.get("Version",
                      col_map.get("Group", col_map.get("Scheme", ""))))))
            pattern = pattern.replace("`", "").strip()

            if not pattern:
                out_lines.append(line)
                continue

            # Resolve authority statuses from YAML
            yaml_nist = resolve_authority_for_pattern(pattern, yaml_entries, "nist")
            yaml_bsi = resolve_authority_for_pattern(pattern, yaml_entries, "bsi")
            yaml_cnsa = resolve_authority_for_pattern(pattern, yaml_entries, "cnsa")

            # Only patch if the pattern was found in the YAML
            yaml_id, yaml_entry, _ = match_pattern_to_yaml(pattern, yaml_entries)
            if yaml_entry is None:
                out_lines.append(line)
                continue

            # Build new cells list (copy of original, then patch authority cols)
            new_cells = list(cells)
            if nist_col is not None and nist_col < len(new_cells):
                new_cells[nist_col] = format_authority_cell(yaml_nist)
            if bsi_col is not None and bsi_col < len(new_cells):
                new_cells[bsi_col] = format_authority_cell(yaml_bsi)
            if cnsa_col is not None and cnsa_col < len(new_cells):
                new_cells[cnsa_col] = format_authority_cell(yaml_cnsa)

            # Reconstruct the markdown row, keeping escaped pipes in cells
            new_line = "| " + " | ".join(new_cells) + " |"
            out_lines.append(new_line)
            continue

        # End-of-table detection
        if in_table and not line.startswith("|") and not line.startswith(">"):
            if line.strip() == "" or line.startswith("#"):
                pass  # table might continue after blank line
            else:
                in_table = False
                after_separator = False

        out_lines.append(line)

    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Main check logic
# ---------------------------------------------------------------------------

def run_check():
    """Main cross-check between markdown and YAML."""
    print(f"Base directory: {BASE_DIR}")
    print(f"Registry dir:  {REGISTRY_DIR}")
    print(f"Markdown file: {MD_FILE}")
    print()

    if not MD_FILE.exists():
        print(f"ERROR: Markdown file not found: {MD_FILE}")
        return 1
    if not REGISTRY_DIR.exists():
        print(f"ERROR: Registry directory not found: {REGISTRY_DIR}")
        return 1

    # Load data
    md_rows = parse_md_tables(MD_FILE)
    yaml_entries = load_yaml_entries(REGISTRY_DIR)

    print(f"Parsed {len(md_rows)} rows from markdown tables")
    print(f"Loaded {len(yaml_entries)} entries from YAML registry")
    print()

    # Sections covered
    sections = OrderedDict()
    for row in md_rows:
        sec = row["section"]
        if sec not in sections:
            sections[sec] = 0
        sections[sec] += 1

    print("Markdown sections found:")
    for sec, count in sections.items():
        print(f"  {sec}: {count} rows")
    print()

    # Cross-check
    matches = 0
    mismatches = 0
    not_found_in_yaml = []
    checked_yaml_ids = set()
    discrepancies = []

    # Sections/subsections to skip (reference tables, not per-algorithm status)
    skip_sections = {
        "11. PQC Candidates and non-standardised Algorithms",
        "12. TLS / Protocol Quick-Reference",
        "13. Deprecated and disallowed consolidated Reference",
        "14. Security Strength Equivalence (SP 800-57 Part 1 Rev 5)",
    }

    skip_subsections = {
        "5.1 Approved elliptic Curves (SP 800-186)",
        "5.2 Key Establishment Scheme Taxonomy (SP 800-56A Rev.3)",
        "10.3 OS-provided Entropy APIs",
        "10.4 Hardware RNG Interfaces",
        "10.5 BSI AIS 20/31 Functionality Classes",
        "10.6 Non-cryptographic PRNGs (always disallowed for security use)",
        # Sub-subsection headers
        "Weierstrass prime Curves (FIPS 186-5 primary curves)",
        "Montgomery Curves (SP 800-186 §2.3)",
        "Twisted Edwards Curves (SP 800-186 §2.4)",
        "Binary Curves (SP 800-186, Appendix G; all deprecated)",
        "Additional Curves (SP 800-186, Appendix H)",
        "Approved FFC (MODP) Groups for IKE (SP 800-56A Rev.3, Table 25)",
        "Approved FFC named Groups for TLS (SP 800-56A Rev.3, Table 26 / RFC 7919)",
        "Key Encapsulation",
        "Broken Algorithms (do not use)",
    }

    for row in md_rows:
        pattern = row["pattern"]
        section = row["section"]
        subsection = row.get("subsection", "")

        # Skip reference-only sections
        if section in skip_sections:
            continue
        if subsection in skip_subsections:
            continue

        # Skip rows that lack all three authority columns
        if not row.get("nist_raw") and not row.get("bsi_raw") and not row.get("cnsa_raw"):
            continue

        # Try to match to YAML
        yaml_id, yaml_entry, param_ctx = match_pattern_to_yaml(pattern, yaml_entries)

        if yaml_entry is None:
            not_found_in_yaml.append((pattern, section, subsection))
            continue

        checked_yaml_ids.add(yaml_id)

        # Get YAML authority data (entry + param level)
        yaml_nist = get_effective_yaml_status(yaml_entry, "nist", param_ctx)
        yaml_bsi = get_effective_yaml_status(yaml_entry, "bsi", param_ctx)
        yaml_cnsa = get_effective_yaml_status(yaml_entry, "cnsa", param_ctx)

        # Normalise markdown statuses
        md_nist = normalise_md_status(row.get("nist_raw", ""))
        md_bsi = normalise_md_status(row.get("bsi_raw", ""))
        md_cnsa = normalise_md_status(row.get("cnsa_raw", ""))

        # Compare each authority
        row_match = True
        row_details = []

        for auth_name, md_norm, yaml_auth, md_raw_key in [
            ("NIST", md_nist, yaml_nist, "nist_raw"),
            ("BSI", md_bsi, yaml_bsi, "bsi_raw"),
            ("CNSA", md_cnsa, yaml_cnsa, "cnsa_raw"),
        ]:
            md_raw = row.get(md_raw_key, "")
            if not md_raw:
                continue

            is_match, detail = compare_status(md_norm, yaml_auth, auth_name)
            row_details.append({
                "authority": auth_name,
                "md_raw": md_raw,
                "md_normalised": md_norm["status"],
                "yaml_status": yaml_auth.get("status"),
                "yaml_note": yaml_auth.get("note"),
                "match": is_match,
                "detail": detail,
            })
            if not is_match:
                row_match = False

        if row_match:
            matches += 1
        else:
            mismatches += 1
            discrepancies.append({
                "pattern": pattern,
                "section": section,
                "subsection": subsection,
                "yaml_id": yaml_id,
                "details": row_details,
            })

    # Report
    print("=" * 72)
    print("CROSS-CHECK REPORT")
    print("=" * 72)
    print()
    total_checked = matches + mismatches
    print(f"Total markdown rows parsed:     {len(md_rows)}")
    print(f"Rows checked (with authority):  {total_checked}")
    print(f"  Matching rows:                {matches}")
    print(f"  Rows with discrepancies:      {mismatches}")
    print(f"  Rows not found in YAML:       {len(not_found_in_yaml)}")
    print()

    if discrepancies:
        # Categorise mismatches
        from collections import Counter
        mismatch_categories = Counter()
        for disc in discrepancies:
            for d in disc["details"]:
                if not d["match"]:
                    mismatch_categories[d["detail"]] += 1

        print("-" * 72)
        print("DISCREPANCY SUMMARY BY CATEGORY")
        print("-" * 72)
        for cat, count in mismatch_categories.most_common():
            print(f"  {count:3d}x  {cat}")
        print()

        print("-" * 72)
        print("DISCREPANCIES (DETAILED)")
        print("-" * 72)
        for disc in discrepancies:
            print()
            print(f"DISCREPANCY: {disc['pattern']}")
            print(f"  Section:   {disc['section']}")
            if disc["subsection"]:
                print(f"  Subsec:    {disc['subsection']}")
            print(f"  YAML ID:   {disc['yaml_id']}")
            for d in disc["details"]:
                status_str = "match" if d["match"] else "MISMATCH"
                yaml_display = d["yaml_status"] if d["yaml_status"] else f"note='{d['yaml_note']}'"
                md_display = d["md_raw"][:60]
                print(f"  {d['authority']:4s}: md=\"{md_display}\"  yaml=\"{yaml_display}\"  -> {status_str}")
                if not d["match"]:
                    print(f"        {d['detail']}")
        print()

    if not_found_in_yaml:
        print("-" * 72)
        print(f"ENTRIES IN MARKDOWN BUT NOT FOUND IN YAML ({len(not_found_in_yaml)})")
        print("-" * 72)
        for pattern, section, subsection in not_found_in_yaml:
            loc = section
            if subsection:
                loc += f" / {subsection}"
            print(f"  {pattern:55s}  [{loc}]")
        print()

    # Entries in YAML but not referenced in markdown
    unreferenced = []
    for eid, entry in yaml_entries.items():
        if eid not in checked_yaml_ids:
            if entry.get("patternStatus") == "deprecated":
                continue
            unreferenced.append((eid, entry.get("_source_file", "")))

    if unreferenced:
        print("-" * 72)
        print(f"ENTRIES IN YAML BUT NOT REFERENCED IN MARKDOWN ({len(unreferenced)})")
        print("-" * 72)
        for eid, src in sorted(unreferenced):
            print(f"  {eid:40s}  [{src}]")
        print()

    print("=" * 72)
    if mismatches == 0 and len(not_found_in_yaml) == 0:
        print("RESULT: All checks passed - no discrepancies found.")
        return 0
    else:
        print(f"RESULT: {mismatches} discrepancies, {len(not_found_in_yaml)} unmatched markdown rows.")
        return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Cross-check or generate cryptographic-algorithm-status.md from YAML registry"
    )
    parser.add_argument("--check", action="store_true",
                        help="Run the cross-check (compare markdown against YAML)")
    parser.add_argument("--generate", action="store_true",
                        help="Patch §1-§10 authority cells from YAML and write to stdout")
    parser.add_argument("--apply", action="store_true",
                        help="Like --generate but write back to the source markdown file")
    parser.add_argument("--output", type=str, default=None,
                        help="Write generated output to this file instead of stdout "
                             "(only with --generate)")
    args = parser.parse_args()

    if not args.check and not args.generate and not args.apply:
        parser.print_help()
        print("\nUse --check, --generate, or --apply.")
        return 0

    if args.check:
        return run_check()

    if args.generate or args.apply:
        if not MD_FILE.exists():
            print(f"ERROR: Markdown file not found: {MD_FILE}", file=sys.stderr)
            return 1
        if not REGISTRY_DIR.exists():
            print(f"ERROR: Registry directory not found: {REGISTRY_DIR}", file=sys.stderr)
            return 1

        yaml_entries = load_yaml_entries(REGISTRY_DIR)
        patched = run_generate(MD_FILE, yaml_entries)

        if args.apply:
            MD_FILE.write_text(patched, encoding="utf-8")
            print(f"Wrote patched output to {MD_FILE}", file=sys.stderr)
            return 0

        # --generate mode
        if args.output:
            out_path = Path(args.output)
            out_path.write_text(patched, encoding="utf-8")
            print(f"Wrote patched output to {out_path}", file=sys.stderr)
        else:
            sys.stdout.write(patched)

        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
