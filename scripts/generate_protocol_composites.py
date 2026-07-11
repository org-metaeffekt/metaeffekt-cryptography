#!/usr/bin/env python3
"""
Generate the protocol composite registries (cr-tls, cr-ssh, cr-ipsec, cr-kerberos,
cr-dnssec, cr-spdm) from IANA / IETF-RFC / DMTF sources, with NIST/BSI overlays.

Fetches (or reads from local cache) IANA CSVs for:
  - Cipher Suites (tls-parameters-4.csv)
  - Supported Groups (tls-parameters-8.csv)
  - Signature Schemes (tls-signaturescheme.csv)

Decomposes each entry into component algorithm patterns and writes
a v2 registry YAML file for use by ae-pattern-validator.

Usage:
    python generate_protocol_composites.py [--check] [--cache-dir DIR]

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
SSH_OUTPUT_PATH = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "cr-ssh.yaml"
IPSEC_OUTPUT_PATH = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "cr-ipsec.yaml"
KERBEROS_OUTPUT_PATH = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "cr-kerberos.yaml"
DNSSEC_OUTPUT_PATH = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "cr-dnssec.yaml"
SPDM_OUTPUT_PATH = REPO_ROOT / "ae-pattern-validator" / "src" / "main" / "resources" / "registry" / "cr-spdm.yaml"
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
    "AES_256_CCM_8": "AES-256-CCM",
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
    "brainpoolP256r1": "ECDH-brainpoolP256r1",
    "brainpoolP384r1": "ECDH-brainpoolP384r1",
    "brainpoolP512r1": "ECDH-brainpoolP512r1",
    "brainpoolP256r1tls13": "ECDH-brainpoolP256r1",
    "brainpoolP384r1tls13": "ECDH-brainpoolP384r1",
    "brainpoolP512r1tls13": "ECDH-brainpoolP512r1",
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
    "ecdsa_brainpoolP256r1tls13_sha256": "ECDSA-brainpoolP256r1-SHA-256",
    "ecdsa_brainpoolP384r1tls13_sha384": "ECDSA-brainpoolP384r1-SHA-384",
    "ecdsa_brainpoolP512r1tls13_sha512": "ECDSA-brainpoolP512r1-SHA-512",
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

# ── SSH algorithm lookup tables ───────────────────────────────────────────────

SSH_KEX_MAP = {
    "curve25519-sha256": ["ECDH-Curve25519", "SHA-256"],
    "curve25519-sha256@libssh.org": ["ECDH-Curve25519", "SHA-256"],
    "ecdh-sha2-nistp256": ["ECDH-P-256", "SHA-256"],
    "ecdh-sha2-nistp384": ["ECDH-P-384", "SHA-384"],
    "ecdh-sha2-nistp521": ["ECDH-P-521", "SHA-512"],
    "diffie-hellman-group14-sha256": ["FFDH-ffdhe2048", "SHA-256"],
    "diffie-hellman-group15-sha512": ["FFDH-ffdhe3072", "SHA-512"],
    "diffie-hellman-group16-sha512": ["FFDH-ffdhe4096", "SHA-512"],
    "diffie-hellman-group17-sha512": ["FFDH-ffdhe6144", "SHA-512"],
    "diffie-hellman-group18-sha512": ["FFDH-ffdhe8192", "SHA-512"],
    "diffie-hellman-group-exchange-sha256": ["FFDH", "SHA-256"],
    "diffie-hellman-group14-sha1": ["FFDH-ffdhe2048", "SHA-1"],
    "diffie-hellman-group1-sha1": ["FFDH-1024", "SHA-1"],
    "diffie-hellman-group-exchange-sha1": ["FFDH", "SHA-1"],
}

SSH_HOST_AUTH_MAP = {
    "ssh-ed25519": ["EdDSA-Ed25519"],
    "ssh-ed448": ["EdDSA-Ed448"],
    "ecdsa-sha2-nistp256": ["ECDSA-P-256-SHA-256"],
    "ecdsa-sha2-nistp384": ["ECDSA-P-384-SHA-384"],
    "ecdsa-sha2-nistp521": ["ECDSA-P-521-SHA-512"],
    "rsa-sha2-256": ["RSASSA-PSS-SHA-256"],
    "rsa-sha2-512": ["RSASSA-PSS-SHA-512"],
    "ssh-rsa": ["RSASSA-PKCS1-v1_5-SHA-1"],
    "ssh-dss": ["DSA-SHA-1"],
}

SSH_CIPHER_MAP = {
    "chacha20-poly1305@openssh.com": ["ChaCha20-Poly1305"],
    "aes256-gcm@openssh.com": ["AES-256-GCM"],
    "aes128-gcm@openssh.com": ["AES-128-GCM"],
    "aes256-ctr": ["AES-256-CTR"],
    "aes192-ctr": ["AES-192-CTR"],
    "aes128-ctr": ["AES-128-CTR"],
    "aes256-cbc": ["AES-256-CBC"],
    "3des-cbc": ["3DES-CBC"],
    "arcfour": ["RC4"],
    "arcfour128": ["RC4"],
    "arcfour256": ["RC4"],
}

SSH_MAC_MAP = {
    "hmac-sha2-256-etm@openssh.com": ["HMAC-SHA-256"],
    "hmac-sha2-512-etm@openssh.com": ["HMAC-SHA-512"],
    "umac-128-etm@openssh.com": ["UMAC"],
    "hmac-sha2-256": ["HMAC-SHA-256"],
    "hmac-sha2-512": ["HMAC-SHA-512"],
    "hmac-sha1": ["HMAC-SHA-1"],
    "hmac-sha1-96": ["HMAC-SHA-1"],
    "hmac-md5": ["HMAC-MD5"],
    "hmac-md5-96": ["HMAC-MD5"],
}


# ── BSI TR-02102-4 v2026-01 + IETF/NIST overlay (SSH recommendations) ─────────
#
# Source: BSI TR-02102-4 v2026-01 (2026-01-27); IETF RFC 9142 (Oct 2021); NIST
# SP 800-131A Rev 2. Tuple form: (status, source). For BSI, when an algorithm
# is "transitional", the note encodes the deadline.

_BSI_SSH_DOC = "TR-02102-4 v2026-01"
_NIST_SSH_DOC = "SP 800-131A Rev 2"
_IETF_SSH_DOCS = {
    "kex": "RFC 9142",
    "auth": "RFC 8332/8709/5656",
    "cipher": "RFC 4253/4344/5647/8758",
    "mac": "RFC 4253/6668",
}

# Tuple form per overlay: (status[, useUpTo or note])
# IETF status uses RFC 9142 / RFC 8332 / RFC 5656 / RFC 4253 requirement levels.

BSI_SSH = {
    # KEX
    "curve25519-sha256":                    {"bsi": ("recommended",  None,   "§3.1.1")},
    "curve25519-sha256@libssh.org":         {"bsi": ("recommended",  None,   "§3.1.1; OpenSSH alias predating RFC 8731")},
    "ecdh-sha2-nistp256":                   {"bsi": ("approved",     None,   "§3.1.3")},
    "ecdh-sha2-nistp384":                   {"bsi": ("approved",     None,   "§3.1.3")},
    "ecdh-sha2-nistp521":                   {"bsi": ("approved",     None,   "§3.1.3")},
    "diffie-hellman-group14-sha256":        {"bsi": ("transitional", "2030", "§3.2.2")},
    "diffie-hellman-group16-sha512":        {"bsi": ("approved",     None,   "§3.2.2")},
    "diffie-hellman-group18-sha512":        {"bsi": ("approved",     None,   "§3.2.2")},
    "diffie-hellman-group14-sha1":          {"bsi": ("disallowed",   None,   "SHA-1 disallowed")},
    "diffie-hellman-group1-sha1":           {"bsi": ("disallowed",   None,   "1024-bit DH and SHA-1")},
    "diffie-hellman-group-exchange-sha1":   {"bsi": ("disallowed",   None,   "SHA-1 disallowed")},
    # group15-sha512, group17-sha512, group-exchange-sha256 not listed in BSI table — no bsi: block
    # Host auth
    "ssh-ed25519":                          {"bsi": ("recommended",  None,   "§4.1")},
    "ecdsa-sha2-nistp256":                  {"bsi": ("approved",     None,   "§4.1")},
    "ecdsa-sha2-nistp384":                  {"bsi": ("approved",     None,   "§4.1")},
    "ecdsa-sha2-nistp521":                  {"bsi": ("approved",     None,   "§4.1")},
    "rsa-sha2-256":                         {"bsi": ("approved",     None,   "§4.1")},
    "rsa-sha2-512":                         {"bsi": ("approved",     None,   "§4.1")},
    "ssh-rsa":                              {"bsi": ("disallowed",   None,   "RSA with SHA-1")},
    "ssh-dss":                              {"bsi": ("disallowed",   None,   "DSA-1024")},
    # ssh-ed448 not listed in BSI table
    # Symmetric encryption
    "chacha20-poly1305@openssh.com":        {"bsi": ("recommended",  None,   "§5.1")},
    "aes256-gcm@openssh.com":               {"bsi": ("recommended",  None,   "§5.1")},
    "aes128-gcm@openssh.com":               {"bsi": ("recommended",  None,   "§5.1")},
    "aes256-ctr":                           {"bsi": ("conditional",  None,   "§5.1"), "requires": ["encrypt-then-MAC (HMAC-ETM)"]},
    "aes192-ctr":                           {"bsi": ("conditional",  None,   "§5.1"), "requires": ["encrypt-then-MAC (HMAC-ETM)"]},
    "aes128-ctr":                           {"bsi": ("conditional",  None,   "§5.1"), "requires": ["encrypt-then-MAC (HMAC-ETM)"]},
    "aes256-cbc":                           {"bsi": ("deprecated",   None,   "§5.1")},
    "3des-cbc":                             {"bsi": ("disallowed",   None,   "§5.1")},
    "arcfour":                              {"bsi": ("disallowed",   None,   "RC4 — broken")},
    "arcfour128":                           {"bsi": ("disallowed",   None,   "RC4 — broken")},
    "arcfour256":                           {"bsi": ("disallowed",   None,   "RC4 — broken")},
    # MACs
    "hmac-sha2-256-etm@openssh.com":        {"bsi": ("recommended",  None,   "§6.1")},
    "hmac-sha2-512-etm@openssh.com":        {"bsi": ("recommended",  None,   "§6.1")},
    "umac-128-etm@openssh.com":             {"bsi": ("approved",     None,   "§6.1; OpenSSH extension")},
    "hmac-sha2-256":                        {"bsi": ("conditional",  None,   "§6.1"), "requires": ["CTR-mode cipher"]},
    "hmac-sha2-512":                        {"bsi": ("conditional",  None,   "§6.1"), "requires": ["CTR-mode cipher"]},
    "hmac-sha1":                            {"bsi": ("disallowed",   None,   "SHA-1 disallowed")},
    "hmac-sha1-96":                         {"bsi": ("disallowed",   None,   "SHA-1 disallowed")},
    "hmac-md5":                             {"bsi": ("disallowed",   None,   "MD5 broken")},
    "hmac-md5-96":                          {"bsi": ("disallowed",   None,   "MD5 broken")},
}

NIST_SSH = {
    # KEX (NIST status from SP 800-131A Rev 2 algorithm transitions)
    "curve25519-sha256":                    ("approved",     "ECDH (Curve25519) — approved"),
    "curve25519-sha256@libssh.org":         ("approved",     "OpenSSH alias for curve25519-sha256"),
    "ecdh-sha2-nistp256":                   ("approved",     "ECDH P-256 — approved"),
    "ecdh-sha2-nistp384":                   ("approved",     "ECDH P-384 — approved"),
    "ecdh-sha2-nistp521":                   ("approved",     "ECDH P-521 — approved"),
    "diffie-hellman-group14-sha256":        ("transitional", "FFDH 2048-bit — 112-bit security; transitional through 2030"),
    "diffie-hellman-group15-sha512":        ("approved",     "FFDH 3072-bit — 128-bit security"),
    "diffie-hellman-group16-sha512":        ("approved",     "FFDH 4096-bit — approved"),
    "diffie-hellman-group17-sha512":        ("approved",     "FFDH 6144-bit — approved"),
    "diffie-hellman-group18-sha512":        ("approved",     "FFDH 8192-bit — approved"),
    "diffie-hellman-group-exchange-sha256": ("approved",     "client-chosen group; SHA-256"),
    "diffie-hellman-group14-sha1":          ("disallowed",   "SHA-1 disallowed for digital-signature use"),
    "diffie-hellman-group1-sha1":           ("disallowed",   "1024-bit DH and SHA-1 — both disallowed"),
    "diffie-hellman-group-exchange-sha1":   ("disallowed",   "SHA-1 disallowed"),
    # Host auth
    "ssh-ed25519":                          ("approved",     "EdDSA Ed25519 — approved (FIPS 186-5)"),
    "ssh-ed448":                            ("approved",     "EdDSA Ed448 — approved (FIPS 186-5)"),
    "ecdsa-sha2-nistp256":                  ("approved",     "ECDSA P-256/SHA-256 — approved"),
    "ecdsa-sha2-nistp384":                  ("approved",     "ECDSA P-384/SHA-384 — approved"),
    "ecdsa-sha2-nistp521":                  ("approved",     "ECDSA P-521/SHA-512 — approved"),
    "rsa-sha2-256":                         ("approved",     "RSA-SHA-256 — approved with ≥ 2048-bit key"),
    "rsa-sha2-512":                         ("approved",     "RSA-SHA-512 — approved with ≥ 2048-bit key"),
    "ssh-rsa":                              ("disallowed",   "RSA with SHA-1 — disallowed for digital signatures"),
    "ssh-dss":                              ("disallowed",   "DSA-1024 — disallowed"),
    # Symmetric encryption
    "chacha20-poly1305@openssh.com":        ("approved",     "ChaCha20-Poly1305 — approved (RFC 7539)"),
    "aes256-gcm@openssh.com":                ("approved",    "AES-256-GCM — approved"),
    "aes128-gcm@openssh.com":                ("approved",    "AES-128-GCM — approved"),
    "aes256-ctr":                           ("approved",     "AES-256-CTR — approved"),
    "aes192-ctr":                           ("approved",     "AES-192-CTR — approved"),
    "aes128-ctr":                           ("approved",     "AES-128-CTR — approved"),
    "aes256-cbc":                           ("conditional",  "CBC mode acceptable but not preferred"),
    "3des-cbc":                             ("disallowed",   "3DES disallowed for encryption since 2024 (SP 800-131A Rev 2)"),
    "arcfour":                              ("disallowed",   "RC4 — broken; disallowed since 2015"),
    "arcfour128":                           ("disallowed",   "RC4 — broken; disallowed since 2015"),
    "arcfour256":                           ("disallowed",   "RC4 — broken; disallowed since 2015"),
    # MACs
    "hmac-sha2-256-etm@openssh.com":        ("approved",     "HMAC-SHA-256 (ETM)"),
    "hmac-sha2-512-etm@openssh.com":        ("approved",     "HMAC-SHA-512 (ETM)"),
    "umac-128-etm@openssh.com":             ("conditional",  "UMAC not FIPS-approved"),
    "hmac-sha2-256":                        ("approved",     "HMAC-SHA-256"),
    "hmac-sha2-512":                        ("approved",     "HMAC-SHA-512"),
    "hmac-sha1":                            ("disallowed",   "SHA-1 disallowed for HMAC use"),
    "hmac-sha1-96":                         ("disallowed",   "SHA-1 disallowed; truncated to 96 bits"),
    "hmac-md5":                             ("disallowed",   "MD5 broken — disallowed"),
    "hmac-md5-96":                          ("disallowed",   "MD5 broken — disallowed"),
}

# ── BSI TR-02102-3 v2026-01 + IETF/NIST overlay (IPsec recommendations) ──────
#
# Source: BSI TR-02102-3 v2026-01 (2026-01-27); IETF RFC 8221 (ESP/AH), RFC 8247
# (IKEv2 algorithms); NIST SP 800-131A Rev 2 + SP 800-186.
#
# Schema mirrors SSH: each ID maps to (subType, components, ietf, nist, bsi).

_BSI_IPSEC_DOC = "TR-02102-3 v2026-01"
_NIST_IPSEC_DOC = "SP 800-131A Rev 2"

# Master IPsec entry table. Each value is a dict with subType, components, and
# optional ietf/nist/bsi overlays. Sources of truth for cr-ipsec.yaml.
IPSEC_ENTRIES = {
    # ── DH groups (IKEv2 Key Exchange) ──
    "ipsec-dh:group14": {
        "subType": "ipsecDhGroup", "components": ["FFDH-ffdhe2048"],
        "description": "2048-bit MODP; 112-bit security",
        "ietf": ("MUST",   "RFC 8247 §2.4"),
        "nist": ("transitional", "FFDH 2048-bit; 112-bit security; transitional through 2030"),
        "bsi":  ("transitional", "2030", "§3.2.2; 112-bit security"),
    },
    "ipsec-dh:group15": {
        "subType": "ipsecDhGroup", "components": ["FFDH-ffdhe3072"],
        "description": "3072-bit MODP; 128-bit security",
        "nist": ("approved", "FFDH 3072-bit; 128-bit security"),
        "bsi":  ("approved", None, "§3.2.2"),
    },
    "ipsec-dh:group16": {
        "subType": "ipsecDhGroup", "components": ["FFDH-ffdhe4096"],
        "description": "4096-bit MODP",
        "nist": ("approved", "FFDH 4096-bit"),
        "bsi":  ("approved", None, "§3.2.2"),
    },
    "ipsec-dh:group17": {
        "subType": "ipsecDhGroup", "components": ["FFDH-ffdhe6144"],
        "description": "6144-bit MODP",
        "nist": ("approved", "FFDH 6144-bit"),
        "bsi":  ("approved", None, "§3.2.2"),
    },
    "ipsec-dh:group18": {
        "subType": "ipsecDhGroup", "components": ["FFDH-ffdhe8192"],
        "description": "8192-bit MODP",
        "nist": ("approved", "FFDH 8192-bit"),
        "bsi":  ("approved", None, "§3.2.2"),
    },
    "ipsec-dh:group19": {
        "subType": "ipsecDhGroup", "components": ["ECDH-P-256"],
        "description": "P-256 (secp256r1); 128-bit security",
        "ietf": ("SHOULD", "RFC 8247 §2.4"),
        "nist": ("approved", "ECDH P-256"),
        "bsi":  ("approved", None, "§3.2.1"),
    },
    "ipsec-dh:group20": {
        "subType": "ipsecDhGroup", "components": ["ECDH-P-384"],
        "description": "P-384 (secp384r1); 192-bit security",
        "nist": ("approved", "ECDH P-384"),
        "bsi":  ("approved", None, "§3.2.1"),
    },
    "ipsec-dh:group21": {
        "subType": "ipsecDhGroup", "components": ["ECDH-P-521"],
        "description": "P-521 (secp521r1); 256-bit security",
        "nist": ("approved", "ECDH P-521"),
        "bsi":  ("approved", None, "§3.2.1"),
    },
    "ipsec-dh:group31": {
        "subType": "ipsecDhGroup", "components": ["ECDH-Curve25519"],
        "description": "Curve25519; 128-bit security",
        "ietf": (None, "RFC 8031"),
        "nist": ("approved", "ECDH Curve25519"),
        "bsi":  ("recommended", None, "§3.2.1"),
        "remarks": ["constant-time scalar multiplication"],
    },
    "ipsec-dh:group32": {
        "subType": "ipsecDhGroup", "components": ["ECDH-Curve448"],
        "description": "Curve448; 224-bit security",
        "ietf": (None, "RFC 8031"),
        "nist": ("approved", "ECDH Curve448"),
        "bsi":  ("recommended", None, "§3.2.1"),
        "remarks": ["constant-time scalar multiplication"],
    },

    # ── Disallowed / suspect DH groups ──
    "ipsec-dh:group25": {
        "subType": "ipsecDhGroup", "components": ["ECDH-P-192"],
        "description": "P-192 ECP; below 128-bit security",
        "nist": ("disallowed", "P-192 below 112-bit security floor"),
        "bsi":  ("deprecated", None, "below 128-bit security"),
    },
    "ipsec-dh:group26": {
        "subType": "ipsecDhGroup", "components": ["ECDH-P-224"],
        "description": "P-224 ECP; 112-bit security",
        "nist": ("transitional", "P-224 — 112-bit security; transitional through 2030"),
        "bsi":  ("transitional", "2030", "112-bit security"),
    },
    "ipsec-dh:group5": {
        "subType": "ipsecDhGroup", "components": ["FFDH-1536"],
        "description": "1536-bit MODP; below 112-bit security",
        "ietf": ("SHOULD-NOT", "RFC 8247 §2.4"),
        "nist": ("disallowed", "1536-bit MODP — below 112-bit security floor"),
        "bsi":  ("disallowed", None, "below 112-bit security"),
    },
    "ipsec-dh:group2": {
        "subType": "ipsecDhGroup", "components": ["FFDH-1024"],
        "description": "1024-bit MODP; 80-bit security",
        "ietf": ("SHOULD-NOT", "RFC 8247 §2.4"),
        "nist": ("disallowed", "1024-bit MODP — 80-bit security; disallowed"),
        "bsi":  ("disallowed", None, "80-bit security"),
    },
    "ipsec-dh:group1": {
        "subType": "ipsecDhGroup", "components": ["FFDH-768"],
        "description": "768-bit MODP; below 80-bit security",
        "ietf": ("MUST-NOT", "RFC 8247 §2.4"),
        "nist": ("disallowed", "768-bit MODP — below 80-bit security; disallowed"),
        "bsi":  ("disallowed", None, "below 80-bit security"),
    },
    "ipsec-dh:group22": {
        "subType": "ipsecDhGroup", "components": ["FFDH-1024"],
        "description": "1024-bit MODP with subgroup; suspect parameters",
        "ietf": ("MUST-NOT", "RFC 8247 §2.4"),
        "nist": ("disallowed", "suspect subgroup parameters"),
        "bsi":  ("disallowed", None, "suspect subgroup parameters"),
        "remarks": ["1024-bit prime with 160-bit subgroup; provenance of parameters questioned"],
    },
    "ipsec-dh:group23": {
        "subType": "ipsecDhGroup", "components": ["FFDH-2048"],
        "description": "2048-bit MODP with 224-bit subgroup; suspect parameters",
        "ietf": ("SHOULD-NOT", "RFC 8247 §2.4"),
        "nist": ("disallowed", "suspect subgroup parameters"),
        "bsi":  ("disallowed", None, "suspect subgroup parameters"),
    },
    "ipsec-dh:group24": {
        "subType": "ipsecDhGroup", "components": ["FFDH-2048"],
        "description": "2048-bit MODP with 256-bit subgroup; suspect parameters",
        "ietf": ("SHOULD-NOT", "RFC 8247 §2.4"),
        "nist": ("disallowed", "suspect subgroup parameters"),
        "bsi":  ("disallowed", None, "suspect subgroup parameters"),
    },

    # ── ESP Encryption Transforms ──
    "ipsec-esp:aes-128-gcm": {
        "subType": "espTransform", "components": ["AES-128-GCM"],
        "ietf": ("MUST",   "RFC 8221 §5"),
        "ietfIkev2": ("SHOULD", "RFC 8247 §2.1"),
        "nist": ("approved", "AES-128-GCM AEAD"),
        "bsi":  ("recommended", None, "§3.3.1"),
        "remarks": ["AEAD; RFC 4106 (ESP), RFC 5282 (IKE)"],
    },
    "ipsec-esp:aes-256-gcm": {
        "subType": "espTransform", "components": ["AES-256-GCM"],
        "ietf": ("MUST",   "RFC 8221 §5"),
        "ietfIkev2": ("SHOULD", "RFC 8247 §2.1"),
        "nist": ("approved", "AES-256-GCM AEAD"),
        "bsi":  ("recommended", None, "§3.3.1"),
        "remarks": ["AEAD; RFC 4106 (ESP), RFC 5282 (IKE)"],
    },
    "ipsec-esp:aes-128-ccm": {
        "subType": "espTransform", "components": ["AES-128-CCM"],
        "ietf": ("SHOULD", "RFC 8221 §5"),
        "ietfIkev2": ("SHOULD", "RFC 8247 §2.1; SHOULD only for IoT"),
        "nist": ("approved", "AES-128-CCM AEAD"),
        "bsi":  ("approved", None, "§3.3.1"),
        "remarks": ["AEAD; RFC 4309"],
    },
    "ipsec-esp:chacha20-poly1305": {
        "subType": "espTransform", "components": ["ChaCha20-Poly1305"],
        "ietf": ("SHOULD", "RFC 8221 §5; RFC 7634"),
        "ietfIkev2": ("SHOULD", "RFC 8247 §2.1"),
        "nist": ("approved", "ChaCha20-Poly1305 AEAD"),
        "bsi":  ("approved", None, "§3.3.1"),
        "remarks": ["AEAD; RFC 7634"],
    },
    "ipsec-esp:aes-128-cbc": {
        "subType": "espTransform", "components": ["AES-128-CBC"],
        "ietf": ("MUST",   "RFC 8221 §5"),
        "ietfIkev2": ("MUST", "RFC 8247 §2.1"),
        "nist": ("conditional", "AES-128-CBC — pair with separate integrity"),
        "bsi":  ("conditional", None, "§3.3.1"),
        "requires": ["separate integrity transform (HMAC-SHA-2 or AES-XCBC-MAC)"],
        "remarks": ["no AEAD", "RFC 4106 (ESP) and RFC 5282 (IKE) define AEAD alternatives"],
    },
    "ipsec-esp:aes-256-cbc": {
        "subType": "espTransform", "components": ["AES-256-CBC"],
        "ietf": ("MUST",   "RFC 8221 §5"),
        "ietfIkev2": ("MUST", "RFC 8247 §2.1"),
        "nist": ("conditional", "AES-256-CBC — pair with separate integrity"),
        "bsi":  ("conditional", None, "§3.3.1"),
        "requires": ["separate integrity transform (HMAC-SHA-2 or AES-XCBC-MAC)"],
        "remarks": ["no AEAD", "RFC 4106 (ESP) and RFC 5282 (IKE) define AEAD alternatives"],
    },
    "ipsec-esp:3des-cbc": {
        "subType": "espTransform", "components": ["3DES-CBC"],
        "ietf": ("SHOULD-NOT", "RFC 8221 §5"),
        "ietfIkev2": ("MAY", "RFC 8247 §2.1"),
        "nist": ("disallowed", "3DES — disallowed for encryption since 2024 (SP 800-131A Rev 2)"),
        "bsi":  ("disallowed", None, "§3.3.1"),
        "remarks": ["64-bit block; birthday-bound vulnerable above 32 GB"],
    },
    "ipsec-esp:aes-128-ctr": {
        "subType": "espTransform", "components": ["AES-128-CTR"],
        "ietf": ("MAY", "RFC 8221 §5"),
        "nist": ("approved", "AES-128-CTR — approved"),
        "bsi":  ("conditional", None, "§3.3.1"),
        "requires": ["separate integrity transform"],
        "remarks": ["no AEAD"],
    },
    "ipsec-esp:aes-192-ctr": {
        "subType": "espTransform", "components": ["AES-192-CTR"],
        "ietf": ("MAY", "RFC 8221 §5"),
        "nist": ("approved", "AES-192-CTR — approved"),
        "bsi":  ("conditional", None, "§3.3.1"),
        "requires": ["separate integrity transform"],
        "remarks": ["no AEAD"],
    },
    "ipsec-esp:aes-256-ctr": {
        "subType": "espTransform", "components": ["AES-256-CTR"],
        "ietf": ("MAY", "RFC 8221 §5"),
        "nist": ("approved", "AES-256-CTR — approved"),
        "bsi":  ("conditional", None, "§3.3.1"),
        "requires": ["separate integrity transform"],
        "remarks": ["no AEAD"],
    },
    "ipsec-esp:des-cbc": {
        "subType": "espTransform", "components": ["DES-CBC"],
        "ietf": ("MUST-NOT", "RFC 8221 §5"),
        "nist": ("disallowed", "DES — 56-bit key broken; disallowed"),
        "bsi":  ("disallowed", None, "56-bit key broken"),
        "remarks": ["56-bit key; brute-forceable"],
    },

    # ── IKEv2 Integrity / PRF ──
    "ipsec-auth:hmac-sha2-256-128": {
        "subType": "ipsecIntegrity", "components": ["HMAC-SHA-256"],
        "ietf": ("MUST",   "RFC 8221 §6; RFC 4868"),
        "ietfIkev2": ("MUST", "RFC 8247 §2.2; PRF_HMAC_SHA2_256 is also MUST as IKEv2 PRF"),
        "nist": ("approved", "HMAC-SHA2-256"),
        "bsi":  ("recommended", None, "§3.4"),
        "remarks": ["truncated to 128 bits per RFC 4868"],
    },
    "ipsec-auth:hmac-sha2-384-192": {
        "subType": "ipsecIntegrity", "components": ["HMAC-SHA-384"],
        "ietf": (None, "RFC 4868"),
        "nist": ("approved", "HMAC-SHA2-384"),
        "bsi":  ("recommended", None, "§3.4"),
        "remarks": ["truncated to 192 bits per RFC 4868"],
    },
    "ipsec-auth:hmac-sha2-512-256": {
        "subType": "ipsecIntegrity", "components": ["HMAC-SHA-512"],
        "ietf": ("SHOULD", "RFC 8221 §6; RFC 4868"),
        "ietfIkev2": ("SHOULD", "RFC 8247 §2.2; SHOULD+ as IKEv2 PRF"),
        "nist": ("approved", "HMAC-SHA2-512"),
        "bsi":  ("recommended", None, "§3.4"),
        "remarks": ["truncated to 256 bits per RFC 4868"],
    },
    "ipsec-auth:aes-xcbc-96": {
        "subType": "ipsecIntegrity", "components": ["AES-CMAC"],
        "ietf": ("SHOULD", "RFC 8221 §6; RFC 3566"),
        "nist": ("conditional", "AES-XCBC — 96-bit truncation"),
        "bsi":  ("approved", None, "§3.4"),
        "remarks": ["RFC 3566; SHOULD for IoT, MAY for general VPN", "96-bit truncation"],
    },
    "ipsec-auth:hmac-sha1-96": {
        "subType": "ipsecIntegrity", "components": ["HMAC-SHA-1"],
        "ietf": ("MUST-",  "RFC 8221 §6"),
        "nist": ("disallowed", "HMAC-SHA-1 — disallowed for new use"),
        "bsi":  ("disallowed", None, "§3.4"),
        "remarks": ["downgraded from MUST to MUST-", "SHA-1 collision-vulnerable"],
    },
    "ipsec-auth:aes-cmac-96": {
        "subType": "ipsecIntegrity", "components": ["AES-CMAC"],
        "description": "AES-CMAC; 96-bit truncation",
        "ietf": (None, "RFC 4494"),
        "nist": ("approved", "AES-CMAC-96 — approved"),
        "bsi":  ("approved", None, "§3.4"),
        "remarks": ["RFC 4494; not addressed in RFC 8221 / RFC 8247"],
    },
    "ipsec-auth:hmac-md5-96": {
        "subType": "ipsecIntegrity", "components": ["HMAC-MD5"],
        "description": "HMAC-MD5; 96-bit truncation",
        "ietf": ("MUST-NOT", "RFC 8221 §6"),
        "nist": ("disallowed", "MD5 broken — disallowed"),
        "bsi":  ("disallowed", None, "§3.4"),
        "remarks": ["MD5 collision attacks; truncated to 96 bits"],
    },
}


# ── Kerberos overlay (NIST SP 800-57 Part 3 Rev 1 §6) ────────────────────────
#
# Sources: NIST SP 800-57 Part 3 Rev 1 (Jan 2015); IETF RFC 6649 (deprecate
# DES, RC4-HMAC-EXP), RFC 8429 (deprecate 3DES, RC4-HMAC), RFC 8009
# (AES-SHA2 for Kerberos 5), RFC 3962 (AES for Kerberos 5), RFC 4556 (PKINIT);
# BSI TR-02102-1 v2026-01.

_NIST_KERB_DOC = "SP 800-57 Part 3 Rev 1 §6"
_BSI_KERB_DOC = "TR-02102-1 v2026-01"

KERBEROS_ENTRIES = {
    # Encryption types
    "krb:aes128-cts-hmac-sha1-96": {
        "subType": "krbEncType", "components": ["AES-128-CBC", "HMAC-SHA-1"],
        "description": "AES-128-CBC + HMAC-SHA-1 truncated to 96 bits",
        "ietf": ("MAY",       "RFC 3962"),
        "nist": ("approved",  "AES-128 — approved"),
        "bsi":  ("approved",  None, "§3.3"),
        "remarks": ["RFC 3962; SHA-1 used in MAC, not signature — still acceptable"],
    },
    "krb:aes256-cts-hmac-sha1-96": {
        "subType": "krbEncType", "components": ["AES-256-CBC", "HMAC-SHA-1"],
        "description": "AES-256-CBC + HMAC-SHA-1 truncated to 96 bits",
        "ietf": ("MAY",       "RFC 3962"),
        "nist": ("approved",  "AES-256 — approved"),
        "bsi":  ("approved",  None, "§3.3"),
        "remarks": ["RFC 3962"],
    },
    "krb:aes128-cts-hmac-sha256-128": {
        "subType": "krbEncType", "components": ["AES-128-CBC", "HMAC-SHA-256"],
        "description": "AES-128-CBC + HMAC-SHA-256 truncated to 128 bits",
        "ietf": ("SHOULD",     "RFC 8009"),
        "nist": ("recommended", "modern Kerberos default"),
        "bsi":  ("recommended", None, "§3.3"),
        "remarks": ["RFC 8009"],
    },
    "krb:aes256-cts-hmac-sha384-192": {
        "subType": "krbEncType", "components": ["AES-256-CBC", "HMAC-SHA-384"],
        "description": "AES-256-CBC + HMAC-SHA-384 truncated to 192 bits",
        "ietf": ("SHOULD",     "RFC 8009"),
        "nist": ("recommended", "preferred for new deployments"),
        "bsi":  ("recommended", None, "§3.3"),
        "remarks": ["RFC 8009"],
    },
    "krb:des-cbc-md5": {
        "subType": "krbEncType", "components": ["DES-CBC", "MD5"],
        "description": "DES-CBC + MD5 (legacy)",
        "ietf": ("SHOULD-NOT", "RFC 6649"),
        "nist": ("disallowed",  "DES — broken; disallowed"),
        "bsi":  ("disallowed",  None, "broken"),
        "remarks": ["RFC 6649 deprecates DES variants; **shall not** be used"],
    },
    "krb:rc4-hmac": {
        "subType": "krbEncType", "components": ["RC4", "HMAC-MD5"],
        "description": "RC4 + HMAC-MD5",
        "ietf": ("SHOULD-NOT", "RFC 8429"),
        "nist": ("disallowed",  "RC4 broken; replaced by AES"),
        "bsi":  ("disallowed",  None, "RC4 broken"),
        "remarks": ["RFC 8429"],
    },
    "krb:rc4-hmac-exp": {
        "subType": "krbEncType", "components": ["RC4", "HMAC-MD5"],
        "description": "RC4 + HMAC-MD5 (40-bit export-grade)",
        "ietf": ("SHOULD-NOT", "RFC 6649"),
        "nist": ("disallowed",  "40-bit export key; broken"),
        "bsi":  ("disallowed",  None, "40-bit export key"),
        "remarks": ["RFC 6649 deprecates"],
    },
    "krb:des3-cbc-sha1-kd": {
        "subType": "krbEncType", "components": ["3DES-CBC", "HMAC-SHA-1"],
        "description": "3DES-CBC + HMAC-SHA-1 with key derivation",
        "ietf": ("SHOULD-NOT", "RFC 8429"),
        "nist": ("disallowed",  "3DES disallowed for encryption since 2024 (SP 800-131A Rev 2)"),
        "bsi":  ("disallowed",  None, "3DES disallowed"),
        "remarks": ["RFC 8429"],
    },
    # Integrity / MAC
    "krb:hmac-sha1": {
        "subType": "krbIntegrity", "components": ["HMAC-SHA-1"],
        "description": "HMAC-SHA-1 (truncated to 96 bits in Kerberos contexts)",
        "ietf": ("MAY",         "RFC 3962"),
        "nist": ("approved",    "HMAC-SHA-1 — 112-bit security; transitional through 2030"),
        "bsi":  ("conditional", None, "transitional"),
        "remarks": ["NIST permits HMAC-SHA-1 at 112-bit security through 2030; BSI cautious"],
    },
    "krb:hmac-sha256-128": {
        "subType": "krbIntegrity", "components": ["HMAC-SHA-256"],
        "description": "HMAC-SHA-256 truncated to 128 bits",
        "ietf": ("SHOULD",      "RFC 8009"),
        "nist": ("recommended", "used in aes128-cts-hmac-sha256-128"),
        "bsi":  ("recommended", None, "§3.3"),
    },
    "krb:hmac-sha384-192": {
        "subType": "krbIntegrity", "components": ["HMAC-SHA-384"],
        "description": "HMAC-SHA-384 truncated to 192 bits",
        "ietf": ("SHOULD",      "RFC 8009"),
        "nist": ("recommended", "used in aes256-cts-hmac-sha384-192"),
        "bsi":  ("recommended", None, "§3.3"),
    },
    # PKINIT key exchange / transport
    "krb:pkinit-dh-2048": {
        "subType": "krbKex", "components": ["FFDH-ffdhe2048"],
        "description": "PKINIT Diffie-Hellman ≥ 2048 bits",
        "ietf": ("MAY",          "RFC 4556"),
        "nist": ("transitional", "112-bit security; transitional through 2030"),
        "bsi":  ("transitional", "2030", "§2.3.3"),
        "remarks": ["RFC 4556 PKINIT pre-authentication"],
    },
    "krb:pkinit-dh-3072": {
        "subType": "krbKex", "components": ["FFDH-ffdhe3072"],
        "description": "PKINIT Diffie-Hellman ≥ 3072 bits",
        "ietf": ("MAY",          "RFC 4556"),
        "nist": ("approved",     "128-bit security"),
        "bsi":  ("approved",     None, "§2.3.3"),
        "remarks": ["meets BSI ≥3000-bit requirement"],
    },
    "krb:pkinit-rsa-2048": {
        "subType": "krbKex", "components": ["RSA-2048"],
        "description": "PKINIT RSA key transport ≥ 2048 bits",
        "ietf": ("MAY",          "RFC 4556"),
        "nist": ("transitional", "112-bit security; transitional through 2030"),
        "bsi":  ("transitional", "2030", "§2.3.2"),
        "remarks": ["RFC 4556 PKINIT pre-authentication"],
    },
}


# ── DNSSEC overlay (NIST SP 800-57 Part 3 Rev 1 §8; RFC 8624; RFC 8945) ──────
#
# Sources: NIST SP 800-57 Part 3 Rev 1 (Jan 2015); IETF RFC 8624 (DNSSEC algorithm
# requirements), RFC 8945 (TSIG), RFC 5155 (NSEC3); BSI TR-02102-1 v2026-01.

_NIST_DNS_DOC = "SP 800-57 Part 3 Rev 1 §8"
_BSI_DNS_DOC = "TR-02102-1 v2026-01"

DNSSEC_ENTRIES = {
    # Zone signing algorithms (RFC 8624 §3.1)
    "dnssec:RSASHA256": {
        "subType": "dnssecAlgorithm", "components": ["RSASSA-PKCS1-v1_5-SHA-256"],
        "description": "RSA + SHA-256",
        "ietf": ("MUST",      "RFC 8624 §3.1"),
        "nist": ("approved",  "RSA-SHA-256 — approved"),
        "bsi":  ("approved",  None, "§5.3"),
        "remarks": ["RFC 8624 §3.1; mandatory for new signing"],
    },
    "dnssec:RSASHA512": {
        "subType": "dnssecAlgorithm", "components": ["RSASSA-PKCS1-v1_5-SHA-512"],
        "description": "RSA + SHA-512",
        "ietf": ("SHOULD-NOT", "RFC 8624 §3.1"),
        "nist": ("approved",   "RSA-SHA-512 — approved (validation MUST)"),
        "bsi":  ("approved",   None, "§5.3"),
        "remarks": ["RFC 8624 §3.1: validation MUST, but signing NOT RECOMMENDED"],
    },
    "dnssec:ECDSAP256SHA256": {
        "subType": "dnssecAlgorithm", "components": ["ECDSA-P-256-SHA-256"],
        "description": "ECDSA P-256 + SHA-256",
        "ietf": ("MUST",       "RFC 8624 §3.1"),
        "nist": ("approved",   "ECDSA P-256/SHA-256 — approved"),
        "bsi":  ("recommended", None, "§5.3"),
        "remarks": ["recommended default for new zones"],
    },
    "dnssec:ECDSAP384SHA384": {
        "subType": "dnssecAlgorithm", "components": ["ECDSA-P-384-SHA-384"],
        "description": "ECDSA P-384 + SHA-384",
        "ietf": ("MAY",        "RFC 8624 §3.1"),
        "nist": ("recommended", "ECDSA P-384/SHA-384 — approved"),
        "bsi":  ("recommended", None, "§5.3"),
        "remarks": ["RFC 8624 §3.1: signing MAY, validation RECOMMENDED"],
    },
    "dnssec:ED25519": {
        "subType": "dnssecAlgorithm", "components": ["EdDSA-Ed25519"],
        "description": "EdDSA Curve25519",
        "ietf": ("SHOULD",     "RFC 8624 §3.1; RFC 8080"),
        "nist": ("approved",   "Ed25519 — approved (FIPS 186-5)"),
        "bsi":  ("recommended", None, "§5.4.4"),
        "remarks": ["expected future default per RFC 8624 §3.1"],
    },
    "dnssec:ED448": {
        "subType": "dnssecAlgorithm", "components": ["EdDSA-Ed448"],
        "description": "EdDSA Curve448",
        "ietf": ("MAY",        "RFC 8624 §3.1; RFC 8080"),
        "nist": ("approved",   "Ed448 — approved (FIPS 186-5)"),
        "bsi":  ("approved",   None, "§5.4.4"),
        "remarks": ["RFC 8624 §3.1: signing MAY, validation RECOMMENDED"],
    },
    "dnssec:RSASHA1": {
        "subType": "dnssecAlgorithm", "components": ["RSASSA-PKCS1-v1_5-SHA-1"],
        "description": "RSA + SHA-1 (legacy)",
        "ietf": ("SHOULD-NOT", "RFC 8624 §3.1"),
        "nist": ("disallowed",  "SHA-1 disallowed for digital signatures"),
        "bsi":  ("disallowed",  None, "SHA-1 disallowed"),
        "remarks": ["RFC 8624 §3.1: validation MUST (legacy), signing NOT RECOMMENDED"],
    },
    "dnssec:RSASHA1-NSEC3-SHA1": {
        "subType": "dnssecAlgorithm", "components": ["RSASSA-PKCS1-v1_5-SHA-1"],
        "description": "RSA + SHA-1 with NSEC3 hash (legacy)",
        "ietf": ("SHOULD-NOT", "RFC 8624 §3.1"),
        "nist": ("disallowed",  "SHA-1 disallowed for digital signatures"),
        "bsi":  ("disallowed",  None, "SHA-1 disallowed"),
        "remarks": ["NSEC3 (RFC 5155) variant of RSASHA1"],
    },
    "dnssec:RSAMD5": {
        "subType": "dnssecAlgorithm", "components": ["RSASSA-PKCS1-v1_5-MD5"],
        "description": "RSA + MD5",
        "ietf": ("MUST-NOT",   "RFC 8624 §3.1"),
        "nist": ("disallowed",  "MD5 broken — disallowed"),
        "bsi":  ("disallowed",  None, "MD5 broken"),
        "remarks": ["RFC 8624 §3.1"],
    },
    "dnssec:DSA": {
        "subType": "dnssecAlgorithm", "components": ["DSA", "SHA-1"],
        "description": "DSA + SHA-1",
        "ietf": ("MUST-NOT",   "RFC 8624 §3.1"),
        "nist": ("disallowed",  "DSA disallowed for new signatures (FIPS 186-5)"),
        "bsi":  ("disallowed",  None, "DSA disallowed"),
        "remarks": ["RFC 8624 §3.1"],
    },
    "dnssec:DSA-NSEC3-SHA1": {
        "subType": "dnssecAlgorithm", "components": ["DSA", "SHA-1"],
        "description": "DSA + SHA-1 with NSEC3 hash",
        "ietf": ("MUST-NOT",   "RFC 8624 §3.1"),
        "nist": ("disallowed",  "DSA disallowed"),
        "bsi":  ("disallowed",  None, "DSA disallowed"),
        "remarks": ["NSEC3 variant of DSA"],
    },

    # TSIG message authentication (RFC 8945)
    "dnssec-tsig:hmac-sha1": {
        "subType": "dnssecTsig", "components": ["HMAC-SHA-1"],
        "description": "HMAC-SHA-1",
        "ietf": ("MUST",        "RFC 8945 §6"),
        "nist": ("approved",    "HMAC-SHA-1 — transitional through 2030"),
        "bsi":  ("conditional", None, "§5.5"),
        "remarks": ["mandatory for interop; HMAC-SHA-1 still acceptable through 2030"],
    },
    "dnssec-tsig:hmac-sha224": {
        "subType": "dnssecTsig", "components": ["HMAC-SHA-224"],
        "description": "HMAC-SHA-224",
        "ietf": ("MAY",         "RFC 8945 §6"),
        "nist": ("approved",    "HMAC-SHA-224"),
        "bsi":  ("approved",    None, "§5.5"),
    },
    "dnssec-tsig:hmac-sha256": {
        "subType": "dnssecTsig", "components": ["HMAC-SHA-256"],
        "description": "HMAC-SHA-256",
        "ietf": ("MUST",        "RFC 8945 §6"),
        "nist": ("recommended", "HMAC-SHA-256"),
        "bsi":  ("recommended", None, "§5.5"),
        "remarks": ["RFC 8945 §6 mandatory"],
    },
    "dnssec-tsig:hmac-sha384": {
        "subType": "dnssecTsig", "components": ["HMAC-SHA-384"],
        "description": "HMAC-SHA-384",
        "ietf": ("MAY",         "RFC 8945 §6"),
        "nist": ("approved",    "HMAC-SHA-384"),
        "bsi":  ("recommended", None, "§5.5"),
    },
    "dnssec-tsig:hmac-sha512": {
        "subType": "dnssecTsig", "components": ["HMAC-SHA-512"],
        "description": "HMAC-SHA-512",
        "ietf": ("MAY",         "RFC 8945 §6"),
        "nist": ("approved",    "HMAC-SHA-512"),
        "bsi":  ("recommended", None, "§5.5"),
    },
    "dnssec-tsig:gss-tsig": {
        "subType": "dnssecTsig", "components": ["GSS-API"],
        "description": "GSS-TSIG (Generic Security Service)",
        "ietf": ("MAY",         "RFC 3645"),
        "nist": ("approved",    "GSS-API mediated"),
        "bsi":  ("approved",    None, "§5.5"),
    },
    "dnssec-tsig:hmac-md5": {
        "subType": "dnssecTsig", "components": ["HMAC-MD5"],
        "description": "HMAC-MD5",
        "ietf": ("MAY",         "RFC 8945 §6"),
        "nist": ("disallowed",  "MD5 broken"),
        "bsi":  ("disallowed",  None, "MD5 broken"),
        "remarks": ["RFC 8945 retains for backward compat; **shall not** be used per NIST/BSI"],
    },
}


# IETF status from RFC 9142 (KEX), RFC 8332/8709/5656 (auth), RFC 4253/4344/5647/8758 (ciphers), RFC 4253/6668 (MACs).
# Tuple: (level, section_or_rfc) — level is one of "MUST", "SHOULD", "MAY", "SHOULD-NOT", "MUST-NOT".

REMARKS_SSH = {
    # KEX
    "curve25519-sha256":              ["constant-time scalar multiplication", "ECDH/Curve25519 + SHA-256"],
    "diffie-hellman-group14-sha256":  ["2048-bit MODP; 112-bit security"],
    "diffie-hellman-group16-sha512":  ["4096-bit MODP"],
    "diffie-hellman-group18-sha512":  ["8192-bit MODP"],
    # Host auth
    "ssh-ed25519":                    ["constant-time signing", "EdDSA over Curve25519"],
    "rsa-sha2-256":                   ["RSA ≥ 3072 bits recommended; ≥ 2048 transitional through 2030"],
    "rsa-sha2-512":                   ["RSA ≥ 3072 bits recommended"],
    # Symmetric encryption
    "chacha20-poly1305@openssh.com":  ["AEAD; preferred over CBC+MAC and CTR+MAC", "OpenSSH-specific (no IETF SSH RFC counterpart)"],
    "aes256-gcm@openssh.com":         ["AEAD; preferred over CBC+MAC and CTR+MAC"],
    "aes128-gcm@openssh.com":         ["AEAD; preferred over CBC+MAC and CTR+MAC"],
    "aes256-ctr":                     ["no AEAD"],
    "aes192-ctr":                     ["no AEAD"],
    "aes128-ctr":                     ["no AEAD"],
    "aes256-cbc":                     ["CBC padding-oracle risk", "prefer AES-GCM (AEAD) or AES-CTR + HMAC-ETM"],
    "3des-cbc":                       ["64-bit block; birthday-bound vulnerable above 32 GB", "disallowed for encryption since 2024 (SP 800-131A Rev 2)"],
    # MACs
    "hmac-sha2-256-etm@openssh.com":  ["encrypt-then-MAC; preferred construction", "OpenSSH-specific (no IETF SSH RFC counterpart)"],
    "hmac-sha2-512-etm@openssh.com":  ["encrypt-then-MAC; preferred construction", "OpenSSH-specific (no IETF SSH RFC counterpart)"],
    "umac-128-etm@openssh.com":       ["UMAC-128 (RFC 4418); OpenSSH-specific"],
    "hmac-sha2-256":                  ["MAC-then-Encrypt construction"],
    "hmac-sha2-512":                  ["MAC-then-Encrypt construction"],
    # New legacy / disallowed entries
    "curve25519-sha256@libssh.org":   ["alias for curve25519-sha256"],
    "diffie-hellman-group15-sha512":  ["3072-bit MODP; not in BSI table"],
    "diffie-hellman-group17-sha512":  ["6144-bit MODP; not in BSI table"],
    "diffie-hellman-group-exchange-sha256": ["client-chosen group (RFC 4419)"],
    "diffie-hellman-group14-sha1":    ["RFC 9142 §3.4 retains MAY despite SHA-1 — NIST/BSI disallow"],
    "diffie-hellman-group1-sha1":     ["1024-bit MODP + SHA-1"],
    "diffie-hellman-group-exchange-sha1": ["SHA-1"],
    "ssh-ed448":                      ["EdDSA over Curve448; not listed in BSI table"],
    "ssh-rsa":                        ["RSA with SHA-1; OpenSSH disabled by default since 8.8"],
    "ssh-dss":                        ["DSA-1024 with SHA-1"],
    "arcfour":                        ["RC4; cryptographically broken; explicitly removed by RFC 8758"],
    "arcfour128":                     ["RC4; cryptographically broken; explicitly removed by RFC 8758"],
    "arcfour256":                     ["RC4; cryptographically broken; explicitly removed by RFC 8758"],
    "hmac-sha1":                      ["SHA-1; was REQUIRED in RFC 4253"],
    "hmac-sha1-96":                   ["SHA-1; truncated to 96 bits"],
    "hmac-md5":                       ["MD5; collision-vulnerable"],
    "hmac-md5-96":                    ["MD5; truncated to 96 bits"],
}


# REMARKS_TLS — top-level remarks for TLS composite entries.
# Most TLS entries get all the citation context they need from iana.references[]
# (the IANA-CSV-derived list with semantic notes). Use this dict only for
# entries where an algorithm-intrinsic fact materially aids interpretation.

REMARKS_TLS = {
    # TLS 1.3 baseline
    "TLS_AES_128_GCM_SHA256":              ["AEAD; default TLS 1.3 baseline", "128-bit security"],
    "TLS_AES_256_GCM_SHA384":              ["AEAD; 256-bit security"],
    "TLS_AES_128_CCM_SHA256":              ["AEAD with 16-byte tag", "128-bit security"],
    "TLS_AES_128_CCM_8_SHA256":            ["AEAD with 8-byte tag — BSI prefers full 16-byte tags"],
    "TLS_CHACHA20_POLY1305_SHA256":        ["AEAD", "BSI does not recommend stream ciphers (TR-02102-1)"],
    # TLS 1.2 PSK without PFS — explains why BSI useUpTo is shorter than DHE_PSK / ECDHE_PSK
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256": ["no Perfect Forward Secrecy (RSA key transport in PSK derivation)"],
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384": ["no Perfect Forward Secrecy (RSA key transport in PSK derivation)"],
    "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256": ["no Perfect Forward Secrecy (RSA key transport in PSK derivation)"],
    "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384": ["no Perfect Forward Secrecy (RSA key transport in PSK derivation)"],
    # TLS 1.2 (EC)DH non-PFS — explains BSI's 2026 short-deadline
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384": ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256":   ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384":   ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256":     ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384":     ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256":     ["static-key cipher suite — no Perfect Forward Secrecy"],
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384":     ["static-key cipher suite — no Perfect Forward Secrecy"],
    # TLS 1.2 CBC suites — Lucky 13 / Encrypt-then-MAC requirement
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":   ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256":     ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256":     ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":     ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":     ["CBC mode — pair with Encrypt-then-MAC extension (RFC 7366) to mitigate Lucky 13"],
}


IETF_SSH = {
    # KEX — RFC 9142
    "curve25519-sha256":                    ("SHOULD",     "RFC 9142 §3.1.1"),
    "curve25519-sha256@libssh.org":         (None,         "OpenSSH alias predating RFC 8731"),
    "ecdh-sha2-nistp256":                   ("SHOULD",     "RFC 9142 §3.1.3"),
    "ecdh-sha2-nistp384":                   ("SHOULD",     "RFC 9142 §3.1.3"),
    "ecdh-sha2-nistp521":                   ("SHOULD",     "RFC 9142 §3.1.3"),
    "diffie-hellman-group14-sha256":        ("MUST",       "RFC 9142 §3.2.2"),
    "diffie-hellman-group15-sha512":        ("MAY",        "RFC 9142 §3.2.2"),
    "diffie-hellman-group16-sha512":        ("SHOULD",     "RFC 9142 §3.2.2"),
    "diffie-hellman-group17-sha512":        ("MAY",        "RFC 9142 §3.2.2"),
    "diffie-hellman-group18-sha512":        ("MAY",        "RFC 9142 §3.2.2"),
    "diffie-hellman-group-exchange-sha256": ("MAY",        "RFC 9142 §3.2.1"),
    "diffie-hellman-group14-sha1":          ("MAY",        "RFC 9142 §3.4"),
    "diffie-hellman-group1-sha1":           ("SHOULD-NOT", "RFC 9142 §3.4"),
    "diffie-hellman-group-exchange-sha1":   ("SHOULD-NOT", "RFC 9142 §3.2.1"),
    # Host auth
    "ssh-ed25519":                          ("MAY",        "RFC 8709"),
    "ssh-ed448":                            ("MAY",        "RFC 8709"),
    "ecdsa-sha2-nistp256":                  ("MAY",        "RFC 5656"),
    "ecdsa-sha2-nistp384":                  ("MAY",        "RFC 5656"),
    "ecdsa-sha2-nistp521":                  ("MAY",        "RFC 5656"),
    "rsa-sha2-256":                         ("SHOULD",     "RFC 8332 §3.3"),
    "rsa-sha2-512":                         ("SHOULD",     "RFC 8332 §3.3"),
    "ssh-rsa":                              ("SHOULD-NOT", "RFC 8332 §3.3"),
    "ssh-dss":                              ("SHOULD-NOT", "RFC 4253"),
    # Symmetric encryption
    "chacha20-poly1305@openssh.com":        (None,         "OpenSSH extension — not in any IETF SSH RFC"),
    "aes256-gcm@openssh.com":               ("MAY",        "RFC 5647"),
    "aes128-gcm@openssh.com":               ("MAY",        "RFC 5647"),
    "aes256-ctr":                           ("SHOULD",     "RFC 4344 §4"),
    "aes192-ctr":                           ("SHOULD",     "RFC 4344 §4"),
    "aes128-ctr":                           ("SHOULD",     "RFC 4344 §4"),
    "aes256-cbc":                           ("MAY",        "RFC 4253"),
    "3des-cbc":                             ("MAY",        "RFC 4253"),
    "arcfour":                              ("MUST-NOT",   "RFC 8758"),
    "arcfour128":                           ("MUST-NOT",   "RFC 8758"),
    "arcfour256":                           ("MUST-NOT",   "RFC 8758"),
    # MACs
    "hmac-sha2-256-etm@openssh.com":        (None,         "OpenSSH extension — not in any IETF SSH RFC"),
    "hmac-sha2-512-etm@openssh.com":        (None,         "OpenSSH extension — not in any IETF SSH RFC"),
    "umac-128-etm@openssh.com":             (None,         "OpenSSH extension — not in any IETF SSH RFC"),
    "hmac-sha2-256":                        ("SHOULD",     "RFC 6668"),
    "hmac-sha2-512":                        ("SHOULD",     "RFC 6668"),
    "hmac-sha1":                            ("MAY",        "RFC 4253"),
    "hmac-sha1-96":                         ("MAY",        "RFC 4253"),
    "hmac-md5":                             ("MAY",        "RFC 4253"),
    "hmac-md5-96":                          ("MAY",        "RFC 4253"),
}


# ── BSI TR-02102-2 v2026-01 overlay (TLS recommendations) ─────────────────────
#
# Source of truth for BSI's per-cipher-suite TLS recommendations. Values are
# emitted into the cr-tls.yaml entries' `bsi:` block. `useUpTo` follows BSI's
# notation: a year, optionally with a "+" suffix meaning the period may be
# extended in a future revision.
#
# Document: BSI TR-02102-2 "Use of Transport Layer Security (TLS)", v2026-01,
# 2026-01-27. Tables 3, 4, 5 (cipher suites), 6, 10 (DH groups), 7, 11, 12
# (signature algorithms), 13 (TLS 1.3 cipher suites).

_BSI_DOC = "TR-02102-2 v2026-01"

BSI_TLS_CIPHER_SUITES = {
    # TLS 1.3 — Table 13
    "TLS_AES_128_GCM_SHA256":                          ("recommended", "2032+", "§3.4.4 Table 13"),
    "TLS_AES_256_GCM_SHA384":                          ("recommended", "2032+", "§3.4.4 Table 13"),
    "TLS_AES_128_CCM_SHA256":                          ("recommended", "2032+", "§3.4.4 Table 13"),
    # TLS 1.2 (EC)DHE PFS — Table 3 (use up to 2031 for ECDHE; 2029 for DHE)
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":         ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":         ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":         ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":         ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM":                ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM":                ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":           ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":           ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":           ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":           ("recommended", "2031",  "§3.3.1.1 Table 3"),
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":             ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_RSA_WITH_AES_128_CCM":                    ("recommended", "2029",  "§3.3.1.1 Table 3"),
    "TLS_DHE_RSA_WITH_AES_256_CCM":                    ("recommended", "2029",  "§3.3.1.1 Table 3"),
    # TLS 1.2 (EC)DH non-PFS — Table 4 (use up to 2026)
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256":          ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384":          ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256":          ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384":          ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256":            ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384":            ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256":            ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384":            ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384":              ("recommended", "2026",  "§3.3.1.2 Table 4"),
    # TLS 1.2 PSK — Table 5
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256":           ("recommended", "2031",  "§3.3.1.3 Table 5"),
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384":           ("recommended", "2031",  "§3.3.1.3 Table 5"),
    "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256":           ("recommended", "2031",  "§3.3.1.3 Table 5"),
    "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384":           ("recommended", "2031",  "§3.3.1.3 Table 5"),
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256":           ("recommended", "2031",  "§3.3.1.3 Table 5"),
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256":             ("recommended", "2029",  "§3.3.1.3 Table 5"),
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384":             ("recommended", "2029",  "§3.3.1.3 Table 5"),
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256":             ("recommended", "2029",  "§3.3.1.3 Table 5"),
    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384":             ("recommended", "2029",  "§3.3.1.3 Table 5"),
    "TLS_DHE_PSK_WITH_AES_128_CCM":                    ("recommended", "2029",  "§3.3.1.3 Table 5"),
    "TLS_DHE_PSK_WITH_AES_256_CCM":                    ("recommended", "2029",  "§3.3.1.3 Table 5"),
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256":             ("recommended", "2026",  "§3.3.1.3 Table 5"),
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384":             ("recommended", "2026",  "§3.3.1.3 Table 5"),
    "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256":             ("recommended", "2026",  "§3.3.1.3 Table 5"),
    "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384":             ("recommended", "2026",  "§3.3.1.3 Table 5"),
}

# Human-readable descriptions for TLS supported groups, rendered as the
# Description column in the §12.5 / §12.8 markdown tables. Optional — the
# renderer falls back to the IANA name when no description is supplied.
DESCRIPTIONS_TLS_GROUPS = {
    "secp256r1":             "P-256 (secp256r1); 128-bit security",
    "secp384r1":             "P-384 (secp384r1); 192-bit security",
    "secp521r1":             "P-521 (secp521r1); 256-bit security",
    "x25519":                "Curve25519; 128-bit security",
    "x448":                  "Curve448; 224-bit security",
    "brainpoolP256r1":       "Brainpool P-256r1 (TLS 1.2); 128-bit security",
    "brainpoolP384r1":       "Brainpool P-384r1 (TLS 1.2); 192-bit security",
    "brainpoolP512r1":       "Brainpool P-512r1 (TLS 1.2); 256-bit security",
    "brainpoolP256r1tls13":  "Brainpool P-256r1 (TLS 1.3); 128-bit security",
    "brainpoolP384r1tls13":  "Brainpool P-384r1 (TLS 1.3); 192-bit security",
    "brainpoolP512r1tls13":  "Brainpool P-512r1 (TLS 1.3); 256-bit security",
    "ffdhe2048":             "2048-bit FFDHE (named, RFC 7919); 112-bit security",
    "ffdhe3072":             "3072-bit FFDHE (named, RFC 7919); 128-bit security",
    "ffdhe4096":             "4096-bit FFDHE (named, RFC 7919)",
    "ffdhe6144":             "6144-bit FFDHE (named, RFC 7919)",
    "ffdhe8192":             "8192-bit FFDHE (named, RFC 7919)",
    "X25519MLKEM768":        "hybrid: X25519 (128-bit classical) + ML-KEM-768 (NIST Level 3)",
    "SecP256r1MLKEM768":     "hybrid: P-256 (128-bit classical) + ML-KEM-768 (NIST Level 3)",
    "SecP384r1MLKEM1024":    "hybrid: P-384 (192-bit classical) + ML-KEM-1024 (NIST Level 5)",
    "MLKEM512":              "ML-KEM-512 (post-quantum; NIST Level 1)",
    "MLKEM768":              "ML-KEM-768 (post-quantum; NIST Level 3)",
    "MLKEM1024":             "ML-KEM-1024 (post-quantum; NIST Level 5)",
}

# DH groups (Tables 6 + 10). IANA value as dict key (string form, e.g. "23").
BSI_TLS_GROUPS = {
    # TLS 1.2 — Table 6 / TLS 1.3 — Table 10
    "secp256r1":            ("recommended", "2031",  "§3.3.2 Table 6 / §3.4.2 Table 10"),
    "secp384r1":            ("recommended", "2031",  "§3.3.2 Table 6 / §3.4.2 Table 10"),
    "secp521r1":            ("recommended", "2031",  "§3.3.2 Table 6 / §3.4.2 Table 10"),
    "brainpoolP256r1":      ("recommended", "2031",  "§3.3.2 Table 6 (TLS 1.2 only)"),
    "brainpoolP384r1":      ("recommended", "2031",  "§3.3.2 Table 6 (TLS 1.2 only)"),
    "brainpoolP512r1":      ("recommended", "2031",  "§3.3.2 Table 6 (TLS 1.2 only)"),
    "brainpoolP256r1tls13": ("recommended", "2031",  "§3.4.2 Table 10 (TLS 1.3 only)"),
    "brainpoolP384r1tls13": ("recommended", "2031",  "§3.4.2 Table 10 (TLS 1.3 only)"),
    "brainpoolP512r1tls13": ("recommended", "2031",  "§3.4.2 Table 10 (TLS 1.3 only)"),
    # ffdhe groups have different end dates per TLS version (2029 for TLS 1.2, 2031 for TLS 1.3)
    # We pick the longer horizon and document the nuance in `note`.
    "ffdhe3072":            ("recommended", "2031",  "§3.3.2 Table 6 (2029 TLS 1.2) / §3.4.2 Table 10 (2031 TLS 1.3)"),
    "ffdhe4096":            ("recommended", "2031",  "§3.3.2 Table 6 (2029 TLS 1.2) / §3.4.2 Table 10 (2031 TLS 1.3)"),
}

# Signature schemes (Tables 7 + 11/12). Keyed on IANA description string used
# in the signature_schemes registry.
BSI_TLS_SIGS = {
    # TLS 1.3 — Table 11 (signature_algorithms)
    "rsa_pss_rsae_sha256":              ("recommended", "2032+", "§3.4.3 Table 11"),
    "rsa_pss_rsae_sha384":              ("recommended", "2032+", "§3.4.3 Table 11"),
    "rsa_pss_rsae_sha512":              ("recommended", "2032+", "§3.4.3 Table 11"),
    "rsa_pss_pss_sha256":               ("recommended", "2032+", "§3.4.3 Table 11"),
    "rsa_pss_pss_sha384":               ("recommended", "2032+", "§3.4.3 Table 11"),
    "rsa_pss_pss_sha512":               ("recommended", "2032+", "§3.4.3 Table 11"),
    "ecdsa_secp256r1_sha256":           ("recommended", "2032+", "§3.4.3 Table 11"),
    "ecdsa_secp384r1_sha384":           ("recommended", "2032+", "§3.4.3 Table 11"),
    "ecdsa_secp521r1_sha512":           ("recommended", "2032+", "§3.4.3 Table 11"),
    "ecdsa_brainpoolP256r1tls13_sha256": ("recommended", "2032+", "§3.4.3 Table 11"),
    "ecdsa_brainpoolP384r1tls13_sha384": ("recommended", "2032+", "§3.4.3 Table 11"),
    "ecdsa_brainpoolP512r1tls13_sha512": ("recommended", "2032+", "§3.4.3 Table 11"),
    # TLS 1.3 — Table 12 (signature_algorithms_cert): adds three PKCS #1 v1.5
    "rsa_pkcs1_sha256":                 ("recommended", "2025",  "§3.4.3 Table 12 (signature_algorithms_cert; PKCS #1 v1.5)"),
    "rsa_pkcs1_sha384":                 ("recommended", "2025",  "§3.4.3 Table 12 (signature_algorithms_cert; PKCS #1 v1.5)"),
    "rsa_pkcs1_sha512":                 ("recommended", "2025",  "§3.4.3 Table 12 (signature_algorithms_cert; PKCS #1 v1.5)"),
}

# ── NIST SP 800-52 Rev 2 overlay (TLS recommendations) ────────────────────────
#
# Source of truth for NIST's per-cipher-suite TLS recommendations. SP 800-52r2
# is a "shall be configured to use only NIST-approved cipher suites"-style
# requirement document; no use-up-to dates are assigned. Status is "approved"
# for any suite that appears in §3.3.1.1 or §3.3.1.2 as allowed for federal use.
#
# Document: NIST SP 800-52 Rev 2 "Guidelines for the Selection, Configuration,
# and Use of Transport Layer Security (TLS) Implementations", August 2019.

_NIST_DOC = "SP 800-52 Rev 2"

NIST_TLS_CIPHER_SUITES = {
    # TLS 1.3 — §3.3.1.2
    "TLS_AES_128_GCM_SHA256":                          ("approved", "§3.3.1.2"),
    "TLS_AES_256_GCM_SHA384":                          ("approved", "§3.3.1.2"),
    "TLS_AES_128_CCM_SHA256":                          ("approved", "§3.3.1.2"),
    "TLS_AES_128_CCM_8_SHA256":                        ("approved", "§3.3.1.2"),
    # TLS 1.2 ECDSA cert — §3.3.1.1.1
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":         ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":         ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM":                ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM":                ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8":              ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8":              ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":         ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":         ("approved", "§3.3.1.1.1"),
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":            ("approved", "§3.3.1.1.1 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":            ("approved", "§3.3.1.1.1 (TLS 1.0/1.1/1.2 interop only)"),
    # TLS 1.2 RSA cert — §3.3.1.1.2
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":           ("approved", "§3.3.1.1.2"),
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":           ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":             ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":             ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_128_CCM":                    ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_256_CCM":                    ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_128_CCM_8":                  ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_256_CCM_8":                  ("approved", "§3.3.1.1.2"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":           ("approved", "§3.3.1.1.2"),
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":           ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":             ("approved", "§3.3.1.1.2"),
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":             ("approved", "§3.3.1.1.2"),
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":              ("approved", "§3.3.1.1.2 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":              ("approved", "§3.3.1.1.2 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA":                ("approved", "§3.3.1.1.2 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA":                ("approved", "§3.3.1.1.2 (TLS 1.0/1.1/1.2 interop only)"),
    # TLS 1.2 DSA cert — §3.3.1.1.3
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256":             ("approved", "§3.3.1.1.3"),
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384":             ("approved", "§3.3.1.1.3"),
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256":             ("approved", "§3.3.1.1.3"),
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256":             ("approved", "§3.3.1.1.3"),
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA":                ("approved", "§3.3.1.1.3 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA":                ("approved", "§3.3.1.1.3 (TLS 1.0/1.1/1.2 interop only)"),
    # TLS 1.2 DH-DSS-signed cert — §3.3.1.1.4
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA":                 ("approved", "§3.3.1.1.4 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA":                 ("approved", "§3.3.1.1.4 (TLS 1.0/1.1/1.2 interop only)"),
    # TLS 1.2 DH-RSA-signed cert — §3.3.1.1.4
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256":              ("approved", "§3.3.1.1.4"),
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA":                 ("approved", "§3.3.1.1.4 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA":                 ("approved", "§3.3.1.1.4 (TLS 1.0/1.1/1.2 interop only)"),
    # TLS 1.2 ECDH-ECDSA-signed cert — §3.3.1.1.5
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256":          ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384":          ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256":          ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384":          ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA":             ("approved", "§3.3.1.1.5 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA":             ("approved", "§3.3.1.1.5 (TLS 1.0/1.1/1.2 interop only)"),
    # TLS 1.2 ECDH-RSA-signed cert — §3.3.1.1.5
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256":            ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384":            ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256":            ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384":            ("approved", "§3.3.1.1.5"),
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA":               ("approved", "§3.3.1.1.5 (TLS 1.0/1.1/1.2 interop only)"),
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA":               ("approved", "§3.3.1.1.5 (TLS 1.0/1.1/1.2 interop only)"),
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


# ── IANA reference parsing ────────────────────────────────────────────────────
#
# IANA references appear in the form `[RFC5246][RFC-ietf-tls-deprecate-...]`.
# We extract each [...] token, normalise `RFC1234` → `RFC 1234`, and attach a
# semantic note when the token is a known IETF in-progress track.

_REF_TOKEN_RE = re.compile(r"\[([^\]]+)\]")
_RFC_NUMBER_RE = re.compile(r"^RFC(\d+)$")

_REFERENCE_NOTES = {
    "RFC-ietf-tls-deprecate-obsolete-kex-08":   "scheduled for deprecation (TLS 1.2 obsolete-kex draft)",
    "RFC-ietf-tls-rfc8446bis-13":               "TLS 1.3 RFC 8446bis revision",
    "RFC-ietf-tls-tls13-pkcs1-07":              "TLS 1.3 PKCS #1 v1.5 signature draft",
    "RFC9155":                                  "deprecates SHA-1 and MD5 in TLS",
    "RFC9847":                                  "deprecates obsolete TLS supported groups",
    "RFC6347":                                  "DTLS 1.2 mapping",
}


def parse_iana_references(reference_field: str) -> list[dict]:
    """Parse an IANA Reference column value into a list of {ref[, note]} dicts.

    Each `[...]` token becomes one entry. `RFC1234` is normalised to `RFC 1234`;
    other tokens are kept as-is. Known semantic notes from `_REFERENCE_NOTES`
    are attached automatically.
    """
    refs = []
    for raw in _REF_TOKEN_RE.findall(reference_field or ""):
        m = _RFC_NUMBER_RE.match(raw)
        if m:
            normalised = f"RFC {m.group(1)}"
        else:
            normalised = raw
        entry = {"ref": normalised}
        # Look up note by both raw and normalised key
        note = _REFERENCE_NOTES.get(raw) or _REFERENCE_NOTES.get(normalised)
        if note:
            entry["note"] = note
        refs.append(entry)
    return refs


# ── Cipher suite decomposition ─────────────────────────────────────────────────

# TLS 1.3 pattern: TLS_<CIPHER>_<HASH>
TLS13_RE = re.compile(r"^TLS_([A-Za-z0-9_]+?)_(SHA\d*|SM3|ASCONHASH256)$")

# TLS 1.2 pattern: TLS_<KEX>_<AUTH>_WITH_<CIPHER>_<HASH>
# Also handles TLS_<KEX>_WITH_<CIPHER>_<HASH> (PSK without separate auth)
TLS12_WITH_RE = re.compile(r"^TLS_(.+?)_WITH_(.+?)_(SHA\d*|MD5|SM3)$")

# CCM-suffixed suites (RFC 6655 / RFC 7251) — `_CCM` or `_CCM_8` ending,
# implicit SHA-256 for the PRF / HKDF.
TLS12_CCM_RE = re.compile(r"^TLS_(.+?)_WITH_(AES_(?:128|256)_CCM(?:_8)?)$")


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
    # Handle CCM-suffixed suites first (no SHA in the name; implicit SHA-256).
    m_ccm = TLS12_CCM_RE.match(name)
    if m_ccm:
        kex_auth_raw, cipher_raw = m_ccm.group(1), m_ccm.group(2)
        hash_raw = "SHA256"
    else:
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


def format_ref_inline(r: dict) -> str:
    """Format a single reference dict as an inline-flow YAML mapping.

    Produces `{ ref: "..." }` or `{ ref: "...", note: "..." }`.
    """
    parts = [f'ref: {yaml_str(r["ref"])}']
    if "note" in r:
        parts.append(f'note: {yaml_str(r["note"])}')
    return "{ " + ", ".join(parts) + " }"


def format_entry(entry: dict) -> str:
    """Format a single registry entry as YAML text."""
    lines = []
    lines.append(f'  - id: {yaml_str(entry["id"])}')
    lines.append(f'    type: "composite"')
    lines.append(f'    subType: {yaml_str(entry["subType"])}')
    lines.append(f'    protocol: "TLS"')
    if entry.get("description"):
        lines.append(f'    description: {yaml_str(entry["description"])}')

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
    # references list — emit inline-flow per item for compactness
    references = iana.get("references", [])
    if references:
        lines.append(f'      references:')
        for r in references:
            lines.append(f'        - {format_ref_inline(r)}')

    # nist block (SP 800-52 Rev 2 overlay)
    nist = entry.get("nist")
    if nist:
        lines.append(f'    nist:')
        lines.append(f'      source: {yaml_str(nist["source"])}')
        lines.append(f'      status: {yaml_str(nist["status"])}')
        if "note" in nist:
            lines.append(f'      note: {yaml_str(nist["note"])}')

    # bsi block (TR-02102-2 v2026-01 overlay)
    bsi = entry.get("bsi")
    if bsi:
        lines.append(f'    bsi:')
        lines.append(f'      source: {yaml_str(bsi["source"])}')
        lines.append(f'      status: {yaml_str(bsi["status"])}')
        if "useUpTo" in bsi:
            lines.append(f'      useUpTo: {yaml_str(bsi["useUpTo"])}')
        if bsi.get("requires"):
            lines.append(f'      requires:')
            for req in bsi["requires"]:
                lines.append(f'        - {yaml_str(req)}')
        if "note" in bsi:
            lines.append(f'      note: {yaml_str(bsi["note"])}')

    # remarks (algorithm-intrinsic / editorial; not tied to a citation or authority)
    remarks = entry.get("remarks", [])
    if remarks:
        lines.append(f'    remarks:')
        for r in remarks:
            lines.append(f'      - {yaml_str(r)}')

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
    parts.append("# Auto-generated from IANA TLS parameter registries with NIST and BSI authority")
    parts.append("# overlays. Source of truth for per-cipher-suite recommendations from:")
    parts.append("#   - IANA  (recommended flag from the TLS Parameters registry)")
    parts.append("#   - NIST  SP 800-52 Rev 2 (Aug 2019) — federal allowed cipher suites by cert type")
    parts.append("#   - BSI   TR-02102-2 v2026-01 (Jan 2026) — recommendations with `useUpTo` deadlines")
    parts.append("#")
    parts.append("# Do not edit manually; regenerate with:")
    parts.append("#   python scripts/generate_protocol_composites.py")
    parts.append("#")
    parts.append("# Authority overlay tables live in scripts/generate_protocol_composites.py")
    parts.append("# (BSI_TLS_CIPHER_SUITES, BSI_TLS_GROUPS, BSI_TLS_SIGS, NIST_TLS_CIPHER_SUITES).")
    parts.append("# Update those tables when the upstream documents are revised.")
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
                "references": parse_iana_references(row.get("Reference", "")),
            },
            "components": result["components"],
        }
        # NIST SP 800-52 Rev 2 overlay
        nist_entry = NIST_TLS_CIPHER_SUITES.get(desc)
        if nist_entry:
            status, section = nist_entry
            entry["nist"] = {
                "source": f"{_NIST_DOC} {section}",
                "status": status,
            }
        # BSI TR-02102-2 v2026-01 overlay
        bsi_entry = BSI_TLS_CIPHER_SUITES.get(desc)
        if bsi_entry:
            status, use_up_to, section = bsi_entry
            entry["bsi"] = {
                "source": f"{_BSI_DOC} {section}",
                "status": status,
                "useUpTo": use_up_to,
            }
        # remarks (algorithm-intrinsic notes)
        remarks = REMARKS_TLS.get(desc)
        if remarks:
            entry["remarks"] = list(remarks)
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
                "references": parse_iana_references(row.get("Reference", "")),
            },
            "components": components,
        }
        if desc in DESCRIPTIONS_TLS_GROUPS:
            entry["description"] = DESCRIPTIONS_TLS_GROUPS[desc]
        # BSI TR-02102-2 v2026-01 overlay (Tables 6 + 10)
        bsi_entry = BSI_TLS_GROUPS.get(desc)
        if bsi_entry:
            status, use_up_to, section = bsi_entry
            entry["bsi"] = {
                "source": f"{_BSI_DOC} {section}",
                "status": status,
                "useUpTo": use_up_to,
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
                "references": parse_iana_references(row.get("Reference", "")),
            },
            "components": [mapping],
        }
        # BSI TR-02102-2 v2026-01 overlay (Tables 11/12)
        bsi_entry = BSI_TLS_SIGS.get(desc)
        if bsi_entry:
            status, use_up_to, section = bsi_entry
            entry["bsi"] = {
                "source": f"{_BSI_DOC} {section}",
                "status": status,
                "useUpTo": use_up_to,
            }
        entries.append(entry)

    return entries, failures


# ── SSH composite generation ──────────────────────────────────────────────────

def _attach_ssh_overlays(entry: dict) -> dict:
    """Attach IETF / NIST / BSI overlays + remarks to an SSH entry."""
    name = entry["id"]
    ietf = IETF_SSH.get(name)
    if ietf:
        level, source = ietf
        entry["ietf"] = {"source": source}
        if level:
            entry["ietf"]["level"] = level
    nist = NIST_SSH.get(name)
    if nist:
        status, note = nist
        entry["nist"] = {
            "source": _NIST_SSH_DOC,
            "status": status,
            "note": note,
        }
    bsi = BSI_SSH.get(name)
    if bsi and bsi.get("bsi"):
        status, use_up_to, section = bsi["bsi"]
        entry["bsi"] = {
            "source": f"{_BSI_SSH_DOC} {section}" if section else _BSI_SSH_DOC,
            "status": status,
        }
        if use_up_to:
            entry["bsi"]["useUpTo"] = use_up_to
        if bsi.get("requires"):
            entry["bsi"]["requires"] = list(bsi["requires"])
    remarks = REMARKS_SSH.get(name)
    if remarks:
        entry["remarks"] = list(remarks)
    return entry


def generate_ssh_entries() -> list[dict]:
    """Generate SSH composite entries from hardcoded lookup tables."""
    entries = []

    for name, components in SSH_KEX_MAP.items():
        entries.append(_attach_ssh_overlays({
            "id": name,
            "subType": "sshKex",
            "components": components,
        }))

    for name, components in SSH_HOST_AUTH_MAP.items():
        entries.append(_attach_ssh_overlays({
            "id": name,
            "subType": "sshHostAuth",
            "components": components,
        }))

    for name, components in SSH_CIPHER_MAP.items():
        entries.append(_attach_ssh_overlays({
            "id": name,
            "subType": "sshCipher",
            "components": components,
        }))

    for name, components in SSH_MAC_MAP.items():
        entries.append(_attach_ssh_overlays({
            "id": name,
            "subType": "sshMac",
            "components": components,
        }))

    return entries


def format_ssh_entry(entry: dict) -> str:
    """Format a single SSH registry entry as YAML text."""
    lines = []
    lines.append(f'  - id: {yaml_str(entry["id"])}')
    lines.append(f'    type: "composite"')
    lines.append(f'    subType: {yaml_str(entry["subType"])}')
    lines.append(f'    protocol: "SSH"')
    if entry.get("description"):
        lines.append(f'    description: {yaml_str(entry["description"])}')

    # ietf block (RFC 9142 / 8332 / 8709 / 5656 / 4253 / 4344 / 5647 / 6668)
    ietf = entry.get("ietf")
    if ietf:
        lines.append(f'    ietf:')
        lines.append(f'      source: {yaml_str(ietf["source"])}')
        if "level" in ietf:
            lines.append(f'      level: {yaml_str(ietf["level"])}')

    # nist block (SP 800-131A Rev 2 transition guidance)
    nist = entry.get("nist")
    if nist:
        lines.append(f'    nist:')
        lines.append(f'      source: {yaml_str(nist["source"])}')
        lines.append(f'      status: {yaml_str(nist["status"])}')
        if "note" in nist:
            lines.append(f'      note: {yaml_str(nist["note"])}')

    # bsi block (TR-02102-4 v2026-01)
    bsi = entry.get("bsi")
    if bsi:
        lines.append(f'    bsi:')
        lines.append(f'      source: {yaml_str(bsi["source"])}')
        lines.append(f'      status: {yaml_str(bsi["status"])}')
        if "useUpTo" in bsi:
            lines.append(f'      useUpTo: {yaml_str(bsi["useUpTo"])}')
        if bsi.get("requires"):
            lines.append(f'      requires:')
            for req in bsi["requires"]:
                lines.append(f'        - {yaml_str(req)}')
        if "note" in bsi:
            lines.append(f'      note: {yaml_str(bsi["note"])}')

    # remarks
    remarks = entry.get("remarks", [])
    if remarks:
        lines.append(f'    remarks:')
        for r in remarks:
            lines.append(f'      - {yaml_str(r)}')

    components = entry.get("components", [])
    comp_str = ", ".join(yaml_str(c) for c in components)
    lines.append(f'    components: [{comp_str}]')

    return "\n".join(lines)


def generate_ssh_yaml(entries: list[dict]) -> str:
    """Generate the full SSH YAML document."""
    parts = []
    parts.append("# SSH protocol composites: KEX, host auth, ciphers, MACs")
    parts.append("#")
    parts.append("# Auto-generated from hardcoded lookup tables with NIST and BSI authority")
    parts.append("# overlays. Source of truth for per-algorithm SSH recommendations from:")
    parts.append("#   - IETF  RFC 9142 (KEX), RFC 8332/8709/5656 (auth), RFC 4253/4344/5647/8758")
    parts.append("#         (ciphers), RFC 4253/6668 (MACs) — IETF requirement level (MUST/SHOULD/MAY)")
    parts.append("#   - NIST  SP 800-131A Rev 2 — algorithm transition status")
    parts.append("#   - BSI   TR-02102-4 v2026-01 — recommendations and migration deadlines")
    parts.append("#")
    parts.append("# Do not edit manually; regenerate with:")
    parts.append("#   python scripts/generate_protocol_composites.py")
    parts.append("#")
    parts.append("# Authority overlay tables live in scripts/generate_protocol_composites.py")
    parts.append("# (BSI_SSH, NIST_SSH, IETF_SSH). Update those tables when the upstream")
    parts.append("# documents are revised.")
    parts.append("#")
    parts.append("# Part of the ae-pattern-validator validation registry.")
    parts.append('version: "2.0"')
    parts.append("")
    parts.append("entries:")

    for entry in entries:
        parts.append("")
        parts.append(format_ssh_entry(entry))

    return "\n".join(parts) + "\n"


def generate_ipsec_entries() -> list[dict]:
    """Generate IPsec composite entries from IPSEC_ENTRIES with overlays."""
    entries = []
    for name, spec in IPSEC_ENTRIES.items():
        entry = {
            "id": name,
            "subType": spec["subType"],
            "components": list(spec["components"]),
        }
        if spec.get("description"):
            entry["description"] = spec["description"]
        ietf = spec.get("ietf")
        if ietf:
            level, source = ietf
            entry["ietf"] = {"source": source}
            if level:
                entry["ietf"]["level"] = level
        ietf_ikev2 = spec.get("ietfIkev2")
        if ietf_ikev2:
            level, source = ietf_ikev2
            entry["ietfIkev2"] = {"source": source}
            if level:
                entry["ietfIkev2"]["level"] = level
        nist = spec.get("nist")
        if nist:
            status, note = nist
            entry["nist"] = {
                "source": _NIST_IPSEC_DOC,
                "status": status,
                "note": note,
            }
        bsi = spec.get("bsi")
        if bsi:
            status, use_up_to, section = bsi
            entry["bsi"] = {
                "source": f"{_BSI_IPSEC_DOC} {section}" if section else _BSI_IPSEC_DOC,
                "status": status,
            }
            if use_up_to:
                entry["bsi"]["useUpTo"] = use_up_to
            if spec.get("requires"):
                entry["bsi"]["requires"] = list(spec["requires"])
        remarks = spec.get("remarks")
        if remarks:
            entry["remarks"] = list(remarks)
        entries.append(entry)
    return entries


def format_ipsec_entry(entry: dict) -> str:
    """Format a single IPsec registry entry as YAML text."""
    lines = []
    lines.append(f'  - id: {yaml_str(entry["id"])}')
    lines.append(f'    type: "composite"')
    lines.append(f'    subType: {yaml_str(entry["subType"])}')
    lines.append(f'    protocol: "IPsec"')
    if entry.get("description"):
        lines.append(f'    description: {yaml_str(entry["description"])}')

    ietf = entry.get("ietf")
    if ietf:
        lines.append(f'    ietf:')
        lines.append(f'      source: {yaml_str(ietf["source"])}')
        if "level" in ietf:
            lines.append(f'      level: {yaml_str(ietf["level"])}')

    # ietfIkev2 — RFC 8247 IKEv2 control-plane requirement level (separate
    # from RFC 8221 ESP/AH data-plane level above; the two RFCs disagree on
    # requirement level for several transforms).
    ietf_ikev2 = entry.get("ietfIkev2")
    if ietf_ikev2:
        lines.append(f'    ietfIkev2:')
        lines.append(f'      source: {yaml_str(ietf_ikev2["source"])}')
        if "level" in ietf_ikev2:
            lines.append(f'      level: {yaml_str(ietf_ikev2["level"])}')

    nist = entry.get("nist")
    if nist:
        lines.append(f'    nist:')
        lines.append(f'      source: {yaml_str(nist["source"])}')
        lines.append(f'      status: {yaml_str(nist["status"])}')
        if "note" in nist:
            lines.append(f'      note: {yaml_str(nist["note"])}')

    bsi = entry.get("bsi")
    if bsi:
        lines.append(f'    bsi:')
        lines.append(f'      source: {yaml_str(bsi["source"])}')
        lines.append(f'      status: {yaml_str(bsi["status"])}')
        if "useUpTo" in bsi:
            lines.append(f'      useUpTo: {yaml_str(bsi["useUpTo"])}')
        if bsi.get("requires"):
            lines.append(f'      requires:')
            for req in bsi["requires"]:
                lines.append(f'        - {yaml_str(req)}')

    # remarks
    remarks = entry.get("remarks", [])
    if remarks:
        lines.append(f'    remarks:')
        for r in remarks:
            lines.append(f'      - {yaml_str(r)}')

    components = entry.get("components", [])
    comp_str = ", ".join(yaml_str(c) for c in components)
    lines.append(f'    components: [{comp_str}]')

    return "\n".join(lines)


def _build_overlay_entry(name: str, spec: dict, protocol_label: str) -> dict:
    """Generic overlay-entry builder used by Kerberos and DNSSEC generators.
    Mirrors the IPsec entry shape: ietf / ietfIkev2 / nist / bsi / remarks /
    requires / description.
    """
    entry = {
        "id": name,
        "subType": spec["subType"],
        "components": list(spec["components"]),
    }
    if spec.get("description"):
        entry["description"] = spec["description"]
    ietf = spec.get("ietf")
    if ietf:
        level, source = ietf
        entry["ietf"] = {"source": source}
        if level:
            entry["ietf"]["level"] = level
    nist = spec.get("nist")
    if nist:
        status, note = nist
        entry["nist"] = {
            "source": _nist_doc_for(protocol_label),
            "status": status,
        }
        if note:
            entry["nist"]["note"] = note
    bsi = spec.get("bsi")
    if bsi:
        status, use_up_to, section = bsi
        entry["bsi"] = {
            "source": f"{_bsi_doc_for(protocol_label)} {section}" if section else _bsi_doc_for(protocol_label),
            "status": status,
        }
        if use_up_to:
            entry["bsi"]["useUpTo"] = use_up_to
        if spec.get("requires"):
            entry["bsi"]["requires"] = list(spec["requires"])
    remarks = spec.get("remarks")
    if remarks:
        entry["remarks"] = list(remarks)
    return entry


def _nist_doc_for(protocol_label: str) -> str:
    return {
        "Kerberos": _NIST_KERB_DOC,
        "DNSSEC":   _NIST_DNS_DOC,
        "SPDM":     _NIST_SPDM_DOC,
    }.get(protocol_label, "")


def _bsi_doc_for(protocol_label: str) -> str:
    return {
        "Kerberos": _BSI_KERB_DOC,
        "DNSSEC":   _BSI_DNS_DOC,
        "SPDM":     _BSI_SPDM_DOC,
    }.get(protocol_label, "")


def _format_overlay_entry(entry: dict, protocol: str) -> str:
    """Common formatter for Kerberos / DNSSEC entries (same shape as IPsec)."""
    lines = []
    lines.append(f'  - id: {yaml_str(entry["id"])}')
    lines.append(f'    type: "composite"')
    lines.append(f'    subType: {yaml_str(entry["subType"])}')
    lines.append(f'    protocol: {yaml_str(protocol)}')
    if entry.get("description"):
        lines.append(f'    description: {yaml_str(entry["description"])}')

    ietf = entry.get("ietf")
    if ietf:
        lines.append(f'    ietf:')
        lines.append(f'      source: {yaml_str(ietf["source"])}')
        if "level" in ietf:
            lines.append(f'      level: {yaml_str(ietf["level"])}')

    nist = entry.get("nist")
    if nist:
        lines.append(f'    nist:')
        lines.append(f'      source: {yaml_str(nist["source"])}')
        lines.append(f'      status: {yaml_str(nist["status"])}')
        if "note" in nist:
            lines.append(f'      note: {yaml_str(nist["note"])}')

    bsi = entry.get("bsi")
    if bsi:
        lines.append(f'    bsi:')
        lines.append(f'      source: {yaml_str(bsi["source"])}')
        lines.append(f'      status: {yaml_str(bsi["status"])}')
        if "useUpTo" in bsi:
            lines.append(f'      useUpTo: {yaml_str(bsi["useUpTo"])}')
        if bsi.get("requires"):
            lines.append(f'      requires:')
            for req in bsi["requires"]:
                lines.append(f'        - {yaml_str(req)}')

    remarks = entry.get("remarks", [])
    if remarks:
        lines.append(f'    remarks:')
        for r in remarks:
            lines.append(f'      - {yaml_str(r)}')

    components = entry.get("components", [])
    comp_str = ", ".join(yaml_str(c) for c in components)
    lines.append(f'    components: [{comp_str}]')

    return "\n".join(lines)


def generate_kerberos_entries() -> list[dict]:
    return [_build_overlay_entry(name, spec, "Kerberos")
            for name, spec in KERBEROS_ENTRIES.items()]


def generate_dnssec_entries() -> list[dict]:
    return [_build_overlay_entry(name, spec, "DNSSEC")
            for name, spec in DNSSEC_ENTRIES.items()]


def generate_kerberos_yaml(entries: list[dict]) -> str:
    parts = [
        "# Kerberos protocol composites",
        "#",
        "# Auto-generated from hardcoded lookup tables with IETF, NIST, and BSI overlays.",
        "# Source of truth for per-algorithm Kerberos recommendations from:",
        "#   - IETF  RFC 6649 (deprecate DES, RC4-HMAC-EXP), RFC 8429 (deprecate 3DES,",
        "#         RC4-HMAC), RFC 8009 (AES-SHA2 for Kerberos 5), RFC 3962 (AES for",
        "#         Kerberos 5), RFC 4556 (PKINIT)",
        "#   - NIST  SP 800-57 Part 3 Rev 1 §6 + SP 800-131A Rev 2",
        "#   - BSI   TR-02102-1 v2026-01",
        "#",
        "# Do not edit manually; regenerate with:",
        "#   python scripts/generate_protocol_composites.py",
        "#",
        "# Authority overlay table lives in scripts/generate_protocol_composites.py",
        "# (KERBEROS_ENTRIES). Update that table when the upstream documents are revised.",
        "#",
        "# Part of the ae-pattern-validator validation registry.",
        'version: "2.0"',
        "",
        "entries:",
    ]
    for entry in entries:
        parts.append("")
        parts.append(_format_overlay_entry(entry, "Kerberos"))
    return "\n".join(parts) + "\n"


def generate_dnssec_yaml(entries: list[dict]) -> str:
    parts = [
        "# DNSSEC protocol composites: zone-signing algorithms and TSIG message authentication",
        "#",
        "# Auto-generated from hardcoded lookup tables with IETF, NIST, and BSI overlays.",
        "# Source of truth for per-algorithm DNSSEC recommendations from:",
        "#   - IETF  RFC 8624 (DNSSEC algorithm requirements), RFC 8945 (TSIG),",
        "#         RFC 8080 (Ed25519/Ed448 in DNSSEC), RFC 5155 (NSEC3)",
        "#   - NIST  SP 800-57 Part 3 Rev 1 §8 + SP 800-131A Rev 2",
        "#   - BSI   TR-02102-1 v2026-01",
        "#",
        "# Do not edit manually; regenerate with:",
        "#   python scripts/generate_protocol_composites.py",
        "#",
        "# Authority overlay table lives in scripts/generate_protocol_composites.py",
        "# (DNSSEC_ENTRIES). Update that table when the upstream documents are revised.",
        "#",
        "# Part of the ae-pattern-validator validation registry.",
        'version: "2.0"',
        "",
        "entries:",
    ]
    for entry in entries:
        parts.append("")
        parts.append(_format_overlay_entry(entry, "DNSSEC"))
    return "\n".join(parts) + "\n"


def generate_ipsec_yaml(entries: list[dict]) -> str:
    """Generate the full IPsec YAML document."""
    parts = []
    parts.append("# IPsec / IKEv2 protocol composites: DH groups, ESP transforms, integrity/PRF")
    parts.append("#")
    parts.append("# Auto-generated from hardcoded lookup tables with IETF, NIST, and BSI overlays.")
    parts.append("# Source of truth for per-algorithm IPsec recommendations from:")
    parts.append("#   - IETF  RFC 8221 (ESP/AH data plane), RFC 8247 (IKEv2 control plane),")
    parts.append("#         RFC 7296 (IKEv2), RFC 4868 (HMAC-SHA2), RFC 4106/5282/7634 (AEAD modes)")
    parts.append("#   - NIST  SP 800-131A Rev 2 + SP 800-186 — algorithm transitions and curves")
    parts.append("#   - BSI   TR-02102-3 v2026-01 — recommendations and migration deadlines")
    parts.append("#")
    parts.append("# Do not edit manually; regenerate with:")
    parts.append("#   python scripts/generate_protocol_composites.py")
    parts.append("#")
    parts.append("# Authority overlay tables live in scripts/generate_protocol_composites.py")
    parts.append("# (IPSEC_ENTRIES). Update that table when the upstream documents are revised.")
    parts.append("#")
    parts.append("# Part of the ae-pattern-validator validation registry.")
    parts.append('version: "2.0"')
    parts.append("")
    parts.append("entries:")

    for entry in entries:
        parts.append("")
        parts.append(format_ipsec_entry(entry))

    return "\n".join(parts) + "\n"


# ── SPDM (DMTF DSP0274) ─────────────────────────────────────────────────────
# SPDM negotiates a crypto suite via NEGOTIATE_ALGORITHMS/ALGORITHMS (DSP0274
# §10.4). Each SPDM-enumerated algorithm is one composite entry. SPDM is DMTF-
# defined and does not rank algorithms, so entries carry no `ietf:` level; the
# `nist:` and `bsi:` overlays record the underlying algorithm's posture in the
# SPDM usage context (signature vs key agreement), mirroring the canonical
# value-level assessments in cr-asymmetric.yaml and the other protocol files.
# NOTE the context split: ECDSA P-256/P-521 are `nist: disallowed` for signature
# generation (spdmAsym) but `nist: recommended` for key agreement (spdmDhe).
# Chinese national algorithms (SM2/SM3/SM4) are addressed by neither NIST nor BSI
# and carry no overlay. EdDSA and ChaCha20-Poly1305 are not in BSI TR-02102-1.
_NIST_SPDM_DOC = "FIPS 186-5; SP 800-131A Rev 2"
_BSI_SPDM_DOC = "TR-02102-1 v2026-01"

SPDM_ENTRIES = {
    # BaseAsymAlgo (verification) / ReqBaseAsymAlg (generation) — DSP0274 §10.4.
    # Signature context: mirrors canonical RSASSA-PKCS1 (deprecated), RSASSA-PSS
    # (recommended), and ECDSA value-level nist statuses (P-256/P-521 disallowed,
    # P-384 transitional 2035). BSI disallows PKCS#1 v1.5 (§1.5) and RSA <3000-bit.
    "spdm:RSASSA_2048": {"subType": "spdmAsym", "components": ["RSASSA-PKCS1-2048"],
        "description": "RSASSA-PKCS#1 v1.5 with RSA-2048 (SigLen 256)",
        "nist": ("deprecated", "PKCS#1 v1.5 signatures removed from FIPS 186-5 for new signing; RSA-2048 = 112-bit"),
        "bsi": ("disallowed", None, "§1.5 (PKCS#1 v1.5) / §5.3.1 (RSA <3000-bit)"),
        "remarks": ["DSP0274 §10.4 BaseAsymAlgo/ReqBaseAsymAlg Byte 0 Bit 0"]},
    "spdm:RSAPSS_2048": {"subType": "spdmAsym", "components": ["RSASSA-PSS-2048"],
        "description": "RSASSA-PSS with RSA-2048 (SigLen 256)",
        "nist": ("approved", "RSA-2048 = 112-bit legacy strength"),
        "bsi": ("disallowed", None, "§5.3.1 (below BSI >=3000-bit RSA minimum)"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 1"]},
    "spdm:RSASSA_3072": {"subType": "spdmAsym", "components": ["RSASSA-PKCS1-3072"],
        "description": "RSASSA-PKCS#1 v1.5 with RSA-3072 (SigLen 384)",
        "nist": ("deprecated", "PKCS#1 v1.5 signatures removed from FIPS 186-5 for new signing"),
        "bsi": ("disallowed", None, "§1.5 (PKCS#1 v1.5)"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 2"]},
    "spdm:RSAPSS_3072": {"subType": "spdmAsym", "components": ["RSASSA-PSS-3072"],
        "description": "RSASSA-PSS with RSA-3072 (SigLen 384)",
        "nist": ("recommended", None),
        "bsi": ("recommended", None, "§5.3.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 3"]},
    "spdm:ECDSA_ECC_NIST_P256": {"subType": "spdmAsym", "components": ["ECDSA-P-256"],
        "description": "ECDSA over NIST P-256 (SigLen 64)",
        "nist": ("disallowed", "signature use: CNSA 2.0 mandates P-384; per canonical ECDSA P-256 value"),
        "bsi": ("recommended", None, "§5.3.3"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 4"]},
    "spdm:RSASSA_4096": {"subType": "spdmAsym", "components": ["RSASSA-PKCS1-4096"],
        "description": "RSASSA-PKCS#1 v1.5 with RSA-4096 (SigLen 512)",
        "nist": ("deprecated", "PKCS#1 v1.5 signatures removed from FIPS 186-5 for new signing"),
        "bsi": ("disallowed", None, "§1.5 (PKCS#1 v1.5)"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 5"]},
    "spdm:RSAPSS_4096": {"subType": "spdmAsym", "components": ["RSASSA-PSS-4096"],
        "description": "RSASSA-PSS with RSA-4096 (SigLen 512)",
        "nist": ("recommended", None),
        "bsi": ("recommended", None, "§5.3.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 6"]},
    "spdm:ECDSA_ECC_NIST_P384": {"subType": "spdmAsym", "components": ["ECDSA-P-384"],
        "description": "ECDSA over NIST P-384 (SigLen 96)",
        "nist": ("transitional", "until 2035 (CNSA 2.0 transitional); per canonical ECDSA P-384 value"),
        "bsi": ("recommended", None, "§5.3.3"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 7"]},
    "spdm:ECDSA_ECC_NIST_P521": {"subType": "spdmAsym", "components": ["ECDSA-P-521"],
        "description": "ECDSA over NIST P-521 (SigLen 132)",
        "nist": ("disallowed", "signature use: CNSA 2.0 mandates P-384; per canonical ECDSA P-521 value"),
        "bsi": ("recommended", None, "§5.3.3"),
        "remarks": ["DSP0274 §10.4 Byte 1 Bit 0"]},
    "spdm:SM2_ECC_SM2_P256": {"subType": "spdmAsym", "components": ["SM2"],
        "description": "SM2 signature over SM2_P256 (SigLen 64)",
        "remarks": ["DSP0274 §10.4 Byte 1 Bit 1", "Chinese national standard GB/T 32918; not addressed by NIST or BSI"]},
    "spdm:EdDSA_ed25519": {"subType": "spdmAsym", "components": ["Ed25519"],
        "description": "EdDSA Ed25519 (SigLen 64)",
        "nist": ("recommended", "FIPS 186-5"),
        "remarks": ["DSP0274 §10.4 Byte 1 Bit 2", "EdDSA not addressed in BSI TR-02102-1"]},
    "spdm:EdDSA_ed448": {"subType": "spdmAsym", "components": ["Ed448"],
        "description": "EdDSA Ed448 (SigLen 114)",
        "nist": ("recommended", "FIPS 186-5"),
        "remarks": ["DSP0274 §10.4 Byte 1 Bit 3", "EdDSA not addressed in BSI TR-02102-1"]},
    # BaseHashAlgo — DSP0274 §10.4 (same set also serves MeasurementHashAlgo).
    # SHA-2 / SHA-3 recommended by both NIST and BSI (TR-02102-1 Table 4.1).
    "spdm:SHA_256": {"subType": "spdmHash", "components": ["SHA-256"],
        "description": "SHA-256", "nist": ("recommended", None), "bsi": ("recommended", None, "Table 4.1"),
        "remarks": ["DSP0274 §10.4 BaseHashAlgo Byte 0 Bit 0; also MeasurementHashAlgo"]},
    "spdm:SHA_384": {"subType": "spdmHash", "components": ["SHA-384"],
        "description": "SHA-384", "nist": ("recommended", None), "bsi": ("recommended", None, "Table 4.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 1"]},
    "spdm:SHA_512": {"subType": "spdmHash", "components": ["SHA-512"],
        "description": "SHA-512", "nist": ("recommended", None), "bsi": ("recommended", None, "Table 4.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 2"]},
    "spdm:SHA3_256": {"subType": "spdmHash", "components": ["SHA3-256"],
        "description": "SHA3-256", "nist": ("recommended", None), "bsi": ("recommended", None, "Table 4.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 3"]},
    "spdm:SHA3_384": {"subType": "spdmHash", "components": ["SHA3-384"],
        "description": "SHA3-384", "nist": ("recommended", None), "bsi": ("recommended", None, "Table 4.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 4"]},
    "spdm:SHA3_512": {"subType": "spdmHash", "components": ["SHA3-512"],
        "description": "SHA3-512", "nist": ("recommended", None), "bsi": ("recommended", None, "Table 4.1"),
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 5"]},
    "spdm:SM3_256": {"subType": "spdmHash", "components": ["SM3"],
        "description": "SM3-256",
        "remarks": ["DSP0274 §10.4 Byte 0 Bit 6", "Chinese national standard GB/T 32905; not addressed by NIST or BSI"]},
    # DHE named groups — DSP0274 §10.4 Table 17. KEY-AGREEMENT context: ECDH
    # P-256/384/521 are recommended by both NIST (§5) and BSI (§2.3.6) — unlike
    # the signature context above where P-256/P-521 are nist-disallowed.
    "spdm:ffdhe2048": {"subType": "spdmDhe", "components": ["FFDH-ffdhe2048"],
        "description": "FFDHE 2048 (public value D = 256)",
        "nist": ("approved", "112-bit; >=3072 preferred"),
        "bsi": ("approved", None, "§2.3.5"),
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 0"]},
    "spdm:ffdhe3072": {"subType": "spdmDhe", "components": ["FFDH-ffdhe3072"],
        "description": "FFDHE 3072 (public value D = 384)",
        "nist": ("approved", None), "bsi": ("approved", None, "§2.3.5"),
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 1"]},
    "spdm:ffdhe4096": {"subType": "spdmDhe", "components": ["FFDH-ffdhe4096"],
        "description": "FFDHE 4096 (public value D = 512)",
        "nist": ("approved", None), "bsi": ("approved", None, "§2.3.5"),
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 2"]},
    "spdm:secp256r1": {"subType": "spdmDhe", "components": ["ECDH-P-256"],
        "description": "ECDHE secp256r1 / NIST P-256 (D = 64, C = 32)",
        "nist": ("recommended", None), "bsi": ("recommended", None, "§2.3.6"),
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 3"]},
    "spdm:secp384r1": {"subType": "spdmDhe", "components": ["ECDH-P-384"],
        "description": "ECDHE secp384r1 / NIST P-384 (D = 96, C = 48)",
        "nist": ("recommended", None), "bsi": ("recommended", None, "§2.3.6"),
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 4"]},
    "spdm:secp521r1": {"subType": "spdmDhe", "components": ["ECDH-P-521"],
        "description": "ECDHE secp521r1 / NIST P-521 (D = 132, C = 66)",
        "nist": ("recommended", None), "bsi": ("recommended", None, "§2.3.6"),
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 5"]},
    "spdm:SM2_P256_dhe": {"subType": "spdmDhe", "components": ["SM2"],
        "description": "SM2 key exchange over SM2_P256 (D = 64, C = 32)",
        "remarks": ["DSP0274 §10.4 DHE Byte 0 Bit 6", "GB/T 32918 Part 3/5; not addressed by NIST or BSI"]},
    # AEAD — DSP0274 §10.4 Table 18. AES-GCM recommended by both; ChaCha20-Poly1305
    # NIST-approved (RFC 8439) but not in BSI TR-02102-1.
    "spdm:AES_128_GCM": {"subType": "spdmAead", "components": ["AES-128-GCM"],
        "description": "AES-128-GCM (128-bit key, 96-bit IV)",
        "nist": ("recommended", None), "bsi": ("recommended", None, "Table 3.2"),
        "remarks": ["DSP0274 §10.4 AEAD Byte 0 Bit 0"]},
    "spdm:AES_256_GCM": {"subType": "spdmAead", "components": ["AES-256-GCM"],
        "description": "AES-256-GCM (256-bit key, 96-bit IV)",
        "nist": ("recommended", None), "bsi": ("recommended", None, "Table 3.2"),
        "remarks": ["DSP0274 §10.4 AEAD Byte 0 Bit 1"]},
    "spdm:CHACHA20_POLY1305": {"subType": "spdmAead", "components": ["ChaCha20-Poly1305"],
        "description": "ChaCha20-Poly1305 (256-bit key, 96-bit IV, 128-bit tag)",
        "nist": ("approved", "RFC 8439; not a FIPS-approved cipher"),
        "remarks": ["DSP0274 §10.4 AEAD Byte 0 Bit 2", "Not in BSI TR-02102-1 (no dedicated stream ciphers recommended)"]},
    "spdm:AEAD_SM4_GCM": {"subType": "spdmAead", "components": ["SM4-GCM"],
        "description": "SM4-GCM (128-bit key, 96-bit IV)",
        "remarks": ["DSP0274 §10.4 AEAD Byte 0 Bit 3", "GB/T 32907; not addressed by NIST or BSI"]},
    # KeySchedule — DSP0274 §10.4 Table 20 / §12
    "spdm:KeySchedule": {"subType": "spdmKeySchedule", "components": ["HKDF"],
        "description": "SPDM Key Schedule (HKDF-based key derivation, DSP0274 §12)",
        "nist": ("approved", "HKDF per SP 800-56C Rev 2"),
        "bsi": ("recommended", None, "Table B.1"),
        "remarks": ["DSP0274 §10.4 KeySchedule Byte 0 Bit 0"]},
}


def generate_spdm_entries() -> list[dict]:
    return [_build_overlay_entry(name, spec, "SPDM")
            for name, spec in SPDM_ENTRIES.items()]


def generate_spdm_yaml(entries: list[dict]) -> str:
    parts = [
        "# SPDM (DMTF DSP0274) protocol composites: NEGOTIATE_ALGORITHMS algorithm registries",
        "#",
        "# Auto-generated from hardcoded lookup tables with NIST overlays.",
        "# Source of truth: DMTF DSP0274 Security Protocol and Data Model (SPDM) v1.3.0 §10.4",
        "#   (BaseAsymAlgo/ReqBaseAsymAlg, BaseHashAlgo, DHE, AEAD, KeySchedule).",
        "#   NIST (FIPS 186-5 / SP 800-131A Rev 2) and BSI (TR-02102-1 v2026-01) postures",
        "#   mirror the canonical value-level assessments in the usage context (signature vs",
        "#   key agreement). SPDM is DMTF-defined and does not rank algorithms, so entries",
        "#   carry no ietf: level. SM2/SM3/SM4 (addressed by neither NIST nor BSI), EdDSA and",
        "#   ChaCha20-Poly1305 (not in BSI TR-02102-1) carry reduced overlays accordingly.",
        "#",
        "# Do not edit manually; regenerate with:",
        "#   python scripts/generate_protocol_composites.py",
        "#",
        "# Authority overlay table lives in scripts/generate_protocol_composites.py",
        "# (SPDM_ENTRIES). Update that table when DSP0274 is revised.",
        "#",
        "# Part of the ae-pattern-validator validation registry.",
        'version: "2.0"',
        "",
        "entries:",
    ]
    for entry in entries:
        parts.append("")
        parts.append(_format_overlay_entry(entry, "SPDM"))
    return "\n".join(parts) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Generate the protocol composite registries (TLS/SSH/IPsec/Kerberos/DNSSEC/SPDM) with NIST/BSI overlays")
    parser.add_argument("--check", action="store_true",
                        help="Compare generated output with existing file; exit non-zero on differences")
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR,
                        help="Directory for cached CSV files")
    args = parser.parse_args()

    print("=== IANA TLS/SSH Composite Generator ===\n")
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

    # Generate SSH composites from hardcoded tables
    print("\nProcessing SSH algorithms...")
    ssh_entries = generate_ssh_entries()
    ssh_yaml_text = generate_ssh_yaml(ssh_entries)
    print(f"  Generated: {len(ssh_entries)} entries")

    # Generate IPsec composites from hardcoded tables
    print("\nProcessing IPsec algorithms...")
    ipsec_entries = generate_ipsec_entries()
    ipsec_yaml_text = generate_ipsec_yaml(ipsec_entries)
    print(f"  Generated: {len(ipsec_entries)} entries")

    # Generate Kerberos composites
    print("\nProcessing Kerberos algorithms...")
    kerberos_entries = generate_kerberos_entries()
    kerberos_yaml_text = generate_kerberos_yaml(kerberos_entries)
    print(f"  Generated: {len(kerberos_entries)} entries")

    # Generate DNSSEC composites
    print("\nProcessing DNSSEC algorithms...")
    dnssec_entries = generate_dnssec_entries()
    dnssec_yaml_text = generate_dnssec_yaml(dnssec_entries)
    print(f"  Generated: {len(dnssec_entries)} entries")

    spdm_entries = generate_spdm_entries()
    spdm_yaml_text = generate_spdm_yaml(spdm_entries)
    print(f"  Generated: {len(spdm_entries)} SPDM entries")

    print(f"\n=== Summary ===")
    print(f"  TLS cipher suites:    {len(cs_entries)}")
    print(f"  TLS supported groups: {len(sg_entries)}")
    print(f"  TLS signature schemes:{len(ss_entries)}")
    print(f"  TLS total entries:    {len(all_entries)}")
    print(f"  TLS decomp failures:  {len(cs_failures) + len(sg_failures) + len(ss_failures)}")
    print(f"  SSH entries:          {len(ssh_entries)}")
    print(f"  IPsec entries:        {len(ipsec_entries)}")
    print(f"  Kerberos entries:     {len(kerberos_entries)}")
    print(f"  DNSSEC entries:       {len(dnssec_entries)}")
    print(f"  SPDM entries:         {len(spdm_entries)}")

    if args.check:
        check_ok = True
        for path, generated, label in [
            (OUTPUT_PATH, yaml_text, "cr-tls.yaml"),
            (SSH_OUTPUT_PATH, ssh_yaml_text, "cr-ssh.yaml"),
            (IPSEC_OUTPUT_PATH, ipsec_yaml_text, "cr-ipsec.yaml"),
            (KERBEROS_OUTPUT_PATH, kerberos_yaml_text, "cr-kerberos.yaml"),
            (DNSSEC_OUTPUT_PATH, dnssec_yaml_text, "cr-dnssec.yaml"),
            (SPDM_OUTPUT_PATH, spdm_yaml_text, "cr-spdm.yaml"),
        ]:
            if not path.exists():
                print(f"\nERROR: {path} does not exist for comparison", file=sys.stderr)
                check_ok = False
                continue
            existing = path.read_text(encoding="utf-8")
            if existing == generated:
                print(f"  {label} is up to date.")
            else:
                print(f"\n  ERROR: {label} is out of date! Re-run without --check to regenerate.",
                      file=sys.stderr)
                check_ok = False
        sys.exit(0 if check_ok else 1)
    else:
        OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_PATH.write_text(yaml_text, encoding="utf-8")
        print(f"\n  Written to {OUTPUT_PATH}")
        SSH_OUTPUT_PATH.write_text(ssh_yaml_text, encoding="utf-8")
        print(f"  Written to {SSH_OUTPUT_PATH}")
        IPSEC_OUTPUT_PATH.write_text(ipsec_yaml_text, encoding="utf-8")
        print(f"  Written to {IPSEC_OUTPUT_PATH}")
        KERBEROS_OUTPUT_PATH.write_text(kerberos_yaml_text, encoding="utf-8")
        print(f"  Written to {KERBEROS_OUTPUT_PATH}")
        DNSSEC_OUTPUT_PATH.write_text(dnssec_yaml_text, encoding="utf-8")
        print(f"  Written to {DNSSEC_OUTPUT_PATH}")
        SPDM_OUTPUT_PATH.write_text(spdm_yaml_text, encoding="utf-8")
        print(f"  Written to {SPDM_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
