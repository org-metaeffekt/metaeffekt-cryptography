#!/usr/bin/env python3
"""
Generate SVG diagrams with deterministic left-aligned layout.

Produces:
  - cryptographic-parameters.svg  (parameter taxonomy)
  - random-number-generators.svg  (RNG classification)
"""

from dataclasses import dataclass, field
from typing import List, Optional

# ─────────────────────────────────────────────────────────────────────────
# Layout constants
# ─────────────────────────────────────────────────────────────────────────

PAGE_MARGIN = 20
SECTION_GAP = 16
SUBSECTION_GAP = 10
PARAM_GAP = 3

SECTION_PADDING_X = 12
SECTION_PADDING_Y = 12
SECTION_HEADER_HEIGHT = 32

SUBSECTION_PADDING_X = 8
SUBSECTION_PADDING_Y = 8
SUBSECTION_HEADER_HEIGHT = 26

PARAM_HEIGHT = 34
PARAM_WIDTH = 300

TITLE_HEIGHT = 60
FONT_FAMILY = "Helvetica, Arial, sans-serif"

# ─────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────

@dataclass
class Param:
    name: str
    description: str
    color: Optional[str] = None  # override default

@dataclass
class Subsection:
    title: str
    params: List[Param]
    fill: str = "#ffffff"
    stroke: str = "#cccccc"

@dataclass
class Section:
    title: str
    subsections: List[Subsection]
    fill: str = "#f5f5f5"
    stroke: str = "#666666"
    columns: int = 1  # number of columns for subsections

# ─────────────────────────────────────────────────────────────────────────
# Layout engine
# ─────────────────────────────────────────────────────────────────────────

def layout_subsection(sub: Subsection) -> tuple[int, int]:
    """Return (width, height) of a subsection."""
    content_h = len(sub.params) * PARAM_HEIGHT + (len(sub.params) - 1) * PARAM_GAP
    h = SUBSECTION_HEADER_HEIGHT + 2 * SUBSECTION_PADDING_Y + content_h
    w = PARAM_WIDTH + 2 * SUBSECTION_PADDING_X
    return w, h

def layout_section(sec: Section) -> tuple[int, int, list]:
    """Return (width, height, subsection_positions)."""
    sub_sizes = [layout_subsection(s) for s in sec.subsections]
    sub_w = max((w for w, _ in sub_sizes), default=PARAM_WIDTH + 2 * SUBSECTION_PADDING_X)

    # Arrange subsections in grid
    positions = []
    rows = [[] for _ in range((len(sec.subsections) + sec.columns - 1) // sec.columns)]
    for i, (w, h) in enumerate(sub_sizes):
        rows[i // sec.columns].append(h)

    row_heights = [max(row) for row in rows] if rows[0] else [0]

    col_x = SECTION_PADDING_X
    row_y = SECTION_HEADER_HEIGHT + SECTION_PADDING_Y

    for i in range(len(sec.subsections)):
        row = i // sec.columns
        col = i % sec.columns
        x = SECTION_PADDING_X + col * (sub_w + SUBSECTION_GAP)
        y = SECTION_HEADER_HEIGHT + SECTION_PADDING_Y + sum(row_heights[:row]) + row * SUBSECTION_GAP
        positions.append((x, y, sub_w, sub_sizes[i][1]))

    total_w = SECTION_PADDING_X * 2 + sec.columns * sub_w + (sec.columns - 1) * SUBSECTION_GAP
    total_h = SECTION_HEADER_HEIGHT + SECTION_PADDING_Y * 2 + sum(row_heights) + (len(row_heights) - 1) * SUBSECTION_GAP
    return total_w, total_h, positions

# ─────────────────────────────────────────────────────────────────────────
# SVG generation
# ─────────────────────────────────────────────────────────────────────────

def escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def render_param(x: int, y: int, p: Param) -> str:
    fill = p.color or "#ffffff"
    parts = []
    parts.append(f'<rect x="{x}" y="{y}" width="{PARAM_WIDTH}" height="{PARAM_HEIGHT}" '
                 f'fill="{fill}" stroke="#cccccc" stroke-width="1" rx="2"/>')
    parts.append(f'<text x="{x + 8}" y="{y + 13}" font-family="{FONT_FAMILY}" '
                 f'font-size="10" font-weight="600" fill="#1a1a1a">{escape(p.name)}</text>')
    parts.append(f'<text x="{x + 8}" y="{y + 27}" font-family="{FONT_FAMILY}" '
                 f'font-size="9" fill="#555555">{escape(p.description)}</text>')
    return "\n".join(parts)

def render_subsection(x: int, y: int, w: int, h: int, sub: Subsection) -> str:
    parts = []
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" '
                 f'fill="{sub.fill}" stroke="{sub.stroke}" stroke-width="1" rx="3"/>')
    parts.append(f'<text x="{x + SUBSECTION_PADDING_X}" y="{y + 17}" '
                 f'font-family="{FONT_FAMILY}" font-size="12" font-weight="700" '
                 f'fill="#1a1a1a">{escape(sub.title)}</text>')
    px = x + SUBSECTION_PADDING_X
    py = y + SUBSECTION_HEADER_HEIGHT + SUBSECTION_PADDING_Y
    for p in sub.params:
        parts.append(render_param(px, py, p))
        py += PARAM_HEIGHT + PARAM_GAP
    return "\n".join(parts)

def render_section(x: int, y: int, sec: Section) -> tuple[str, int, int]:
    w, h, positions = layout_section(sec)
    parts = []
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" '
                 f'fill="{sec.fill}" stroke="{sec.stroke}" stroke-width="2" rx="4"/>')
    parts.append(f'<text x="{x + SECTION_PADDING_X}" y="{y + 21}" '
                 f'font-family="{FONT_FAMILY}" font-size="14" font-weight="700" '
                 f'fill="#1a1a1a">{escape(sec.title)}</text>')
    for sub, (sx, sy, sw, sh) in zip(sec.subsections, positions):
        parts.append(render_subsection(x + sx, y + sy, sw, sh, sub))
    return "\n".join(parts), w, h

def render_diagram(title: str, subtitle: str, sections: List[Section]) -> str:
    # Compute total size
    section_sizes = []
    for sec in sections:
        w, h, _ = layout_section(sec)
        section_sizes.append((w, h))

    max_w = max(w for w, _ in section_sizes)
    total_h = TITLE_HEIGHT + sum(h for _, h in section_sizes) + (len(sections) - 1) * SECTION_GAP

    page_w = max_w + 2 * PAGE_MARGIN
    page_h = total_h + 2 * PAGE_MARGIN

    parts = []
    parts.append(f'<?xml version="1.0" encoding="UTF-8"?>')
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{page_w}" height="{page_h}" '
                 f'viewBox="0 0 {page_w} {page_h}">')
    parts.append(f'<rect width="{page_w}" height="{page_h}" fill="#fafafa"/>')

    # Title
    parts.append(f'<text x="{PAGE_MARGIN}" y="{PAGE_MARGIN + 22}" '
                 f'font-family="{FONT_FAMILY}" font-size="20" font-weight="700" '
                 f'fill="#1a1a1a">{escape(title)}</text>')
    parts.append(f'<text x="{PAGE_MARGIN}" y="{PAGE_MARGIN + 42}" '
                 f'font-family="{FONT_FAMILY}" font-size="11" fill="#666666">{escape(subtitle)}</text>')

    # Sections
    y = PAGE_MARGIN + TITLE_HEIGHT
    for sec in sections:
        svg_part, w, h = render_section(PAGE_MARGIN, y, sec)
        parts.append(svg_part)
        y += h + SECTION_GAP

    parts.append('</svg>')
    return "\n".join(parts)

# ─────────────────────────────────────────────────────────────────────────
# Parameter taxonomy content
# ─────────────────────────────────────────────────────────────────────────

def build_parameters_diagram() -> str:
    general = Section(
        title="§1–§8  General Parameters",
        fill="#f5f5f5", stroke="#666666",
        columns=4,
        subsections=[
            Subsection("§1 Size & Length", [
                Param("{keyLength}", "symmetric key / modulus size"),
                Param("{saltLength}", "PSS / PBKDF salt (bytes)"),
                Param("{dkLen}", "derived key length"),
                Param("{tagLenBytes}", "AEAD tag length (bytes)"),
                Param("{outputLength}", "XOF / hash output length"),
                Param("{dkmLength}", "derived keying material length"),
                Param("{length}", "generic length parameter"),
                Param("{parameterSetIdentifier}", "algorithm parameter set"),
            ]),
            Subsection("§2 Mode & Variant", [
                Param("{mode}", "cipher mode (GCM, CBC, CTR, …)"),
                Param("{symmetricCipher}", "cipher name"),
                Param("{cipherAlgorithm}", "block cipher algorithm"),
                Param("{blockCipher}", "underlying block cipher"),
                Param("{encryptionAlgorithm}", "encryption primitive"),
                Param("{kem}", "KEM algorithm"),
                Param("{otherBlockCipher}", "secondary block cipher"),
            ]),
            Subsection("§3 Hash & Digest", [
                Param("{hashAlgorithm}", "hash function (SHA-256, …)"),
                Param("{maskGenAlgorithm}", "MGF (typically MGF1)"),
                Param("{prfFunction}", "pseudorandom function"),
                Param("{auxFunction}", "auxiliary function"),
                Param("{hashfun}/{nbits}/{treeHeight}", "LMS/XMSS parameter triple"),
            ]),
            Subsection("§4 Curve & Group", [
                Param("{ellipticCurve}", "elliptic curve name"),
                Param("{namedGroup}", "DH named group"),
                Param("{group}", "generic group identifier"),
            ]),
            Subsection("§5 Auth & Tag", [
                Param("{tagLength}", "MAC / AEAD tag length (bits)"),
                Param("{ivLength}", "IV / nonce length"),
                Param("{mac}", "MAC algorithm"),
                Param("{macAlgorithm}", "MAC primitive"),
                Param("{aead}", "AEAD algorithm"),
            ]),
            Subsection("§6 KDF & Password", [
                Param("{kdf}", "key derivation function"),
                Param("{iterations}", "PBKDF iteration count"),
                Param("{memoryKiB}", "Argon2 memory cost"),
                Param("{passes}", "Argon2 time cost"),
                Param("{parallelism}", "Argon2 threads"),
                Param("{saltLenBytes}", "salt length (bytes)"),
                Param("{N}/{r}/{p}", "scrypt cost parameters"),
                Param("{cost}", "bcrypt cost factor"),
                Param("{ksf}", "key stretching function"),
                Param("{N_log2}/{t}", "yescrypt cost/time"),
            ]),
            Subsection("§7 Padding & IV", [
                Param("{padding}", "padding scheme"),
            ]),
            Subsection("§8 Protocol & Misc", [
                Param("{compressionRounds}/{finalizationRounds}", "SipHash rounds"),
                Param("{SRP version}", "SRP-3 | SRP-6 | SRP-6a"),
            ]),
        ],
    )

    pqc = Section(
        title="§9  PQC Internal Parameters  (FIPS 203 / 204 / 205 / 206 / HQC)",
        fill="#e8f0fe", stroke="#4285f4",
        columns=3,
        subsections=[
            Subsection("ML-KEM  (FIPS 203)", [
                Param("{parameterSetIdentifier}", "512 | 768 | 1024"),
                Param("{k}", "module rank (2 | 3 | 4)"),
                Param("{eta1}", "noise parameter (keygen)"),
                Param("{eta2}", "noise parameter (encryption)"),
                Param("{du}", "ciphertext compression u"),
                Param("{dv}", "ciphertext compression v"),
                Param("{q}", "modulus (3329)"),
            ], fill="#f0f6ff"),
            Subsection("ML-DSA  (FIPS 204)", [
                Param("{parameterSetIdentifier}", "44 | 65 | 87"),
                Param("{k}, {l}", "lattice matrix dimensions"),
                Param("{eta}", "secret key coefficient bound"),
                Param("{gamma1}", "masking range"),
                Param("{gamma2}", "low-order rounding range"),
                Param("{tau}", "challenge polynomial weight"),
                Param("{lambda}", "collision strength (bits)"),
                Param("{beta}", "norm bound (tau·eta)"),
                Param("{omega}", "hint weight bound"),
                Param("{q}", "modulus (8380417)"),
                Param("{context}", "domain separation"),
                Param("{deterministicSigning}", "hedged | deterministic"),
            ], fill="#f0f6ff"),
            Subsection("SLH-DSA  (FIPS 205)", [
                Param("{parameterSetIdentifier}", "128s|128f|192s|192f|256s|256f"),
                Param("{n}", "security parameter (bytes)"),
                Param("{h} / {d}", "total height / layer count"),
                Param("{h_prime}", "subtree height (h/d)"),
                Param("{a}", "FORS tree height"),
                Param("{k}", "number of FORS trees"),
                Param("{w} / {lg_w}", "Winternitz parameter"),
                Param("{m}", "message digest blocks"),
                Param("{context}", "domain separation"),
                Param("{deterministicSigning}", "hedged | deterministic"),
            ], fill="#f0f6ff"),
            Subsection("FN-DSA  (FIPS 206 IPD / Falcon)", [
                Param("{parameterSetIdentifier}", "FN-DSA-512 | FN-DSA-1024"),
                Param("{n}", "ring dimension (512 | 1024)"),
                Param("{q}", "modulus (12289)"),
                Param("{sigma}", "Gaussian standard deviation"),
                Param("{floatingPointMode}", "IEEE 754 | integer-only"),
                Param("{context}", "domain separation"),
                Param("{deterministicSigning}", "hedged | deterministic"),
            ], fill="#f0f6ff"),
            Subsection("HQC  (NIST Round 4, FIPS pending)", [
                Param("{parameterSetIdentifier}", "128 | 192 | 256 (L1 | L3 | L5)"),
                Param("internal params", "n, k, w, wr, we (fixed per set)"),
            ], fill="#f0f6ff"),
            Subsection("Pre-Hash Variants", [
                Param("{preHashVariant}", "HashML-DSA | HashSLH-DSA"),
            ], fill="#f0f6ff"),
        ],
    )

    national = Section(
        title="§10  Lightweight & National Standards",
        fill="#fff3e0", stroke="#ff9800",
        columns=3,
        subsections=[
            Subsection("Ascon  (NIST SP 800-232)", [
                Param("Ascon-AEAD128", "128-bit key/tag/nonce"),
                Param("Ascon-Hash256", "fixed 256-bit output"),
                Param("Ascon-XOF128", "variable output, 128-bit sec"),
                Param("Ascon-CXOF128", "customisable XOF"),
            ], fill="#fff8e1"),
            Subsection("SM9  (GM/T 0044-2016)", [
                Param("{masterPublicKey}", "SM9 BN curve element"),
                Param("SM9-SIG", "signature"),
                Param("SM9-KEX", "key exchange"),
                Param("SM9-KEM", "key encapsulation"),
                Param("SM9-ENC", "identity-based encryption"),
            ], fill="#fff8e1"),
            Subsection("3GPP AKA  (TS 35.206 / 35.231)", [
                Param("MILENAGE", "AES-128-based AKA"),
                Param("TUAK", "Keccak-based AKA"),
                Param("128-EEA1/EEA3", "confidentiality"),
                Param("128-EIA1/EIA3", "integrity"),
                Param("3GPP-XOR", "test vector algorithm"),
            ], fill="#fff8e1"),
        ],
    )

    key_mgmt = Section(
        title="§11  SP 800-57 Key Management",
        fill="#f3e5f5", stroke="#9c27b0",
        columns=1,
        subsections=[
            Subsection("Cryptoperiod", [
                Param("{originator-usage-period}", "max time to apply protection (1-3 yrs)"),
                Param("{recipient-usage-period}", "max time to process (OUP + 3 yrs)"),
            ], fill="#fce4ec"),
        ],
    )

    hybrid = Section(
        title="Hybrid & Composite Constructions",
        fill="#e8f5e9", stroke="#4caf50",
        columns=2,
        subsections=[
            Subsection("Hybrid KEM", [
                Param("{hybridKemCombiner}", "concat | xor | HKDF"),
                Param("Classical + PQC KEM pair", "X25519+ML-KEM, P-256+HQC, …"),
            ], fill="#e8f5e9"),
            Subsection("Composite Signatures", [
                Param("Composite ML-DSA", "draft-ietf-lamps-pq-composite-sigs"),
                Param("ML-DSA + classical", "RSA-PSS | RSA-PKCS1 | ECDSA | EdDSA"),
                Param("18 registered OIDs", "arc 1.3.6.1.5.5.7.6.37–54"),
            ], fill="#e8f5e9"),
        ],
    )

    return render_diagram(
        "Cryptographic Algorithm Parameter Taxonomy",
        "Grouped by taxonomy section; each block is self-contained.",
        [general, pqc, national, key_mgmt, hybrid],
    )

# ─────────────────────────────────────────────────────────────────────────
# RNG taxonomy content
# ─────────────────────────────────────────────────────────────────────────

def build_rng_diagram() -> str:
    COLOR_BROKEN = "#ffebee"
    COLOR_DEPRECATED = "#fff3e0"

    csprng = Section(
        title="CSPRNG / DRBG  (cryptographically secure)",
        fill="#e8f0fe", stroke="#4285f4",
        columns=3,
        subsections=[
            Subsection("NIST SP 800-90A DRBGs", [
                Param("Hash_DRBG", "SHA-based; seeded from entropy"),
                Param("HMAC_DRBG", "HMAC-based; widely deployed"),
                Param("CTR_DRBG", "block cipher counter mode"),
                Param("Dual_EC_DRBG", "backdoored; disallowed 2014", COLOR_BROKEN),
            ], fill="#f0f6ff"),
            Subsection("Accumulator-based CSPRNGs", [
                Param("Fortuna", "32 entropy pools + AES-256-CTR"),
                Param("Yarrow", "predecessor of Fortuna"),
            ], fill="#f0f6ff"),
            Subsection("Stream-cipher-based", [
                Param("ChaCha20-DRNG", "Linux kernel CSPRNG (4.8+)"),
                Param("RC4-PRNG", "deprecated; RC4 biases", COLOR_DEPRECATED),
            ], fill="#f0f6ff"),
        ],
    )

    os_hw = Section(
        title="OS Entropy APIs & Hardware RNG",
        fill="#fff3e0", stroke="#ff9800",
        columns=2,
        subsections=[
            Subsection("OS Entropy APIs", [
                Param("getrandom()", "Linux syscall"),
                Param("getentropy()", "OpenBSD / glibc 2.25+"),
                Param("/dev/urandom", "Linux non-blocking device"),
                Param("/dev/random", "Linux blocking device (legacy)"),
                Param("BCryptGenRandom", "Windows CNG API"),
            ], fill="#fff8e1"),
            Subsection("Hardware RNG", [
                Param("RDRAND", "Intel/AMD on-chip DRBG"),
                Param("RDSEED", "Intel/AMD entropy source"),
                Param("TPM_RNG", "TPM 2.0 hardware RNG"),
                Param("HRNG", "generic hardware RNG"),
                Param("TRNG", "true RNG (physical entropy)"),
            ], fill="#fff8e1"),
        ],
    )

    prng = Section(
        title="Non-cryptographic PRNGs  (statistical use only — NOT crypto-safe)",
        fill="#f3e5f5", stroke="#9c27b0",
        columns=2,
        subsections=[
            Subsection("Modern PRNGs", [
                Param("MT19937", "Mersenne Twister; state recoverable"),
                Param("Xoshiro (256/512)", "linear feedback; fast"),
                Param("Xoroshiro (128/64)", "small-state Xoshiro variant"),
                Param("PCG", "LCG + output permutation"),
                Param("SplitMix64", "seed-initialiser for Xoshiro"),
            ], fill="#fce4ec"),
            Subsection("Legacy PRNGs", [
                Param("LCG", "linear congruential; trivially predictable"),
                Param("ISAAC", "historical; replaced by ChaCha20"),
                Param("ANSIX931", "withdrawn 2011", COLOR_DEPRECATED),
            ], fill="#fce4ec"),
        ],
    )

    historical = Section(
        title="Historical & Broken  (telecom / legacy)",
        fill="#ffebee", stroke="#c62828",
        columns=1,
        subsections=[
            Subsection("GSM stream ciphers", [
                Param("A5/1", "GSM stream cipher; broken", COLOR_BROKEN),
                Param("A5/2", "GSM stream cipher; broken (export)", COLOR_BROKEN),
            ], fill="#ffebee"),
        ],
    )

    return render_diagram(
        "Random Number Generator Taxonomy",
        "Classified by construction and cryptographic suitability.",
        [csprng, os_hw, prng, historical],
    )

# ─────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys, os
    out_dir = os.path.dirname(os.path.abspath(__file__))

    with open(os.path.join(out_dir, "cryptographic-parameters.svg"), "w") as f:
        f.write(build_parameters_diagram())
    print(f"Wrote {out_dir}/cryptographic-parameters.svg")

    with open(os.path.join(out_dir, "random-number-generators.svg"), "w") as f:
        f.write(build_rng_diagram())
    print(f"Wrote {out_dir}/random-number-generators.svg")
