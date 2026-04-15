# Cryptographic Authority Inconsistencies

Cross-authority comparison of cryptographic algorithm guidance from **IETF**, **NIST**,
**BSI**, **NSA CNSA 2.0**, and **CA/Browser Forum**. This document records concrete
cases where the authorities disagree on an algorithm's status, highlights substantive
policy disagreements, and explains the recurring patterns behind them.

The findings are generated automatically by `scripts/validate_consistency.py`
(check #9 — *NIST/BSI authority divergence*) which scans both
[`cryptographic-algorithm-status.md`](cryptographic-algorithm-status.md) and
[`cryptographic-protocol-status.md`](cryptographic-protocol-status.md), normalises
each cell to a 6-tier severity scale, and reports any row where authorities differ.

> **Last updated:** 2026-04-11. Re-run `python3 scripts/validate_consistency.py`
> to refresh.

> **Note on continuous revision:** Authorities update their guidance on different
> cycles (NIST SP 800-131A revisions, BSI annual TR-02102-1 updates, NSA CNSA
> milestones). The list below should be re-validated against the latest published
> versions before relying on it for compliance decisions.

---

## Comparing Authorities

| Authority | Scope | Document |
|:---|:---|:---|
| **IETF** | Protocol-level — RFCs that mandate algorithms within a given protocol | RFC 9142 (SSH), RFC 8221/8247 (IPsec), RFC 8624 (DNSSEC), RFC 8945 (TSIG), RFC 8429 (Kerberos), … |
| **NIST** | US civilian / federal — algorithm-level | SP 800-131A Rev 2, SP 800-57, FIPS 197/180-4/186-5/202/203/204/205 |
| **BSI** | German / EU civilian — algorithm-level + protocol-level | TR-02102-1 v2026-01 (algorithms), TR-02102-3 (IPsec), TR-02102-4 (SSH) |
| **CNSA** | US military / National Security Systems — algorithm-level | NSA CNSA 2.0 Cybersecurity Advisory PP-22-1338 (Sep 2022) |
| **CABF** | Public-trust PKI — used only in PKI tables | CA/Browser Forum Baseline Requirements §6.1.5 |

> **Why no IETF column at the algorithm level?** IETF rarely issues normative
> requirements at the primitive level — most IETF cryptographic RFCs either
> *specify* an algorithm without mandating its use (RFC 8017 for RSA, RFC 5869
> for HKDF) or are *informational* (RFC 6151 for MD5, RFC 6194 for SHA-1). Where
> IETF does tabulate algorithm requirements (RFC 9142 SSH, RFC 8221/8247 IPsec,
> RFC 8624 DNSSEC, RFC 8945 TSIG), the scope is *protocol-level* and lives in
> [`cryptographic-protocol-status.md`](cryptographic-protocol-status.md).

---

## Methodology

### Severity Tiers

Every status cell is normalised to one of six tiers, lowest = most permissive:

| Tier | NIST/BSI | IETF | CNSA | Examples |
|:---:|:---|:---|:---|:---|
| 0 | ✅ Recommended | ✅ MUST / REQUIRED | ✅ Mandatory | "✅ Recommended", "MUST", "Mandatory" |
| 1 | ✓ Approved / Acceptable | ✓ SHOULD / RECOMMENDED | ✓ Approved | "✓ Approved", "SHOULD" |
| 2 | ⚠ Conditional | ◯ MAY / OPTIONAL · ⚠ MUST- | ⚠ Conditional | "MAY", "MUST minus", "Conditional" |
| 3 | 🔜 Transitional / Until \<year\> | — | 🔜 Transitional | "🔜 Transitional", "✅ Until 2031" |
| 4 | ❌ Deprecated / Removed | ❌ SHOULD NOT / NOT RECOMMENDED | ❌ Deprecated | "Deprecated", "SHOULD NOT" |
| 5 | 🚫 Disallowed / Broken | 🚫 MUST NOT / PROHIBITED | 🚫 Not in CNSA | "Disallowed", "MUST NOT", "Not in CNSA" |

### Divergence Classification

For each row, the maximum tier difference among the present authorities is computed:

| Class | Tier difference | Interpretation |
|:---|:---:|:---|
| **MAJOR** | ≥ 3 | Substantive policy disagreement; one authority recommends or permits while another disallows |
| **MEDIUM** | 2 | Notable nuance; e.g., one says Recommended, another says Conditional |
| **minor** | 1 | Wording difference (Approved vs Recommended) without practical impact |

### Normalisation Rules

The following textual cues take precedence over the leading status symbol:

- `until` → tier 3 (e.g., BSI's "✅ Until 2031" is treated as transitional, not Recommended)
- `conditional` → tier 2 (even if cell starts with ✓ or ✅)
- `transitional` → tier 3

This avoids misclassifying time-bounded approvals as full Recommendations.

The parser also handles **escaped pipes** (`\|`) inside markdown cells so that
patterns like `AES-[128\|192\|256]-GCM` are correctly recognised as a single column
rather than being split into multiple columns.

---

## Summary

Total comparable rows across both files: **217**

| Category | Count | Share |
|:---|---:|---:|
| All authorities agree | 61 | 28 % |
| Diverging guidance | 156 | 72 % |
| ↳ MAJOR (tier diff ≥ 3) | 56 | 26 % |
| ↳ MEDIUM (tier diff = 2) | 23 | 11 % |
| ↳ minor (tier diff = 1) | 77 | 35 % |

The high MAJOR count is **driven primarily by CNSA 2.0's restrictive scope** —
CNSA mandates only AES-256, SHA-384, ML-KEM-1024, ML-DSA-87, and the SP 800-208
stateful HBS algorithms. Anything outside this list is "Not in CNSA" (effectively
disallowed for US National Security Systems), even though NIST and BSI may
approve it.

---

## MAJOR Divergence Patterns

The 56 MAJOR divergences cluster into a few distinct policy disagreements:

### Pattern A: CNSA excludes NIST/BSI approved Algorithms

CNSA 2.0 is intentionally a *restrictive subset* of NIST-approved algorithms.
Algorithms that NIST/BSI fully approve but CNSA excludes:

| Algorithm | NIST | BSI | CNSA | Reason |
|:---|:---|:---|:---|:---|
| `AES-[128\|192]-*` | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | CNSA mandates AES-256 only |
| `SHA-256` | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | CNSA mandates SHA-384 |
| `SHA-512/256` | ✅ Recommended | ✓ Approved | 🚫 Not in CNSA | Truncated SHA-512 not in CNSA suite |
| `SHA3-[256\|384\|512]` | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | CNSA only specifies SHA-2 |
| `SHAKE128` / `SHAKE256` | ✅ Recommended | ✓ Approved | 🚫 Not in CNSA | Keccak-based XOFs not in CNSA |
| `BLAKE2`, `BLAKE3` | — | ⚠ Conditional | 🚫 Not in CNSA | Not in any FIPS-approved list |
| `HMAC-SHA-256` | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | CNSA mandates HMAC-SHA-384/512 |
| `HMAC-SHA3-*` | ✓ Approved | ✅ Recommended | 🚫 Not in CNSA | SHA-3 not in CNSA |
| `KMAC128` / `KMAC256` | ✓ Approved | ✅ Recommended | 🚫 Not in CNSA | Keccak-based MACs not in CNSA |
| `Poly1305` | ⚠ Conditional | ✅ Recommended | 🚫 Not in CNSA | Standalone Poly1305 not in CNSA |
| `ChaCha20-Poly1305` | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | CNSA mandates AES-GCM only |
| `RSAES-OAEP-2048-*` | ✓ Approved | 🔜 Transitional | 🚫 Not in CNSA | CNSA requires ≥3072-bit RSA |
| `ECDH-[P-256\|P-521]` | ✅ Recommended | ✅ Until 2031 | 🚫 Not in CNSA | CNSA mandates P-384 only |
| `ECDH-[Curve25519\|X25519]` | ✅ Recommended | ✅ Until 2031 | 🚫 Not in CNSA | Edwards curves not in CNSA |
| `EdDSA-[Ed25519\|Ed448]` | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | EdDSA not in CNSA |
| `ML-KEM-512` | ✓ Approved | ❌ Not recommended | 🚫 Not in CNSA | CNSA mandates ML-KEM-1024 |
| `ML-KEM-768` | ✅ Recommended | ✅ Recommended (hybrid) | 🚫 Not in CNSA | CNSA mandates ML-KEM-1024 |
| `ML-DSA-44` / `ML-DSA-65` | ✓ Approved / ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | CNSA mandates ML-DSA-87 |
| `SLH-DSA-*` (all variants) | ✓ Approved | ✅ Recommended | 🚫 Not in CNSA | SLH-DSA not in CNSA suite |
| `FN-DSA-512` / `FN-DSA-1024` | ⚠ Conditional | — Not yet evaluated | 🚫 Not in CNSA | FIPS 206 IPD; CNSA mandates ML-DSA-87 |

**Action:** For US National Security Systems (NSS), only the CNSA 2.0 algorithm
suite is permitted. For civilian systems, NIST and BSI guidance is sufficient.

### Pattern B: NIST/BSI Disagreement on PQC Security Margin

| Algorithm | NIST | BSI | Issue |
|:---|:---|:---|:---|
| `ML-KEM-512` | ✓ Approved | ❌ Not recommended | BSI requires NIST Category 3 minimum (ML-KEM-768 / 1024) for quantum resistance margin |

### Pattern C: IETF retains weak Algorithms for Protocol Interop

IETF protocol RFCs prioritise interoperability with installed bases, often
retaining algorithms that NIST and BSI disallow:

| # | Protocol | Algorithm | IETF | NIST | BSI | Reason |
|:---:|:---|:---|:---|:---|:---|:---|
| 1 | SSH KEX | `diffie-hellman-group14-sha256` | ✅ MUST (RFC 9142 §3.2.2) | 🔜 Transitional | 🔜 Transitional | Required for SSH-2 interop with legacy peers; only KEX with MUST status |
| 2 | SSH KEX | `diffie-hellman-group14-sha1` | ◯ MAY (RFC 9142 §3.4) | 🚫 Disallowed | 🚫 Disallowed | Retained in §3.4 "Algorithms with Security Concerns" for legacy interop |
| 3 | SSH cipher | `3des-cbc` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | RFC 4253 not updated; OpenSSH disabled by default but spec still permits |
| 4 | SSH MAC | `hmac-sha1*` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | RFC 4253 not updated |
| 5 | SSH MAC | `hmac-md5*` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | RFC 4253 not updated |
| 6 | IPsec IKEv2 | Group 14 (2048-bit MODP) | ✅ MUST (RFC 8247 §2.4) | 🔜 Transitional | 🔜 Transitional | Required for IKEv2 interop |
| 7 | IPsec ESP/AH | `HMAC-SHA1-96` | ⚠ MUST- (RFC 8221 §6) | 🚫 Disallowed | 🚫 Disallowed | "MUST minus" — downgraded from MUST but still required for interop |
| 8 | DNSSEC TSIG | `HMAC-MD5` | ◯ MAY (RFC 8945) | 🚫 Disallowed | 🚫 Disallowed | RFC 8945 retains for backward compat |

**Action:** Where the underlying primitive is broken or weak, prefer IETF's
stricter modern alternatives (e.g., SHA-256 over SHA-1, AES over 3DES) and treat
the IETF backward-compat retention as advisory only. NIST/BSI cryptographic policy
overrides IETF interop requirements in regulated environments.

### Pattern D: NIST disallows, BSI grants Migration Window

BSI TR-02102-1 sets explicit calendar deadlines (typically 2029–2031) for
algorithms NIST has already disallowed:

| Algorithm | NIST | BSI | Migration deadline |
|:---|:---|:---|:---|
| `RSAES-PKCS1-[2048\|3072\|4096]` | 🚫 Disallowed | ✅ Until 2031 | BSI: 2031 |
| `RSASSA-PKCS1-2048-*` | ❌ Deprecated | ✅ Until 2031 | BSI: 2031 |
| `RSASSA-*-1024-*` | 🚫 Disallowed | ✅ Until 2031 | BSI: 2031 |
| `DSA-1024-*` | 🚫 Disallowed | 🔜 Until 2029 | BSI: 2029 |
| `FFDH-[1024\|1536]` | 🚫 Disallowed | ✅ Until 2031 | BSI: 2031 |
| `ECDH-secp256k1` | ❌ Deprecated | ✅ Until 2031 | BSI: 2031 |
| `PBKDF1-*` | 🚫 Disallowed | ✅ Recommended (TR-02102-1 §B.2) | (BSI text appears anomalous; verify) |
| `PBKDF2-HMAC-SHA-1-*` | ❌ Deprecated | ✅ Recommended (TR-02102-1 §4) | (BSI text appears anomalous; verify) |

**Action:** Both NIST and BSI agree these algorithms are weak; the disagreement
is purely about migration timing. Plan migration on the **earlier** deadline
(NIST's) for safety margin. The two PBKDF entries marked anomalous likely
reflect transcription errors and should be cross-checked against the actual
TR-02102-1 §B.2 text.

### Pattern E: BSI more permissive than NIST on specific Modes

Algorithms where BSI accepts a mode/use that NIST flags conditional or disallowed:

| Algorithm | NIST | BSI | Reason |
|:---|:---|:---|:---|
| `AES-*-GCM-[32\|64]` (truncated tag) | 🚫 Disallowed | ✅ Recommended | BSI's BSI-approved IPsec/TLS profiles permit short tags |
| `AES-[128\|192\|256]-ECB` | 🚫 Disallowed | ✅ Recommended | BSI table covers single-block use cases (CMAC underlying primitive); NIST disallows for general use |

These appear to be **listing-coverage anomalies** — BSI's tables list AES modes
as approved at the algorithm level even though they're meant for specific use
cases. They warrant cross-checking against the actual BSI text.

---

## MEDIUM Divergences (23)

Notable nuances; one tier of separation indicates a meaningful caveat that should
be flagged in security reviews. Selected examples:

### Algorithm-Level

| Algorithm | NIST | BSI | CNSA | Notes |
|:---|:---|:---|:---|:---|
| `AES-*-GCM-96` (96-bit tag) | ⚠ Conditional | ✅ Recommended | ⚠ AES-256 only | NIST allows only for IPsec/TLS where the protocol enforces nonce uniqueness |
| `Poly1305` (standalone) | ⚠ Conditional | ✅ Recommended | 🚫 Not in CNSA | NIST cautious about standalone use |
| `HMAC-SHA-1` | 🔜 Transitional | 🚫 Not recommended | 🚫 Not in CNSA | NIST allows through 2030 at 112-bit security |
| `DSA-1024-*` | 🚫 Disallowed | 🔜 Until 2029 | 🚫 Not in CNSA | BSI grants longer migration window |
| `TLS12-PRF-SHA-256` | ⚠ Conditional | ✅ Recommended | — | NIST flags TLS 1.2 as transitional |

### Protocol-Level

| Protocol | Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|
| SSH cipher | `aes256-cbc` | ◯ MAY | ⚠ Conditional | ❌ Deprecated | BSI most conservative |
| PKI signing | `RSA-2048` | ✓ Permitted (CABF) | ✓ Approved | 🔜 Transitional | BSI requires ≥3000 bits for new CA keys |
| Kerberos PKINIT | DH ≥ 2048 bits | ✓ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional | NIST/BSI flag 2048-bit DH |
| TSIG | `HMAC-SHA-1` | ✅ MUST (RFC 8945) | ✓ Approved | ⚠ Conditional | RFC 8945 makes SHA-1 mandatory for DNSSEC TSIG interop |
| TSIG | `HMAC-SHA-384` / `HMAC-SHA-512` | ◯ MAY (RFC 8945) | ✓ Approved | ✅ Recommended | BSI prefers stronger TSIG variants |

---

## Minor Divergences (77)

Mostly differences between "Recommended" and "Approved" terminology, or between
IETF SHOULD/MAY and NIST/BSI Approved. These are wording-level differences without
practical impact on security posture.

Common patterns:

- **NIST `✓ Approved` ↔ BSI `✅ Recommended`** — applies to KMAC128, KMAC256, HSS,
  XMSSMT, Fortuna, ML-KEM-1024, ML-DSA-44, ML-DSA-87, SLH-DSA variants. BSI tends
  to mark PQC and modern primitives as Recommended where NIST uses Approved.
- **NIST `✅ Recommended` ↔ BSI `✓ Approved`** — applies to SHA-512/256, SHAKE128,
  SHAKE256. NIST gives stronger endorsement.
- **IETF `◯ MAY` ↔ NIST/BSI `✓ Approved`** — applies to many SSH and IPsec
  algorithms. IETF's neutral "MAY" doesn't carry the same endorsement as NIST/BSI's
  "Approved".
- **IETF `❌ SHOULD NOT` ↔ NIST/BSI `🚫 Disallowed`** — applies to legacy algorithms
  (SSH ssh-rsa, dh-group1-sha1, etc.). IETF discourages but doesn't prohibit.
- **AES-256 multi-key-size rows** — patterns like `AES-[128|192|256]-MODE` carry
  CNSA = "✓ AES-256 only" (tier 1) versus NIST/BSI ✅ Recommended (tier 0).
  Considered minor because the row covers AES-256 (CNSA-acceptable) plus weaker
  variants (CNSA-excluded).

For the full list, run `python3 scripts/validate_consistency.py`.

---

## Recurring Patterns (summary)

| Pattern | Direction | Number of Cases | Reconciliation |
|:---|:---|:---:|:---|
| **A: CNSA excludes NIST/BSI approved** | CNSA stricter | ~25 | Use CNSA suite for NSS; NIST/BSI for civilian |
| **B: BSI rejects NIST PQC parameter set** | BSI stricter | 1 | Use ML-KEM-768 / ML-KEM-1024 for BSI compliance |
| **C: IETF retains for protocol interop** | IETF more permissive | 8 | NIST/BSI override in regulated environments |
| **D: BSI grants migration window** | BSI more permissive | ~6 | Plan migration on the earlier (NIST) deadline |
| **E: BSI table coverage anomaly** | BSI more permissive | 2 | Verify against actual BSI text |

---

## Reconciliation Guidance

When NIST, BSI, and CNSA all agree → use the algorithm without restrictions.

When they disagree, choose based on the deployment context:

| Context | Authority to follow | Rationale |
|:---|:---|:---|
| US National Security Systems (NSS) | **CNSA 2.0** | CNSA is mandatory for all US federal NSS; NIST baseline is *insufficient* |
| US federal civilian / FIPS 140-3 | **NIST** | SP 800-131A Rev 2 + SP 800-57; CNSA optional for non-NSS |
| German / EU enterprise / eIDAS | **BSI** | TR-02102-1 is the German baseline; NIST + BSI typically aligned |
| Public-trust web PKI | **CABF + NIST** | CA/Browser Forum BR is mandatory; NIST baseline complementary |
| Protocol implementations (SSH, IPsec, DNSSEC, TSIG) | **IETF + the strictest of NIST/BSI/CNSA** | IETF defines the protocol; algorithm policy adds restrictions |
| New designs (no legacy constraints) | **Strictest of {NIST, BSI, CNSA}** | Future-proofing |
| Migration of legacy systems | **NIST migration deadlines** | NIST is typically earlier than BSI; plan for the earlier date |

---

## Sources

- [`cryptographic-algorithm-status.md`](cryptographic-algorithm-status.md) — algorithm-level NIST + BSI + CNSA guidance
- [`cryptographic-protocol-status.md`](cryptographic-protocol-status.md) — protocol-level IETF + NIST + BSI + CABF guidance
- `scripts/validate_consistency.py` (check #9) — automated divergence detection
- IETF RFCs: 9142 (SSH KEX), 8332 (SSH RSA-SHA2), 8709 (SSH Ed25519), 5656 (SSH ECDSA),
  4344 (SSH CTR), 5647 (SSH AES-GCM), 6668 (SSH HMAC-SHA2), 4253 (SSH-2 transport),
  8221 (IPsec ESP/AH algorithms), 8247 (IKEv2 algorithms), 8624 (DNSSEC algorithms),
  8945 (TSIG), 6649 (Kerberos DES deprecation), 8429 (Kerberos 3DES/RC4 deprecation),
  8009 (Kerberos AES-SHA2), 4556 (Kerberos PKINIT)
- NIST: SP 800-131A Rev 2 (algorithm transitions), SP 800-57 Part 3 Rev 1
  (PKI/S/MIME/Kerberos/DNSSEC), SP 800-186 (curves), SP 800-90A Rev 1 (DRBGs),
  SP 800-208 (stateful HBS), FIPS 197 (AES), FIPS 180-4 (SHA-2), FIPS 186-5 (DSA/ECDSA),
  FIPS 202 (SHA-3), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- BSI: TR-02102-1 v2026-01 (cryptographic mechanisms), TR-02102-3 v2026-01 (IPsec),
  TR-02102-4 v2026-01 (SSH)
- NSA CNSA 2.0: Cybersecurity Advisory PP-22-1338, "Announcing the Commercial
  National Security Algorithm Suite 2.0", September 2022
- CA/Browser Forum: Baseline Requirements (BR) §6.1.5 (CA key size and algorithm requirements)
