# Cryptographic Authority Inconsistencies

Cross-authority comparison of cryptographic algorithm guidance from IETF, NIST, BSI,
and CA/Browser Forum. This document records concrete cases where the four
authorities disagree on an algorithm's status, highlights substantive policy
disagreements, and explains the recurring patterns behind them.

The findings are generated automatically by `scripts/validate_consistency.py`
(check #9 — *NIST/BSI authority divergence*) which scans both
[`cryptographic-algorithm-status.md`](cryptographic-algorithm-status.md) and
[`cryptographic-protocol-status.md`](cryptographic-protocol-status.md), normalises
each cell to a 6-tier severity scale, and reports any row where authorities differ.

> **Last updated:** 2026-04-11. Re-run `python3 scripts/validate_consistency.py`
> to refresh.

---

## Methodology

### Severity Tiers

Every status cell is normalised to one of six tiers, lowest = most permissive:

| Tier | NIST/BSI | IETF | CABF | Examples |
|:---:|:---|:---|:---|:---|
| 0 | ✅ Recommended | ✅ MUST / REQUIRED | — | "✅ Recommended", "MUST" |
| 1 | ✓ Approved / Acceptable | ✓ SHOULD / RECOMMENDED | ✓ Permitted | "✓ Approved", "SHOULD" |
| 2 | ⚠ Conditional | ◯ MAY / OPTIONAL · ⚠ MUST- | — | "MAY", "MUST minus", "Conditional" |
| 3 | 🔜 Transitional / Until \<year\> | — | — | "🔜 Transitional", "✅ Until 2031" |
| 4 | ❌ Deprecated / Removed | ❌ SHOULD NOT / NOT RECOMMENDED | — | "Deprecated", "SHOULD NOT" |
| 5 | 🚫 Disallowed / Broken | 🚫 MUST NOT / PROHIBITED | — | "Disallowed", "MUST NOT" |

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

---

## Summary

Total comparable rows across both files: **142**

| Category | Count | Share |
|:---|---:|---:|
| All authorities agree | 58 | 41 % |
| Diverging guidance | 84 | 59 % |
| ↳ MAJOR (tier diff ≥ 3) | 9 | 6 % |
| ↳ MEDIUM (tier diff = 2) | 13 | 9 % |
| ↳ minor (tier diff = 1) | 62 | 44 % |

---

## MAJOR Divergences (9)

These represent substantive policy disagreements worth documenting in security
posture analyses and migration plans. Continuous revision is mandatory.

### 1. ML-KEM-512 — NIST/BSI Disagreement on Post-Quantum Security Level

| Authority | Status | Reference |
|:---|:---|:---|
| NIST | ✓ Approved | FIPS 203 (standardised) |
| BSI | ❌ Not recommended | TR-02102-1 |

**Context:** NIST FIPS 203 standardised ML-KEM at three parameter sets (512, 768, 1024).
ML-KEM-512 targets NIST Category 1 (~128-bit classical, ~64-bit post-quantum). BSI
considers this insufficient against future quantum attackers and only recommends
ML-KEM-768 (Category 3) and ML-KEM-1024 (Category 5) for hybrid deployments.

**Action:** Use ML-KEM-768 or ML-KEM-1024 for new deployments requiring BSI compliance.

### 2-8. SSH and IPsec Legacy Algorithm Retention by IETF

The recurring pattern: **IETF retains weak algorithms as MAY (or even MUST/MUST-)
for backward compatibility, while NIST and BSI disallow them**.

| # | Protocol | Algorithm | IETF | NIST | BSI | IETF reason |
|:---:|:---|:---|:---|:---|:---|:---|
| 2 | SSH KEX | `diffie-hellman-group14-sha256` | ✅ MUST (RFC 9142 §3.2.2) | 🔜 Transitional | 🔜 Transitional | Required for SSH-2 interop with legacy peers; only KEX with MUST status |
| 3 | SSH KEX | `diffie-hellman-group14-sha1` | ◯ MAY (RFC 9142 §3.4) | 🚫 Disallowed | 🚫 Disallowed | Retained in §3.4 "Algorithms with Security Concerns" for legacy interop |
| 4 | SSH cipher | `3des-cbc` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | RFC 4253 not updated; OpenSSH disabled by default but spec still permits |
| 5 | SSH MAC | `hmac-sha1*` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | RFC 4253 not updated |
| 6 | SSH MAC | `hmac-md5*` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | RFC 4253 not updated |
| 7 | IPsec IKEv2 | Group 14 (2048-bit MODP) | ✅ MUST (RFC 8247 §2.4) | 🔜 Transitional | 🔜 Transitional | Required for IKEv2 interop |
| 8 | IPsec ESP/AH | `HMAC-SHA1-96` | ⚠ MUST- (RFC 8221 §6) | 🚫 Disallowed | 🚫 Disallowed | "MUST minus" — downgraded from MUST but still required for interop |

**Action:** Where the underlying primitive is broken or weak, prefer IETF's stricter
modern alternatives (e.g., SHA-256 over SHA-1, AES over 3DES) and treat the IETF
backward-compat retention as advisory only. NIST/BSI cryptographic policy
overrides IETF interop requirements in regulated environments.

### 9. DNSSEC TSIG HMAC-MD5

| Authority | Status | Reference |
|:---|:---|:---|
| IETF | ◯ MAY | RFC 8945 |
| NIST | 🚫 Disallowed | SP 800-131A Rev 2 |
| BSI | 🚫 Disallowed | TR-02102-1 |

**Context:** RFC 8945 (the TSIG specification) retains HMAC-MD5 as MAY for backward
compatibility with legacy DNSSEC deployments. Both NIST and BSI prohibit MD5 in
any cryptographic role.

**Action:** Migrate to HMAC-SHA-256 (mandatory in RFC 8945) for all new DNSSEC
deployments.

---

## MEDIUM Divergences (13)

Notable nuances; one tier of separation indicates a meaningful caveat that should
be flagged in security reviews.

### Algorithm-Level (algorithm-status.md)

| Algorithm | NIST | BSI | Notes |
|:---|:---|:---|:---|
| `AES-*-GCM-96` (96-bit tag) | ⚠ Conditional | ✅ Recommended | NIST allows only for IPsec/TLS where the protocol enforces nonce uniqueness; BSI accepts for IPsec/TLS use |
| `Poly1305` (standalone) | ⚠ Conditional | ✅ Recommended | NIST cautious about standalone use (only as part of ChaCha20-Poly1305); BSI permits |
| `HMAC-SHA-1` | 🔜 Transitional | 🚫 Not recommended | NIST allows through 2030 at 112-bit security; BSI more restrictive |
| `DSA-1024-*` | 🚫 Disallowed | 🔜 Until 2029 | BSI grants longer migration window for legacy systems |
| `RSASSA-*-1024-*` | 🚫 Disallowed | 🔜 Until 2031 | BSI's longer migration horizon |
| `TLS12-PRF-SHA-256` | ⚠ Conditional | ✅ Recommended | NIST flags TLS 1.2 use as transitional; BSI accepts in maintained deployments |

### Protocol-Level (protocol-status.md)

| Protocol | Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|
| SSH cipher | `aes256-cbc` | ◯ MAY | ⚠ Conditional | ❌ Deprecated | BSI most conservative |
| PKI signing | `RSA-2048` | ✓ Permitted (CABF) | ✓ Approved | 🔜 Transitional | BSI requires ≥3000 bits for new CA keys |
| Kerberos PKINIT | DH ≥ 2048 bits | ✓ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional | NIST/BSI flag 2048-bit DH; IETF still permits |
| Kerberos PKINIT | RSA ≥ 2048 bits | ✓ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional | Same as above |
| TSIG | `HMAC-SHA-1` | ✅ MUST (RFC 8945) | ✓ Approved | ⚠ Conditional | RFC 8945 makes SHA-1 mandatory for DNSSEC TSIG interop |
| TSIG | `HMAC-SHA-384` | ◯ MAY (RFC 8945) | ✓ Approved | ✅ Recommended | BSI prefers stronger TSIG variants |
| TSIG | `HMAC-SHA-512` | ◯ MAY (RFC 8945) | ✓ Approved | ✅ Recommended | Same as above |

---

## Minor Divergences (62)

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

For the full list, run `python3 scripts/validate_consistency.py`.

---

## Recurring Patterns

### Pattern 1: IETF Retains for Interop, NIST/BSI Disallow for Security

**Where:** SSH (RFC 4253, RFC 9142), IPsec (RFC 8221, RFC 8247), TSIG (RFC 8945).

**Examples:** 8 of 9 MAJOR divergences fall into this category.

**Why:** IETF protocol RFCs prioritise interoperability with installed bases.
Removing an algorithm entirely would break legacy peers. NIST and BSI prioritise
cryptographic strength and disallow algorithms once they fall below their security
thresholds.

**Reconciliation:** Treat NIST/BSI as overriding when:
- Operating in regulated environments (FIPS 140-3, BSI BSI-CC, eIDAS)
- New deployments where legacy peers are not a concern
- Security reviews / audits

Treat IETF as overriding when:
- Maintaining interop with legacy peers (e.g., SSH to older OpenSSH versions)
- Implementing the protocol stack itself

### Pattern 2: BSI Longer Migration Horizons

**Where:** RSA-2048, DSA-1024, RSASSA-*-1024, ECDH-secp256k1, FFDH-ffdhe2048.

**Why:** BSI TR-02102-1 sets explicit calendar deadlines (typically 2029-2031) for
algorithms that NIST has already disallowed. This reflects BSI's policy of granting
longer migration windows for installed bases in German/EU enterprise environments.

**Reconciliation:** Both NIST and BSI agree these algorithms are weak; the
disagreement is purely about migration timing. Plan migration on the **earlier**
deadline (NIST's) for safety margin.

### Pattern 3: BSI Stricter on Specific Constructions

**Where:** ML-KEM-512 (rejected by BSI, approved by NIST), HMAC-SHA-1 (BSI not
recommended, NIST transitional through 2030).

**Why:** BSI's TR-02102-1 sets a 120-bit minimum security strength baseline,
stricter than NIST's tiered approach. ML-KEM-512 only reaches 128-bit classical
but BSI requires Category 3 (192-bit) for quantum resistance margin.

**Reconciliation:** Use BSI-acceptable parameters where possible — they generally
satisfy NIST too.

---

## Sources

- [`cryptographic-algorithm-status.md`](cryptographic-algorithm-status.md) — algorithm-level NIST + BSI guidance
- [`cryptographic-protocol-status.md`](cryptographic-protocol-status.md) — protocol-level IETF + NIST + BSI + CABF guidance
- `scripts/validate_consistency.py` (check #9) — automated divergence detection
- IETF RFCs: 9142 (SSH KEX), 8332 (SSH RSA-SHA2), 8709 (SSH Ed25519), 5656 (SSH ECDSA),
  4344 (SSH CTR), 5647 (SSH AES-GCM), 6668 (SSH HMAC-SHA2), 4253 (SSH-2 transport),
  8221 (IPsec ESP/AH algorithms), 8247 (IKEv2 algorithms), 8624 (DNSSEC algorithms),
  8945 (TSIG), 6649 (Kerberos DES deprecation), 8429 (Kerberos 3DES/RC4 deprecation),
  8009 (Kerberos AES-SHA2), 4556 (Kerberos PKINIT)
- NIST: SP 800-131A Rev 2 (algorithm transitions), SP 800-57 Part 3 Rev 1 (PKI/S/MIME/Kerberos/DNSSEC),
  SP 800-186 (curves), SP 800-90A Rev 1 (DRBGs), FIPS 203/204/205 (PQC)
- BSI: TR-02102-1 v2026-01 (cryptographic mechanisms), TR-02102-3 v2026-01 (IPsec),
  TR-02102-4 v2026-01 (SSH)
- CA/Browser Forum: Baseline Requirements (BR) §6.1.5 (CA key size and algorithm requirements)
