# Cryptographic Algorithm Status and Alerts

> Characteristics, status, and alerts derived from NIST and BSI publications.
> Algorithms and RNGs are expressed using the CycloneDX pattern notation extended with two
> wildcard conventions defined below.
>
> **Primary sources:** NIST SP 800-57 Pt 1 Rev 5 (May 2020; Rev 6 IPD Dec 2025) · SP 800-57 Pt 2 Rev 1 (May 2019) · SP 800-57 Pt 3 Rev 1 (Jan 2015) ·
> SP 800-107 Rev 1 · SP 800-131A Rev 2 (Rev 3 IPD Oct 2024) · SP 800-38 series ·
> SP 800-56A Rev 3 · SP 800-56B/C · SP 800-90A Rev 1 (Rev 2 pre-draft 2025) · SP 800-90B · SP 800-132 · SP 800-135 ·
> SP 800-186 · SP 800-208 · NIST IR 8214C · FIPS 140-3 · FIPS 180-4 · FIPS 186-5 · FIPS 197 · FIPS 198-1 · FIPS 202 · FIPS 203/204/205 · FIPS 206 (IPD) ·
> NSA CNSA 2.0 (PP-22-1338, Sep 2022) ·
> BSI TR-02102-1 v2026-01 (2026-01-23) · BSI TR-02102-2 v2026-01 (2025-12-27) ·
> BSI TR-02102-3 v2026-01 (2026-01-27) · BSI TR-02102-4 v2026-01 (2026-01-27) · BSI AIS 20/31 v3 (2022) ·
> ENISA "Post-Quantum Cryptography: Current state and quantum mitigation" v2 (May 2021)

---

## Notation

Standard CycloneDX pattern symbols apply throughout. Two extensions are used in this document only:

| Symbol | Meaning |
|:---|:---|
| `*` | Wildcard — the recommendation is agnostic to the value of this parameter; any conforming value is acceptable |
| `[v1\|v2]` | Enumeration — only these specific values are applicable to this recommendation (not an optional segment) |

Examples: `AES-[128|192|256]-*` — AES with any of the listed key sizes, any mode; `AES-*-ECB` — AES in ECB mode regardless of key size.

---

## Status Legend

| Symbol | Status | Meaning |
|:---|:---|:---|
| ✅ | **Recommended** | Actively recommended for new designs |
| ✓ | **Approved** | Approved; acceptable for new designs |
| ⚠ | **Conditional** | Approved only with stated restrictions |
| 🔜 | **Transitional** | Acceptable until stated horizon; migrate away |
| ❌ | **Deprecated** | Must not be used in new designs |
| 🚫 | **Disallowed** | Must not be used at all |

---

## Authorities Compared

This document compares cryptographic primitives against three authorities that issue
**algorithm-level** normative guidance: **NIST**, **BSI**, and **NSA CNSA 2.0**.

| Authority | Role | Document |
|:---|:---|:---|
| **NIST** | US civilian / federal | SP 800-131A Rev 2, FIPS 197/180-4/186-5/202/203/204/205 |
| **BSI** | German / EU civilian | TR-02102-1 v2026-01 |
| **CNSA** | US military / National Security Systems | NSA CNSA 2.0 (PP-22-1338, Sep 2022) |

> **Why no IETF column at the algorithm level?** IETF rarely issues normative
> requirements at the primitive level — most IETF cryptographic RFCs either
> *specify* an algorithm (e.g., RFC 8017 for RSA, RFC 5869 for HKDF) without
> mandating its use, or are *informational* (RFC 6151 for MD5, RFC 6194 for SHA-1).
> Where IETF does tabulate algorithm requirements (RFC 9142 for SSH, RFC 8221/8247
> for IPsec, RFC 8624 for DNSSEC, RFC 8945 for TSIG), the scope is *protocol-level*
> and is documented in [`cryptographic-protocol-status.md`](cryptographic-protocol-status.md)
> instead.

> **CNSA 2.0 column conventions:**
> - **✅ Mandatory** — explicitly named in CNSA 2.0 as the required algorithm and parameter set
> - **🔜 Transitional** — permitted only during the 2025-2030 transition window; will be replaced by PQC
> - **🚫 Not in CNSA** — not part of the CNSA 2.0 suite (effectively disallowed for NSS use)
> - **—** — no CNSA position (out-of-scope: e.g., non-cryptographic checksums, password hashes)

---

## 1. Symmetric Encryption

### 1.1 Block Cipher Key Length

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `AES-256-*` | 256 bit | ✅ Recommended | ✅ Recommended | ✅ Mandatory | FIPS 197; SP 800-57; BSI TR-02102-1 §3.3; CNSA 2.0 | CNSA 2.0 mandates AES-256 only |
| `AES-[128\|192]-*` | 128–192 bit | ✅ Recommended | ✅ Recommended | 🚫 Not in CNSA | FIPS 197; SP 800-57; BSI TR-02102-1 §3.3 | NIST/BSI accept; CNSA 2.0 only allows AES-256 |
| `CAMELLIA-[128\|256]-*` | 128–256 bit | ✓ Approved | ✅ Recommended | 🚫 Not in CNSA | BSI TR-02102-1 §3.3 | Approved by BSI; not in NIST FIPS or CNSA list |
| `3DES-*` | ≤112 bit | ❌ Deprecated | 🚫 Not recommended (TR-02102-1) | 🚫 Not in CNSA | SP 800-131A Rev 2 §2; NIST IR 8214C | Disallowed for encryption after 2023; 64-bit block causes birthday-bound issues at ≥ 2³² blocks |
| `DES-*` | 56 bit | 🚫 Disallowed | 🚫 Not recommended (TR-02102-1) | 🚫 Not in CNSA | SP 800-131A Rev 2 | Cryptographically broken |
| `RC2-*` | ≤128 bit | 🚫 Disallowed | 🚫 Not recommended | 🚫 Not in CNSA | SP 800-131A Rev 2 | Legacy only; no new use |
| `RC4-*` | — | 🚫 Disallowed | 🚫 Not recommended | 🚫 Not in CNSA | SP 800-131A Rev 2; RFC 7465 | Stream cipher; statistically weak; banned in TLS |
| `IDEA-*` | 128 bit | ❌ Deprecated | ❌ Removed (TR-02102-1) | 🚫 Not in CNSA | BSI | Not NIST/FIPS approved; BSI removed |
| `Blowfish-*` | ≤448 bit | ❌ Deprecated | ❌ Not listed (TR-02102-1) | 🚫 Not in CNSA | — | 64-bit block; birthday bound vulnerable |

> ⚠ **3DES birthday bound:** With a 64-bit block, collisions become probable after ~2³² (4 GB) encrypted blocks under the same key. NIST disallowed 3DES for all new encryption effective 2024. Existing uses must migrate.

### 1.2 Block Cipher Modes

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `AES-[128\|192\|256]-GCM` | 128–256 bit | ✅ Recommended | ✅ Recommended | ✓ AES-256 only | SP 800-38D; BSI TR-02102-1 §3.3; CNSA 2.0 | AEAD; preferred for authenticated encryption; CNSA 2.0 mandates AES-256 |
| `AES-[128\|192\|256]-CCM` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38C; BSI TR-02102-1 | AEAD; suitable for constrained environments |
| `AES-[128\|192\|256]-GCM-SIV` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | RFC 8452; BSI TR-02102-1 | Nonce-misuse resistant; deterministic AEAD |
| `AES-[128\|192\|256]-CTR` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38A | No authentication; counter must never repeat with same key |
| `AES-[128\|192\|256]-CBC` | 128–256 bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38A; BSI TR-02102-1 | Requires unpredictable (pseudorandom) IV; no integrity protection |
| `AES-[128\|192\|256]-CFB[128]` | 128–256 bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38A | IV must be unique; rarely preferred over CTR |
| `AES-[128\|192\|256]-OFB` | 128–256 bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38A | IV must be unique; malleable without MAC |
| `AES-[128\|192\|256]-XTS` | 128–256 bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38E; IEEE 1619 | **Storage encryption only**; not for network use; provides no integrity |
| `AES-[128\|192\|256]-ECB` | 128–256 bit | 🚫 Disallowed | ✅ Recommended (TR-02102-1 §3.3) | 🚫 Not in CNSA | SP 800-38A; BSI TR-02102-1 | Deterministic; reveals identical blocks; prohibited for multi-block use |
| `AES-KW-[128\|192\|256]` | 128–256 bit | ✓ Approved | — | ✓ AES-256 only | SP 800-38F | Key-wrapping only; not a general encryption mode |
| `ChaCha20-Poly1305` | 256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §3.4) | 🚫 Not in CNSA | RFC 8439; BSI TR-02102-1 (2024) | AEAD; constant-time; preferred when AES-NI unavailable. Note: not in NIST FIPS approved list but BSI-approved; not in CNSA 2.0 |

> ⚠ **GCM IV uniqueness:** IV reuse under AES-GCM with the same key allows full key recovery. Use 96-bit random IVs with a CSPRNG, or a deterministic counter with strict uniqueness guarantees. After 2³² random IVs, collision probability exceeds 2⁻³² — implement rekey policies. (SP 800-38D §8.3)

> ⚠ **CBC IV:** The IV for AES-CBC **must be unpredictable** (generated by an approved CSPRNG before each encryption). A predictable or reused IV enables chosen-plaintext attacks (BEAST). (SP 800-38A §B.2)

> ⚠ **Authentication:** CBC, CTR, CFB, and OFB provide **no integrity or authenticity**. Always pair with an approved MAC (HMAC or GMAC) or use an AEAD mode.

### 1.3 Tag Length (AEAD)

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `AES-*-GCM[-128]` | 128-bit tag | ✅ Recommended | ✅ Recommended (TR-02102-1 §3.4) | ✓ AES-256 only | SP 800-38D; BSI TR-02102-1; RFC 5116 | Full 128-bit tag required for general use |
| `AES-*-GCM-96` | 96-bit tag | ⚠ Conditional | ✅ Recommended (TR-02102-1 §3.4) | ⚠ AES-256 only | SP 800-38D §5.2.1.2 | Permitted only for specific protocols (IPsec, TLS); verify protocol allows truncation |
| `AES-*-GCM-[32\|64]` | 32–64-bit tag | 🚫 Disallowed | ✅ Recommended (TR-02102-1 §3.4) | 🚫 Not in CNSA | SP 800-38D | Forgery probability too high for general use |

---

## 2. Hash Functions

| Pattern | Output | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|:---|
| `SHA-384` | 384 bit | 192 bit | ✅ Recommended (TR-02102-1 §4) | ✅ Recommended | ✅ Mandatory | FIPS 180-4; CNSA 2.0 | CNSA 2.0 mandates SHA-384 for general use |
| `SHA-512` | 512 bit | 256 bit | ✅ Recommended (TR-02102-1 §4) | ✅ Recommended | ✓ Approved | FIPS 180-4 | Acceptable in CNSA 2.0 contexts; SHA-384 preferred |
| `SHA-256` | 256 bit | 128 bit | ✅ Recommended (TR-02102-1 §4) | ✅ Recommended | 🚫 Not in CNSA | FIPS 180-4; BSI TR-02102-1 | Minimum for NIST/BSI; CNSA 2.0 mandates SHA-384 |
| `SHA-512/256` | 256 bit | 256 bit | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | 🚫 Not in CNSA | FIPS 180-4 | Truncated SHA-512; efficient on 64-bit |
| `SHA3-[256\|384\|512]` | 256–512 bit | 128–256 bit | ✅ Recommended (TR-02102-1 §4) | ✅ Recommended | 🚫 Not in CNSA | FIPS 202; BSI TR-02102-1 | Structurally independent of SHA-2; CNSA 2.0 only specifies SHA-2 |
| `SHAKE128` | variable | 128 bit | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | 🚫 Not in CNSA | FIPS 202 | XOF; use ≥ 32-byte (256-bit) output for 128-bit security |
| `SHAKE256` | variable | 256 bit | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | 🚫 Not in CNSA | FIPS 202 | XOF; use ≥ 64-byte (512-bit) output for 256-bit security |
| `BLAKE2b-[256\|384\|512]` | variable | 128–256 bit | — | ⚠ Conditional | 🚫 Not in CNSA | BSI | Approved by BSI; not in NIST FIPS or CNSA list |
| `BLAKE3` | variable | 128 bit | — | ⚠ Conditional | 🚫 Not in CNSA | — | Not yet in NIST or BSI formal guidance |
| `SHA-224` | 224 bit | 112 bit | ✅ Recommended (TR-02102-1 §4) | 🔜 Transitional | 🚫 Not in CNSA | FIPS 180-4; SP 800-131A | 112-bit security; acceptable through 2030; disallowed from 2031 per SP 800-131A Rev 3 IPD; prefer SHA-256 for new designs |
| `SHA-1` | 160 bit | 69 bit (collision) | 🚫 Not recommended (TR-02102-1) | ❌ Deprecated | 🚫 Not in CNSA | SP 800-131A Rev 2 §9; BSI TR-02102-1 | **Disallowed for signatures, certificates, and collision-resistance** since 2013. Permitted only for HMAC-SHA-1 at legacy 112-bit security level through 2030 (NIST only, not BSI) |
| `MD5` | 128 bit | — | 🚫 Not recommended (TR-02102-1) | 🚫 Disallowed | 🚫 Not in CNSA | SP 800-131A; RFC 6151 | Collision attacks demonstrated; disallowed for all security purposes |
| `MD4` | 128 bit | — | — | 🚫 Disallowed | 🚫 Not in CNSA | — | Broken |

> ⚠ **SHA-1 collision:** SHAttered attack (2017) demonstrated SHA-1 collisions at cost of ~2⁶³·¹ SHA-1 compressions. SHA-1 is fully deprecated for any collision-resistance use. NIST certificates with SHA-1 expired or were revoked by 2019.

---

## 3. Message Authentication Codes (MAC)

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `HMAC-[SHA-384\|SHA-512]` | 192–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | FIPS 198-1; SP 800-107; BSI TR-02102-1 | CNSA-compatible since SHA-384/512 are |
| `HMAC-SHA-256` | 128 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 198-1; SP 800-107 | NIST/BSI accept; CNSA mandates SHA-384 |
| `HMAC-[SHA3-256\|SHA3-384\|SHA3-512]` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 198-1; FIPS 202 | CNSA does not include SHA-3 |
| `HMAC-SHA-256[-128]` | 128 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | SP 800-107 | Truncated HMAC; output ≥ 128 bits |
| `AES-[128\|192\|256]-CMAC` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §3.3) | ✓ AES-256 only | SP 800-38B; FIPS 198-1; BSI TR-02102-1 | Preferred MAC when HMAC is impractical (hardware AES available); CNSA mandates AES-256 |
| `KMAC128` | 128 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §5) | 🚫 Not in CNSA | SP 800-185 | CNSA does not include Keccak-based MACs |
| `KMAC256` | 256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §5) | 🚫 Not in CNSA | SP 800-185 | CNSA does not include Keccak-based MACs |
| `Poly1305` | 128 bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §3.4) | 🚫 Not in CNSA | RFC 8439; BSI TR-02102-1 | One-time MAC; secure only as part of ChaCha20-Poly1305 or AES-Poly1305; not standalone |
| `HMAC-SHA-1` | 112 bit | 🔜 Transitional | 🚫 Not recommended (TR-02102-1) | 🚫 Not in CNSA | SP 800-131A Rev 2 | Permitted through 2030 for legacy; 112-bit security minimum. **BSI: no longer recommended** |
| `HMAC-MD5` | — | 🚫 Disallowed | 🚫 Not recommended (TR-02102-1) | 🚫 Not in CNSA | SP 800-131A | MD5 key-size weakness exploitable; disallowed |
| `CBC-MAC-*` | — | ❌ Deprecated | — | 🚫 Not in CNSA | SP 800-38B | Variable-length input attacks; superseded by CMAC |
| `AES-*-GMAC` | 128–256 bit | ⚠ Conditional | ⚠ Conditional (TR-02102-1 §5) | ✓ AES-256 only | SP 800-38D | AES-GCM with empty plaintext; inherits GCM IV-uniqueness requirement strictly |

> ⚠ **Truncated MAC:** Truncated HMAC output must be ≥ 128 bits per SP 800-107 §5.3.4. Shorter tags (e.g., 96-bit) require explicit approval and protocol binding.

---

## 4. Asymmetric Encryption / Key Encapsulation

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `RSAES-OAEP-[3072\|4096]-SHA-384-MGF1` | 128–150+ bit | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | 🔜 Transitional | SP 800-56B Rev 2; FIPS 186-5; BSI TR-02102-1; CNSA 2.0 | CNSA 2.0: transitional with RSA-3072+ and SHA-384 only |
| `RSAES-OAEP-[3072\|4096]-[SHA-256\|SHA-512]-MGF1` | 128–150+ bit | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | SP 800-56B Rev 2; FIPS 186-5; BSI TR-02102-1 | CNSA mandates SHA-384 |
| `RSAES-OAEP-2048-*` | 112 bit | ✓ Approved | 🔜 Transitional | 🚫 Not in CNSA | SP 800-56B Rev 2; FIPS 186-5 | CNSA requires ≥3072 bits |
| `RSAES-PKCS1-[2048\|3072\|4096]` | ≤112 bit | 🚫 Disallowed | ✅ Until 2031 (TR-02102-1 §2.3.2); ≥3000 bit | 🚫 Not in CNSA | SP 800-131A Rev 2; FIPS 186-5 | PKCS#1 v1.5 encryption **disallowed for new use** (Bleichenbacher oracle; not IND-CCA2); legacy decryption only with caution |
| `ML-KEM-1024` | 256 bit (quantum) | ✓ Approved | ✅ Recommended hybrid (TR-02102-1 §2.4.3) | ✅ Mandatory | FIPS 203; CNSA 2.0 | CNSA 2.0 mandates ML-KEM-1024 (Category 5) |
| `ML-KEM-[512\|768]` | 128–192 bit (quantum) | ✓ Approved | ✅ ML-KEM-768 only (TR-02102-1 §2.4.3) | 🚫 Not in CNSA | FIPS 203 | NIST-standardised; CNSA mandates ML-KEM-1024 only; BSI accepts ML-KEM-768 (rejects 512) |
| `ECIES-[P-256\|P-384\|P-521]-*` | 128–192 bit | ✓ Approved | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🚫 Not in CNSA | BSI TR-02102-1 §3.6; SP 800-56A | Hybrid encryption; use ECDH + KDF + AEAD; not in CNSA suite |

> ⚠ **RSAES-PKCS1 (v1.5):** The Bleichenbacher '98 attack and its variants (ROBOT 2017, Lucky Thirteen) allow ciphertext forgery and plaintext recovery. Disallowed for new implementations. Constant-time decryption with rejection of malformed messages is required even in legacy modes.

---

## 5. Key Agreement

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `ECDH-P-384` | 192 bit | ✅ Recommended | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🔜 Transitional | SP 800-56A Rev 3; FIPS 186-5; BSI TR-02102-1 §3.5; CNSA 2.0 | CNSA 2.0 transitional; will be replaced by ML-KEM-1024 |
| `ECDH-[P-256\|P-521]` | 128–260 bit | ✅ Recommended | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🚫 Not in CNSA | SP 800-56A Rev 3; FIPS 186-5; BSI TR-02102-1 §3.5 | CNSA mandates P-384 only |
| `ECDH-[brainpoolP256r1\|brainpoolP384r1\|brainpoolP512r1]` | 128–256 bit | ✓ Approved | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🚫 Not in CNSA | BSI TR-02102-1 §3.5 | BSI-preferred alternative to NIST curves; not in NIST FIPS or CNSA |
| `ECDH-[Curve25519\|X25519]` | 128 bit | ✅ Recommended | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🚫 Not in CNSA | SP 800-186; RFC 7748; BSI TR-02102-1 | Constant-time; default in TLS 1.3; not in CNSA |
| `ECDH-[Curve448\|X448]` | 224 bit | ✓ Approved | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🚫 Not in CNSA | SP 800-186; RFC 7748; BSI TR-02102-1 | 224-bit security |
| `FFDH-[ffdhe3072\|ffdhe4096\|ffdhe6144\|ffdhe8192]` | 128–192 bit | ✓ Approved | ✅ Until 2031 (TR-02102-1 §2.3.5); ≥3000 bit | 🔜 Transitional | SP 800-56A; RFC 7919; BSI TR-02102-1; CNSA 2.0 | CNSA 2.0 transitional with DH ≥3072 |
| `FFDH-ffdhe2048` | 112 bit | 🔜 Transitional | ✅ Until 2031 (TR-02102-1 §2.3.5); ≥3000 bit | 🚫 Not in CNSA | SP 800-57; SP 800-56A | 112-bit security; CNSA requires ≥3072 |
| `FFDH-[1024\|1536]` | <112 bit | 🚫 Disallowed | ✅ Until 2031 (TR-02102-1 §2.3.5); ≥3000 bit | 🚫 Not in CNSA | SP 800-131A Rev 2 | Logjam attack; disallowed |
| `ECDH-secp256k1` | 128 bit | ❌ Deprecated | ✅ Until 2031 (TR-02102-1 §2.3.6); ≥250 bit | 🚫 Not in CNSA | — | Not in NIST SP 800-186 or BSI approved list; used in blockchain only |

> ⚠ **Ephemeral key agreement:** Static (non-ephemeral) ECDH and DH provide no forward secrecy. SP 800-56A requires ephemeral keys for forward-secret key establishment. TLS 1.3 mandates ECDHE or DHE.

### 5.1 Approved Elliptic Curves (SP 800-186)

SP 800-186 (February 2023) specifies the complete catalogue of NIST-approved elliptic curve domain parameters. The table below summarises security strength, approval status, and allowed usage:

#### Weierstrass Prime Curves (FIPS 186-5 Primary Curves)

| Curve | Also known as | Security strength | ECDH | ECDSA / EdDSA | Notes |
|:---|:---|:---|:---|:---|:---|
| P-192 | secp192r1 | 96-bit | ❌ Legacy only | ❌ Legacy only | SP 800-131A Rev 2: disallowed for new use after 2013; legacy verification only |
| P-224 | secp224r1 | 112-bit | ⚠ Transitional | ⚠ Transitional | Through 2030; not recommended for new designs |
| P-256 | secp256r1, prime256v1 | 128-bit | ✅ Recommended | ✅ Recommended | Most widely deployed; TLS 1.3 mandatory curve |
| P-384 | secp384r1 | 192-bit | ✅ Recommended | ✅ Recommended | Required for NSS / CNSA 1.0; NSA baseline |
| P-521 | secp521r1 | 260-bit | ✅ Recommended | ✅ Recommended | Highest NIST prime curve security |

#### Montgomery Curves (SP 800-186 §2.3)

| Curve | Form | Cofactor h | Security | ECDH | Notes |
|:---|:---|:---|:---|:---|:---|
| Curve25519 | By = x³ + Ax² + x; A=486662, B=1 | 8 | 128-bit | ✅ Recommended | Used as X25519 (RFC 7748); constant-time |
| Curve448 | By = x³ + Ax² + x; A=156326, B=1 | 4 | 224-bit | ✓ Approved | Used as X448 (RFC 7748); 224-bit security |

#### Twisted Edwards Curves (SP 800-186 §2.4)

| Curve | Form | Cofactor h | Security | Signature | Notes |
|:---|:---|:---|:---|:---|:---|
| Edwards25519 | ax² + y² = 1 + dx²y²; a=−1, d=−121665/121666 | 8 | 128-bit | ✅ Recommended (Ed25519) | Birationally equivalent to Curve25519; deterministic signing |
| Edwards448 | ax² + y² = 1 + dx²y²; a=1, d=−39081 | 4 | 224-bit | ✓ Approved (Ed448) | Birationally equivalent to Curve448 |

#### Binary Curves (SP 800-186, Appendix G; all deprecated)

All K-series and B-series binary curves (K-163, K-233, K-283, K-409, K-571, B-163, B-233, B-283, B-409, B-571) defined in earlier FIPS 186 editions are **deprecated** in SP 800-186. They are not approved for new implementations due to implementation complexity and side-channel concerns.

#### Additional Curves (SP 800-186, Appendix H)

| Curve family | Approval status | Notes |
|:---|:---|:---|
| Brainpool curves (brainpoolP256r1, brainpoolP384r1, brainpoolP512r1, brainpoolP512t1, …) | ✓ Approved (SP 800-186 Appx H.1) | BSI-mandated alternative; may be used with NIST-approved schemes; not in FIPS 186-5 primary list |
| secp256k1 | ❌ Not approved for general use | SP 800-186 Appendix H.2: discussed in context of blockchain/Bitcoin applications only; not approved for NSS or general-purpose cryptography |

### 5.2 Key Establishment Scheme Taxonomy (SP 800-56A Rev.3)

SP 800-56A Rev.3 (April 2018) organises key establishment schemes by the number of key-establishment transactions (i and j) and static/ephemeral roles (s/e). The `C(i,e;j,s)` notation counts: i ephemeral + j static contributions per party.

| Scheme | Description | Forward secrecy | NIST status |
|:---|:---|:---|:---|
| C(2e, 0s) — Full ephemeral | Both parties contribute only ephemeral keys | ✅ Full FS | Approved (SP 800-56A §6.2) |
| C(1e, 1s) — Ephemeral + static | One ephemeral + one static key per party | ✅ Partial FS | Approved (SP 800-56A §6.2) |
| C(0e, 2s) — Full static | Both parties use only static keys | ❌ No FS | Approved for specific uses; SP 800-57 deprecates for new TLS use |
| C(1e, 0s) — One-pass ephemeral | Initiator-only ephemeral; no static | Limited | Approved for specific contexts |

#### Approved FFC (MODP) Groups for IKE (SP 800-56A Rev.3, Table 25)

| Group | Prime size | Security | NIST |
|:---|:---|:---|:---|
| MODP-2048 | 2048 bit | 112-bit | ⚠ Transitional (through 2030) |
| MODP-3072 | 3072 bit | 128-bit | ✓ Approved |
| MODP-4096 | 4096 bit | 140-bit | ✓ Approved |
| MODP-6144 | 6144 bit | 152-bit | ✓ Approved |
| MODP-8192 | 8192 bit | 192-bit | ✓ Approved |

#### Approved FFC Named Groups for TLS (SP 800-56A Rev.3, Table 26 / RFC 7919)

| Group | Prime size | Security | NIST |
|:---|:---|:---|:---|
| ffdhe2048 | 2048 bit | 112-bit | ⚠ Transitional (through 2030) |
| ffdhe3072 | 3072 bit | 128-bit | ✅ Recommended |
| ffdhe4096 | 4096 bit | 140-bit | ✓ Approved |
| ffdhe6144 | 6144 bit | 152-bit | ✓ Approved |
| ffdhe8192 | 8192 bit | 192-bit | ✓ Approved |

> ℹ **Key confirmation:** SP 800-56A §5.9 requires MAC-based key confirmation when assurance of possession of shared secret is needed. Acceptable MAC algorithms: HMAC, CMAC, KMAC. Minimum MacTagBits ≥ 64. The MAC key is derived from the shared secret, not reused.

> ℹ **ECC CDH cofactor primitive:** For curves with cofactor h > 1 (Curve25519 h=8, Curve448 h=4, Edwards25519 h=8, Edwards448 h=4), the ECC CDH primitive must multiply the scalar by the cofactor: Z = h·dA·QB. This prevents small-subgroup attacks. SP 800-56A Rev.3 §5.7.1.2.

---

## 6. Digital Signatures

### 6.1 Classical Signatures

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `ECDSA-P-384-SHA-384` | 192 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🔜 Transitional | FIPS 186-5; SP 800-57; BSI TR-02102-1 §3.4; CNSA 2.0 | CNSA 2.0 transitional; will be replaced by ML-DSA-87 |
| `ECDSA-[P-256\|P-521]-[SHA-256\|SHA-384\|SHA-512]` | 128–260 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 186-5; SP 800-57; BSI TR-02102-1 §3.4 | CNSA mandates P-384 only |
| `ECDSA-P-384-[SHA-256\|SHA-512]` | 192 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 186-5; SP 800-57 | CNSA mandates SHA-384 with P-384 |
| `ECDSA-[brainpoolP256r1\|brainpoolP384r1\|brainpoolP512r1]-*` | 128–256 bit | ✓ Approved | ✅ Until 2035 (TR-02102-1 §5.3.3); ≥250 bit | 🚫 Not in CNSA | BSI TR-02102-1 §3.4 | BSI-preferred alternative; not in NIST FIPS or CNSA |
| `EdDSA-[Ed25519\|Ed448]` | 128–224 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §5.3.3) | 🚫 Not in CNSA | FIPS 186-5; RFC 8032; BSI TR-02102-1 | Deterministic; immune to k-reuse; not in CNSA |
| `RSASSA-PSS-[3072\|4096\|7680\|15360]-SHA-384-*` | 128–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🔜 Transitional | FIPS 186-5; SP 800-131A; BSI TR-02102-1 §3.6; CNSA 2.0 | CNSA 2.0 transitional with RSA-3072+ and SHA-384 |
| `RSASSA-PSS-[3072\|4096\|7680\|15360]-[SHA-256\|SHA-512]-*` | 128–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 186-5; SP 800-131A | CNSA mandates SHA-384 |
| `RSASSA-PSS-2048-[SHA-256\|SHA-384\|SHA-512]-*` | 112 bit | 🔜 Transitional | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | SP 800-131A Rev 2; SP 800-57 | CNSA requires ≥3072 bits |
| `RSASSA-PKCS1-[3072\|4096]-[SHA-256\|SHA-384\|SHA-512]` | 128–150+ bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 186-5 | PKCS#1 v1.5 **removed from FIPS 186-5 for new signing**; CNSA mandates PSS |
| `RSASSA-PKCS1-2048-*` | 112 bit | ❌ Deprecated | ✅ Until 2031 (TR-02102-1 §2.3.2); ≥3000 bit | 🚫 Not in CNSA | FIPS 186-5; SP 800-131A | New signing disallowed per FIPS 186-5 |
| `DSA-[2048\|3072]-[SHA-256\|SHA-384\|SHA-512]` | 112–128 bit | ❌ Deprecated | ✅ Recommended (TR-02102-1 §4) | 🚫 Not in CNSA | FIPS 186-5 §3.7 | DSA **removed from FIPS 186-5** for new use (2023) |
| `ECDSA-[P-192\|secp192r1]` | 96 bit | 🚫 Disallowed | ✅ Until 2035 (TR-02102-1 §5.3.3); ≥250 bit | 🚫 Not in CNSA | SP 800-131A Rev 2; FIPS 186-5 | Disallowed after 2013 |
| `DSA-1024-*` | 80 bit | 🚫 Disallowed | 🔜 Until 2029 (TR-02102-1 §5.3.2) | 🚫 Not in CNSA | SP 800-131A Rev 2 | Disallowed after 2013 |
| `RSASSA-*-1024-*` | 80 bit | 🚫 Disallowed | ✅ Until 2031 (TR-02102-1 §2.3.2); ≥3000 bit | 🚫 Not in CNSA | SP 800-131A Rev 2 | Disallowed after 2013 |

> ⚠ **ECDSA nonce reuse:** ECDSA is catastrophically vulnerable to k (nonce) reuse — reusing k for two signatures with the same key exposes the private key directly. Use an RFC 6979 deterministic nonce or an approved CSPRNG per signing operation.

> ⚠ **EdDSA hedged signing:** EdDSA is deterministic by design, which eliminates k-reuse risk but makes it vulnerable to fault injection (single-fault differential). Use hedged mode (rfc8032 §5.1 with randomizer) in hardware implementations or when fault attacks are a concern.

### 6.2 Stateful Hash-Based Signatures (SP 800-208)

| Pattern | Security | NIST | BSI | CNSA | Sources | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `LMS_SHA256_M32_H{5\|10\|15\|20\|25}` | 128-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §5.3.4.3) | ✅ Mandatory | SP 800-208; RFC 8554; CNSA 2.0 | **Stateful** — 256-bit classical / 128-bit post-quantum; n=32; CNSA 2.0 software/firmware signing |
| `LMS_SHA256_M24_H{5\|10\|15\|20\|25}` | 96-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §5.3.4.3) | ✅ Mandatory | SP 800-208; RFC 8554; CNSA 2.0 | CNSA 2.0 recommended parameter family for NSS; n=24 |
| `LMS_SHAKE_M32_H{5\|10\|15\|20\|25}` | 128-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | SP 800-208 | SHAKE256/256 hash variant; n=32; CNSA permits SP 800-208 LMS variants |
| `LMS_SHAKE_M24_H{5\|10\|15\|20\|25}` | 96-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | SP 800-208 | SHAKE256/192 hash variant; n=24 |
| `HSS-*` | 128-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §5.3.4.3) | ✅ Mandatory | SP 800-208; RFC 8554; CNSA 2.0 | Multi-level LMS; product of per-level capacities; state at each level |
| `XMSS-SHA2_[10\|16\|20]_[256\|512]` | 128–256-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | ✅ Mandatory | SP 800-208; RFC 8391; CNSA 2.0 | **Stateful** — WOTS+ OTS; SHA-256 (n=32) or SHA-512 (n=64); CNSA software signing |
| `XMSS-SHAKE_[10\|16\|20]_[256\|512]` | 128–256-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | SP 800-208; RFC 8391 | SHAKE-based XMSS variants |
| `XMSS-SHA2_[10\|16\|20]_192` | 96-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | SP 800-208 | SHA-256/192 (n=24); SP 800-208 addition |
| `XMSS-SHAKE256_[10\|16\|20]_192` | 96-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | ✓ Approved | SP 800-208 | SHAKE256/192 (n=24); SP 800-208 addition |
| `XMSSMT-*` | 128–256-bit PQ | ✓ Approved | ✅ Recommended (TR-02102-1 §5.3.4.3) | ✅ Mandatory | SP 800-208; RFC 8391; CNSA 2.0 | Multi-tree XMSS; very large signing volumes; d-layer hypertree |

> ⚠ **Statefulness:** Signing the same state twice under LMS, HSS, XMSS, or XMSS^MT is cryptographically catastrophic — it directly exposes the private key. Not suitable for general-purpose signing; use for code/firmware signing where frequency is low and state is fully controlled.

> 🔒 **SP 800-208 §5.3 hardware mandate:** Private key state for LMS and XMSS **shall** be maintained within a hardware cryptographic module validated to **FIPS 140-2/3 Level 3 or higher**. The current index value (state) must be stored in nonvolatile memory **before** any signature is exported from the module. Signing outside a validated hardware module is non-compliant.

> ℹ **Signing capacity planning:** Tree height h determines the maximum number of one-time signatures per key pair (2^h). For HSS/XMSS^MT with L levels, total capacity is 2^(h₁+h₂+…+hₗ). Choose heights to outlast the expected key lifetime with margin; re-keying a root is a significant operation. SP 800-208 §3.4 requires use of an approved DRBG (SP 800-90A) seeded to at least 8n bits of entropy for key generation.

---

## 7. Key Derivation Functions

| Pattern | Security | NIST | BSI | Sources | Notes |
|:---|:---|:---|:---|:---|:---|
| `HKDF-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | RFC 5869; SP 800-56C Rev 2; SP 800-135; BSI TR-02102-1 | Standard two-step KDF (Extract + Expand); use in TLS 1.3, HPKE, OPAQUE |
| `SP800-108-[HMAC-SHA256\|HMAC-SHA384\|HMAC-SHA512\|AES-CMAC]` | 128–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §5) | SP 800-108r1 | Counter, feedback, and double-pipeline modes; approved for FIPS 140-3 |
| `SP800-56C-*` | 128–256 bit | ✓ Approved | — | SP 800-56C Rev 2 | One-step and two-step KDFs for key-establishment protocols |
| `TLS13-PRF-[SHA-256\|SHA-384]` | 128–192 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | RFC 8446; SP 800-135 | TLS 1.3 HKDF-based PRF |
| `TLS12-PRF-SHA-256` | 128 bit | ⚠ Conditional | ✅ Recommended (TR-02102-1 §4) | SP 800-135; RFC 5246 | TLS 1.2 only; SHA-256 minimum; acceptable in maintained TLS 1.2 deployments |
| `ANSI-KDF-[X9.42\|X9.63]-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | SP 800-56A; SP 800-135 | Used in ECIES and CMS key agreement |
| `TLS10-PRF-*` | <112 bit | 🚫 Disallowed | 🚫 Not recommended (TR-02102-1) | SP 800-131A Rev 2; RFC 8996 | TLS 1.0/1.1 PRF (MD5+SHA-1); disallowed |
| `SSL30-PRF-*` | — | 🚫 Disallowed | — | RFC 7568 | SSLv3 disallowed entirely |

---

## 8. Password-Based Key Derivation and Password Hashing

| Pattern | Security | NIST | BSI | Sources | Notes |
|:---|:---|:---|:---|:---|:---|
| `Argon2id-*-[19456\|65536\|262144\|1048576]-[2\|3]-1` | 128+ bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §B.2) | BSI TR-02102-1 §3.9; OWASP 2023 | PHC winner; memory-hard; side-channel resistant variant; min m=19456 KiB, t=2, p=1 (OWASP web); m=65536 KiB for higher security |
| `scrypt-[32768\|65536\|1048576]-8-1-*` | 128+ bit | ✓ Approved | ✓ Acceptable (TR-02102-1 §B.2) | RFC 7914; BSI TR-02102-1 | N=32768 minimum (OWASP); N=1048576 high-security |
| `bcrypt-[12\|13\|14]-*` | 128 bit | ✓ Approved | ✓ Acceptable (TR-02102-1 §B.2) | BSI | Cost ≥ 12 (2024 minimum); input truncated at 72 bytes |
| `PBKDF2-HMAC-[SHA-256\|SHA-384\|SHA-512]-[600000\|1000000]-*-[32\|48\|64]` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | SP 800-132; OWASP 2023; BSI TR-02102-1 | Minimum 600,000 iterations for PBKDF2-HMAC-SHA-256 (SP 800-132 2023 update); salt ≥ 128 bits |
| `PBKDF2-HMAC-SHA-1-*` | ≤112 bit | ❌ Deprecated | ✅ Recommended (TR-02102-1 §4) | SP 800-132 | SHA-1 deprecation applies; use SHA-256 minimum |
| `PBKDF1-*` | — | 🚫 Disallowed | ✅ Recommended (TR-02102-1 §B.2) | RFC 8018 §6.1 | PBKDF1 disallowed; only supports short keys; superseded by PBKDF2 |

> ⚠ **Password hash without memory hardness:** PBKDF2 lacks memory hardness and is GPU-parallelisable. For password storage, prefer Argon2id or scrypt. PBKDF2 is acceptable for derived key material in standards-constrained environments (TLS, IKE).

> ⚠ **bcrypt 72-byte limit:** bcrypt silently truncates passwords at 72 bytes. Passwords longer than 72 bytes with identical first 72 bytes hash identically. Pre-hash with SHA-256 if longer passwords must be supported — but use a proper memory-hard function for new designs.

---

## 9. Random Number Generators and DRBGs

### 9.1 NIST SP 800-90A DRBGs

| Pattern | Security | NIST | BSI | Sources | Notes |
|:---|:---|:---|:---|:---|:---|
| `HMAC_DRBG-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | SP 800-90A Rev 1; BSI AIS 20/31 (DRG.2+) | Best-proven security (machine-verified proof); preferred DRBG for general use |
| `Hash_DRBG-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | SP 800-90A Rev 1 | Hash-only; no block cipher required; formal security proof |
| `CTR_DRBG-[AES-128\|AES-192\|AES-256]` | 128–256 bit | ✓ Approved | ✅ Recommended (BSI AIS 20/31) | SP 800-90A Rev 1; BSI AIS 20/31 | Fastest; used internally by Windows BCryptGenRandom and Intel RDRAND; **no formal security proof** |
| `CTR_DRBG-AES-256` | 256 bit | ✅ Recommended | ✅ Recommended (BSI AIS 20/31) | SP 800-90A Rev 1; FIPS 140-3 | Preferred CTR_DRBG instantiation for FIPS 140-3 modules |
| `CTR_DRBG-AES-[128\|192\|256]-noDF` | 128–256 bit | ❌ Deprecated | ✅ Recommended (TR-02102-1 §3.3) | SP 800-90A Rev 1 §10.2.1 | Without derivation function; entropy input must equal seed length exactly; security properties degraded |
| `Hash_DRBG-[SHA-1\|SHA-224]` | 112 bit | 🔜 Transitional | ❌ Not recommended (TR-02102-1) | SP 800-90A Rev 1; SP 800-131A | SHA-1 at 112-bit security; acceptable through 2030 (NIST); not recommended by BSI |
| `CTR_DRBG-3DES` | 112 bit | 🚫 Disallowed | 🚫 Not recommended (TR-02102-1) | SP 800-90A Rev 1; SP 800-131A Rev 2 | 3DES deprecated 2023; do not use |
| `Dual_EC_DRBG` | — | 🚫 Disallowed | 🚫 Not recommended (BSI AIS 20/31) | SP 800-90A Rev 1 (withdrawn 2014) | Deliberately backdoored via NSA-chosen elliptic curve points; withdrawn June 2015 |

> ⚠ **Prediction resistance:** Enable prediction resistance (`{predictionResistance}=true`) only if a live entropy source is always available. For most software deployments, use periodic reseeding instead (every 2²⁴ generate calls or per schedule). Prediction resistance adds a live entropy-source dependency that can fail in VMs and embedded systems.

> ⚠ **DRBG reseed interval:** SP 800-90A mandates reseeding after ≤ 2⁴⁸ generate calls. Implementations should use shorter intervals (e.g., 2²⁴) for defence in depth, especially in virtualised environments where VM snapshots can replay DRBG state.

> ⚠ **Personalization string:** Always supply a unique `{personalizationString}` at DRBG instantiation (e.g., application name + PID + timestamp). This provides domain separation at no security cost and prevents multiple instances seeded from the same entropy source from producing correlated output (SP 800-90A §8.7.1).

### 9.2 Accumulator-Based CSPRNGs

| Pattern | Security | NIST | BSI | Sources | Notes |
|:---|:---|:---|:---|:---|:---|
| `Fortuna-AES-256-SHA-256` | 256 bit | ✅ Recommended | ✅ Recommended (TR-02102-1 §4) | BSI AIS 20/31; Ferguson-Schneier *Cryptography Engineering* | 32 entropy pools; automatic pool-based reseeding; no entropy estimator required; deployed in macOS/iOS since 2020 |
| `Fortuna-*` | 128–256 bit | ✓ Approved | ✅ Recommended (TR-02102-1 §4) | BSI AIS 20/31 | Non-standard cipher/hash variants reduce assurance; prefer canonical AES-256-SHA-256 form |
| `Yarrow-*` | variable | ❌ Deprecated | — | — | Superseded by Fortuna; entropy estimator requirement difficult to implement correctly; do not use for new designs |

### 9.3 OS-Provided Entropy APIs

| Pattern | NIST | BSI | Sources | Notes |
|:---|:---|:---|:---|:---|
| `getrandom()` | ✅ Recommended | Linux ≥ 3.17; SP 800-90B | Blocks only until initialization; same pool as /dev/urandom; preferred over /dev/urandom for new Linux code |
| `/dev/urandom` | ✓ Approved | Linux / macOS / BSD | Never blocks after boot; identical to /dev/random on Linux ≥ 5.6; backed by ChaCha20-DRNG (Linux) or Fortuna (macOS) |
| `/dev/random` | ⚠ Conditional | Linux ≤ 5.5 | **Blocking** on Linux < 5.6; identical to /dev/urandom on Linux ≥ 5.6; avoid blocking behaviour in daemons |
| `BCryptGenRandom` | ✅ Recommended | Windows CNG; FIPS 140-3 | CTR_DRBG-AES-256 internally; FIPS 140-3 validated |
| `getentropy()` | ✅ Recommended | macOS / BSDs; RFC-like | Non-blocking; limited to 256 bytes per call; preferred on macOS/BSDs |

### 9.4 Hardware RNG Interfaces

| Pattern | NIST | BSI | Sources | Notes |
|:---|:---|:---|:---|:---|
| `RDRAND` | ⚠ Conditional | Intel/AMD; SP 800-90B | CTR_DRBG on-die; **must not be the sole entropy source**; combine with OS entropy (XOR or HKDF); trust concerns about Intel microcode control |
| `RDSEED` | ✓ Approved | Intel/AMD; SP 800-90B | Direct conditioned hardware entropy; suitable for **seeding** DRBGs; slower than RDRAND; may return failure (CF=0) — must retry |
| `TPM_RNG-*` | ✓ Approved | TCG TPM 2.0; SP 800-90B | FIPS 140-3 validated TPMs; low throughput (10–50 KB/s); excellent trust boundary; provides independent entropy from CPU |

### 9.5 BSI AIS 20/31 Functionality Classes

| Class | Description | Minimum use case |
|:---|:---|:---|
| **DRG.2** | Software DRBG (SP 800-90A mechanisms qualify) | Key generation, nonces for standard applications |
| **DRG.3** | DRBG with prediction resistance (live entropy before each output) | High-security key generation |
| **DRG.4** | Enhanced prediction resistance | Long-term key generation in FIPS 140-3 / CC EAL 4+ modules |
| **PTG.2** | Physical TRNG (validated entropy source + conditioner) | Seeding software DRBGs in hardware modules |
| **PTG.3** | Enhanced TRNG | Smart card / HSM key generation |
| **NTG.1** | Non-deterministic RBG (TRNG + DRBG, highest assurance) | CA root key generation, HSM master keys |

### 9.6 Non-Cryptographic PRNGs (always disallowed for security use)

| Pattern | NIST | Notes |
|:---|:---|:---|
| `MT19937` | 🚫 Disallowed | State fully recoverable from 624 consecutive 32-bit outputs; default `random` in Python, PHP, Ruby |
| `Xoshiro(256\|512)(+\|++\|**)` | 🚫 Disallowed | Linear feedback; fast but cryptographically insecure |
| `PCG-*` | 🚫 Disallowed | LCG + output permutation; statistically good but not crypto-safe |
| `LCG-*` | 🚫 Disallowed | Trivially predictable from one output value |

> ⚠ **Language default PRNGs:** `Math.random()` (JavaScript), `random.random()` (Python), `rand()` (C stdlib), `Random` (Java) — all use non-cryptographic PRNGs. Never use these for key generation, nonces, session tokens, CSRF tokens, or any security material. Use `crypto.getRandomValues()` (Web), `secrets` (Python), `SecureRandom` (Java), or OS-level APIs.

---

## 10. Post-Quantum Cryptography (FIPS 203 / 204 / 205 / 206)

### 10.1 ML-KEM Key Encapsulation (FIPS 203)

| Pattern | NIST Level | Security (classical / quantum) | NIST | BSI | CNSA | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `ML-KEM-512` | 1 | 128 / 128 bit | ✓ Approved | ❌ Not recommended | 🚫 Not in CNSA | Below BSI minimum (Category 3 required); CNSA mandates ML-KEM-1024 |
| `ML-KEM-768` | 3 | 192 / 192 bit | ✅ Recommended | ✅ Recommended hybrid (§2.4.3) | 🚫 Not in CNSA | NIST default recommendation; BSI requires hybrid with classical KEM until 2031; CNSA mandates ML-KEM-1024 |
| `ML-KEM-1024` | 5 | 256 / 256 bit | ✓ Approved | ✅ Recommended hybrid (§2.4.3) | ✅ Mandatory | CNSA 2.0 mandates this parameter set; BSI requires hybrid with classical KEM |

> ⚠ **Hybrid deployment:** Until ML-KEM implementations have accrued operational confidence, deploy as **hybrid** with a classical key exchange (X25519 or P-256). The TLS 1.3 hybrid scheme `X25519MLKEM768` is defined in `draft-ietf-tls-hybrid-design` and is the current recommendation. The combiner is simple concatenation fed into the TLS 1.3 HKDF key schedule (`{hybridKemCombiner}=concat`).

### 10.2 ML-DSA Digital Signatures (FIPS 204)

| Pattern | NIST Level | Security | NIST | BSI | CNSA | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `ML-DSA-44` | 2 | 128 bit | ✓ Approved | ✅ Recommended (§5.3.4.2) | 🚫 Not in CNSA | Smallest signatures (2420 B); CNSA mandates ML-DSA-87 |
| `ML-DSA-65` | 3 | 192 bit | ✅ Recommended | ✅ Recommended (§5.3.4.2) | 🚫 Not in CNSA | Balanced; NIST recommends; CNSA mandates ML-DSA-87 |
| `ML-DSA-87` | 5 | 256 bit | ✓ Approved | ✅ Recommended (§5.3.4.2) | ✅ Mandatory | CNSA 2.0 mandates this parameter set for general signing |
| `ML-DSA-[44\|65\|87]-(deterministic)` | — | — | ❌ Deprecated | ❌ Not recommended | ❌ Deprecated | Deterministic mode vulnerable to fault attacks; use hedged mode |
| `ML-DSA-[44\|65\|87]-(hedged)` | — | — | ✅ Recommended | ✅ Recommended (§5.3.4.2) | ✓ ML-DSA-87 only | FIPS 204 §5.2 hedged mode; fault-attack resistant; CNSA only at Level 5 |

> ⚠ **ML-DSA constant-time requirement:** Non-constant-time implementations of `SampleInBall` and the τ non-zero position sampling leak information about the signing key. All ML-DSA implementations must sample in constant time with respect to secret inputs. (NIST PQC Forum, Jan 2026)

### 10.3 SLH-DSA Digital Signatures (FIPS 205)

| Pattern | NIST Level | Security | NIST | BSI | CNSA | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `SLH-DSA-SHA2-128s` | 1 | 128 bit | ✓ Approved | ✅ Recommended (§5.3.4.1) | 🚫 Not in CNSA | Small signatures (7856 B); slow signing; CNSA does not include SLH-DSA |
| `SLH-DSA-SHA2-128f` | 1 | 128 bit | ✓ Approved | ✅ Recommended (§5.3.4.1) | 🚫 Not in CNSA | Fast signing; larger signatures (17088 B); CNSA does not include SLH-DSA |
| `SLH-DSA-SHA2-[192s\|192f]` | 3 | 192 bit | ✓ Approved | ✅ Recommended (§5.3.4.1) | 🚫 Not in CNSA | CNSA does not include SLH-DSA |
| `SLH-DSA-SHA2-[256s\|256f]` | 5 | 256 bit | ✓ Approved | ✅ Recommended (§5.3.4.1) | 🚫 Not in CNSA | CNSA does not include SLH-DSA |
| `SLH-DSA-SHAKE-[128s\|128f\|192s\|192f\|256s\|256f]` | 1–5 | 128–256 bit | ✓ Approved | ✅ Recommended (§5.3.4.1) | 🚫 Not in CNSA | SHAKE-based variants; identical security, different internal hash; CNSA does not include SLH-DSA |

> ℹ **Stateless:** SLH-DSA is stateless (unlike LMS/XMSS); no state management required. Signing is slow but requires no storage state. Suitable where signing frequency is low and verification speed matters more than signing speed.

### 10.4 FN-DSA / Falcon Digital Signatures (FIPS 206 IPD)

| Pattern | NIST Level | Security | NIST | BSI | CNSA | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| `FN-DSA-512` | 1 | 128 bit | ⚠ Conditional | — Not yet evaluated | 🚫 Not in CNSA | FIPS 206 IPD (submitted Aug 2025; final expected late 2026 / early 2027); compact signatures (666 B); floating-point dependency; CNSA mandates ML-DSA-87 |
| `FN-DSA-1024` | 5 | 256 bit | ⚠ Conditional | — Not yet evaluated | 🚫 Not in CNSA | FIPS 206 IPD; 1280 B signatures; CNSA does not include FN-DSA |

> ⚠ **IEEE 754 compliance (`{floatingPointMode}`):** FN-DSA/Falcon uses FFT-based Gaussian sampling that relies on IEEE 754 floating-point arithmetic. Execution with extended precision (x87), flush-to-zero, or non-standard rounding **deviates from the specification** and may weaken or break security. Require `ieee754-strict` mode or `integer-emulation` in FIPS 140-3 and CC environments. FIPS 206 is still in the Initial Public Draft stage (IPD submitted for Department of Commerce clearance August 2025; final standard not yet published as of Q1 2026).

> ℹ **FIPS 206 standardisation status:** FIPS 203, 204, and 205 were published as final standards on 13 August 2024. FIPS 206 (FN-DSA / Falcon) followed a separate timeline: the IPD was submitted for internal NIST approval in August 2025 and is awaiting Department of Commerce clearance. The final standard is expected late 2026 or early 2027. Implementations may reference the Falcon Round 3.1 specification in the interim.

### 10.5 Notable Non-Standardised PQC Algorithms

> **Source:** NIST IR 8545, *Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process*, March 2025 (doi:10.6028/NIST.IR.8545). Covers the Round 4 evaluation of HQC, BIKE, Classic McEliece, and SIKE.

#### Key Encapsulation

| Algorithm | Security | NIST | Key sizes | Notes |
|:---|:---|:---|:---|:---|
| `HQC-128` / `HQC-192` / `HQC-256` | 128 / 192 / 256 bit | ⚠ Conditional | ek: 2241 / 4514 / 7237 B; dk: 2321 / 4602 / 7333 B (or 32 B compressed); ct: 4433 / 8978 / 14421 B; K: 32 B | **NIST selected March 2025** (Round 4) as fifth PQC standard (code-based backup KEM); FIPS draft + final expected ~2027; SP 800-227 (draft Jan 2025) covers KEM usage guidance; sizes from HQC spec v2025-08-22 |
| `FrodoKEM-640` / `976` / `1344` | 128 / 192 / 256 bit | ❌ Not standardised | pk: 9616 / 15632 / 21520 B; ct: 9720 / 15744 / 21632 B | Conservative plain-LWE basis (no ring/module structure); available in liboqs / OQS-OpenSSL |
| `Classic McEliece` (all parameter sets) | 128–256 bit | ❌ Not standardised by NIST | pk: 261 KB–1.36 MB; ct: 96–208 B | **Not selected Round 4 (NIST IR 8545)**: NIST skeptical of widespread adoption due to large public keys; mceliece460896/f fall short of claimed Category 3 (meet at least Category 2 per NIST); ISO/IEC 18033-2 concurrent standardisation effort ongoing — NIST may develop standard if ISO version gains wide use; ciphertext is smallest of all PQC KEMs; used in McTiny and post-quantum WireGuard |
| `BIKE-L1` / `L3` / `L5` | 128 / 192 / 256 bit | ❌ Not standardised | pk: ~1541 / ~3083 / ~6162 B; ct: ~1573 / ~3115 / ~6194 B | **Not selected Round 4 (NIST IR 8545)**: decisive concern is immature DFR analysis — a new weak-key class (gathering property) found in Round 4 causes DFR ≥ 2⁻¹¹⁷ at Level 1, defeating IND-CCA2 security; would require ~9% block-size increase (r: 12 323 → 13 477) and post-selection tweaks; 6–10× slower key generation and 5–7× slower decapsulation than HQC; smaller keys/ciphertext than HQC (~70%/~30%); available in liboqs |
| `NTRU-HPS-2048-677` (Level 1) | 128 bit | ❌ Not standardised | pk + ct: ~930 B | NTRU patents expired 2017; perfectly correct (no decryption failures); round 3 finalist not selected |
| `LightSaber` / `Saber` / `FireSaber` | 128 / 192 / 256 bit | ❌ Not standardised | pk: 672 / 992 / 1312 B; ct: 736 / 1088 / 1472 B | Module-LWR (power-of-two moduli); Round 3 finalist not selected in favour of ML-KEM |

#### Broken Algorithms (do not use)

| Algorithm | Broken by | Year | Notes |
|:---|:---|:---|:---|
| `SIKE` / `SIDH` (all parameter sets) | Castryck-Decru classical polynomial-time attack | 2022 | Isogeny-based KEM; completely broken — no computationally hard problem remains |
| `Rainbow` (all levels) | Ward Beullens ("Breaking Rainbow Takes a Weekend on a Laptop") | 2022 | Multivariate OV signature — Round 3 finalist; private key recoverable efficiently |
| `GeMSS` (all levels) | Multiple cryptanalysis results (2020–2022) | 2020–2022 | Big-Field multivariate signature — security claims invalidated |

---

## 11. TLS / Protocol Quick-Reference

| Version | NIST | Sources | Notes |
|:---|:---|:---|:---|
| **TLS 1.3** | ✅ Recommended | RFC 8446; BSI TR-02102-2 (2024) | ECDHE-only forward secrecy; AEAD-only cipher suites; no renegotiation |
| **TLS 1.2** + strong ciphers | ⚠ Conditional | RFC 5246; BSI TR-02102-2 | Acceptable with ECDHE + AES-GCM + SHA-256+; disable RC4, 3DES, CBC-SHA1 cipher suites |
| **TLS 1.0 / 1.1** | 🚫 Disallowed | RFC 8996; BSI TR-02102-2 | POODLE, BEAST, SWEET32; disallowed |
| **SSL 3.0** | 🚫 Disallowed | RFC 7568 | POODLE; disallowed |
| **TLS 1.2 cipher suites with SHA-1** | 🚫 Disallowed | BSI TR-02102-2; RFC 9155 | e.g., TLS_RSA_WITH_AES_128_CBC_SHA; disallowed for new configurations |
| **TLS cipher suites with NULL / EXPORT** | 🚫 Disallowed | — | No encryption / deliberately weakened |

---

## 12. Deprecated and Disallowed Consolidated Reference

| Pattern | Reason | Disallowed since | Source |
|:---|:---|:---|:---|
| `DES-*` | 56-bit key; brute-forceable | 2001 (NIST) | SP 800-131A |
| `3DES-*` | 64-bit block; birthday bound; 112-bit max | Encryption: 2024 | SP 800-131A Rev 2 §2 |
| `RC4-*` | Statistical biases; NOMORE, RC4NOMORE attacks | 2015 | RFC 7465; SP 800-131A |
| `RC2-*` | Legacy; key-size attacks | 2014 | SP 800-131A |
| `IDEA-*` | Not FIPS; patented legacy | — | BSI |
| `Blowfish-*` | 64-bit block; birthday bound | — | — |
| `AES-*-ECB` | Deterministic; pattern-revealing | Never approved | SP 800-38A |
| `MD5` | Collision attacks (2004+); preimage weakness | 2013 | SP 800-131A |
| `SHA-1` | Collision attacks (SHAttered 2017) | Signatures: 2013 | SP 800-131A Rev 2 §9 |
| `RSASSA-PKCS1-*-new-signing` | Not IND-CCA2; timing oracles | 2016 (new signing) | FIPS 186-5 |
| `RSAES-PKCS1-*` | Bleichenbacher; ROBOT attack | New use: disallowed | SP 800-131A |
| `DSA-1024-*` | 80-bit security | 2013 | SP 800-131A Rev 2 |
| `ECDSA-P-192-*` | 96-bit security | 2013 | SP 800-131A Rev 2 |
| `RSASSA-*-1024-*` | 80-bit security | 2013 | SP 800-131A Rev 2 |
| `Dual_EC_DRBG` | NSA kleptographic backdoor | 2013 (withdrawn 2015) | SP 800-90A withdrawn |
| `CTR_DRBG-3DES` | 3DES deprecated | 2023 | SP 800-131A Rev 2 |
| `CTR_DRBG-*-noDF` | Degraded security; fixed-length entropy only | — | SP 800-90A Rev 1 |
| `Hash_DRBG-SHA-1` | SHA-1 deprecation at DRBG level | Transitional 2030 | SP 800-131A Rev 2 |
| `TLS 1.0 / 1.1` | BEAST, POODLE, weak PRF | 2020 (RFC 8996) | RFC 8996 |
| `MT19937` | State recoverable; not CSPRNG | Never secure | — |
| `LCG-*` | Trivially predictable | Never secure | — |
| `Rainbow-[I\|III\|V]-*` | Broken 2022 — private key recoverable in hours (Beullens) | 2022 | NIST Round 3 delisted |
| `SIKE-*` / `SIDH-*` | Broken 2022 — classical polynomial-time attack (Castryck-Decru) | 2022 | NIST Round 3 delisted |
| `GeMSS-*` | Security claims invalidated by cryptanalysis (2020–2022) | 2022 | NIST Round 3 delisted |

---

## 13. Security Strength Equivalence (SP 800-57 Part 1 Rev 5)

Key-length equivalence guidance derived from NIST SP 800-57 Part 1 Rev 5, *Recommendation for Key Management: Part 1 — General* (May 2020).

### 13.1 Comparable Security Strengths across Algorithm Families (Table 2)

All values from §5.6.1 Table 2 (pp. 54–55).

| Security strength (bits) | Symmetric cipher | FFC key size (L, N) | IFC key size (k) | ECC key size (f) | NIST |
|:---|:---|:---|:---|:---|:---|
| < 80 | 2TDEA, SKIPJACK | L=1024, N=160 | 1024 | 160–223 | 🚫 Disallowed |
| 112 | 3TDEA | L=2048, N=224 | 2048 | 224–255 | 🔜 Transitional (through 2030) |
| 128 | AES-128 | L=3072, N=256 | 3072 | 256–383 | ✅ Recommended |
| 192 | AES-192 | L=7680, N=384 | 7680 | 384–511 | ✅ Recommended |
| 256 | AES-256 | L=15360, N=512 | 15360 | 512+ | ✅ Recommended |

**Column definitions:**

- **FFC (L, N):** L = bit length of the field order *p*; N = bit length of the subgroup order *q*. Applies to DSA, DH, and MQV over finite fields.
- **IFC (k):** bit length of the RSA modulus *n = pq*. Applies to RSA encryption (RSAES-OAEP) and RSA signatures (RSASSA-PSS, RSASSA-PKCS1-v1_5).
- **ECC (f):** bit length of the elliptic-curve base-point order. Applies to ECDSA, ECDH, EdDSA, and related schemes. Ranges reflect that any curve order within the interval provides the stated security strength.

> ℹ **FFC parameters (SP 800-57 §5.6.1.1):** Use only NIST-approved or RFC 7919 named groups — custom prime generation requires full validation per SP 800-56A.

> ℹ **IFC (RSA) security strength:** A 2048-bit RSA modulus provides approximately 112 bits of security, not 128. The common assumption that "2048-bit RSA = 128-bit security" is incorrect per SP 800-57 Table 2. 3072-bit RSA is the minimum for 128-bit security.

### 13.2 Planning Horizon and Security-Strength Adequacy

SP 800-57 Rev 5 §5.6.2–§5.6.3 and SP 800-131A Rev 2:

| Security strength (bits) | NIST | Planning horizon |
|:---|:---|:---|
| < 80 | 🚫 Disallowed | Disallowed since 2013. No algorithm providing only 80-bit security may be used to protect data. |
| 112 | 🔜 Transitional | Acceptable minimum through **31 December 2030**. Keys remaining in use beyond 2030 must provide at least 128-bit security. |
| 128 | ✅ Recommended | Required minimum from **1 January 2031** onward. Recommended for all new designs. |
| 192 | ✅ Recommended | Exceeds minimum requirements; appropriate for high-assurance applications. |
| 256 | ✅ Recommended | Highest tier; recommended for long-term protection and quantum-resilient symmetric designs. |

**Table 4 — Security strength time frames** (SP 800-57 Rev 5 §5.6.3):

| Security strength | Through 2030 — Applying protection | Through 2030 — Processing | 2031 and beyond — Applying protection | 2031 and beyond — Processing |
|:---|:---|:---|:---|:---|
| < 112 | 🚫 Disallowed | Legacy use | 🚫 Disallowed | Legacy use |
| 112 | Acceptable | Acceptable | 🚫 Disallowed | Legacy use |
| 128 | Acceptable | Acceptable | Acceptable | Acceptable |
| 192 | Acceptable | Acceptable | Acceptable | Acceptable |
| 256 | Acceptable | Acceptable | Acceptable | Acceptable |

- **Applying protection:** Using an algorithm/key to encrypt, sign, or generate a MAC.
- **Processing:** Decrypting, verifying a signature, or verifying a MAC on data that was previously protected.
- **Legacy use:** The algorithm/key may be used only to process already-protected data, not to protect new data.

### 13.3 Approved Algorithms per Security-Strength Tier

Based on SP 800-57 Rev 5 §5.6.1 and the referenced FIPS standards.

| Security strength (bits) | Symmetric encryption | Hash (collision resistance) | Digital signatures | Key agreement | KEM (post-quantum) |
|:---|:---|:---|:---|:---|:---|
| < 80 | 2TDEA (🚫) | SHA-1 (🚫 for signatures) | DSA-1024, RSA-1024, ECDSA-P-192 (all 🚫) | DH-1024, ECDH-P-192 (all 🚫) | — |
| 112 | 3TDEA (🔜 deprecated 2024) | SHA-224 | RSA-2048 (PSS/PKCS1), DSA-2048 (🔜), ECDSA-P-224 | DH-2048, ECDH-P-224 | — |
| 128 | AES-128 | SHA-256, SHA3-256 | RSA-3072+, ECDSA-P-256+, EdDSA-Ed25519, ML-DSA-44 | ECDH-P-256, X25519, FFDH-3072+, ML-KEM-512 | ML-KEM-512 |
| 192 | AES-192 | SHA-384, SHA3-384 | RSA-7680, ECDSA-P-384, ML-DSA-65 | ECDH-P-384, FFDH-7680, ML-KEM-768 | ML-KEM-768 |
| 256 | AES-256 | SHA-512, SHA3-512 | RSA-15360, ECDSA-P-521, EdDSA-Ed448, ML-DSA-87 | ECDH-P-521, X448, FFDH-15360, ML-KEM-1024 | ML-KEM-1024 |

> ℹ **PQC note:** ML-KEM (FIPS 203) and ML-DSA (FIPS 204) were standardised in August 2024, after SP 800-57 Rev 5 was published. They are included here at the NIST security levels stated in their respective FIPS publications. SP 800-57 Rev 6 (Initial Public Draft December 2025) is expected to incorporate PQC algorithm mappings formally.

### 13.4 Hash Function Security Strength (SP 800-57 Rev 5 §5.6.1)

Hash functions provide two distinct security properties with different bit strengths:

| Hash function | Output (bits) | Collision resistance (bits) | Preimage resistance (bits) |
|:---|:---|:---|:---|
| SHA-1 | 160 | < 80 (broken) | 160 |
| SHA-224 | 224 | 112 | 224 |
| SHA-256 | 256 | 128 | 256 |
| SHA-384 | 384 | 192 | 384 |
| SHA-512 | 512 | 256 | 512 |
| SHA3-256 | 256 | 128 | 256 |
| SHA3-384 | 384 | 192 | 384 |
| SHA3-512 | 512 | 256 | 512 |

> For digital signatures and certificates, the collision-resistance strength of the hash must meet or exceed the security strength of the signing key. For HMAC, preimage resistance applies — HMAC-SHA-1 can still provide 112-bit security (transitional through 2030 per NIST; not recommended by BSI).

### 13.5 Quantum Impact on Security-Strength Equivalence

The equivalence table in §13.1 assumes classical (non-quantum) adversaries. Grover's algorithm halves the effective security of symmetric ciphers and hash preimage resistance; Shor's algorithm breaks RSA, DH, DSA, and ECC entirely in polynomial time.

| Algorithm family | Classical security | Quantum security | Mitigation |
|:---|:---|:---|:---|
| AES-128 | 128 bit | ~64 bit (Grover) | Use AES-256 for quantum resilience |
| AES-256 | 256 bit | ~128 bit (Grover) | Sufficient post-quantum |
| RSA, DH, DSA (all sizes) | 80–256 bit | 0 (Shor) | Migrate to ML-KEM / ML-DSA |
| ECDSA, ECDH (all curves) | 128–256 bit | 0 (Shor) | Migrate to ML-KEM / ML-DSA |
| ML-KEM-768 | — | ~192 bit (NIST Level 3) | NIST-standardised PQC |
| ML-DSA-65 | — | ~192 bit (NIST Level 3) | NIST-standardised PQC |

> ⚠ **Harvest-now-decrypt-later:** Data encrypted today with RSA or ECDH may be stored by adversaries and decrypted once a cryptographically relevant quantum computer is available. SP 800-57 Rev 5 does not yet address quantum threat timelines, but NIST's PQC programme (FIPS 203/204/205) and the forthcoming SP 800-57 Rev 6 provide the migration path.

### 13.6 Cryptoperiod Recommendations (SP 800-57 Rev 5 §5.3)

A *cryptoperiod* is the time span during which a specific key is authorised for use. SP 800-57 Part 1 §5.3, Table 1:

| Key type | Originator-usage period | Recipient-usage period |
|:---|:---|:---|
| Private signature key | 1–3 years | — |
| Public signature-verification key | Several years (depends on key size and security strength) | |
| Symmetric authentication key | ≤ 2 years | ≤ OUP + 3 years |
| Private authentication key | 1–2 years | |
| Symmetric data-encryption key | ≤ 2 years | ≤ OUP + 3 years |
| Symmetric key-wrapping key | ≤ 2 years | ≤ OUP + 3 years |
| Symmetric RBG key | Per SP 800-90 | — |
| Symmetric master / key-derivation key | ~1 year | — |
| Private key-transport key | ≤ 2 years | |
| Symmetric key-agreement key | 1–2 years | |
| Private static key-agreement key | 1–2 years | |
| Private ephemeral key-agreement key | One transaction | |

Key rules:
- A single key **shall** be used for only one purpose (§5.2).
- Private signature keys **shall** be destroyed at the end of their cryptoperiod.
- Ephemeral private keys **shall** be destroyed immediately after use.
- Key update (deriving a new key from the current key to replace it) is **disallowed** for federal applications.

### 13.7 FIPS 140 Validation Requirements (SP 800-57 Part 2 Rev 1)

SP 800-57 Part 2 Rev 1 (May 2019) establishes key management policy requirements for federal agencies. All cryptographic functions **shall** be performed using FIPS 140-validated cryptographic modules.

| FIPS 199 impact level | Required FIPS 140 level | Notes |
|:---|:---|:---|
| Low | Level 1+ | |
| Moderate | Level 3+ | Cryptographic module must provide physical tamper evidence/response |
| High | Level 3+ | |

Application-specific requirements (SP 800-57 Part 3 Rev 1):

| System role | FIPS 140 level | Source |
|:---|:---|:---|
| Certificate Authority (CA), Key Recovery Server | Level 3+ | Part 3 §2 |
| Registration Authority (RA) | Level 2+ | Part 3 §2 |
| OCSP Responder | Level 3+ | Part 3 §2 |
| End-user / relying party | Level 1+ | Part 3 §2 |

### 13.8 Key Protection Requirements (SP 800-57 Rev 5 §6)

| Key/information type | Confidentiality | Integrity | Backup | Archive |
|:---|:---|:---|:---|:---|
| Private signature key | Required | Required | No | No |
| Private key-agreement key | Required | Required | Yes | Yes |
| Symmetric encryption key | Required | Required | Yes | Yes |
| Symmetric authentication key | Required | Required | Yes | No |
| Public key (any) | — | Required | Yes | Yes |
| Shared secret | Required | Required | No | No |
| RBG seed | Required | Required | No | No |
| Ephemeral private key | Required | Required | No | No |

---

For protocol-specific deployment guidance (SSH, IPsec/IKEv2, CNSA 2.0, quantum threat context, PKI, S/MIME, Kerberos, DNSSEC), see [cryptographic-protocol-status.md](cryptographic-protocol-status.md).

---

*Last updated: 2026-04-06 (§14–§21 moved to cryptographic-protocol-status.md). Consult current NIST SP 800-131A, BSI TR-02102, and NSA CNSA advisory editions for horizon dates and any post-publication amendments.*
