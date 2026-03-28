# Cryptographic Algorithm Recommendations and Alerts

> Characteristics, recommendations, and alerts derived from NIST and BSI publications.
> Algorithms and RNGs are expressed using the CycloneDX pattern notation extended with two
> wildcard conventions defined below.
>
> **Primary sources:** NIST SP 800-57 Pt 1 Rev 5 (Rev 6 IPD Dec 2025) · SP 800-131A Rev 2 (Rev 3 IPD Oct 2024) · SP 800-38 series ·
> SP 800-90A Rev 1 (Rev 2 pre-draft 2025) · SP 800-90B · SP 800-56A/B/C · SP 800-132 · SP 800-135 · SP 800-186 ·
> FIPS 140-3 · FIPS 180-4 · FIPS 186-5 · FIPS 197 · FIPS 198-1 · FIPS 202 · FIPS 203/204/205 · FIPS 206 (IPD) ·
> BSI TR-02102-1 (2026-01) · BSI TR-02102-2 (2026) · BSI AIS 20/31 v3 (2022)

---

## Notation

Standard CycloneDX pattern symbols apply throughout. Two extensions are used in this document only:

| Symbol | Meaning |
|:---|:---|
| `*` | Wildcard — the recommendation is agnostic to the value of this parameter; any conforming value is acceptable |
| `[v1\|v2]` | Enumeration — only these specific values are applicable to this recommendation (not an optional segment) |

Examples: `AES-[128|192|256]-*` — AES with any of the listed key sizes, any mode; `AES-*-ECB` — AES in ECB mode regardless of key size.

---

## Status legend

| Symbol | Status | Meaning |
|:---|:---|:---|
| ✅ | **Recommended** | Actively recommended for new designs |
| ✓ | **Approved** | Approved; acceptable for new designs |
| ⚠ | **Conditional** | Approved only with stated restrictions |
| 🔜 | **Transitional** | Acceptable until stated horizon; migrate away |
| ❌ | **Deprecated** | Must not be used in new designs |
| 🚫 | **Disallowed** | Must not be used at all |

---

## 1. Symmetric Encryption

### 1.1 Block cipher — key length

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `AES-[128\|192\|256]-*` | 128–256 bit | ✅ Recommended | FIPS 197; SP 800-57; BSI TR-02102-1 §3.3 | AES-128 sufficient for most uses; AES-256 recommended for quantum-resilient designs |
| `CAMELLIA-[128\|256]-*` | 128–256 bit | ✓ Approved | BSI TR-02102-1 §3.3 | Approved by BSI; not in NIST FIPS approved list |
| `3DES-*` | ≤112 bit | ❌ Deprecated | SP 800-131A Rev 2 §2; NIST IR 8214C | Disallowed for encryption after 2023; 64-bit block causes birthday-bound issues at ≥ 2³² blocks |
| `DES-*` | 56 bit | 🚫 Disallowed | SP 800-131A Rev 2 | Cryptographically broken |
| `RC2-*` | ≤128 bit | 🚫 Disallowed | SP 800-131A Rev 2 | Legacy only; no new use |
| `RC4-*` | — | 🚫 Disallowed | SP 800-131A Rev 2; RFC 7465 | Stream cipher; statistically weak; banned in TLS |
| `IDEA-*` | 128 bit | ❌ Deprecated | BSI TR-02102-1 | Not NIST/FIPS approved; BSI removed |
| `Blowfish-*` | ≤448 bit | ❌ Deprecated | — | 64-bit block; birthday bound vulnerable |

> ⚠ **3DES birthday bound:** With a 64-bit block, collisions become probable after ~2³² (4 GB) encrypted blocks under the same key. NIST disallowed 3DES for all new encryption effective 2024. Existing uses must migrate.

### 1.2 Block cipher modes

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `AES-[128\|192\|256]-GCM` | 128–256 bit | ✅ Recommended | SP 800-38D; BSI TR-02102-1 §3.3 | AEAD; preferred for authenticated encryption |
| `AES-[128\|192\|256]-CCM` | 128–256 bit | ✓ Approved | SP 800-38C; BSI TR-02102-1 | AEAD; suitable for constrained environments |
| `AES-[128\|192\|256]-GCM-SIV` | 128–256 bit | ✓ Approved | RFC 8452; BSI TR-02102-1 | Nonce-misuse resistant; deterministic AEAD |
| `AES-[128\|192\|256]-CTR` | 128–256 bit | ✓ Approved | SP 800-38A | No authentication; counter must never repeat with same key |
| `AES-[128\|192\|256]-CBC` | 128–256 bit | ⚠ Conditional | SP 800-38A; BSI TR-02102-1 | Requires unpredictable (pseudorandom) IV; no integrity protection |
| `AES-[128\|192\|256]-CFB[128]` | 128–256 bit | ⚠ Conditional | SP 800-38A | IV must be unique; rarely preferred over CTR |
| `AES-[128\|192\|256]-OFB` | 128–256 bit | ⚠ Conditional | SP 800-38A | IV must be unique; malleable without MAC |
| `AES-[128\|192\|256]-XTS` | 128–256 bit | ⚠ Conditional | SP 800-38E; IEEE 1619 | **Storage encryption only**; not for network use; provides no integrity |
| `AES-[128\|192\|256]-ECB` | 128–256 bit | 🚫 Disallowed | SP 800-38A; BSI TR-02102-1 | Deterministic; reveals identical blocks; prohibited for multi-block use |
| `AES-KW-[128\|192\|256]` | 128–256 bit | ✓ Approved | SP 800-38F | Key-wrapping only; not a general encryption mode |
| `ChaCha20-Poly1305` | 256 bit | ✅ Recommended | RFC 8439; BSI TR-02102-1 (2024) | AEAD; constant-time; preferred when AES-NI unavailable. Note: not in NIST FIPS approved list but BSI-approved |

> ⚠ **GCM IV uniqueness:** IV reuse under AES-GCM with the same key allows full key recovery. Use 96-bit random IVs with a CSPRNG, or a deterministic counter with strict uniqueness guarantees. After 2³² random IVs, collision probability exceeds 2⁻³² — implement rekey policies. (SP 800-38D §8.3)

> ⚠ **CBC IV:** The IV for AES-CBC **must be unpredictable** (generated by an approved CSPRNG before each encryption). A predictable or reused IV enables chosen-plaintext attacks (BEAST). (SP 800-38A §B.2)

> ⚠ **Authentication:** CBC, CTR, CFB, and OFB provide **no integrity or authenticity**. Always pair with an approved MAC (HMAC or GMAC) or use an AEAD mode.

### 1.3 Tag length (AEAD)

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `AES-*-GCM[-128]` | 128-bit tag | ✅ Recommended | SP 800-38D; BSI TR-02102-1; RFC 5116 | Full 128-bit tag required for general use |
| `AES-*-GCM-96` | 96-bit tag | ⚠ Conditional | SP 800-38D §5.2.1.2 | Permitted only for specific protocols (IPsec, TLS); verify protocol allows truncation |
| `AES-*-GCM-[32\|64]` | 32–64-bit tag | 🚫 Disallowed | SP 800-38D | Forgery probability too high for general use |

---

## 2. Hash Functions

| Pattern | Output | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|:---|
| `SHA-256` | 256 bit | 128 bit | ✅ Recommended | FIPS 180-4; BSI TR-02102-1 | Minimum for new designs |
| `SHA-384` | 384 bit | 192 bit | ✅ Recommended | FIPS 180-4 | |
| `SHA-512` | 512 bit | 256 bit | ✅ Recommended | FIPS 180-4 | |
| `SHA-512/256` | 256 bit | 256 bit | ✓ Approved | FIPS 180-4 | Truncated SHA-512; efficient on 64-bit |
| `SHA3-[256\|384\|512]` | 256–512 bit | 128–256 bit | ✅ Recommended | FIPS 202; BSI TR-02102-1 | Structurally independent of SHA-2; recommended for diversity |
| `SHAKE128` | variable | 128 bit | ✓ Approved | FIPS 202 | XOF; use ≥ 32-byte (256-bit) output for 128-bit security |
| `SHAKE256` | variable | 256 bit | ✓ Approved | FIPS 202 | XOF; use ≥ 64-byte (512-bit) output for 256-bit security |
| `BLAKE2b-[256\|384\|512]` | variable | 128–256 bit | ⚠ Conditional | BSI TR-02102-1 | Approved by BSI; not in NIST FIPS list; high performance |
| `BLAKE3` | variable | 128 bit | ⚠ Conditional | — | Not yet in NIST or BSI formal guidance; monitor standardisation |
| `SHA-224` | 224 bit | 112 bit | 🔜 Transitional | FIPS 180-4; SP 800-131A | 112-bit security; acceptable through 2030; disallowed from 2031 per SP 800-131A Rev 3 IPD; prefer SHA-256 for new designs |
| `SHA-1` | 160 bit | 69 bit (collision) | ❌ Deprecated | SP 800-131A Rev 2 §9; BSI TR-02102-1 | **Disallowed for signatures, certificates, and collision-resistance** since 2013. Permitted only for HMAC-SHA-1 at legacy 112-bit security level through 2030 (NIST only, not BSI) |
| `MD5` | 128 bit | — | 🚫 Disallowed | SP 800-131A; RFC 6151 | Collision attacks demonstrated; disallowed for all security purposes |
| `MD4` | 128 bit | — | 🚫 Disallowed | — | Broken |

> ⚠ **SHA-1 collision:** SHAttered attack (2017) demonstrated SHA-1 collisions at cost of ~2⁶³·¹ SHA-1 compressions. SHA-1 is fully deprecated for any collision-resistance use. NIST certificates with SHA-1 expired or were revoked by 2019.

---

## 3. Message Authentication Codes (MAC)

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `HMAC-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | FIPS 198-1; SP 800-107; BSI TR-02102-1 | Preferred MAC construction for all new designs |
| `HMAC-[SHA3-256\|SHA3-384\|SHA3-512]` | 128–256 bit | ✓ Approved | FIPS 198-1; FIPS 202 | |
| `HMAC-SHA-256[-128]` | 128 bit | ✅ Recommended | SP 800-107 | Truncated HMAC; output ≥ 128 bits |
| `AES-[128\|192\|256]-CMAC` | 128–256 bit | ✓ Approved | SP 800-38B; FIPS 198-1; BSI TR-02102-1 | Preferred MAC when HMAC is impractical (hardware AES available) |
| `KMAC128` | 128 bit | ✓ Approved | SP 800-185 | |
| `KMAC256` | 256 bit | ✓ Approved | SP 800-185 | |
| `Poly1305` | 128 bit | ⚠ Conditional | RFC 8439; BSI TR-02102-1 | One-time MAC; secure only as part of ChaCha20-Poly1305 or AES-Poly1305; not standalone |
| `HMAC-SHA-1` | 112 bit | 🔜 Transitional | SP 800-131A Rev 2 | Permitted through 2030 for legacy; 112-bit security minimum. **BSI: no longer recommended** |
| `HMAC-MD5` | — | 🚫 Disallowed | SP 800-131A | MD5 key-size weakness exploitable; disallowed |
| `CBC-MAC-*` | — | ❌ Deprecated | SP 800-38B | Variable-length input attacks; superseded by CMAC |
| `AES-*-GMAC` | 128–256 bit | ⚠ Conditional | SP 800-38D | AES-GCM with empty plaintext; inherits GCM IV-uniqueness requirement strictly |

> ⚠ **Truncated MAC:** Truncated HMAC output must be ≥ 128 bits per SP 800-107 §5.3.4. Shorter tags (e.g., 96-bit) require explicit approval and protocol binding.

---

## 4. Asymmetric Encryption / Key Encapsulation

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `RSAES-OAEP-[2048\|3072\|4096]-[SHA-256\|SHA-384\|SHA-512]-MGF1` | 112–150+ bit | ✓ Approved | SP 800-56B Rev 2; FIPS 186-5; BSI TR-02102-1 | Recommended RSA encryption scheme |
| `RSAES-OAEP-[3072\|4096]-*` | 128–150+ bit | ✅ Recommended | SP 800-57; BSI TR-02102-1 §3.6 | Preferred key sizes for new designs. BSI: 3000+ bits minimum |
| `RSAES-PKCS1-[2048\|3072\|4096]` | ≤112 bit | 🚫 Disallowed | SP 800-131A Rev 2; FIPS 186-5 | PKCS#1 v1.5 encryption **disallowed for new use** (Bleichenbacher oracle; not IND-CCA2); legacy decryption only with caution |
| `ML-KEM-[512\|768\|1024]` | 128–256 bit (quantum) | ✅ Recommended | FIPS 203 | NIST-standardised PQC KEM; ML-KEM-768 recommended default for TLS 1.3 |
| `ECIES-[P-256\|P-384\|P-521]-*` | 128–192 bit | ✓ Approved | BSI TR-02102-1 §3.6; SP 800-56A | Hybrid encryption; use ECDH + KDF + AEAD |

> ⚠ **RSAES-PKCS1 (v1.5):** The Bleichenbacher '98 attack and its variants (ROBOT 2017, Lucky Thirteen) allow ciphertext forgery and plaintext recovery. Disallowed for new implementations. Constant-time decryption with rejection of malformed messages is required even in legacy modes.

---

## 5. Key Agreement

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `ECDH-[P-256\|P-384\|P-521]` | 128–260 bit | ✅ Recommended | SP 800-56A Rev 3; FIPS 186-5; BSI TR-02102-1 §3.5 | Ephemeral use (ECDHE) required for forward secrecy |
| `ECDH-[brainpoolP256r1\|brainpoolP384r1\|brainpoolP512r1]` | 128–256 bit | ✓ Approved | BSI TR-02102-1 §3.5 | BSI-preferred alternative to NIST curves; not in NIST FIPS |
| `ECDH-[Curve25519\|X25519]` | 128 bit | ✅ Recommended | SP 800-186; RFC 7748; BSI TR-02102-1 | Constant-time; immune to timing attacks by design; default in TLS 1.3 |
| `ECDH-[Curve448\|X448]` | 224 bit | ✓ Approved | SP 800-186; RFC 7748; BSI TR-02102-1 | 224-bit security |
| `FFDH-[ffdhe3072\|ffdhe4096\|ffdhe6144\|ffdhe8192]` | 128–192 bit | ✓ Approved | SP 800-56A; RFC 7919; BSI TR-02102-1 | Use RFC 7919 named groups only; custom primes require full validation |
| `FFDH-ffdhe2048` | 112 bit | 🔜 Transitional | SP 800-57; SP 800-56A | 112-bit security; acceptable through 2030. BSI: 3000+ bits recommended for new designs |
| `FFDH-[1024\|1536]` | <112 bit | 🚫 Disallowed | SP 800-131A Rev 2 | Logjam attack; disallowed |
| `ECDH-secp256k1` | 128 bit | ❌ Deprecated | — | Not in NIST SP 800-186 or BSI approved list; used in blockchain only |

> ⚠ **Ephemeral key agreement:** Static (non-ephemeral) ECDH and DH provide no forward secrecy. SP 800-56A requires ephemeral keys for forward-secret key establishment. TLS 1.3 mandates ECDHE or DHE.

---

## 6. Digital Signatures

### 6.1 Classical signatures

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `ECDSA-[P-256\|P-384\|P-521]-[SHA-256\|SHA-384\|SHA-512]` | 128–260 bit | ✅ Recommended | FIPS 186-5; SP 800-57; BSI TR-02102-1 §3.4 | RFC 8422 defines TLS use |
| `ECDSA-[brainpoolP256r1\|brainpoolP384r1\|brainpoolP512r1]-*` | 128–256 bit | ✓ Approved | BSI TR-02102-1 §3.4 | BSI-preferred alternative to NIST curves |
| `EdDSA-[Ed25519\|Ed448]` | 128–224 bit | ✅ Recommended | FIPS 186-5; RFC 8032; BSI TR-02102-1 | Deterministic; immune to k-reuse attacks; constant-time |
| `RSASSA-PSS-[3072\|4096\|7680\|15360]-[SHA-256\|SHA-384\|SHA-512]-*` | 128–256 bit | ✅ Recommended | FIPS 186-5; SP 800-131A; BSI TR-02102-1 §3.6 | PSS with salt ≥ hLen bytes (SP 800-131A); BSI: 3000+ bit minimum |
| `RSASSA-PSS-2048-[SHA-256\|SHA-384\|SHA-512]-*` | 112 bit | 🔜 Transitional | SP 800-131A Rev 2; SP 800-57 | 112-bit security; acceptable through 2030 |
| `RSASSA-PKCS1-[3072\|4096]-[SHA-256\|SHA-384\|SHA-512]` | 128–150+ bit | ⚠ Conditional | FIPS 186-5 | PKCS#1 v1.5 **removed from FIPS 186-5 for new signing**; legacy signature verification only |
| `RSASSA-PKCS1-2048-*` | 112 bit | ❌ Deprecated | FIPS 186-5; SP 800-131A | New signing disallowed per FIPS 186-5; verification of existing signatures permitted |
| `DSA-[2048\|3072]-[SHA-256\|SHA-384\|SHA-512]` | 112–128 bit | ❌ Deprecated | FIPS 186-5 §3.7 | DSA **removed from FIPS 186-5** for new use (2023); legacy verification only |
| `ECDSA-[P-192\|secp192r1]` | 96 bit | 🚫 Disallowed | SP 800-131A Rev 2; FIPS 186-5 | Disallowed after 2013 |
| `DSA-1024-*` | 80 bit | 🚫 Disallowed | SP 800-131A Rev 2 | Disallowed after 2013 |
| `RSASSA-*-1024-*` | 80 bit | 🚫 Disallowed | SP 800-131A Rev 2 | Disallowed after 2013 |

> ⚠ **ECDSA nonce reuse:** ECDSA is catastrophically vulnerable to k (nonce) reuse — reusing k for two signatures with the same key exposes the private key directly. Use an RFC 6979 deterministic nonce or an approved CSPRNG per signing operation.

> ⚠ **EdDSA hedged signing:** EdDSA is deterministic by design, which eliminates k-reuse risk but makes it vulnerable to fault injection (single-fault differential). Use hedged mode (rfc8032 §5.1 with randomizer) in hardware implementations or when fault attacks are a concern.

### 6.2 Stateful hash-based signatures (SP 800-208)

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `LMS-*` | 128–256 bit | ✓ Approved | SP 800-208; RFC 8554 | **Stateful** — state (counter) must never repeat; suitable for firmware signing, code signing |
| `XMSS-*` | 128–256 bit | ✓ Approved | SP 800-208; RFC 8391 | Stateful — same state-management requirements as LMS |

> ⚠ **Statefulness:** Signing the same state twice under LMS or XMSS is cryptographically catastrophic. State must be managed by a trusted, crash-safe store. Not suitable for general-purpose signing; use for code/firmware where signing frequency is low and state is fully controlled.

---

## 7. Key Derivation Functions

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `HKDF-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | RFC 5869; SP 800-56C Rev 2; SP 800-135; BSI TR-02102-1 | Standard two-step KDF (Extract + Expand); use in TLS 1.3, HPKE, OPAQUE |
| `SP800-108-[HMAC-SHA256\|HMAC-SHA384\|HMAC-SHA512\|AES-CMAC]` | 128–256 bit | ✅ Recommended | SP 800-108r1 | Counter, feedback, and double-pipeline modes; approved for FIPS 140-3 |
| `SP800-56C-*` | 128–256 bit | ✓ Approved | SP 800-56C Rev 2 | One-step and two-step KDFs for key-establishment protocols |
| `TLS13-PRF-[SHA-256\|SHA-384]` | 128–192 bit | ✅ Recommended | RFC 8446; SP 800-135 | TLS 1.3 HKDF-based PRF |
| `TLS12-PRF-SHA-256` | 128 bit | ⚠ Conditional | SP 800-135; RFC 5246 | TLS 1.2 only; SHA-256 minimum; acceptable in maintained TLS 1.2 deployments |
| `ANSI-KDF-[X9.42\|X9.63]-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✓ Approved | SP 800-56A; SP 800-135 | Used in ECIES and CMS key agreement |
| `TLS10-PRF-*` | <112 bit | 🚫 Disallowed | SP 800-131A Rev 2; RFC 8996 | TLS 1.0/1.1 PRF (MD5+SHA-1); disallowed |
| `SSL30-PRF-*` | — | 🚫 Disallowed | RFC 7568 | SSLv3 disallowed entirely |

---

## 8. Password-Based Key Derivation and Password Hashing

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `Argon2id-*-[19456\|65536\|262144\|1048576]-[2\|3]-1` | 128+ bit | ✅ Recommended | BSI TR-02102-1 §3.9; OWASP 2023 | PHC winner; memory-hard; side-channel resistant variant; min m=19456 KiB, t=2, p=1 (OWASP web); m=65536 KiB for higher security |
| `scrypt-[32768\|65536\|1048576]-8-1-*` | 128+ bit | ✓ Approved | RFC 7914; BSI TR-02102-1 | N=32768 minimum (OWASP); N=1048576 high-security |
| `bcrypt-[12\|13\|14]-*` | 128 bit | ✓ Approved | BSI TR-02102-1 | Cost ≥ 12 (2024 minimum); input truncated at 72 bytes |
| `PBKDF2-HMAC-[SHA-256\|SHA-384\|SHA-512]-[600000\|1000000]-*-[32\|48\|64]` | 128–256 bit | ✓ Approved | SP 800-132; OWASP 2023; BSI TR-02102-1 | Minimum 600,000 iterations for PBKDF2-HMAC-SHA-256 (SP 800-132 2023 update); salt ≥ 128 bits |
| `PBKDF2-HMAC-SHA-1-*` | ≤112 bit | ❌ Deprecated | SP 800-132 | SHA-1 deprecation applies; use SHA-256 minimum |
| `PBKDF1-*` | — | 🚫 Disallowed | RFC 8018 §6.1 | PBKDF1 disallowed; only supports short keys; superseded by PBKDF2 |

> ⚠ **Password hash without memory hardness:** PBKDF2 lacks memory hardness and is GPU-parallelisable. For password storage, prefer Argon2id or scrypt. PBKDF2 is acceptable for derived key material in standards-constrained environments (TLS, IKE).

> ⚠ **bcrypt 72-byte limit:** bcrypt silently truncates passwords at 72 bytes. Passwords longer than 72 bytes with identical first 72 bytes hash identically. Pre-hash with SHA-256 if longer passwords must be supported — but use a proper memory-hard function for new designs.

---

## 9. Random Number Generators and DRBGs

### 9.1 NIST SP 800-90A DRBGs

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `HMAC_DRBG-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | SP 800-90A Rev 1; BSI AIS 20/31 (DRG.2+) | Best-proven security (machine-verified proof); preferred DRBG for general use |
| `Hash_DRBG-[SHA-256\|SHA-384\|SHA-512]` | 128–256 bit | ✅ Recommended | SP 800-90A Rev 1 | Hash-only; no block cipher required; formal security proof |
| `CTR_DRBG-[AES-128\|AES-192\|AES-256]` | 128–256 bit | ✓ Approved | SP 800-90A Rev 1; BSI AIS 20/31 | Fastest; used internally by Windows BCryptGenRandom and Intel RDRAND; **no formal security proof** |
| `CTR_DRBG-AES-256` | 256 bit | ✅ Recommended | SP 800-90A Rev 1; FIPS 140-3 | Preferred CTR_DRBG instantiation for FIPS 140-3 modules |
| `CTR_DRBG-AES-[128\|192\|256]-noDF` | 128–256 bit | ❌ Deprecated | SP 800-90A Rev 1 §10.2.1 | Without derivation function; entropy input must equal seed length exactly; security properties degraded |
| `Hash_DRBG-[SHA-1\|SHA-224]` | 112 bit | 🔜 Transitional | SP 800-90A Rev 1; SP 800-131A | SHA-1 at 112-bit security; acceptable through 2030 (NIST); not recommended by BSI |
| `CTR_DRBG-3DES` | 112 bit | 🚫 Disallowed | SP 800-90A Rev 1; SP 800-131A Rev 2 | 3DES deprecated 2023; do not use |
| `Dual_EC_DRBG` | — | 🚫 Disallowed | SP 800-90A Rev 1 (withdrawn 2014) | Deliberately backdoored via NSA-chosen elliptic curve points; withdrawn June 2015 |

> ⚠ **Prediction resistance:** Enable prediction resistance (`{predictionResistance}=true`) only if a live entropy source is always available. For most software deployments, use periodic reseeding instead (every 2²⁴ generate calls or per schedule). Prediction resistance adds a live entropy-source dependency that can fail in VMs and embedded systems.

> ⚠ **DRBG reseed interval:** SP 800-90A mandates reseeding after ≤ 2⁴⁸ generate calls. Implementations should use shorter intervals (e.g., 2²⁴) for defence in depth, especially in virtualised environments where VM snapshots can replay DRBG state.

> ⚠ **Personalization string:** Always supply a unique `{personalizationString}` at DRBG instantiation (e.g., application name + PID + timestamp). This provides domain separation at no security cost and prevents multiple instances seeded from the same entropy source from producing correlated output (SP 800-90A §8.7.1).

### 9.2 Accumulator-based CSPRNGs

| Pattern | Security | Status | Sources | Notes |
|:---|:---|:---|:---|:---|
| `Fortuna-AES-256-SHA-256` | 256 bit | ✅ Recommended | BSI AIS 20/31; Ferguson-Schneier *Cryptography Engineering* | 32 entropy pools; automatic pool-based reseeding; no entropy estimator required; deployed in macOS/iOS since 2020 |
| `Fortuna-*` | 128–256 bit | ✓ Approved | BSI AIS 20/31 | Non-standard cipher/hash variants reduce assurance; prefer canonical AES-256-SHA-256 form |
| `Yarrow-*` | variable | ❌ Deprecated | — | Superseded by Fortuna; entropy estimator requirement difficult to implement correctly; do not use for new designs |

### 9.3 OS-provided entropy APIs

| Pattern | Status | Sources | Notes |
|:---|:---|:---|:---|
| `getrandom()` | ✅ Recommended | Linux ≥ 3.17; SP 800-90B | Blocks only until initialization; same pool as /dev/urandom; preferred over /dev/urandom for new Linux code |
| `/dev/urandom` | ✓ Approved | Linux / macOS / BSD | Never blocks after boot; identical to /dev/random on Linux ≥ 5.6; backed by ChaCha20-DRNG (Linux) or Fortuna (macOS) |
| `/dev/random` | ⚠ Conditional | Linux ≤ 5.5 | **Blocking** on Linux < 5.6; identical to /dev/urandom on Linux ≥ 5.6; avoid blocking behaviour in daemons |
| `BCryptGenRandom` | ✅ Recommended | Windows CNG; FIPS 140-3 | CTR_DRBG-AES-256 internally; FIPS 140-3 validated |
| `getentropy()` | ✅ Recommended | macOS / BSDs; RFC-like | Non-blocking; limited to 256 bytes per call; preferred on macOS/BSDs |

### 9.4 Hardware RNG interfaces

| Pattern | Status | Sources | Notes |
|:---|:---|:---|:---|
| `RDRAND` | ⚠ Conditional | Intel/AMD; SP 800-90B | CTR_DRBG on-die; **must not be the sole entropy source**; combine with OS entropy (XOR or HKDF); trust concerns about Intel microcode control |
| `RDSEED` | ✓ Approved | Intel/AMD; SP 800-90B | Direct conditioned hardware entropy; suitable for **seeding** DRBGs; slower than RDRAND; may return failure (CF=0) — must retry |
| `TPM_RNG-*` | ✓ Approved | TCG TPM 2.0; SP 800-90B | FIPS 140-3 validated TPMs; low throughput (10–50 KB/s); excellent trust boundary; provides independent entropy from CPU |

### 9.5 BSI AIS 20/31 functionality classes

| Class | Description | Minimum use case |
|:---|:---|:---|
| **DRG.2** | Software DRBG (SP 800-90A mechanisms qualify) | Key generation, nonces for standard applications |
| **DRG.3** | DRBG with prediction resistance (live entropy before each output) | High-security key generation |
| **DRG.4** | Enhanced prediction resistance | Long-term key generation in FIPS 140-3 / CC EAL 4+ modules |
| **PTG.2** | Physical TRNG (validated entropy source + conditioner) | Seeding software DRBGs in hardware modules |
| **PTG.3** | Enhanced TRNG | Smart card / HSM key generation |
| **NTG.1** | Non-deterministic RBG (TRNG + DRBG, highest assurance) | CA root key generation, HSM master keys |

### 9.6 Non-cryptographic PRNGs — always disallowed for security use

| Pattern | Status | Notes |
|:---|:---|:---|
| `MT19937` | 🚫 Disallowed | State fully recoverable from 624 consecutive 32-bit outputs; default `random` in Python, PHP, Ruby |
| `Xoshiro(256\|512)(+\|++\|**)` | 🚫 Disallowed | Linear feedback; fast but cryptographically insecure |
| `PCG-*` | 🚫 Disallowed | LCG + output permutation; statistically good but not crypto-safe |
| `LCG-*` | 🚫 Disallowed | Trivially predictable from one output value |

> ⚠ **Language default PRNGs:** `Math.random()` (JavaScript), `random.random()` (Python), `rand()` (C stdlib), `Random` (Java) — all use non-cryptographic PRNGs. Never use these for key generation, nonces, session tokens, CSRF tokens, or any security material. Use `crypto.getRandomValues()` (Web), `secrets` (Python), `SecureRandom` (Java), or OS-level APIs.

---

## 10. Post-Quantum Cryptography (FIPS 203 / 204 / 205 / 206)

### 10.1 Key Encapsulation — ML-KEM (FIPS 203)

| Pattern | NIST Level | Security (classical / quantum) | Status | Notes |
|:---|:---|:---|:---|:---|
| `ML-KEM-512` | 1 | 128 / 128 bit | ✓ Approved | Smallest keys/ciphertext; constrained devices |
| `ML-KEM-768` | 3 | 192 / 192 bit | ✅ Recommended | **Default recommendation** for TLS 1.3 hybrid (PQC forum consensus Jan 2026); balanced size/security |
| `ML-KEM-1024` | 5 | 256 / 256 bit | ✓ Approved | Highest security; larger keys (1568 B) and ciphertext (1568 B) |

> ⚠ **Hybrid deployment:** Until ML-KEM implementations have accrued operational confidence, deploy as **hybrid** with a classical key exchange (X25519 or P-256). The TLS 1.3 hybrid scheme `X25519MLKEM768` is defined in `draft-ietf-tls-hybrid-design` and is the current recommendation. The combiner is simple concatenation fed into the TLS 1.3 HKDF key schedule (`{hybridKemCombiner}=concat`).

### 10.2 Digital Signatures — ML-DSA (FIPS 204)

| Pattern | NIST Level | Security | Status | Notes |
|:---|:---|:---|:---|:---|
| `ML-DSA-44` | 2 | 128 bit | ✓ Approved | Smallest signatures (2420 B); good for high-volume signing |
| `ML-DSA-65` | 3 | 192 bit | ✅ Recommended | Balanced; recommended for general use |
| `ML-DSA-87` | 5 | 256 bit | ✓ Approved | Highest security |
| `ML-DSA-[44\|65\|87]-(deterministic)` | — | — | ❌ Deprecated | Deterministic mode vulnerable to fault attacks; use hedged mode |
| `ML-DSA-[44\|65\|87]-(hedged)` | — | — | ✅ Recommended | FIPS 204 §5.2 hedged mode (rnd from approved DRBG); fault-attack resistant |

> ⚠ **ML-DSA constant-time requirement:** Non-constant-time implementations of `SampleInBall` and the τ non-zero position sampling leak information about the signing key. All ML-DSA implementations must sample in constant time with respect to secret inputs. (NIST PQC Forum, Jan 2026)

### 10.3 Digital Signatures — SLH-DSA (FIPS 205)

| Pattern | NIST Level | Security | Status | Notes |
|:---|:---|:---|:---|:---|
| `SLH-DSA-SHA2-128s` | 1 | 128 bit | ✓ Approved | Small signatures (7856 B); slow signing |
| `SLH-DSA-SHA2-128f` | 1 | 128 bit | ✓ Approved | Fast signing; larger signatures (17088 B) |
| `SLH-DSA-SHA2-[192s\|192f]` | 3 | 192 bit | ✓ Approved | |
| `SLH-DSA-SHA2-[256s\|256f]` | 5 | 256 bit | ✓ Approved | |
| `SLH-DSA-SHAKE-[128s\|128f\|192s\|192f\|256s\|256f]` | 1–5 | 128–256 bit | ✓ Approved | SHAKE-based variants; identical security, different internal hash |

> ℹ **Stateless:** SLH-DSA is stateless (unlike LMS/XMSS); no state management required. Signing is slow but requires no storage state. Suitable where signing frequency is low and verification speed matters more than signing speed.

### 10.4 Digital Signatures — FN-DSA / Falcon (FIPS 206 IPD)

| Pattern | NIST Level | Security | Status | Notes |
|:---|:---|:---|:---|:---|
| `FN-DSA-512` | 1 | 128 bit | ⚠ Conditional | FIPS 206 IPD (submitted Aug 2025; final expected late 2026 / early 2027); compact signatures (666 B); floating-point dependency (see alert) |
| `FN-DSA-1024` | 5 | 256 bit | ⚠ Conditional | FIPS 206 IPD; 1280 B signatures |

> ⚠ **IEEE 754 compliance (`{floatingPointMode}`):** FN-DSA/Falcon uses FFT-based Gaussian sampling that relies on IEEE 754 floating-point arithmetic. Execution with extended precision (x87), flush-to-zero, or non-standard rounding **deviates from the specification** and may weaken or break security. Require `ieee754-strict` mode or `integer-emulation` in FIPS 140-3 and CC environments. FIPS 206 is still in the Initial Public Draft stage (IPD submitted for Department of Commerce clearance August 2025; final standard not yet published as of March 2026).

> ℹ **FIPS 206 standardisation status:** FIPS 203, 204, and 205 were published as final standards on 13 August 2024. FIPS 206 (FN-DSA / Falcon) followed a separate timeline: the IPD was submitted for internal NIST approval in August 2025 and is awaiting Department of Commerce clearance. The final standard is expected late 2026 or early 2027. Implementations may reference the Falcon Round 3.1 specification in the interim.

---

## 11. TLS / Protocol Quick-Reference

| Version | Status | Sources | Notes |
|:---|:---|:---|:---|
| **TLS 1.3** | ✅ Recommended | RFC 8446; BSI TR-02102-2 (2024) | ECDHE-only forward secrecy; AEAD-only cipher suites; no renegotiation |
| **TLS 1.2** + strong ciphers | ⚠ Conditional | RFC 5246; BSI TR-02102-2 | Acceptable with ECDHE + AES-GCM + SHA-256+; disable RC4, 3DES, CBC-SHA1 cipher suites |
| **TLS 1.0 / 1.1** | 🚫 Disallowed | RFC 8996; BSI TR-02102-2 | POODLE, BEAST, SWEET32; disallowed |
| **SSL 3.0** | 🚫 Disallowed | RFC 7568 | POODLE; disallowed |
| **TLS 1.2 cipher suites with SHA-1** | 🚫 Disallowed | BSI TR-02102-2; RFC 9155 | e.g., TLS_RSA_WITH_AES_128_CBC_SHA; disallowed for new configurations |
| **TLS cipher suites with NULL / EXPORT** | 🚫 Disallowed | — | No encryption / deliberately weakened |

---

## 12. Deprecated and Disallowed — Consolidated Reference

| Pattern | Reason | Disallowed since | Source |
|:---|:---|:---|:---|
| `DES-*` | 56-bit key; brute-forceable | 2001 (NIST) | SP 800-131A |
| `3DES-*` | 64-bit block; birthday bound; 112-bit max | Encryption: 2024 | SP 800-131A Rev 2 §2 |
| `RC4-*` | Statistical biases; NOMORE, RC4NOMORE attacks | 2015 | RFC 7465; SP 800-131A |
| `RC2-*` | Legacy; key-size attacks | 2014 | SP 800-131A |
| `IDEA-*` | Not FIPS; patented legacy | — | BSI TR-02102-1 |
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

---

*Last updated: 2026-03-28. Consult current NIST SP 800-131A and BSI TR-02102-1 editions for horizon dates and any post-publication amendments.*
