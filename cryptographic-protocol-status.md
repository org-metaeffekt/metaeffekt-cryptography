# Cryptographic Protocol Guidance

> Protocol-specific and domain-specific deployment guidance for cryptographic algorithms.
> Covers SSH, IPsec/IKEv2, CNSA 2.0 migration, quantum threat context, PKI, S/MIME,
> Kerberos, and DNSSEC.
>
> For algorithm-level security status (approved/deprecated/disallowed/broken), see
> [cryptographic-algorithm-status.md](cryptographic-algorithm-status.md).
>
> **Primary sources:** BSI TR-02102-2 v2026-01 (TLS) · BSI TR-02102-3 v2026-01 (IPsec) ·
> BSI TR-02102-4 v2026-01 (SSH) · NSA CNSA 2.0 (PP-22-1338, Sep 2022) ·
> ENISA "Post-Quantum Cryptography" v2 (May 2021) · NIST SP 800-57 Part 3 Rev 1 (Jan 2015)

---

## 1. SSH (BSI TR-02102-4 v2026-01)

Recommendations for SSH protocol usage. Source: BSI TR-02102-4, Version 2026-01 (2026-01-27). SSH-2 is the only acceptable version; SSH-1 is 🚫 Disallowed.

### 1.1 Key Exchange

> **Authorities:** IETF RFC 9142 (Oct 2021); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01.

| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `curve25519-sha256` | ✓ SHOULD (§3.1.1) | ✓ Approved | ✅ Recommended | RFC 8731; ECDH/Curve25519+SHA-256; constant-time |
| `curve25519-sha256@libssh.org` | — | ✓ Approved | ✅ Recommended | OpenSSH alias predating RFC 8731 |
| `ecdh-sha2-nistp256` | ✓ SHOULD (§3.1.3) | ✓ Approved | ✓ Approved | RFC 5656; P-256 |
| `ecdh-sha2-nistp384` | ✓ SHOULD (§3.1.3) | ✓ Approved | ✓ Approved | RFC 5656; P-384 |
| `ecdh-sha2-nistp521` | ✓ SHOULD (§3.1.3) | ✓ Approved | ✓ Approved | RFC 5656; P-521 |
| `diffie-hellman-group14-sha256` | ✅ MUST (§3.2.2) | 🔜 Transitional | 🔜 Transitional | RFC 8268; 2048-bit DH; 112-bit security; acceptable through 2030 |
| `diffie-hellman-group15-sha512` | ◯ MAY (§3.2.2) | ✓ Approved | — | 3072-bit DH; 128-bit security; not listed in BSI table |
| `diffie-hellman-group16-sha512` | ✓ SHOULD (§3.2.2) | ✓ Approved | ✓ Approved | RFC 8268; 4096-bit DH |
| `diffie-hellman-group17-sha512` | ◯ MAY (§3.2.2) | ✓ Approved | — | 6144-bit DH; not listed in BSI table |
| `diffie-hellman-group18-sha512` | ◯ MAY (§3.2.2) | ✓ Approved | ✓ Approved | RFC 8268; 8192-bit DH |
| `diffie-hellman-group-exchange-sha256` | ◯ MAY (§3.2.1) | ✓ Approved | — | RFC 4419; client-chosen group; not listed in BSI table |
| `diffie-hellman-group14-sha1` | ◯ MAY (§3.4) | 🚫 Disallowed | 🚫 Disallowed | RFC 9142 §3.4 retains MAY despite SHA-1; NIST/BSI disallow due to SHA-1 |
| `diffie-hellman-group1-sha1` | ❌ SHOULD NOT (§3.4) | 🚫 Disallowed | 🚫 Disallowed | 1024-bit DH; SHA-1 |
| `diffie-hellman-group-exchange-sha1` | ❌ SHOULD NOT (§3.2.1) | 🚫 Disallowed | 🚫 Disallowed | SHA-1 |

### 1.2 Host Authentication

> **Authorities:** IETF RFC 8332 (RSA-SHA2), RFC 8709 (Ed25519/Ed448), RFC 5656 (ECDSA), RFC 4253 (legacy); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01.

| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `ssh-ed25519` | ✓ MAY (RFC 8709) | ✓ Approved | ✅ Recommended | EdDSA over Curve25519; constant-time |
| `ssh-ed448` | ✓ MAY (RFC 8709) | ✓ Approved | — | EdDSA over Curve448; not listed in BSI table |
| `ecdsa-sha2-nistp256` | ✓ MAY (RFC 5656) | ✓ Approved | ✓ Approved | ECDSA P-256 with SHA-256 |
| `ecdsa-sha2-nistp384` | ✓ MAY (RFC 5656) | ✓ Approved | ✓ Approved | ECDSA P-384 with SHA-384 |
| `ecdsa-sha2-nistp521` | ✓ MAY (RFC 5656) | ✓ Approved | ✓ Approved | ECDSA P-521 with SHA-512 |
| `rsa-sha2-256` | ✓ SHOULD (RFC 8332 §3.3) | ✓ Approved | ✓ Approved | RSA ≥ 3072 bits with SHA-256; ≥ 2048 transitional through 2030 |
| `rsa-sha2-512` | ✓ SHOULD (RFC 8332 §3.3) | ✓ Approved | ✓ Approved | RSA ≥ 3072 bits with SHA-512 |
| `ssh-rsa` | ❌ SHOULD NOT (RFC 8332 §3.3) | 🚫 Disallowed | 🚫 Disallowed | RSA with SHA-1; OpenSSH disabled by default since 8.8 |
| `ssh-dss` | ❌ SHOULD NOT (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | DSA-1024; disallowed |

### 1.3 Symmetric Encryption

> **Authorities:** IETF RFC 4253 (original SSH-2 ciphers), RFC 4344 (CTR modes), RFC 5647 (AES-GCM in SSH), RFC 8758 (arcfour deprecation); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01.

| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `chacha20-poly1305@openssh.com` | — | ✓ Approved | ✅ Recommended | OpenSSH extension; not in any IETF SSH RFC; ChaCha20-Poly1305 AEAD |
| `aes256-gcm@openssh.com` | ✓ MAY (RFC 5647) | ✓ Approved | ✅ Recommended | AES-256-GCM AEAD; RFC 5647 defines AES-GCM in SSH |
| `aes128-gcm@openssh.com` | ✓ MAY (RFC 5647) | ✓ Approved | ✅ Recommended | AES-128-GCM AEAD |
| `aes256-ctr` | ✓ SHOULD (RFC 4344 §4) | ✓ Approved | ⚠ Conditional | CTR mode; use only with HMAC-ETM; no AEAD |
| `aes192-ctr` | ✓ SHOULD (RFC 4344 §4) | ✓ Approved | ⚠ Conditional | CTR mode; use only with HMAC-ETM |
| `aes128-ctr` | ✓ SHOULD (RFC 4344 §4) | ✓ Approved | ⚠ Conditional | CTR mode; use only with HMAC-ETM |
| `aes256-cbc` | ◯ MAY (RFC 4253) | ⚠ Conditional | ❌ Deprecated | CBC mode; padding oracle risk; use GCM or CTR+ETM |
| `3des-cbc` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | 3DES; 64-bit block; birthday-bound vulnerable; SP 800-131A Rev 2 disallowed since 2024 |
| `arcfour*` | 🚫 MUST NOT (RFC 8758) | 🚫 Disallowed | 🚫 Disallowed | RC4; cryptographically broken; explicitly removed by RFC 8758 |

### 1.4 MAC (for CTR-mode ciphers; not needed with AEAD)

> **Authorities:** IETF RFC 4253 (original SSH-2 MACs), RFC 6668 (HMAC-SHA2 in SSH); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01. Note: ETM (encrypt-then-MAC) variants are OpenSSH extensions and not in any IETF SSH RFC.

| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `hmac-sha2-256-etm@openssh.com` | — | ✓ Approved | ✅ Recommended | OpenSSH extension; encrypt-then-MAC; preferred construction |
| `hmac-sha2-512-etm@openssh.com` | — | ✓ Approved | ✅ Recommended | OpenSSH extension; encrypt-then-MAC |
| `umac-128-etm@openssh.com` | — | ⚠ Conditional | ✓ Approved | OpenSSH extension; UMAC not FIPS-approved |
| `hmac-sha2-256` | ✓ SHOULD (RFC 6668) | ✓ Approved | ⚠ Conditional | MAC-then-Encrypt; acceptable only with CTR mode |
| `hmac-sha2-512` | ✓ SHOULD (RFC 6668) | ✓ Approved | ⚠ Conditional | MAC-then-Encrypt; acceptable only with CTR mode |
| `hmac-sha1*` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | SHA-1; was REQUIRED in RFC 4253 |
| `hmac-md5*` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | MD5 |

---

## 2. IPsec / IKEv2 (BSI TR-02102-3 v2026-01)

Recommendations for IPsec with IKEv2. Source: BSI TR-02102-3, Version 2026-01 (2026-01-27). IKEv1 is 🚫 Disallowed; IKEv2 (RFC 7296) only.

### 2.1 IKEv2 Key Exchange (Diffie-Hellman groups)

> **Authorities:** IETF RFC 8247 §2.4 (IKEv2 algorithms); NIST SP 800-131A Rev 2 + SP 800-186; BSI TR-02102-3 v2026-01. RFC 8247 does not address Groups 15–18, 20, 21, 25, 26, 31, 32 (these come from later RFCs and IANA registry assignments).

| Group | Description | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|
| Group 14 | 2048-bit MODP | ✅ MUST (§2.4) | 🔜 Transitional | 🔜 Transitional | 112-bit security; acceptable through 2030 |
| Group 15 | 3072-bit MODP | — | ✓ Approved | ✓ Approved | 128-bit security |
| Group 16 | 4096-bit MODP | — | ✓ Approved | ✓ Approved | |
| Group 17 | 6144-bit MODP | — | ✓ Approved | ✓ Approved | |
| Group 18 | 8192-bit MODP | — | ✓ Approved | ✓ Approved | |
| Group 19 | 256-bit ECP (P-256) | ✓ SHOULD (§2.4) | ✓ Approved | ✓ Approved | |
| Group 20 | 384-bit ECP (P-384) | — | ✓ Approved | ✓ Approved | |
| Group 21 | 521-bit ECP (P-521) | — | ✓ Approved | ✓ Approved | |
| Group 25 | 192-bit ECP | — | 🚫 Disallowed | ❌ Deprecated | < 128-bit security |
| Group 26 | 224-bit ECP | — | 🔜 Transitional | 🔜 Transitional | 112-bit security; acceptable through 2030 |
| Group 31 | Curve25519 | — | ✓ Approved | ✅ Recommended | RFC 8031; constant-time |
| Group 32 | Curve448 | — | ✓ Approved | ✅ Recommended | RFC 8031; 224-bit security |
| Group 5 | 1536-bit MODP | ❌ SHOULD NOT (§2.4) | 🚫 Disallowed | 🚫 Disallowed | < 112-bit security |
| Group 2 | 1024-bit MODP | ❌ SHOULD NOT (§2.4) | 🚫 Disallowed | 🚫 Disallowed | 80-bit security |
| Group 1 | 768-bit MODP | 🚫 MUST NOT (§2.4) | 🚫 Disallowed | 🚫 Disallowed | < 80-bit security |
| Group 22 | 1024-bit MODP w/ subgroup | 🚫 MUST NOT (§2.4) | 🚫 Disallowed | 🚫 Disallowed | Suspect parameters |
| Groups 23–24 | 2048-bit MODP w/ subgroup | ❌ SHOULD NOT (§2.4) | 🚫 Disallowed | 🚫 Disallowed | Suspect parameters |

### 2.2 IKEv2 Encryption (ESP and IKE SA)

> **Authorities:** IETF RFC 8221 (ESP/AH data plane), RFC 8247 (IKEv2 control plane); NIST SP 800-131A Rev 2; BSI TR-02102-3 v2026-01. ESP and IKEv2 have slightly different requirement levels — table shows ESP (RFC 8221) status; IKEv2 differences noted.

| Algorithm | IETF (ESP) | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `AES-[128\|192\|256]-GCM` | ✅ MUST (RFC 8221 §5) | ✓ Approved | ✅ Recommended | AEAD; RFC 4106 (ESP), RFC 5282 (IKE); RFC 8247: SHOULD for IKEv2 |
| `AES-[128\|192\|256]-CCM` | ✓ SHOULD (RFC 8221 §5) | ✓ Approved | ✓ Approved | AEAD; RFC 4309; SHOULD only for IoT (RFC 8247) |
| `ChaCha20-Poly1305` | ✓ SHOULD (RFC 8221 §5) | ✓ Approved | ✓ Approved | AEAD; RFC 7634; SHOULD in both RFC 8221 and 8247 |
| `AES-[128\|192\|256]-CBC` | ✅ MUST (RFC 8221 §5) | ⚠ Conditional | ⚠ Conditional | Must pair with separate integrity algorithm; RFC 8247: MUST for IKEv2 |
| `AES-[128\|192\|256]-CTR` | ◯ MAY (RFC 8221 §5) | ✓ Approved | ⚠ Conditional | Must pair with separate integrity algorithm |
| `3DES-CBC` | ❌ SHOULD NOT (RFC 8221 §5) | 🚫 Disallowed | 🚫 Disallowed | 64-bit block; birthday bound; SP 800-131A disallowed since 2024; RFC 8247: MAY |
| `DES-CBC` | 🚫 MUST NOT (RFC 8221 §5) | 🚫 Disallowed | 🚫 Disallowed | 56-bit key; broken |

### 2.3 IKEv2 Integrity / PRF

> **Authorities:** IETF RFC 8221 §6 (ESP/AH integrity), RFC 8247 §2.2–§2.3 (IKEv2 PRF and integrity); NIST SP 800-131A Rev 2; BSI TR-02102-3 v2026-01.

| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `HMAC-SHA2-256-128` | ✅ MUST (RFC 8221 §6) | ✓ Approved | ✅ Recommended | RFC 4868; PRF_HMAC_SHA2_256 also MUST in IKEv2 (RFC 8247 §2.2) |
| `HMAC-SHA2-384-192` | — | ✓ Approved | ✅ Recommended | RFC 4868; not explicitly addressed in RFC 8247 |
| `HMAC-SHA2-512-256` | ✓ SHOULD (RFC 8221 §6) | ✓ Approved | ✅ Recommended | RFC 4868; SHOULD+ for PRF in IKEv2 |
| `AES-XCBC-96` | ✓ SHOULD (RFC 8221 §6) | ⚠ Conditional | ✓ Approved | RFC 3566; SHOULD for IoT; MAY for general VPN |
| `AES-CMAC-96` | — | ✓ Approved | ✓ Approved | RFC 4494; not addressed in RFC 8221/8247 |
| `HMAC-SHA1-96` | ⚠ MUST- (RFC 8221 §6) | 🚫 Disallowed | 🚫 Disallowed | SHA-1; downgraded from MUST to MUST- |
| `HMAC-MD5-96` | 🚫 MUST NOT (RFC 8221 §6) | 🚫 Disallowed | 🚫 Disallowed | MD5 |

---

## 3. NSA CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)

> **Source:** NSA Cybersecurity Advisory *"Announcing the Commercial National Security Algorithm Suite 2.0"*, PP-22-1338, September 2022, Version 1.0. Applies to National Security Systems (NSS) — all classified and unclassified NSS operated by the US government and Defence Industrial Base. Issued under NSD-42, NSM-8, NSM-10, CNSSP 11, and CNSSP 15. CNSA 2.0 replaces CNSA 1.0 (listed in CNSSP 15, Annex B). All products providing cryptographic services require NIAP or NSA validation in addition to meeting CNSA requirements.

### 3.1 Algorithm Requirements

CNSA 2.0 comprises three groups of algorithms. In the 2022 advisory, the general-use public-key algorithms were identified by their pre-standardisation names (CRYSTALS-Kyber and CRYSTALS-Dilithium) with specifications listed as TBD, pending final NIST FIPS publication. These correspond to ML-KEM and ML-DSA, standardised as FIPS 203 and FIPS 204 in August 2024.

**Table I — Software and firmware signing (immediate use)**

| Algorithm | Function | Specification | Parameters |
|:---|:---|:---|:---|
| Leighton-Micali Signature (LMS) | Digitally signing firmware and software | NIST SP 800-208 | All parameters approved for all classification levels. **SHA-256/192 recommended.** |
| Xtended Merkle Signature Scheme (XMSS) | Digitally signing firmware and software | NIST SP 800-208 | All parameters approved for all classification levels. |

> ⚠ **Stateful signatures:** Both LMS and XMSS are stateful. SP 800-208 requires state to be managed and signing to be implemented in hardware. Reuse of the same state catastrophically weakens security. See §3.2 for state-management requirements.

**Table II — Symmetric-key algorithms**

| Algorithm | Function | Specification | Parameters |
|:---|:---|:---|:---|
| Advanced Encryption Standard (AES) | Symmetric block cipher for information protection | FIPS PUB 197 | **Use 256-bit keys for all classification levels.** |
| Secure Hash Algorithm (SHA) | Computing a condensed representation of information | FIPS PUB 180-4 | **Use SHA-384 or SHA-512 for all classification levels.** SHA-512 added in CNSA 2.0; CNSA 1.0 required only SHA-384. |

**Table III — General-use quantum-resistant public-key algorithms**

| Algorithm (2022 name) | Standardised name | Function | Specification | Parameters |
|:---|:---|:---|:---|:---|
| CRYSTALS-Kyber | ML-KEM | Key establishment | FIPS 203 (finalised Aug 2024; listed as TBD in 2022 advisory) | **Use Level V parameters (ML-KEM-1024) for all classification levels.** |
| CRYSTALS-Dilithium | ML-DSA | Digital signatures | FIPS 204 (finalised Aug 2024; listed as TBD in 2022 advisory) | **Use Level V parameters (ML-DSA-87) for all classification levels.** |

**Explicitly excluded from CNSA 2.0** (will be deprecated when mandated):

- RSA (any key size) — for both key establishment and signatures
- Diffie-Hellman (DH) — any modulus size
- ECDH and ECDSA (any curve)
- SLH-DSA (FIPS 205) — not included in the advisory
- FN-DSA / Falcon (FIPS 206) — not included in the advisory
- AES-128 and AES-192

### 3.2 Migration Timeline

NSA provides per-category transition timelines. The overall deadline is **2035** (NSM-10). Compliance is tracked via the Risk Management Framework (RMF) SC-12 control. Legacy systems not refreshed regularly will require a waiver and a remediation plan.

The three transition phases per category are:
- **Added as option and tested** — CNSA 2.0 algorithms supported alongside CNSA 1.0
- **Default and preferred** — CNSA 2.0 algorithms are the preferred/default configuration
- **Exclusively use** — CNSA 1.0 algorithms alone no longer approved (hybrid may still be required for interoperability but CNSA 2.0 must be selected)

| System / product category | Support and prefer CNSA 2.0 by | Exclusively use CNSA 2.0 by |
|:---|:---|:---|
| Software and firmware signing | **2025** (begin immediately) | **2030** |
| Web browsers / servers / cloud services | **2025** | **2033** |
| Traditional networking equipment (VPNs, routers) | **2026** | **2030** |
| Operating systems | **2027** | **2033** |
| Niche equipment (constrained devices, large PKI systems) | **2030** | **2033** |
| Custom applications and legacy equipment | — | **2033** (update or replace) |

> ⚠ **Hybrid note (footnote 1 of the advisory):** Even though hybrid solutions may be allowed or required due to protocol standards, product availability, or interoperability requirements, CNSA 2.0 algorithms will become mandatory to select at the given date, and selecting CNSA 1.0 algorithms alone will no longer be approved.

### 3.3 CNSA 1.0 Reference (algorithms being phased out)

CNSA 1.0, listed in CNSSP 15 Annex B, remains required during the transition period. These algorithms will be deprecated when CNSA 2.0 is mandated per the timeline above.

| Algorithm | Function | Specification | Parameters |
|:---|:---|:---|:---|
| AES | Symmetric encryption | FIPS PUB 197 | 256-bit keys |
| ECDH | Key establishment | NIST SP 800-56A | **Curve P-384** |
| ECDSA | Digital signatures | FIPS PUB 186-4 | **Curve P-384** |
| SHA | Hashing | FIPS PUB 180-4 | **SHA-384** (only; SHA-512 not listed in CNSA 1.0) |
| Diffie-Hellman (DH) | Key establishment | IETF RFC 3526 | **Minimum 3072-bit modulus** |
| RSA | Key establishment | FIPS SP 800-56B | **Minimum 3072-bit modulus** |
| RSA | Digital signatures | FIPS PUB 186-4 | **Minimum 3072-bit modulus** |

### 3.4 Relationship to NIST Standards and CNSA 2.0 Compliance RFCs

| CNSA 2.0 requirement | NIST standard | NIST level | Notes |
|:---|:---|:---|:---|
| ML-KEM-1024 (CRYSTALS-Kyber Level V) | FIPS 203 | Level 5 | Only Level 5 approved; ML-KEM-512/768 not sufficient for NSS |
| ML-DSA-87 (CRYSTALS-Dilithium Level V) | FIPS 204 | Level 5 | Only Level 5 approved |
| LMS (SHA-256/192 recommended) | SP 800-208 | ≥192-bit | SHA-256/192 is the NSA-recommended parameter set |
| XMSS | SP 800-208 | ≥192-bit | All SP 800-208 XMSS parameter sets approved |
| AES-256 | FIPS 197 | — | Unchanged from CNSA 1.0 |
| SHA-384 / SHA-512 | FIPS 180-4 | 192/256-bit | SHA-512 is new in CNSA 2.0 |

> ℹ **Level 5 only:** NSA mandates the highest NIST PQC parameter set for all NSS regardless of data classification. This differs from general NIST guidance (SP 800-57), which recommends ML-KEM-768 / ML-DSA-65 as the balanced default for non-NSS use.

The following RFCs specify protocol-level CNSA 1.0 compliance (updated guidance for CNSA 2.0 is forthcoming from NSA):

| RFC | Topic |
|:---|:---|
| RFC 8603 | X.509 Certificate and CRL Profile |
| RFC 8755 | S/MIME |
| RFC 8756 | Certificate Management over CMS |
| RFC 9151 | TLS and DTLS 1.2 / 1.3 |
| RFC 9206 | IPsec |
| RFC 9212 | SSH |

The following RFCs define how CNSA 2.0 algorithms are encoded in X.509 Public Key Infrastructure (PKIX) certificates and private key structures:

| RFC | Algorithm | Key usage | Key details |
|:---|:---|:---|:---|
| RFC 9881 (Oct 2025) | ML-DSA (FIPS 204) in X.509 PKIX | `digitalSignature`, `nonRepudiation`, `keyCertSign`, `cRLSign` | OIDs `2.16.840.1.101.3.4.3.17/18/19`; parameters MUST be absent; pure ML-DSA only (HashML-DSA excluded from PKIX); pk 1312/1952/2592 B; sig 2420/3309/4627 B; seed 32 B |
| RFC 9935 (Mar 2026) | ML-KEM (FIPS 203) in X.509 PKIX | `keyEncipherment` only | OIDs `2.16.840.1.101.3.4.4.1/2/3`; parameters MUST be absent; encap key 800/1184/1568 B; ciphertext 768/1088/1568 B; shared secret 32 B; private key: 64-byte seed or expanded key (1632/2400/3168 B) |

For hybrid/transition deployments, the IETF LAMPS Working Group is standardising Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-15, February 2026), which combines ML-DSA with RSA, ECDSA, Ed25519, or Ed448 in a single X.509 algorithm identifier (OIDs `1.3.6.1.5.5.7.6.37–54`). This enables organisations to deploy PQC in existing PKIX infrastructure without requiring protocol changes, while retaining fallback protection from the classical component. Composite ML-DSA provides EUF-CMA but not SUF-CMA security. 4 ML-DSA-44 (L1), 8 ML-DSA-65 (L3), and 6 ML-DSA-87 (L5) combinations are registered. See also `cryptographic-algorithms.md` §21.

---

## 4. Quantum Threat and Migration Context

> **Primary source:** ENISA "Post-Quantum Cryptography: Current state and quantum mitigation", v2, May 2021. Authors: Ward Beullens, Jan-Pieter D'Anvers, Andreas Hülsing, Tanja Lange, Lorenz Panny, Cyprien de Saint Guilhem, Nigel P. Smart. DOI: 10.2824/92307. Note: the 2021 report reflects NIST Round 3 status. NIST published final standards (ML-KEM, ML-DSA, SLH-DSA) in August 2024; HQC was selected March 2025.

### 4.1 The Harvest Now, Decrypt Later (HNDL) Threat

An adversary with access to large-scale network recording capabilities can intercept and archive ciphertext today and decrypt it once a sufficiently powerful quantum computer becomes available. This threat model — called **Harvest Now, Decrypt Later (HNDL)** or **retrospective decryption** — applies to all key establishment schemes based on RSA, ECDH, or Diffie-Hellman: Shor's algorithm solves these problems in polynomial time on a quantum computer.

Key implications:
- Data encrypted today under RSA/ECDH key exchange that must remain confidential for **10 or more years** is already at risk.
- Signatures (unlike encryption) can be replaced when broken — old signature keys can be revoked when the threat materialises. But the window for signature migration is narrow: if a post-quantum signature scheme is not deployed before a large quantum computer exists, an attacker could forge software update signatures and prevent remediation.
- Symmetric encryption (AES-256, ChaCha20) is affected only by Grover's algorithm (square-root speedup), which halves the effective security level. AES-256 (128-bit quantum security) is the current recommendation; AES-128 provides only 64-bit quantum security.

> ⚠ **Recommended action:** Migrate key establishment to ML-KEM (preferably as a hybrid with X25519 or P-256) immediately. Key establishment migration is urgent specifically because of HNDL. Signature migration is less time-critical but must precede quantum computer availability for critical infrastructure.

### 4.2 PQC Algorithm Families

Post-quantum algorithms are classified by the mathematical hard problem they are built on. All five families are considered quantum-resistant (as of 2026):

| Family | Hard problem | Standardised examples | Notes |
|:---|:---|:---|:---|
| Lattice-based | Module-LWE / Module-LWR / NTRU | ML-KEM, ML-DSA, FN-DSA | Dominant family; efficient; strong QROM proofs |
| Hash-based | Preimage resistance of hash functions | SLH-DSA, LMS, XMSS | Conservative; security rests only on hash security |
| Code-based | Decoding random linear codes | HQC, Classic McEliece | Long history; large keys (Classic McEliece); HQC as NIST KEM backup |
| Multivariate | Multivariate quadratic equations | UOV, MAYO, QR-UOV | Signatures only; small sig sizes but large public keys |
| Isogeny-based | Isogeny problem on elliptic curves | SQIsign, SQIsign2D | SIDH/SIKE broken 2022; SQIsign uses different assumption (CSIDH/SQI) |

Note: The original NIST Round 3 multivariate finalist Rainbow was broken in 2022. SIKE (isogeny-based KEM) was broken in July 2022 via a classical polynomial-time attack by Castryck-Decru. These do not affect the surviving algorithms above.

### 4.3 Hybrid Deployment Strategy

A hybrid scheme runs a classical and a PQC algorithm in parallel. Security holds as long as at least one component is unbroken — this is prudent during the transition period when PQC implementations are accumulating operational experience.

**KEM / key establishment hybrid construction:**
1. Run classical KEM (e.g., X25519): obtain shared secret `ss_classical`
2. Run PQC KEM (e.g., ML-KEM-768): obtain shared secret `ss_pqc`
3. Combine: derive session key as `KDF(ss_classical ∥ ss_pqc, context)` — both secrets feed a single KDF

The TLS 1.3 hybrid `X25519MLKEM768` (draft-ietf-tls-hybrid-design) uses this construction. Chrome and Firefox have enabled it by default.

**Digital signature hybrid construction:**
1. Generate and distribute two independent public keys (one classical, one PQC)
2. Produce two independent signatures per message
3. Verify both signatures; accept only if both are valid

> ℹ **When to deploy hybrids:** Deploy ML-KEM hybrid immediately for key establishment (HNDL risk). Maintain classical algorithm for backward compatibility. Remove classical algorithm only after PQC has become operationally validated and interoperability permits.

### 4.4 Pre-shared Key (PSK) quantum Mitigation

For organisations that cannot yet deploy PQC but need to protect long-lived confidential communications, a pre-shared symmetric key can be mixed into the key derivation alongside the public-key-derived secret. An attacker who later breaks the public-key exchange with a quantum computer still cannot recover the session key without the PSK.

Construction (following ZRTP §10, WireGuard `preshared-key`):
```
session_key = KDF(ss_public_key, "session key", psk, handshake_context)
```
After each session, update the retained secret:
```
psk_new = KDF(session_key, "retained secret")
```

**Limitations:**
- Requires secure out-of-band PSK provisioning (e.g., physical meeting, QR code exchange)
- Does not scale to open public-key infrastructure
- Not applicable to virtual machines restored from snapshots (PSK may be copied)
- Recommended only for systems with a small, known set of communication partners

### 4.5 Why QKD is not a Substitute for PQC

Quantum Key Distribution (QKD) distributes symmetric keys using quantum-physics principles (BB84, E91). An eavesdropper cannot copy quantum states without disturbing them, making interception detectable. However:

- QKD provides key agreement only — it does not provide authentication or message confidentiality
- It requires a classical **authenticated** side-channel, which itself depends on public-key cryptography or pre-shared keys
- It requires specialised hardware (optical links, single-photon detectors) and cannot run over the standard Internet
- It is not scalable to open PKI, TLS, or HTTPS deployments

ENISA's position (2021, endorsed by BSI and NIST): **PQC is the primary migration path.** QKD may complement PQC in specific high-value, point-to-point scenarios (e.g., inter-datacenter links) but does not substitute for it.

### 4.6 Migration Timeline (BSI TR-02102-1 v2026-01)

> **Source:** BSI TR-02102-1 v2026-01 (January 23, 2026), §2.1 "Use of Quantum-Safe Mechanisms".

The BSI defines explicit end-dates for the sole use of classical asymmetric mechanisms:

| Mechanism class | Sole use recommended until | Hybrid required from | Notes |
|:---|:---|:---|:---|
| Classical key agreement (RSA, DH, ECDH) | End of **2031** | **2032** onward | Hybrid with quantum-safe KEM (ML-KEM, HQC, FrodoKEM, or Classic McEliece) required |
| Classical key agreement (high protection) | End of **2030** | **2031** onward | Joint BSI/EU recommendation for very high protection requirements |
| Classical signatures (RSA, ECDSA, EdDSA) | End of **2035** | **2036** onward | EU roadmap deadline; hybrid or standalone PQC signature required |
| DSA signatures | End of **2029** | — | Discontinued due to low prevalence |

**BSI-recommended quantum-safe KEMs** (hybrid use only):

| Algorithm | BSI section | Parameters | Notes |
|:---|:---|:---|:---|
| ML-KEM | §2.4.3 | ML-KEM-768 (Category 3), ML-KEM-1024 (Category 5) | NIST FIPS 203; ML-KEM-512 not recommended by BSI |
| HQC | §2.4.4 | HQC-128, HQC-192, HQC-256 | Code-based; NIST Round 4 selected |
| FrodoKEM | §2.4.1 | FrodoKEM-976, FrodoKEM-1344 | Conservative LWE (unstructured); not NIST-standardised |
| Classic McEliece | §2.4.2 | mceliece6688128, mceliece8192128 | Code-based; ISO standardisation pending; very large public keys |

**BSI-recommended hybridisation mechanisms** (TR-02102-1 §2.2):

| Mechanism | Description |
|:---|:---|
| CatKDF (with KMAC or HKDF) | Concatenation KDF per NIST SP 800-56C; recommended combination method |
| KeyCombine (SP 800-56C §4.6.1 Eq. 9 + §4.6.2 Eq. 15) | NIST key combination with KDF or KMAC |

**BSI minimum security level:** 120 bits (TR-02102-1 §1.2). All recommended mechanisms achieve at least this level. AES-128 maps to 128 bits; EC curves must be ≥250 bits; RSA/DH moduli must be ≥3000 bits.

---

## 5. PKI Key Management (SP 800-57 Part 3 Rev 1 §2)

> **Source:** NIST SP 800-57 Part 3 Rev 1, January 2015. Note: this predates NIST PQC standardisation (2024) and current BSI guidance (2026). Algorithm-specific parameters should be cross-referenced with `cryptographic-algorithm-status.md` §13 (security strength equivalence) and SP 800-131A for current approval status.

### 5.1 CA and OCSP Responder Signing

> **Authorities:** IETF RFC 5280 (X.509 profile) — does not normatively specify algorithm preferences; CA/Browser Forum Baseline Requirements §6.1.5 (the de-facto authority for publicly-trusted CAs); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01 §3.5/§3.6. The IETF column shows CA/Browser Forum BR status since RFC 5280 itself does not constrain algorithm choice.

| Public key algorithm / key size | Hash | Padding | CABF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| RSA-2048 | SHA-256 | PKCS#1 v1.5 or PSS | ✓ Permitted | ✓ Approved | 🔜 Transitional | CABF BR §6.1.5 minimum 2048 for RSA; BSI requires ≥3000 bits for new CA keys (until 2030 for legacy) |
| RSA-3072 | SHA-256 | PKCS#1 v1.5 or PSS | ✓ Permitted | ✅ Recommended | ✅ Recommended | Meets BSI ≥3000-bit requirement |
| ECDSA P-256 | SHA-256 | — | ✓ Permitted | ✓ Approved | ✓ Approved | CABF BR §6.1.5 permits NIST P-256/P-384 |
| ECDSA P-384 | SHA-384 | — | ✓ Permitted | ✅ Recommended | ✅ Recommended | Meets BSI ≥250-bit curve requirement |

### 5.2 End-Entity Key Recommendations

| Authentication key | Signature key | Key establishment key | Symmetric cipher |
|:---|:---|:---|:---|
| RSA-2048 | RSA-2048 | RSA-2048 or DH-2048 | AES-128 |
| ECDSA P-256 | ECDSA P-256 | ECDH P-256 | AES-128 |
| ECDSA P-256 | ECDSA P-384 | ECDH P-384 | AES-256 |
| ECDSA P-384 | ECDSA P-384 | ECDH P-384 | AES-256 |

- Components supporting P-384 and SHA-384 **shall** support AES-256.
- Legacy RSA components **should** support 3-key 3DES (deprecated).
- Key-usage extension in X.509v3 certificates **shall** restrict keys to a single cryptographic function (signatures OR key establishment, not both).
- CA signing key security strength **shall** be ≥ subject public key strength for signature certificates.

---

## 6. S/MIME (SP 800-57 Part 3 Rev 1 §5)

> **Source:** NIST SP 800-57 Part 3 Rev 1, January 2015.

### 6.1 Cipher Suites

**Cipher Suite 1 (mandatory for federal systems):**

| Mechanism | Algorithm |
|:---|:---|
| Digital signatures | DSA ≥ 2048 bits |
| Hash | SHA-256 |
| Key agreement | DH ≥ 2048 bits |
| Encryption | AES-128-CBC |

**Suite B Level 1 (128-bit security):**

| Mechanism | Algorithm |
|:---|:---|
| Digital signatures | ECDSA P-256 |
| Hash | SHA-256 |
| Key agreement | ECDH P-256 |
| Key wrap | AES-128 (RFC 3394) |
| Encryption | AES-128-CBC |

**Suite B Level 2 (192-bit security):**

| Mechanism | Algorithm |
|:---|:---|
| Digital signatures | ECDSA P-384 |
| Hash | SHA-384 |
| Key agreement | ECDH P-384 |
| Key wrap | AES-256 (RFC 3394) |
| Encryption | AES-256-CBC |

### 6.2 Restrictions

- SHA-1 **shall not** be used for digital signature generation (verification of legacy signatures permitted).
- RC2 **may** be supported only for receiving (decrypting) legacy messages.
- Federal systems **shall** support Cipher Suite 1; procurements **should** support Suite B.

---

## 7. Kerberos (SP 800-57 Part 3 Rev 1 §6)

> **Source:** NIST SP 800-57 Part 3 Rev 1, January 2015.

> **Authorities:** IETF RFC 6649 (deprecate DES, RC4-HMAC-EXP), RFC 8429 (deprecate 3DES, RC4-HMAC), RFC 8009 (AES-SHA2 for Kerberos 5); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01.

| Mechanism | Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|
| Encryption | aes128-cts-hmac-sha1-96 | ✓ MAY (RFC 3962) | ✓ Approved | ✓ Approved | RFC 3962; SHA-1 used in MAC, not signature — still acceptable |
| Encryption | aes256-cts-hmac-sha1-96 | ✓ MAY (RFC 3962) | ✓ Approved | ✓ Approved | RFC 3962 |
| Encryption | aes128-cts-hmac-sha256-128 | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | RFC 8009; modern Kerberos default |
| Encryption | aes256-cts-hmac-sha384-192 | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | RFC 8009; preferred for new deployments |
| Encryption | DES (all variants) | ❌ SHOULD NOT (RFC 6649) | 🚫 Disallowed | 🚫 Disallowed | RFC 6649; **shall not** be used |
| Encryption | RC4-HMAC | ❌ SHOULD NOT (RFC 8429) | 🚫 Disallowed | 🚫 Disallowed | RFC 8429; replaced by AES |
| Encryption | 3DES (des3-cbc-sha1-kd) | ❌ SHOULD NOT (RFC 8429) | 🚫 Disallowed | 🚫 Disallowed | RFC 8429; SP 800-131A Rev 2 disallowed since 2024 |
| Integrity (MAC) | HMAC-SHA-1 | ✓ MAY (RFC 3962) | ✓ Approved | ⚠ Conditional | NIST permits HMAC-SHA-1 at 112-bit security through 2030; BSI cautious |
| Integrity (MAC) | HMAC-SHA-256-128 | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | Used in aes128-cts-hmac-sha256-128 |
| Integrity (MAC) | HMAC-SHA-384-192 | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | Used in aes256-cts-hmac-sha384-192 |
| Key exchange (PKINIT) | DH ≥ 2048 bits | ✓ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional | ≥ 112-bit security; acceptable through 2030 |
| Key exchange (PKINIT) | DH ≥ 3072 bits | ✓ MAY (RFC 4556) | ✓ Approved | ✓ Approved | Meets BSI ≥3000-bit requirement |
| Key transport (PKINIT) | RSA ≥ 2048 bits | ✓ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional | RFC 4556 |
| Password RNG | SP 800-90A DRBG | — | ✅ Recommended | ✅ Recommended | For random password generation |

---

## 8. DNSSEC (SP 800-57 Part 3 Rev 1 §8)

> **Source:** NIST SP 800-57 Part 3 Rev 1, January 2015.

### 8.1 Zone Data Signing Algorithms

> **Authorities:** IETF RFC 8624 §3.1 (DNSSEC algorithm requirements); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01.

| Suite | Authentication | Hash | IETF (signing) | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|:---|
| RSASHA256 | RSA | SHA-256 | ✅ MUST | ✓ Approved | ✓ Approved | RFC 8624 §3.1; mandatory for new signing |
| RSASHA512 | RSA | SHA-512 | ❌ NOT RECOMMENDED | ✓ Approved | ✓ Approved | RFC 8624 §3.1: validation MUST, but signing NOT RECOMMENDED |
| ECDSAP256SHA256 | ECDSA P-256 | SHA-256 | ✅ MUST | ✓ Approved | ✅ Recommended | RFC 8624 §3.1; recommended default for new zones |
| ECDSAP384SHA384 | ECDSA P-384 | SHA-384 | ◯ MAY | ✅ Recommended | ✅ Recommended | RFC 8624 §3.1: signing MAY, validation RECOMMENDED |
| ED25519 | EdDSA Curve25519 | — | ✓ RECOMMENDED | ✓ Approved | ✅ Recommended | RFC 8080; expected future default per RFC 8624 §3.1 |
| ED448 | EdDSA Curve448 | — | ◯ MAY | ✓ Approved | ✓ Approved | RFC 8624 §3.1: signing MAY, validation RECOMMENDED |
| RSASHA1 / RSASHA1-NSEC3-SHA1 | RSA | SHA-1 | ❌ NOT RECOMMENDED | 🚫 Disallowed | 🚫 Disallowed | RFC 8624 §3.1: validation MUST (legacy), signing NOT RECOMMENDED |
| RSAMD5 | RSA | MD5 | 🚫 MUST NOT | 🚫 Disallowed | 🚫 Disallowed | RFC 8624 §3.1 |
| DSA / DSA-NSEC3-SHA1 | DSA | SHA-1 | 🚫 MUST NOT | 🚫 Disallowed | 🚫 Disallowed | RFC 8624 §3.1 |

### 8.2 TSIG Message Authentication

> **Authorities:** IETF RFC 8945 (TSIG, replaces RFC 2845); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01. RFC 8624 does not address TSIG algorithms.

| Suite | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| HMAC-SHA-1 | ✅ MUST (RFC 8945) | ✓ Approved | ⚠ Conditional | RFC 8945 §6 mandatory for interop; HMAC-SHA-1 still acceptable through 2030 |
| HMAC-SHA-224 | ◯ MAY (RFC 8945) | ✓ Approved | ✓ Approved | |
| HMAC-SHA-256 | ✅ MUST (RFC 8945) | ✅ Recommended | ✅ Recommended | RFC 8945 §6 mandatory |
| HMAC-SHA-384 | ◯ MAY (RFC 8945) | ✓ Approved | ✅ Recommended | |
| HMAC-SHA-512 | ◯ MAY (RFC 8945) | ✓ Approved | ✅ Recommended | |
| GSS-TSIG | ◯ MAY (RFC 3645) | ✓ Approved | ✓ Approved | Generic Security Service algorithm |
| HMAC-MD5 | ◯ MAY (RFC 8945) | 🚫 Disallowed | 🚫 Disallowed | RFC 8945 retains for backward compat; **shall not** be used per NIST/BSI |

### 8.3 Key Management

- RSA-2048 keys strongly recommended; 1024-bit RSA ZSKs were allowed only until October 2015.
- KSK (Key Signing Key) **shall** follow SP 800-57 Part 1 key size guidance.
- Migration to ECDSA recommended for smaller key/signature sizes (solves DNS UDP packet size constraints).
- NSEC3 uses SHA-1 for hashing; transition to SHA-256 recommended.

---

*Last updated: 2026-04-06 (split from cryptographic-algorithm-status.md §14–§21; sections renumbered §1–§8). Consult current BSI TR-02102, NSA CNSA advisory, and NIST SP 800-57 Part 3 for any post-publication amendments.*
