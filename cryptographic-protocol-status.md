# Cryptographic Protocol Guidance

> [!WARNING]  
> The content in this repository is aggregated with artificial intelligence (Claude and partially Gemini).
> There is absolutely no claim on completeness and correctness. All usages are at your own risk.

> Protocol-specific and domain-specific deployment status information for cryptographic algorithms.
> Covers SSH, IPsec/IKEv2, CNSA 2.0 migration, quantum threat context, PKI, S/MIME,
> Kerberos, and DNSSEC.
>
> For algorithm-level security status (approved/deprecated/disallowed/broken), see
> [cryptographic-algorithm-status.md](cryptographic-algorithm-status.md).
>
> **Primary sources:** BSI TR-02102-2 v2026-01 (TLS) · BSI TR-02102-3 v2026-01 (IPsec) ·
> BSI TR-02102-4 v2026-01 (SSH) · NIST SP 800-52 Rev 2 (Aug 2019, TLS) · NSA CNSA 2.0 (PP-22-1338, Sep 2022) ·
> ENISA "Post-Quantum Cryptography" v2 (May 2021) · NIST SP 800-57 Part 3 Rev 1 (Jan 2015) ·
> NIST IR 8547 IPD (Nov 2024)
>
> For per-cipher-suite TLS recommendations from NIST and BSI side-by-side, see
> [cryptographic-tls-cipher-suites.md §12 / §13 / §14](cryptographic-tls-cipher-suites.md#12-bsi-tr-02102-2-v2026-01-tls-recommendations).

---

## 1. SSH (BSI TR-02102-4 v2026-01)

Recommendations for SSH protocol usage. Source: BSI TR-02102-4, Version 2026-01 (2026-01-27). SSH-2 is the only acceptable version; SSH-1 is 🚫 Disallowed.

### 1.1 Key Exchange

> **Authorities:** IETF RFC 9142 (Oct 2021); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01.
>
> **Source of truth:** [`cr-ssh.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ssh.yaml) — every entry, including non-recommended legacy/disallowed algorithms, is encoded in the registry and surfaced via the auto-generated table below.

<!-- AUTOGEN:BEGIN ssh-kex -->
| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `curve25519-sha256` | ✓ SHOULD (RFC 9142 §3.1.1) | ✓ Approved | ✅ Recommended | constant-time scalar multiplication; ECDH/Curve25519 + SHA-256 |
| `curve25519-sha256@libssh.org` | (OpenSSH alias predating RFC 8731) | ✓ Approved | ✅ Recommended | alias for curve25519-sha256 |
| `ecdh-sha2-nistp256` | ✓ SHOULD (RFC 9142 §3.1.3) | ✓ Approved | ✓ Approved |  |
| `ecdh-sha2-nistp384` | ✓ SHOULD (RFC 9142 §3.1.3) | ✓ Approved | ✓ Approved |  |
| `ecdh-sha2-nistp521` | ✓ SHOULD (RFC 9142 §3.1.3) | ✓ Approved | ✓ Approved |  |
| `diffie-hellman-group14-sha256` | ✅ MUST (RFC 9142 §3.2.2) | 🔜 Transitional | 🔜 Transitional (use up to 2030) | 2048-bit MODP; 112-bit security |
| `diffie-hellman-group15-sha512` | ◯ MAY (RFC 9142 §3.2.2) | ✓ Approved | — | 3072-bit MODP; not in BSI table |
| `diffie-hellman-group16-sha512` | ✓ SHOULD (RFC 9142 §3.2.2) | ✓ Approved | ✓ Approved | 4096-bit MODP |
| `diffie-hellman-group17-sha512` | ◯ MAY (RFC 9142 §3.2.2) | ✓ Approved | — | 6144-bit MODP; not in BSI table |
| `diffie-hellman-group18-sha512` | ◯ MAY (RFC 9142 §3.2.2) | ✓ Approved | ✓ Approved | 8192-bit MODP |
| `diffie-hellman-group-exchange-sha256` | ◯ MAY (RFC 9142 §3.2.1) | ✓ Approved | — | client-chosen group (RFC 4419) |
| `diffie-hellman-group14-sha1` | ◯ MAY (RFC 9142 §3.4) | 🚫 Disallowed | 🚫 Disallowed | RFC 9142 §3.4 retains MAY despite SHA-1 — NIST/BSI disallow |
| `diffie-hellman-group1-sha1` | ❌ SHOULD NOT (RFC 9142 §3.4) | 🚫 Disallowed | 🚫 Disallowed | 1024-bit MODP + SHA-1 |
| `diffie-hellman-group-exchange-sha1` | ❌ SHOULD NOT (RFC 9142 §3.2.1) | 🚫 Disallowed | 🚫 Disallowed | SHA-1 |
<!-- AUTOGEN:END ssh-kex -->

### 1.2 Host Authentication

> **Authorities:** IETF RFC 8332 (RSA-SHA2), RFC 8709 (Ed25519/Ed448), RFC 5656 (ECDSA), RFC 4253 (legacy); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01.
>
> **Source of truth:** [`cr-ssh.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ssh.yaml).

<!-- AUTOGEN:BEGIN ssh-host-auth -->
| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `ssh-ed25519` | ◯ MAY (RFC 8709) | ✓ Approved | ✅ Recommended | constant-time signing; EdDSA over Curve25519 |
| `ssh-ed448` | ◯ MAY (RFC 8709) | ✓ Approved | — | EdDSA over Curve448; not listed in BSI table |
| `ecdsa-sha2-nistp256` | ◯ MAY (RFC 5656) | ✓ Approved | ✓ Approved |  |
| `ecdsa-sha2-nistp384` | ◯ MAY (RFC 5656) | ✓ Approved | ✓ Approved |  |
| `ecdsa-sha2-nistp521` | ◯ MAY (RFC 5656) | ✓ Approved | ✓ Approved |  |
| `rsa-sha2-256` | ✓ SHOULD (RFC 8332 §3.3) | ✓ Approved | ✓ Approved | RSA ≥ 3072 bits recommended; ≥ 2048 transitional through 2030 |
| `rsa-sha2-512` | ✓ SHOULD (RFC 8332 §3.3) | ✓ Approved | ✓ Approved | RSA ≥ 3072 bits recommended |
| `ssh-rsa` | ❌ SHOULD NOT (RFC 8332 §3.3) | 🚫 Disallowed | 🚫 Disallowed | RSA with SHA-1; OpenSSH disabled by default since 8.8 |
| `ssh-dss` | ❌ SHOULD NOT (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | DSA-1024 with SHA-1 |
<!-- AUTOGEN:END ssh-host-auth -->

### 1.3 Symmetric Encryption

> **Authorities:** IETF RFC 4253 (original SSH-2 ciphers), RFC 4344 (CTR modes), RFC 5647 (AES-GCM in SSH), RFC 8758 (arcfour deprecation); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01.
>
> **Source of truth:** [`cr-ssh.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ssh.yaml).

<!-- AUTOGEN:BEGIN ssh-symmetric-encryption -->
| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `chacha20-poly1305@openssh.com` | (OpenSSH extension — not in any IETF SSH RFC) | ✓ Approved | ✅ Recommended | AEAD; preferred over CBC+MAC and CTR+MAC; OpenSSH-specific (no IETF SSH RFC counterpart) |
| `aes256-gcm@openssh.com` | ◯ MAY (RFC 5647) | ✓ Approved | ✅ Recommended | AEAD; preferred over CBC+MAC and CTR+MAC |
| `aes128-gcm@openssh.com` | ◯ MAY (RFC 5647) | ✓ Approved | ✅ Recommended | AEAD; preferred over CBC+MAC and CTR+MAC |
| `aes256-ctr` | ✓ SHOULD (RFC 4344 §4) | ✓ Approved | ⚠ Conditional — requires encrypt-then-MAC (HMAC-ETM) | no AEAD |
| `aes192-ctr` | ✓ SHOULD (RFC 4344 §4) | ✓ Approved | ⚠ Conditional — requires encrypt-then-MAC (HMAC-ETM) | no AEAD |
| `aes128-ctr` | ✓ SHOULD (RFC 4344 §4) | ✓ Approved | ⚠ Conditional — requires encrypt-then-MAC (HMAC-ETM) | no AEAD |
| `aes256-cbc` | ◯ MAY (RFC 4253) | ⚠ Conditional | ❌ Deprecated | CBC padding-oracle risk; prefer AES-GCM (AEAD) or AES-CTR + HMAC-ETM |
| `3des-cbc` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | 64-bit block; birthday-bound vulnerable above 32 GB; disallowed for encryption since 2024 (SP 800-131A Rev 2) |
| `arcfour` | 🚫 MUST NOT (RFC 8758) | 🚫 Disallowed | 🚫 Disallowed | RC4; cryptographically broken; explicitly removed by RFC 8758 |
| `arcfour128` | 🚫 MUST NOT (RFC 8758) | 🚫 Disallowed | 🚫 Disallowed | RC4; cryptographically broken; explicitly removed by RFC 8758 |
| `arcfour256` | 🚫 MUST NOT (RFC 8758) | 🚫 Disallowed | 🚫 Disallowed | RC4; cryptographically broken; explicitly removed by RFC 8758 |
<!-- AUTOGEN:END ssh-symmetric-encryption -->

### 1.4 MAC (for CTR-mode ciphers; not needed with AEAD)

> **Authorities:** IETF RFC 4253 (original SSH-2 MACs), RFC 6668 (HMAC-SHA2 in SSH); NIST SP 800-131A Rev 2; BSI TR-02102-4 v2026-01. Note: ETM (encrypt-then-MAC) variants are OpenSSH extensions and not in any IETF SSH RFC.
>
> **Source of truth:** [`cr-ssh.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ssh.yaml).

<!-- AUTOGEN:BEGIN ssh-mac -->
| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `hmac-sha2-256-etm@openssh.com` | (OpenSSH extension — not in any IETF SSH RFC) | ✓ Approved | ✅ Recommended | encrypt-then-MAC; preferred construction; OpenSSH-specific (no IETF SSH RFC counterpart) |
| `hmac-sha2-512-etm@openssh.com` | (OpenSSH extension — not in any IETF SSH RFC) | ✓ Approved | ✅ Recommended | encrypt-then-MAC; preferred construction; OpenSSH-specific (no IETF SSH RFC counterpart) |
| `umac-128-etm@openssh.com` | (OpenSSH extension — not in any IETF SSH RFC) | ⚠ Conditional | ✓ Approved | UMAC-128 (RFC 4418); OpenSSH-specific |
| `hmac-sha2-256` | ✓ SHOULD (RFC 6668) | ✓ Approved | ⚠ Conditional — requires CTR-mode cipher | MAC-then-Encrypt construction |
| `hmac-sha2-512` | ✓ SHOULD (RFC 6668) | ✓ Approved | ⚠ Conditional — requires CTR-mode cipher | MAC-then-Encrypt construction |
| `hmac-sha1` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | SHA-1; was REQUIRED in RFC 4253 |
| `hmac-sha1-96` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | SHA-1; truncated to 96 bits |
| `hmac-md5` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | MD5; collision-vulnerable |
| `hmac-md5-96` | ◯ MAY (RFC 4253) | 🚫 Disallowed | 🚫 Disallowed | MD5; truncated to 96 bits |
<!-- AUTOGEN:END ssh-mac -->

---

## 2. IPsec / IKEv2 (BSI TR-02102-3 v2026-01)

Recommendations for IPsec with IKEv2. Source: BSI TR-02102-3, Version 2026-01 (2026-01-27). IKEv1 is 🚫 Disallowed; IKEv2 (RFC 7296) only.

### 2.1 IKEv2 Key Exchange (Diffie-Hellman groups)

> **Authorities:** IETF RFC 8247 §2.4 (IKEv2 algorithms); NIST SP 800-131A Rev 2 + SP 800-186; BSI TR-02102-3 v2026-01.
>
> **Source of truth:** [`cr-ipsec.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ipsec.yaml).

<!-- AUTOGEN:BEGIN ipsec-dh-groups -->
| Group | Description | IETF | NIST | BSI |
|:---|:---|:---|:---|:---|
| `ipsec-dh:group14` | 2048-bit MODP; 112-bit security | ✅ MUST (RFC 8247 §2.4) | 🔜 Transitional | 🔜 Transitional (use up to 2030) |
| `ipsec-dh:group15` | 3072-bit MODP; 128-bit security | — | ✓ Approved | ✓ Approved |
| `ipsec-dh:group16` | 4096-bit MODP | — | ✓ Approved | ✓ Approved |
| `ipsec-dh:group17` | 6144-bit MODP | — | ✓ Approved | ✓ Approved |
| `ipsec-dh:group18` | 8192-bit MODP | — | ✓ Approved | ✓ Approved |
| `ipsec-dh:group19` | P-256 (secp256r1); 128-bit security | ✓ SHOULD (RFC 8247 §2.4) | ✓ Approved | ✓ Approved |
| `ipsec-dh:group20` | P-384 (secp384r1); 192-bit security | — | ✓ Approved | ✓ Approved |
| `ipsec-dh:group21` | P-521 (secp521r1); 256-bit security | — | ✓ Approved | ✓ Approved |
| `ipsec-dh:group31` | Curve25519; 128-bit security | (RFC 8031) | ✓ Approved | ✅ Recommended |
| `ipsec-dh:group32` | Curve448; 224-bit security | (RFC 8031) | ✓ Approved | ✅ Recommended |
| `ipsec-dh:group25` | P-192 ECP; below 128-bit security | — | 🚫 Disallowed | ❌ Deprecated |
| `ipsec-dh:group26` | P-224 ECP; 112-bit security | — | 🔜 Transitional | 🔜 Transitional (use up to 2030) |
| `ipsec-dh:group5` | 1536-bit MODP; below 112-bit security | ❌ SHOULD NOT (RFC 8247 §2.4) | 🚫 Disallowed | 🚫 Disallowed |
| `ipsec-dh:group2` | 1024-bit MODP; 80-bit security | ❌ SHOULD NOT (RFC 8247 §2.4) | 🚫 Disallowed | 🚫 Disallowed |
| `ipsec-dh:group1` | 768-bit MODP; below 80-bit security | 🚫 MUST NOT (RFC 8247 §2.4) | 🚫 Disallowed | 🚫 Disallowed |
| `ipsec-dh:group22` | 1024-bit MODP with subgroup; suspect parameters | 🚫 MUST NOT (RFC 8247 §2.4) | 🚫 Disallowed | 🚫 Disallowed |
| `ipsec-dh:group23` | 2048-bit MODP with 224-bit subgroup; suspect parameters | ❌ SHOULD NOT (RFC 8247 §2.4) | 🚫 Disallowed | 🚫 Disallowed |
| `ipsec-dh:group24` | 2048-bit MODP with 256-bit subgroup; suspect parameters | ❌ SHOULD NOT (RFC 8247 §2.4) | 🚫 Disallowed | 🚫 Disallowed |
<!-- AUTOGEN:END ipsec-dh-groups -->

### 2.2 IKEv2 Encryption (ESP and IKE SA)

> **Authorities:** IETF RFC 8221 (ESP/AH data plane), RFC 8247 (IKEv2 control plane); NIST SP 800-131A Rev 2; BSI TR-02102-3 v2026-01. ESP and IKEv2 have slightly different requirement levels — table shows ESP (RFC 8221) status; IKEv2 differences noted.
>
> **Source of truth:** [`cr-ipsec.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ipsec.yaml). The auto-generated rows list specific transform IDs (e.g. `ipsec-esp:aes-128-gcm`); the umbrella patterns shown in the hand-curated supplement aggregate per family.

<!-- AUTOGEN:BEGIN ipsec-esp-encryption -->
| Transform | IETF (ESP / IKEv2) | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `ipsec-esp:aes-128-gcm` | ESP: ✅ MUST (RFC 8221 §5)<br>IKEv2: ✓ SHOULD (RFC 8247 §2.1) | ✓ Approved | ✅ Recommended | AEAD; RFC 4106 (ESP), RFC 5282 (IKE) |
| `ipsec-esp:aes-256-gcm` | ESP: ✅ MUST (RFC 8221 §5)<br>IKEv2: ✓ SHOULD (RFC 8247 §2.1) | ✓ Approved | ✅ Recommended | AEAD; RFC 4106 (ESP), RFC 5282 (IKE) |
| `ipsec-esp:aes-128-ccm` | ESP: ✓ SHOULD (RFC 8221 §5)<br>IKEv2: ✓ SHOULD (RFC 8247 §2.1; SHOULD only for IoT) | ✓ Approved | ✓ Approved | AEAD; RFC 4309 |
| `ipsec-esp:chacha20-poly1305` | ESP: ✓ SHOULD (RFC 8221 §5; RFC 7634)<br>IKEv2: ✓ SHOULD (RFC 8247 §2.1) | ✓ Approved | ✓ Approved | AEAD; RFC 7634 |
| `ipsec-esp:aes-128-cbc` | ESP: ✅ MUST (RFC 8221 §5)<br>IKEv2: ✅ MUST (RFC 8247 §2.1) | ⚠ Conditional | ⚠ Conditional — requires separate integrity transform (HMAC-SHA-2 or AES-XCBC-MAC) | no AEAD; RFC 4106 (ESP) and RFC 5282 (IKE) define AEAD alternatives |
| `ipsec-esp:aes-256-cbc` | ESP: ✅ MUST (RFC 8221 §5)<br>IKEv2: ✅ MUST (RFC 8247 §2.1) | ⚠ Conditional | ⚠ Conditional — requires separate integrity transform (HMAC-SHA-2 or AES-XCBC-MAC) | no AEAD; RFC 4106 (ESP) and RFC 5282 (IKE) define AEAD alternatives |
| `ipsec-esp:3des-cbc` | ESP: ❌ SHOULD NOT (RFC 8221 §5)<br>IKEv2: ◯ MAY (RFC 8247 §2.1) | 🚫 Disallowed | 🚫 Disallowed | 64-bit block; birthday-bound vulnerable above 32 GB |
| `ipsec-esp:aes-128-ctr` | ◯ MAY (RFC 8221 §5) | ✓ Approved | ⚠ Conditional — requires separate integrity transform | no AEAD |
| `ipsec-esp:aes-192-ctr` | ◯ MAY (RFC 8221 §5) | ✓ Approved | ⚠ Conditional — requires separate integrity transform | no AEAD |
| `ipsec-esp:aes-256-ctr` | ◯ MAY (RFC 8221 §5) | ✓ Approved | ⚠ Conditional — requires separate integrity transform | no AEAD |
| `ipsec-esp:des-cbc` | 🚫 MUST NOT (RFC 8221 §5) | 🚫 Disallowed | 🚫 Disallowed | 56-bit key; brute-forceable |
<!-- AUTOGEN:END ipsec-esp-encryption -->

### 2.3 IKEv2 Integrity / PRF

> **Authorities:** IETF RFC 8221 §6 (ESP/AH integrity), RFC 8247 §2.2–§2.3 (IKEv2 PRF and integrity); NIST SP 800-131A Rev 2; BSI TR-02102-3 v2026-01.
>
> **Source of truth:** [`cr-ipsec.yaml`](ae-pattern-validator/src/main/resources/registry/cr-ipsec.yaml).

<!-- AUTOGEN:BEGIN ipsec-integrity -->
| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `ipsec-auth:hmac-sha2-256-128` | ESP: ✅ MUST (RFC 8221 §6; RFC 4868)<br>IKEv2: ✅ MUST (RFC 8247 §2.2; PRF_HMAC_SHA2_256 is also MUST as IKEv2 PRF) | ✓ Approved | ✅ Recommended | truncated to 128 bits per RFC 4868 |
| `ipsec-auth:hmac-sha2-384-192` | (RFC 4868) | ✓ Approved | ✅ Recommended | truncated to 192 bits per RFC 4868 |
| `ipsec-auth:hmac-sha2-512-256` | ESP: ✓ SHOULD (RFC 8221 §6; RFC 4868)<br>IKEv2: ✓ SHOULD (RFC 8247 §2.2; SHOULD+ as IKEv2 PRF) | ✓ Approved | ✅ Recommended | truncated to 256 bits per RFC 4868 |
| `ipsec-auth:aes-xcbc-96` | ✓ SHOULD (RFC 8221 §6; RFC 3566) | ⚠ Conditional | ✓ Approved | RFC 3566; SHOULD for IoT, MAY for general VPN; 96-bit truncation |
| `ipsec-auth:hmac-sha1-96` | ⚠ MUST- (RFC 8221 §6) | 🚫 Disallowed | 🚫 Disallowed | downgraded from MUST to MUST-; SHA-1 collision-vulnerable |
| `ipsec-auth:aes-cmac-96` | (RFC 4494) | ✓ Approved | ✓ Approved | RFC 4494; not addressed in RFC 8221 / RFC 8247 |
| `ipsec-auth:hmac-md5-96` | 🚫 MUST NOT (RFC 8221 §6) | 🚫 Disallowed | 🚫 Disallowed | MD5 collision attacks; truncated to 96 bits |
<!-- AUTOGEN:END ipsec-integrity -->

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

### 4.7 NIST IR 8547 PQC Transition Timeline

> **Source:** NIST IR 8547 IPD (Initial Public Draft), November 2024, "Transition to Post-Quantum Cryptography Standards". This is an Initial Public Draft; Timelines may be adjusted in the final Version.

NIST IR 8547 defines federal Deadlines for migrating away from classical asymmetric Cryptography. NSM-10 (National Security Memorandum 10) establishes **2035** as the primary Target for completing the PQC Transition across US federal Systems.

| Algorithm class | 112-bit Security | ≥128-bit Security |
|:---|:---|:---|
| Digital Signatures (ECDSA, EdDSA, RSA) | deprecated after 2030 | disallowed after 2035 |
| Key Establishment (DH, ECDH, RSA) | deprecated after 2030 | disallowed after 2035 |
| Symmetric (AES-128+) | unchanged | Category 1+ quantum Security |

**Key Points:**

- **Key Establishment migrates first.** Because of the harvest-now-decrypt-later Threat, key establishment Mechanisms should transition to PQC sooner than Signatures — encrypted Data captured today can be decrypted retroactively once a cryptographically relevant quantum Computer is available.
- **Hybrid Schemes are explicitly supported.** IR 8547 permits hybrid key Establishment combining a classical and a PQC Component. The classical Component in a hybrid Scheme is **not** disallowed after 2035; only sole use of classical Algorithms is subject to the Deadline.
- **NSM-10 Target.** National Security Memorandum 10 (January 2022) establishes 2035 as the primary federal Target for PQC Transition Completion.
- **IPD Status.** This is an Initial Public Draft. Final Timelines may be adjusted based on public Comment and the evolving quantum Threat Landscape.

---

## 5. PKI Key Management (SP 800-57 Part 3 Rev 1 §2)

> **Source:** NIST SP 800-57 Part 3 Rev 1, January 2015. Note: this predates NIST PQC standardisation (2024) and current BSI guidance (2026). Algorithm-specific parameters should be cross-referenced with `cryptographic-algorithm-status.md` §14 (Security Strength Equivalence) and SP 800-131A for current approval status.

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
>
> **Authorities:** IETF RFC 6649 (deprecate DES, RC4-HMAC-EXP), RFC 8429 (deprecate 3DES, RC4-HMAC), RFC 8009 (AES-SHA2 for Kerberos 5); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01.
>
> **Source of truth:** [`cr-kerberos.yaml`](ae-pattern-validator/src/main/resources/registry/cr-kerberos.yaml).

<!-- AUTOGEN:BEGIN kerberos -->
| Mechanism | Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|
| Encryption | `krb:aes128-cts-hmac-sha1-96` | ◯ MAY (RFC 3962) | ✓ Approved | ✓ Approved | AES-128-CBC + HMAC-SHA-1 truncated to 96 bits; RFC 3962; SHA-1 used in MAC, not signature — still acceptable |
| Encryption | `krb:aes256-cts-hmac-sha1-96` | ◯ MAY (RFC 3962) | ✓ Approved | ✓ Approved | AES-256-CBC + HMAC-SHA-1 truncated to 96 bits; RFC 3962 |
| Encryption | `krb:aes128-cts-hmac-sha256-128` | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | AES-128-CBC + HMAC-SHA-256 truncated to 128 bits; RFC 8009 |
| Encryption | `krb:aes256-cts-hmac-sha384-192` | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | AES-256-CBC + HMAC-SHA-384 truncated to 192 bits; RFC 8009 |
| Encryption | `krb:des-cbc-md5` | ❌ SHOULD NOT (RFC 6649) | 🚫 Disallowed | 🚫 Disallowed | DES-CBC + MD5 (legacy); RFC 6649 deprecates DES variants; **shall not** be used |
| Encryption | `krb:rc4-hmac` | ❌ SHOULD NOT (RFC 8429) | 🚫 Disallowed | 🚫 Disallowed | RC4 + HMAC-MD5; RFC 8429 |
| Encryption | `krb:rc4-hmac-exp` | ❌ SHOULD NOT (RFC 6649) | 🚫 Disallowed | 🚫 Disallowed | RC4 + HMAC-MD5 (40-bit export-grade); RFC 6649 deprecates |
| Encryption | `krb:des3-cbc-sha1-kd` | ❌ SHOULD NOT (RFC 8429) | 🚫 Disallowed | 🚫 Disallowed | 3DES-CBC + HMAC-SHA-1 with key derivation; RFC 8429 |
| Integrity (MAC) | `krb:hmac-sha1` | ◯ MAY (RFC 3962) | ✓ Approved | ⚠ Conditional | HMAC-SHA-1 (truncated to 96 bits in Kerberos contexts); NIST permits HMAC-SHA-1 at 112-bit security through 2030; BSI cautious |
| Integrity (MAC) | `krb:hmac-sha256-128` | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | HMAC-SHA-256 truncated to 128 bits |
| Integrity (MAC) | `krb:hmac-sha384-192` | ✓ SHOULD (RFC 8009) | ✅ Recommended | ✅ Recommended | HMAC-SHA-384 truncated to 192 bits |
| Key exchange (PKINIT) | `krb:pkinit-dh-2048` | ◯ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional (use up to 2030) | PKINIT Diffie-Hellman ≥ 2048 bits; RFC 4556 PKINIT pre-authentication |
| Key exchange (PKINIT) | `krb:pkinit-dh-3072` | ◯ MAY (RFC 4556) | ✓ Approved | ✓ Approved | PKINIT Diffie-Hellman ≥ 3072 bits; meets BSI ≥3000-bit requirement |
| Key exchange (PKINIT) | `krb:pkinit-rsa-2048` | ◯ MAY (RFC 4556) | 🔜 Transitional | 🔜 Transitional (use up to 2030) | PKINIT RSA key transport ≥ 2048 bits; RFC 4556 PKINIT pre-authentication |
<!-- AUTOGEN:END kerberos -->

> **Password RNG:** SP 800-90A DRBG — recommended for random password generation (algorithm-level guidance lives in `cryptographic-algorithm-status.md` §10).

---

## 8. DNSSEC (SP 800-57 Part 3 Rev 1 §8)

> **Source:** NIST SP 800-57 Part 3 Rev 1, January 2015.

### 8.1 Zone Data Signing Algorithms

> **Authorities:** IETF RFC 8624 §3.1 (DNSSEC algorithm requirements); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01.
>
> **Source of truth:** [`cr-dnssec.yaml`](ae-pattern-validator/src/main/resources/registry/cr-dnssec.yaml).

<!-- AUTOGEN:BEGIN dnssec-zone-signing -->
| Algorithm | Description | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|:---|
| `dnssec:RSASHA256` | RSA + SHA-256 | ✅ MUST (RFC 8624 §3.1) | ✓ Approved | ✓ Approved | RFC 8624 §3.1; mandatory for new signing |
| `dnssec:RSASHA512` | RSA + SHA-512 | ❌ SHOULD NOT (RFC 8624 §3.1) | ✓ Approved | ✓ Approved | RFC 8624 §3.1: validation MUST, but signing NOT RECOMMENDED |
| `dnssec:ECDSAP256SHA256` | ECDSA P-256 + SHA-256 | ✅ MUST (RFC 8624 §3.1) | ✓ Approved | ✅ Recommended | recommended default for new zones |
| `dnssec:ECDSAP384SHA384` | ECDSA P-384 + SHA-384 | ◯ MAY (RFC 8624 §3.1) | ✅ Recommended | ✅ Recommended | RFC 8624 §3.1: signing MAY, validation RECOMMENDED |
| `dnssec:ED25519` | EdDSA Curve25519 | ✓ SHOULD (RFC 8624 §3.1; RFC 8080) | ✓ Approved | ✅ Recommended | expected future default per RFC 8624 §3.1 |
| `dnssec:ED448` | EdDSA Curve448 | ◯ MAY (RFC 8624 §3.1; RFC 8080) | ✓ Approved | ✓ Approved | RFC 8624 §3.1: signing MAY, validation RECOMMENDED |
| `dnssec:RSASHA1` | RSA + SHA-1 (legacy) | ❌ SHOULD NOT (RFC 8624 §3.1) | 🚫 Disallowed | 🚫 Disallowed | RFC 8624 §3.1: validation MUST (legacy), signing NOT RECOMMENDED |
| `dnssec:RSASHA1-NSEC3-SHA1` | RSA + SHA-1 with NSEC3 hash (legacy) | ❌ SHOULD NOT (RFC 8624 §3.1) | 🚫 Disallowed | 🚫 Disallowed | NSEC3 (RFC 5155) variant of RSASHA1 |
| `dnssec:RSAMD5` | RSA + MD5 | 🚫 MUST NOT (RFC 8624 §3.1) | 🚫 Disallowed | 🚫 Disallowed | RFC 8624 §3.1 |
| `dnssec:DSA` | DSA + SHA-1 | 🚫 MUST NOT (RFC 8624 §3.1) | 🚫 Disallowed | 🚫 Disallowed | RFC 8624 §3.1 |
| `dnssec:DSA-NSEC3-SHA1` | DSA + SHA-1 with NSEC3 hash | 🚫 MUST NOT (RFC 8624 §3.1) | 🚫 Disallowed | 🚫 Disallowed | NSEC3 variant of DSA |
<!-- AUTOGEN:END dnssec-zone-signing -->

### 8.2 TSIG Message Authentication

> **Authorities:** IETF RFC 8945 (TSIG, replaces RFC 2845); NIST SP 800-57 Part 3 + SP 800-131A Rev 2; BSI TR-02102-1 v2026-01. RFC 8624 does not address TSIG algorithms.
>
> **Source of truth:** [`cr-dnssec.yaml`](ae-pattern-validator/src/main/resources/registry/cr-dnssec.yaml).

<!-- AUTOGEN:BEGIN dnssec-tsig -->
| Algorithm | IETF | NIST | BSI | Notes |
|:---|:---|:---|:---|:---|
| `dnssec-tsig:hmac-sha1` | ✅ MUST (RFC 8945 §6) | ✓ Approved | ⚠ Conditional | mandatory for interop; HMAC-SHA-1 still acceptable through 2030 |
| `dnssec-tsig:hmac-sha224` | ◯ MAY (RFC 8945 §6) | ✓ Approved | ✓ Approved |  |
| `dnssec-tsig:hmac-sha256` | ✅ MUST (RFC 8945 §6) | ✅ Recommended | ✅ Recommended | RFC 8945 §6 mandatory |
| `dnssec-tsig:hmac-sha384` | ◯ MAY (RFC 8945 §6) | ✓ Approved | ✅ Recommended |  |
| `dnssec-tsig:hmac-sha512` | ◯ MAY (RFC 8945 §6) | ✓ Approved | ✅ Recommended |  |
| `dnssec-tsig:gss-tsig` | ◯ MAY (RFC 3645) | ✓ Approved | ✓ Approved |  |
| `dnssec-tsig:hmac-md5` | ◯ MAY (RFC 8945 §6) | 🚫 Disallowed | 🚫 Disallowed | RFC 8945 retains for backward compat; **shall not** be used per NIST/BSI |
<!-- AUTOGEN:END dnssec-tsig -->

### 8.3 Key Management

- RSA-2048 keys strongly recommended; 1024-bit RSA ZSKs were allowed only until October 2015.
- KSK (Key Signing Key) **shall** follow SP 800-57 Part 1 key size guidance.
- Migration to ECDSA recommended for smaller key/signature sizes (solves DNS UDP packet size constraints).
- NSEC3 uses SHA-1 for hashing; transition to SHA-256 recommended.

---

## 9. SPDM (DMTF DSP0274 v1.3.0)

> **Source:** DMTF DSP0274, *Security Protocol and Data Model (SPDM) Specification*, v1.3.0 (2023-06-28; supersedes 1.2.1). Machine-readable registry: [`cr-spdm.yaml`](ae-pattern-validator/src/main/resources/registry/cr-spdm.yaml) (generated). SPDM is DMTF's hardware attestation/authentication protocol (PCIe/CXL/USB device identity, firmware measurement, secure sessions). It negotiates one algorithm per class in the NEGOTIATE_ALGORITHMS/ALGORITHMS exchange (§10.4). Unlike IETF protocols, SPDM does not rank algorithms — all listed values are optional/negotiable; the NIST column reflects the underlying algorithm's posture. SPDM reuses the TCG Algorithm Registry `TPM_ALG_*` identifiers for its asymmetric and hash algorithms.

### 9.1 Negotiable Algorithm Registries (§10.4)

| Class (SPDM field) | Algorithms | NIST posture |
|:---|:---|:---|
| Asymmetric signature (`BaseAsymAlgo` / `ReqBaseAsymAlg`) | RSASSA-PKCS1 & RSASSA-PSS at 2048/3072/4096; ECDSA P-256/384/521; SM2; Ed25519; Ed448 | PKCS#1 v1.5 ❌ deprecated (FIPS 186-5 removed for new signing); PSS / ECDSA / EdDSA ✅ approved; SM2 — not in NIST FIPS |
| Base hash (`BaseHashAlgo`, also `MeasurementHashAlgo`) | SHA-256/384/512, SHA3-256/384/512, SM3-256 | SHA-2 / SHA-3 ✅ approved; SM3 — not in NIST FIPS |
| DHE named group (`DHE`) | ffdhe2048/3072/4096; secp256r1/384r1/521r1; SM2_P256 | FFDHE (≥3072 preferred) / ECDHE P-256/384/521 ✅ approved; SM2_P256 — not in NIST FIPS |
| AEAD (`AEAD`) | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305, SM4-GCM | AES-GCM ✅ approved; ChaCha20-Poly1305 (RFC 8439, not FIPS); SM4-GCM — not in NIST FIPS |
| Key schedule (`KeySchedule`) | SPDM Key Schedule (HKDF-based, §12) | HKDF ✅ approved (SP 800-56C Rev 2) |

### 9.2 SPDM Certificate OIDs (§10.8.2)

Base arc `id-DMTF-spdm` = `1.3.6.1.4.1.412.274`.

| OID | Name | Purpose |
|:---|:---|:---|
| `1.3.6.1.4.1.412.274.1` | `id-DMTF-device-info` | `otherName` carrying manufacturer / product / serial number |
| `1.3.6.1.4.1.412.274.2` | `id-DMTF-hardware-identity` | Marks the hardware-identity certificate in a chain |
| `1.3.6.1.4.1.412.274.3` | SPDM Responder Authentication | Extended Key Usage: leaf usable for Responder authentication |
| `1.3.6.1.4.1.412.274.4` | SPDM Requester Authentication | Extended Key Usage: leaf usable for Requester authentication |
| `1.3.6.1.4.1.412.274.5` | `id-DMTF-mutable-certificate` | Marks a mutable certificate |
| `1.3.6.1.4.1.412.274.6` | `id-DMTF-spdm-extension` | Non-critical container for SPDM OIDs (RFC 5280 extension) |

---

*Last updated: 2026-04-06 (split from cryptographic-algorithm-status.md §14–§21; sections renumbered §1–§8; §9 SPDM added 2026-07-03). Consult current BSI TR-02102, NSA CNSA advisory, and NIST SP 800-57 Part 3 for any post-publication amendments.*
