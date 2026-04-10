# Validator Test Report

Test statistics for the `ae-pattern-validator` module (Java 17, JUnit 6.1.0-M1,
Spring Boot 4.1.0-M4). Generated from the test suite against the YAML validation
registry (9 files, 338 registered algorithm families, 178 unique OIDs indexed).

Build: `cd ae-pattern-validator && mvn clean verify`

---

## Test Summary

| Test class | Tests | Scope |
|------------|------:|-------|
| `InstanceValidationSymmetricTest` | 87 | All 77 symmetric families (incl. 2TDEA, RC4-HMAC-EXP) |
| `InstanceValidationHashMacTest` | 57 | All 40 hash + 10 MAC families (incl. HMAC-MD5, GMAC) |
| `InstanceValidationAsymmetricTest` | 44 | All 37 asymmetric families (incl. DLIES, MLS, SRTP) |
| `InstanceValidationPqcTest` | 51 | All 40 PQC families (incl. ALTEQ) |
| `InstanceValidationKdfTest` | 25 | All 25 KDF families (incl. CatKDF, KeyCombine) |
| `InstanceValidationRngTest` | 31 | All 25 RNG families (incl. OS entropy APIs) |
| `TemplateValidationTest` | 33 | Templates, constraints, normalisation, choice groups, fixed identifiers, equivalentPattern |
| `CycloneDxRegistryCoverageTest` | 213 | Full CycloneDX cryptography-defs.json coverage (as of 2026-02-24) + all 33 cdx families + alternative pattern variants |
| `SpdxCoverageTest` | 169 | Full SPDX cryptographic-algorithm-list coverage (127 identifiers) |
| `CertificateAnalyserTest` | 5 | X.509 certificate analysis (RSA-2048, EC-P256) |
| `CmsAnalyserTest` | 7 | CMS/PKCS#7 SignedData + EnvelopedData analysis |
| `CBomAnalyserTest` | 8 | CycloneDX CBOM validation (6 components, compliance check) |
| `CBomGeneratorTest` | 4 | CBOM JSON generation from cert/CMS analysis |
| `MainTest` | 26 | CLI integration (all modes incl. cert, cms, cbom, table/verbose) |
| `AlgorithmRegistryTest` | 15 | Registry loading, duplicate detection, OID index, cross-validation, coverage |
| **Total** | **775** | |

---

## Registry Statistics

| Registry file | Families | With segments | Fixed identifiers | Wildcard |
|---------------|:--------:|:-------------:|:-----------------:|:--------:|
| `cr-symmetric-ciphers.yaml` | 77 | 28 | 10 | 39 |
| `cr-hash-functions.yaml` | 49 | 20 | 28 | 1 |
| `cr-macs.yaml` | 14 | 8 | 6 | 0 |
| `cr-asymmetric.yaml` | 37 | 27 | 4 | 6 |
| `cr-pqc.yaml` | 40 | 20 | 5 | 15 |
| `cr-kdfs.yaml` | 25 | 21 | 1 | 3 |
| `cr-rngs.yaml` | 25 | 8 | 15 | 2 |
| `cr-cdx.yaml` | 33 | 3 | 30 | 0 |
| `cr-spdx.yaml` | 38 | 0 | 38 | 0 |
| **Total** | **338** | **143** | **137** | **58** |

### Family validation modes

| Mode | Count | Behaviour |
|------|:-----:|-----------|
| Parameters defined | 143 | Parameters validated against controlled vocabulary + constraints |
| Fixed identifiers (`parameters: []`) | 124 | Trailing parameters rejected (`EXTRA_SEGMENT`) |
| Wildcard (no `parameters` field) | 57 | Any trailing parameters accepted |

### Status Distribution

Family-level `status:` (security posture of the algorithm — canonical families only):

| Status | Count | Examples |
|--------|:-----:|---------|
| Approved (implicit default) | 219 | AES, ML-KEM, SHA, ECDH, ChaCha20 |
| Deprecated | 8 | DSA, MD6, Blowfish, IDEA, CAST5, RC5, Yarrow, RC4-PRNG |
| Disallowed | 18 | 3DES, 3DES-TKW, Skipjack, RC2, RC4, RC4-HMAC, 2TDEA, PBKDF1, Dual_EC_DRBG, ANSIX931, A5/1, MT19937, PCG, LCG, SplitMix64, ISAAC, Xoshiro, Xoroshiro |
| Broken | 8 | DES, MD5, MD4, MD2, FEAL, CMEA, PANAMA, A5/2 |

In addition, `cdx:` and `spdx:` naming-alternative entries carry `patternStatus: deprecated` (pattern canonicity — separate from security posture).

---

## SPDX Coverage (159 tests)

Tests validating all 127 algorithm identifiers from the SPDX cryptographic algorithm
list (https://github.com/spdx/cryptographic-algorithm-list). All identifiers are fully
matched — zero unmatched. Split into two test sets.

| Test set | Count | What is validated |
|----------|:-----:|-------------------|
| `directMatches` | 124 | SPDX identifiers matched to a family: canonical (89), via alias (8), via `spdx:` deprecated family (27) |
| `compoundMatches` | 35 | SPDX identifiers matched via compound patterns (SHA-256, SNOW-3G, ChaCha20-Poly1305, etc.) |

### SPDX Resolution Breakdown

| Mechanism | Count | Examples |
|-----------|:-----:|---------|
| Direct canonical match | 89 | AES, MD5, ECDH, PBKDF2, Fortuna |
| Alias on canonical family | 8 | rijndael → AES, desede/tdes → 3DES, sms4 → SM4, chacha → ChaCha20, diffiehellman/dhe → FFDH, kazumi → KASUMI |
| Deprecated `spdx:` family | 24 | spdx:shs, spdx:rsa, spdx:keccak, spdx:cast, spdx:gost, spdx:md160, spdx:tnepres, spdx:pkcs12 |
| New `spdx:` family (no canonical) | 4 | spdx:dcc, spdx:ubi, spdx:uffizi, spdx:uxn |
| Compound pattern match | 35 | SHA-256, SNOW-3G, GOSTR3410, ChaCha20-Poly1305 |

---

## Appendix A: All Instance Patterns Tested (276)

Concrete algorithm strings validated in `INSTANCE` mode, organized by taxonomy.

### Symmetric Ciphers (91 patterns)

| Pattern | Family |
|---------|--------|
| `128-EEA1` | `128-EEA1` |
| `128-EEA3` | `128-EEA3` |
| `128-EIA1` | `128-EIA1` |
| `128-EIA3` | `128-EIA3` |
| `2TDEA` | `2TDEA` |
| `3DES` | `3DES` |
| `3DES-TKW` | `3DES-TKW` |
| `3GPP-XOR` | `3GPP-XOR` |
| `3Way` | `3Way` |
| `AES-128-CBC` | `AES` |
| `AES-128-GCM` | `AES` |
| `AES-256-ECB` | `AES` |
| `AES-256-GCM` | `AES` |
| `AES-256-GCM-SIV` | `AES` |
| `AES-999-GCM` | `AES` |
| `AES-FF1-10` | `AES-FF1` |
| `AES-FF3-1-10` | `AES-FF3-1` |
| `AES-KW-128` | `AES-KW` |
| `AES-KWP-128` | `AES-KWP` |
| `AES-Wrap-256` | `AES-KW` |
| `ARIA-128` | `ARIA` |
| `Adiantum` | `Adiantum` |
| `Ascon-AEAD128` | `Ascon-AEAD128` |
| `Blowfish` | `Blowfish` |
| `Blowfish-128` | `Blowfish` |
| `Blowfish-448-CBC` | `Blowfish` |
| `CAMELLIA-128` | `Camellia` |
| `CAST5` | `CAST5` |
| `CAST6-128` | `CAST6` |
| `CMEA` | `CMEA` |
| `ChaCha20` | `ChaCha20` |
| `ChaCha20-Poly1305` | `ChaCha20` |
| `Cobra` | `Cobra` |
| `DES` | `DES` |
| `DES-ECB` | `DES` |
| `FCrypt` | `FCrypt` |
| `FEAL` | `FEAL` |
| `GEA-4` | `GEA` |
| `GOST-28147` | `GOST-28147` |
| `Grain-128` | `Grain-128` |
| `Grasshopper` | `Grasshopper` |
| `HC-128` | `HC` |
| `HC-256` | `HC` |
| `ICE` | `ICE` |
| `IDEA` | `IDEA` |
| `Juniper` | `Juniper` |
| `KASUMI` | `KASUMI` |
| `Khazad` | `Khazad` |
| `LOKI91` | `LOKI91` |
| `Lucifer` | `Lucifer` |
| `MILENAGE` | `MILENAGE` |
| `MISTY1` | `MISTY1` |
| `MULTI2` | `MULTI2` |
| `NOEKEON` | `NOEKEON` |
| `Nimbus` | `Nimbus` |
| `PANAMA` | `PANAMA` |
| `QUAD` | `QUAD` |
| `RABBIT` | `Rabbit` |
| `RC2` | `RC2` |
| `RC2-40` | `RC2` |
| `RC4` | `RC4` |
| `RC4-HMAC` | `RC4-HMAC` |
| `RC4-HMAC-EXP` | `RC4-HMAC` |
| `RC5` | `RC5` |
| `RC6-128` | `RC6` |
| `Rabbit` | `Rabbit` |
| `SEAL` | `SEAL` |
| `SEED-128-CBC` | `SEED` |
| `SHACAL-1` | `SHACAL` |
| `SHARK` | `SHARK` |
| `SM4` | `SM4` |
| `SNOW-3G` | `SNOW-3G` |
| `SNOW-V` | `SNOW-V` |
| `SOBER` | `SOBER` |
| `SOSEMANUK` | `SOSEMANUK` |
| `Salsa20` | `Salsa20` |
| `Sapphire` | `Sapphire` |
| `Serpent-128` | `Serpent` |
| `Skipjack` | `Skipjack` |
| `TCrypt` | `TCrypt` |
| `TEA` | `TEA` |
| `TUAK` | `TUAK` |
| `Threefish-256` | `Threefish` |
| `Twofish-128` | `Twofish` |
| `VMPC` | `VMPC` |
| `WAKE` | `WAKE` |
| `XChaCha20-Poly1305` | `XChaCha20` |
| `XTEA` | `XTEA` |
| `ZUC` | `ZUC` |
| `ZipCrypt` | `ZipCrypt` |
| `f8` | `f8` |

### Hash Functions and Checksums (35 patterns)

| Pattern | Family |
|---------|--------|
| `Adler-32` | `Adler` |
| `Ascon-CXOF128` | `Ascon-CXOF128` |
| `Ascon-Hash256` | `Ascon-Hash256` |
| `Ascon-XOF128` | `Ascon-XOF128` |
| `BLAKE2b-256-HMAC` | `BLAKE2b` |
| `BLAKE2s-256-HMAC` | `BLAKE2s` |
| `BLAKE3-256` | `BLAKE3` |
| `CRC-32` | `CRC` |
| `FNV1-32` | `FNV1` |
| `FastHash` | `FastHash` |
| `Fletcher-32` | `Fletcher` |
| `GOSTR3411` | `GOSTR3411` |
| `GOSTR3411-2012-256` | `GOSTR3411-2012` |
| `HAVAL-3-256` | `HAVAL` |
| `MD2` | `MD2` |
| `MD4` | `MD4` |
| `MD5` | `MD5` |
| `MD5-extra` | `MD5` |
| `MD6-256` | `MD6` |
| `MDC-2` | `MDC-2` |
| `RIPEMD-160` | `RIPEMD` |
| `SHA-1` | `SHA` |
| `SHA-224` | `SHA` |
| `SHA3-224` | `SHA3` |
| `SHA3-256` | `SHA3` |
| `SHAKE128-256` | `SHAKE128` |
| `SHAKE256-256` | `SHAKE256` |
| `SM3` | `SM3` |
| `SNERFU` | `SNERFU` |
| `SipHash-128` | `SipHash` |
| `Skein-512` | `Skein` |
| `Tiger-192` | `Tiger` |
| `Whirlpool` | `Whirlpool` |
| `cSHAKE128-256` | `cSHAKE128` |
| `cSHAKE256-256` | `cSHAKE256` |

### Message Authentication Codes (12 patterns)

| Pattern | Family |
|---------|--------|
| `AES-CMAC-128` | `AES-CMAC` |
| `AES-CMAC-PRF-128` | `AES-CMAC` |
| `CBC-MAC` | `CBC-MAC` |
| `GMAC-128` | `GMAC` |
| `HMAC-SHA-224` | `HMAC` |
| `HMAC-MD5` | `HMAC` |
| `HMAC-SHA-256` | `HMAC` |
| `KMAC128-256` | `KMAC128` |
| `KMAC256-256` | `KMAC256` |
| `Poly1305` | `Poly1305` |
| `Poly1305-AES` | `Poly1305` |
| `UMAC-128` | `UMAC` |

### Asymmetric Cryptography (42 patterns)

| Pattern | Family |
|---------|--------|
| `BLS-BLS12-381` | `BLS` |
| `BlumGoldwasser` | `BlumGoldwasser` |
| `DLIES-2048-SHA-256` | `DLIES` |
| `DSA-2048-test` | `DSA` |
| `ECDH-Curve25519` | `ECDH` |
| `ECDH-P-256` | `ECDH` |
| `ECDSA-P-256-SHA-256` | `ECDSA` |
| `ECIES-test-test` | `ECIES` |
| `Ed25519` | `Ed25519` |
| `Ed25519-foo` | `Ed25519` |
| `Ed448` | `Ed448` |
| `EdDSA-Ed25519` | `EdDSA` |
| `ElGamal-2048` | `ElGamal` |
| `FFDH-ffdhe3072` | `FFDH` |
| `GOSTR3410` | `GOSTR3410` |
| `GOSTR3410-2012` | `GOSTR3410-2012` |
| `HPKE-test-test-test` | `HPKE` |
| `LMOTS-test` | `LMOTS` |
| `LMS-test` | `LMS` |
| `LUC-2048` | `LUC` |
| `MQV-test` | `MQV` |
| `McEliece` | `McEliece` |
| `MLS` | `MLS` |
| `NTRUEncrypt-test` | `NTRUEncrypt` |
| `OPAQUE-3DH` | `OPAQUE-3DH` |
| `RSA-OAEP-3072` | `RSAES-OAEP` |
| `RSA-PSS-2048` | `RSASSA-PSS` |
| `RSAES-OAEP-3072` | `RSAES-OAEP` |
| `RSAES-PKCS1-2048` | `RSAES-PKCS1` |
| `RSASSA-PKCS1-2048` | `RSASSA-PKCS1` |
| `RSASSA-PSS-3072` | `RSASSA-PSS` |
| `Rabin-2048` | `Rabin` |
| `SM2` | `SM2` |
| `SM9-SIG` | `SM9` |
| `SPAKE2` | `SPAKE2` |
| `SPAKE2+` | `SPAKE2+` |
| `SRP-6a-test` | `SRP` |
| `SRTP` | `SRTP` |
| `X25519` | `ECDH` |
| `XMSS-test` | `XMSS` |
| `XMSSMT-test` | `XMSSMT` |
| `XTR` | `XTR` |

### Post-Quantum Cryptography (44 patterns)

| Pattern | Family |
|---------|--------|
| `BIKE-L1` | `BIKE` |
| `CROSS` | `CROSS` |
| `ClassicMcEliece-348864` | `ClassicMcEliece` |
| `FAEST-128s` | `FAEST` |
| `FN-DSA-512` | `FN-DSA` |
| `FireSaber` | `FireSaber` |
| `FrodoKEM-640` | `FrodoKEM` |
| `GeMSS-128` | `GeMSS` |
| `HAWK-512` | `HAWK` |
| `HQC-128` | `HQC` |
| `HashML-DSA-44` | `HashML-DSA` |
| `HashSLH-DSA-SHA2-128s` | `HashSLH-DSA` |
| `HashSLH-DSA-SHAKE-128s` | `HashSLH-DSA` |
| `LESS` | `LESS` |
| `LightSaber` | `LightSaber` |
| `MAYO-1` | `MAYO` |
| `MAYO-3` | `MAYO` |
| `ML-DSA-44-hedged` | `ML-DSA` |
| `ML-DSA-65` | `ML-DSA` |
| `ML-DSA-65-hedged` | `ML-DSA` |
| `ML-KEM-768` | `ML-KEM` |
| `MLDSA44-RSA2048-PSS-SHA256` | `MLDSA44` |
| `MLDSA65-RSA3072-PSS-SHA512` | `MLDSA65` |
| `MLDSA87-ECDSA-P384-SHA512` | `MLDSA87` |
| `MQOM` | `MQOM` |
| `Mirath` | `Mirath` |
| `NTRU-HPS` | `NTRU-HPS` |
| `NTRU-HRSS` | `NTRU-HRSS` |
| `PERK` | `PERK` |
| `Picnic` | `Picnic` |
| `QR-UOV` | `QR-UOV` |
| `RYDE` | `RYDE` |
| `Rainbow` | `Rainbow` |
| `SDitH` | `SDitH` |
| `SIKE-p434` | `SIKE` |
| `SLH-DSA-SHA2-128s` | `SLH-DSA` |
| `SLH-DSA-SHAKE-128s` | `SLH-DSA` |
| `SNOVA` | `SNOVA` |
| `SQIsign` | `SQIsign` |
| `SQIsign2D` | `SQIsign2D` |
| `Saber` | `Saber` |
| `UOV` | `UOV` |
| `ntrulpr761` | `ntrulpr761` |
| `sntrup761` | `sntrup761` |

### Key Derivation and Password Hashing (25 patterns)

| Pattern | Family |
|---------|--------|
| `ANSI-KDF-X9.42-SHA-256` | `ANSI-KDF-X9.42` |
| `ANSI-KDF-X9.63-SHA-256` | `ANSI-KDF-X9.63` |
| `Argon2d` | `Argon2d` |
| `Argon2i` | `Argon2i` |
| `CatKDF-KMAC` | `CatKDF` |
| `Argon2id` | `Argon2id` |
| `HKDF-SHA-256` | `HKDF` |
| `IKEv2-PRF-SHA-256` | `IKEv2-PRF` |
| `KeyCombine` | `KeyCombine` |
| `MGF1-SHA-256` | `MGF1` |
| `MSCash` | `MSCash` |
| `MSCash2` | `MSCash2` |
| `PBE` | `PBE` |
| `PBES1-SHA-256-DES` | `PBES1` |
| `PBES2-PBKDF2-AES` | `PBES2` |
| `PBKDF1-SHA-256` | `PBKDF1` |
| `PBKDF2-SHA-256` | `PBKDF2` |
| `SP800-108-CounterKDF-HMAC` | `SP800-108` |
| `SP800-56C-OneStep-SHA-256` | `SP800-56C` |
| `SSH-KDF-SHA-256` | `SSH-KDF` |
| `TLS12-PRF-SHA-256` | `TLS12-PRF` |
| `TLS13-HKDF-SHA-256` | `TLS13-HKDF` |
| `bcrypt-12` | `bcrypt` |
| `scrypt-16384-8-1` | `scrypt` |
| `yescrypt` | `yescrypt` |

### Random Number Generators (23 patterns)

| Pattern | Family |
|---------|--------|
| `A5/1` | `A5/1` |
| `A5/1-something` | `A5/1` |
| `A5/2` | `A5/2` |
| `ANSIX931-AES` | `ANSIX931` |
| `BCryptGenRandom` | `BCryptGenRandom` |
| `CTR_DRBG-AES-256` | `CTR_DRBG` |
| `CTR_DRBG-AES-256-noDF` | `CTR_DRBG` |
| `Dual_EC_DRBG` | `Dual_EC_DRBG` |
| `Fortuna-AES` | `Fortuna` |
| `HMAC_DRBG-SHA-256` | `HMAC_DRBG` |
| `Hash_DRBG-SHA-512` | `Hash_DRBG` |
| `ISAAC` | `ISAAC` |
| `LCG` | `LCG` |
| `MT19937` | `MT19937` |
| `PCG` | `PCG` |
| `RC4-PRNG` | `RC4-PRNG` |
| `RDRAND` | `RDRAND` |
| `RDSEED` | `RDSEED` |
| `SplitMix64` | `SplitMix64` |
| `TPM_RNG` | `TPM_RNG` |
| `Xoroshiro` | `Xoroshiro` |
| `Xoshiro` | `Xoshiro` |
| `Yarrow-AES` | `Yarrow` |

### CycloneDX-Specific Families (4 patterns)

| Pattern | Family |
|---------|--------|
| `ECDHE-P-256` | `cdx:ECDHE` |
| `Ed25519ph` | `cdx:Ed25519ph` |
| `Ed448ctx` | `cdx:Ed448ctx` |
| `FFDHE-ffdhe4096` | `cdx:FFDHE` |

## Appendix B: All Template Patterns Tested (149)

Pattern templates validated in `TEMPLATE` mode, organized by taxonomy. Templates may
contain wildcards (`*`), enumerations (`[a\|b]`, `(a\|b)`), and variable placeholders
(`{x}`). Enumeration values are checked against the controlled vocabulary.

### Symmetric Ciphers (48 patterns)

| Pattern | Family |
|---------|--------|
| `128-EEA1` | `128-EEA1` |
| `128-EEA3` | `128-EEA3` |
| `128-EIA1` | `128-EIA1` |
| `128-EIA3` | `128-EIA3` |
| `3DES[-{keyLength}][-{mode}]` | `3DES` |
| `3GPP-XOR[-KDF]` | `3GPP-XOR` |
| `3GPP-XOR[-MAC]` | `3GPP-XOR` |
| `AES-(128\|192\|256)-(GCM\|CCM)` | `AES` |
| `AES-[128\|192\|256]-*` | `AES` |
| `AES[-(128\|192\|256)]-GCM-SIV[-{tagLength}][-{ivLength}]` | `AES` |
| `AES[-(128\|192\|256)]-OCB[-{tagLength}]` | `AES` |
| `AES[-(128\|192\|256)]-SIV` | `AES` |
| `AES[-(128\|192\|256)][-(ECB\|CBC\|CFB128\|OFB\|CTR\|XTS\|CTS)]` | `AES` |
| `AES[-(128\|192\|256)][-(GCM\|CCM)][-{tagLength}][-{ivLength}]` | `AES` |
| `AES[-(128\|192\|256)][-(GMAC\|CMAC)]` | `AES` |
| `AES[-(128\|192\|256)][-(KW\|KWP)]` | `AES` |
| `ARIA-(128\|192\|256)[-{mode}][-{padding}]` | `ARIA` |
| `Ascon-AEAD128` | `Ascon-AEAD128` |
| `Blowfish[-{keyLength}][-{mode}][-{padding}]` | `Blowfish` |
| `CAMELLIA-(128\|192\|256)[-{mode}][-{padding}]` | `Camellia` |
| `CAST5[-{keyLength}][-{mode}]` | `CAST5` |
| `CAST6[-{keyLength}][-{mode}]` | `CAST6` |
| `CMEA` | `CMEA` |
| `ChaCha20` | `ChaCha20` |
| `ChaCha20-Poly1305` | `ChaCha20` |
| `DES[-{keyLength}][-{mode}]` | `DES` |
| `HC-128` | `HC` |
| `HC-256` | `HC` |
| `IDEA[-{mode}]` | `IDEA` |
| `MILENAGE[-KDF]` | `MILENAGE` |
| `MILENAGE[-MAC]` | `MILENAGE` |
| `RABBIT` | `Rabbit` |
| `RC2[-{keyLength}][-{mode}]` | `RC2` |
| `RC4[-{keyLength}]` | `RC4` |
| `RC5[-{keyLength}][-{mode}]` | `RC5` |
| `RC6[-{keyLength}][-{mode}]` | `RC6` |
| `SEED-128-(CCM\|GCM)` | `SEED` |
| `SEED-128[-{mode}][-{padding}]` | `SEED` |
| `SM4-(GCM\|CCM)[-{tagLength}][-{ivLength}]` | `SM4` |
| `SM4[-(ECB\|CBC\|CFB\|OFB\|CTR\|XTS)][-{padding}][-{ivlen}]` | `SM4` |
| `Salsa20` | `Salsa20` |
| `Salsa20-Poly1305` | `Salsa20` |
| `Serpent-(128\|192\|256)[-{mode}][-{padding}]` | `Serpent` |
| `Skipjack[-{mode}][-{padding}]` | `Skipjack` |
| `TUAK[-KDF]` | `TUAK` |
| `TUAK[-MAC]` | `TUAK` |
| `Twofish-(128\|192\|256)[-{mode}][-{padding}]` | `Twofish` |
| `XChaCha20-Poly1305` | `XChaCha20` |

### Hash Functions and Checksums (18 patterns)

| Pattern | Family |
|---------|--------|
| `Ascon-CXOF128` | `Ascon-CXOF128` |
| `Ascon-Hash256` | `Ascon-Hash256` |
| `Ascon-XOF128` | `Ascon-XOF128` |
| `BLAKE2b-(160\|256\|384\|512)` | `BLAKE2b` |
| `BLAKE2b-(160\|256\|384\|512)-HMAC` | `BLAKE2b` |
| `BLAKE2s-(160\|256)` | `BLAKE2s` |
| `BLAKE2s-(160\|256)-HMAC` | `BLAKE2s` |
| `BLAKE3[-{outputLength}]` | `BLAKE3` |
| `GOSTR3411` | `GOSTR3411` |
| `MD2` | `MD2` |
| `MD4` | `MD4` |
| `MD5` | `MD5` |
| `RIPEMD-(128\|160\|256\|320)` | `RIPEMD` |
| `SHA-1` | `SHA` |
| `SHA3-(224\|256\|384\|512)` | `SHA3` |
| `SM3` | `SM3` |
| `SipHash[-{compressionRounds}-{finalizationRounds}]` | `SipHash` |
| `Whirlpool` | `Whirlpool` |

### Message Authentication Codes (4 patterns)

| Pattern | Family |
|---------|--------|
| `AES-CMAC-PRF-128` | `AES-CMAC` |
| `HMAC[-{hashAlgorithm}][-{tagLength}]` | `HMAC` |
| `Poly1305` | `Poly1305` |
| `UMAC[-(32\|64\|96\|128)]` | `UMAC` |

### Asymmetric Cryptography (15 patterns)

| Pattern | Family |
|---------|--------|
| `BLS[-{ellipticCurve}]` | `BLS` |
| `DSA[-{length}][-{hashAlgorithm}]` | `DSA` |
| `ECDSA[-{ellipticCurve}][-{hashAlgorithm}]` | `ECDSA` |
| `ElGamal[-{keyLength}]` | `ElGamal` |
| `GOSTR3410` | `GOSTR3410` |
| `OPAQUE-3DH[-{group}][-{hashAlgorithm}][-{ksf}][-{kdf}][-{mac}]` | `OPAQUE-3DH` |
| `SM2[-256]` | `SM2` |
| `SM9-(ENC\|ENCRYPTION\|PKE\|PUBLICKEY-ENCRYPTION\|PUBLIC-KEY-ENCRYPTION)` | `SM9` |
| `SM9-(KEM\|KEYENCAPSULATION\|KEY-ENCAPSULATION)` | `SM9` |
| `SM9-(KEX\|KEYEXCHANGE\|KEY-EXCHANGE\|KEYAGREE\|KEY-AGREE\|KEYAGREEMENT\|KEY-AGREEMENT)` | `SM9` |
| `SM9-(SIG\|SIGNATURE)` | `SM9` |
| `SPAKE2+[-{group}][-{hashAlgorithm}][-{kdf}][-{mac}]` | `SPAKE2+` |
| `SPAKE2[-{group}][-{hashAlgorithm}][-{kdf}][-{mac}]` | `SPAKE2` |
| `XMSS-(SHA2\|SHAKE)` | `XMSS` |
| `XMSSMT-(SHA2\|SHAKE)` | `XMSSMT` |

### Post-Quantum Cryptography (5 patterns)

| Pattern | Family |
|---------|--------|
| `HashML-DSA-(44\|65\|87)[-{hashAlgorithm}]` | `HashML-DSA` |
| `HashSLH-DSA-(SHA2\|SHAKE)-(128s\|128f\|192s\|192f\|256s\|256f)[-{hashAlgorithm}]` | `HashSLH-DSA` |
| `ML-DSA-(44\|65\|87)` | `ML-DSA` |
| `ML-KEM-(512\|768\|1024)` | `ML-KEM` |
| `SLH-DSA-(SHA2\|SHAKE)-(128s\|128f\|192s\|192f\|256s\|256f)` | `SLH-DSA` |

### Key Derivation and Password Hashing (12 patterns)

| Pattern | Family |
|---------|--------|
| `ANSI-KDF-X9.42[-{hashAlgorithm}]` | `ANSI-KDF-X9.42` |
| `ANSI-KDF-X9.63[-{hashAlgorithm}]` | `ANSI-KDF-X9.63` |
| `HKDF[-{hashAlgorithm}]` | `HKDF` |
| `PBES1[-{encryptionAlgorithm}][-{kdf}][-{dkLen}][-{iterations}]` | `PBES1` |
| `PBES2[-{encryptionAlgorithm}][-{kdf}][-{dkLen}][-{iterations}]` | `PBES2` |
| `PBKDF1[-{hashAlgorithm}][-{iterations}][-{dkLen}]` | `PBKDF1` |
| `PBKDF2[-{hashAlgorithm}][-{iterations}][-{dkLen}]` | `PBKDF2` |
| `SSH-KDF[-{hashAlgorithm}]` | `SSH-KDF` |
| `TLS12-PRF[-RFC7627][-{hashAlgorithm}]` | `TLS12-PRF` |
| `TLS13-PRF` | `TLS13-HKDF` |
| `bcrypt[-{cost}]` | `bcrypt` |
| `scrypt[-{N}][-{r}][-{p}][-{dkLen}]` | `scrypt` |

### Random Number Generators (7 patterns)

| Pattern | Family |
|---------|--------|
| `A5/1` | `A5/1` |
| `A5/2` | `A5/2` |
| `CTR_DRBG[-{cipherAlgorithm}][-{keyLength}]` | `CTR_DRBG` |
| `Fortuna[-{blockCipher}][-{hashAlgorithm}]` | `Fortuna` |
| `HMAC_DRBG[-{hashAlgorithm}]` | `HMAC_DRBG` |
| `Hash_DRBG[-{hashAlgorithm}]` | `Hash_DRBG` |
| `Yarrow[-{blockCipher}][-{hashAlgorithm}]` | `Yarrow` |

### CycloneDX-Specific Families (40 patterns)

| Pattern | Family |
|---------|--------|
| `CMAC` | `cdx:CMAC` |
| `CMAC[-{cipherAlgorithm}][-{length}]` | `cdx:CMAC` |
| `EC-ElGamal[-{ellipticCurve}]` | `cdx:EC-ElGamal` |
| `ECMQV[-{ellipticCurve}]` | `cdx:ECMQV` |
| `Ed` | `cdx:Ed` |
| `FFMQV[-{namedGroup}]` | `cdx:FFMQV` |
| `GOST38147[-{mode}][-{padding}]` | `cdx:GOST38147` |
| `GOST38147_MAC` | `cdx:GOST38147_MAC` |
| `GOSTR3411_HMAC` | `cdx:GOSTR3411_HMAC` |
| `IKE1_Extended_DERIVE` | `cdx:IKE1_Extended_DERIVE` |
| `IKE1_PRF_DERIVE` | `cdx:IKE1_PRF_DERIVE` |
| `IKE2_PRF_PLUS_DERIVE[-{hashAlgorithm}]` | `cdx:IKE2_PRF_PLUS_DERIVE` |
| `IKE_PRF_DERIVE[-{hashAlgorithm}]` | `cdx:IKE_PRF_DERIVE` |
| `J-PAKE[-{namedGroup}][-{kdf}][-{mac}]` | `cdx:J-PAKE` |
| `KMACXOF128` | `cdx:KMACXOF128` |
| `KMACXOF256` | `cdx:KMACXOF256` |
| `PBMAC1` | `cdx:PBMAC1` |
| `PBMAC1[-{macAlgorithm}][-{hashAlgorithm}][-{iterations}][-{dkLen}]` | `cdx:PBMAC1` |
| `ParallelHash128` | `cdx:ParallelHash128` |
| `ParallelHash256` | `cdx:ParallelHash256` |
| `ParallelHashXOF128` | `cdx:ParallelHashXOF128` |
| `ParallelHashXOF256` | `cdx:ParallelHashXOF256` |
| `SP800_108_CounterKDF` | `cdx:SP800_108_CounterKDF` |
| `SP800_108_DoublePipelineKDF` | `cdx:SP800_108_DoublePipelineKDF` |
| `SP800_108_FeedbackKDF` | `cdx:SP800_108_FeedbackKDF` |
| `SP800_108_KMAC` | `cdx:SP800_108_KMAC` |
| `SP800_56C_OneStep[-{auxFunction}][-{dkmLength}]` | `cdx:SP800_56C_OneStep` |
| `SP800_56C_TwoStep_CounterKDF` | `cdx:SP800_56C_TwoStep_CounterKDF` |
| `SP800_56C_TwoStep_DoublePipelineKDF` | `cdx:SP800_56C_TwoStep_DoublePipelineKDF` |
| `SP800_56C_TwoStep_FeedbackKDF` | `cdx:SP800_56C_TwoStep_FeedbackKDF` |
| `SRP-3[-{hashAlgorithm}][-{namedGroup}]` | `cdx:SRP-3` |
| `SRP-6[-{hashAlgorithm}][-{namedGroup}]` | `cdx:SRP-6` |
| `TLS1-PRF[-RFC7627]` | `cdx:TLS1-PRF` |
| `TupleHash128` | `cdx:TupleHash128` |
| `TupleHash256` | `cdx:TupleHash256` |
| `TupleHashXOF128` | `cdx:TupleHashXOF128` |
| `TupleHashXOF256` | `cdx:TupleHashXOF256` |
| `WOTSP-(SHA2\|SHAKE)` | `cdx:WOTSP` |
| `X3DH` | `cdx:X3DH` |
| `X3DH[-{hashAlgorithm}]` | `cdx:X3DH` |
