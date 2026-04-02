# Cryptographic Algorithm Parameter Taxonomy

> Extracted from the CycloneDX Cryptography Registry pattern notation (`cryptography-defs.json`, last updated 2026-02-24).
> Every `{placeholder}` appearing in any CycloneDX algorithm variant pattern is documented here.
> Cross-referenced with SPDX Cryptographic Algorithm List, NIST PQC Forum, and NIST standards.
>
> **Revision note (2026-03-28):** Section 9 added covering PQC-specific internal parameters
> identified via gap analysis against the NIST PQC Forum and FIPS 203/204/205/206 specifications.
> These parameters are fixed by the parameter set choice but are essential for implementation
> analysis, memory planning, and understanding active standardisation discussions.
> Affects: ML-DSA, ML-KEM, SLH-DSA, FN-DSA, and cross-cutting hybrid/protocol parameters.
>
> **Revision note (2026-03-31):** Section 9 updated with missing parameters cross-checked
> against the authoritative FIPS 203, 204, 205, and 206 documents: added `{q}` modulus values
> for ML-KEM, ML-DSA, and FN-DSA; added `{omega}` (ML-DSA hint bits); added `{beta}` (ML-DSA
> norm bound); added `{n}` and `{sigma}` for FN-DSA; added `{m}` and `{h_prime}` for SLH-DSA;
> completed the SLH-DSA parameter table to all 12 parameter sets; added key/signature/ciphertext
> size reference tables for all four PQC algorithm families.
>
> **Revision note (2026-04-02):** `{hashfun}/{nbits}/{treeHeight}` entry (§3) expanded from a
> minimal stub to full parameter tables covering all SP 800-208 LMS (20 sets), LMOTS (16 sets),
> HSS, XMSS (18 sets), and XMSS^MT parameter sets. Added security strengths, signing capacity
> guidance, LMOTS signature sizes, and the SP 800-208 §5.3 hardware module mandate.

## Pattern notation conventions

| Symbol | Meaning | Example |
|:---|:---|:---|
| `[]` | Optional parameter | `AES[-128]` |
| `(a\|b)` | Required choice between alternatives | `Ed(25519\|448)` |
| `{x}` | Variable placeholder | `HMAC[-{hashAlgorithm}]` |
| `[-{x}]` | Optional variable parameter | `RSA-PSS[-{saltLength}]` |

---

## 1. Size & length parameters

Parameters that specify numeric bit or byte quantities, directly determining security level and output size.

---


### `{keyLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Key size in bits |
| **Description** | Specifies the symmetric key size or asymmetric key modulus length. The dominant size parameter across all algorithm families. |
| **Type** | integer (bits) |
| **Canonical values** | `40` `56` `64` `80` `112` `128` `192` `256` `512` `1024` `2048` `3072` `4096` `7680` `8192` `15360` |
| **Implementation note** | For symmetric ciphers: 128/192/256 (AES, Camellia, SM4). For RSA: 1024 (broken), 2048 (minimum), 3072+ (recommended). For DH: 2048–8192. |
| **Used in** | AES, 3DES, DES, Blowfish, CAMELLIA, ARIA, SEED, RC2, RC4, RC5, RC6, CAST5, CAST6, IDEA, RSASSA-PKCS1, RSASSA-PSS, RSAES-PKCS1, RSAES-OAEP, DSA, ElGamal |

---


### `{saltLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | PSS salt length in bytes |
| **Description** | In RSA-PSS, the salt adds randomness to each signature. Longer salt = more security margin, but increases signature size. |
| **Type** | integer (bytes) |
| **Canonical values** | `0` `20` `28` `32` `48` `64` `hLen` `maxLen` |
| **Implementation note** | RFC 8017: recommended salt length = hLen (hash output length). NIST SP 800-131Ar2: minimum 32 bytes for SHA-256-based PSS. |
| **Used in** | RSASSA-PSS |

---


### `{dkLen}`

| Aspect | Detail |
|:---|:---|
| **Short** | Derived key length in bytes |
| **Description** | The desired length of the output keying material from a KDF. |
| **Type** | integer (bytes) |
| **Canonical values** | `16` `24` `32` `48` `64` `128` |
| **Implementation note** | Must match the consuming algorithm (e.g. dkLen=32 for AES-256). PBKDF2 supports arbitrary length via PRF chaining. |
| **Used in** | PBKDF1, PBKDF2, PBES1, PBES2 |

---


### `{tagLenBytes}`

| Aspect | Detail |
|:---|:---|
| **Short** | Output tag / hash length in bytes |
| **Description** | Output length of a hash, XOF, or variable-length MAC in bytes. Relevant where the underlying construction supports variable output (BLAKE3, SHAKE, KMAC). |
| **Type** | integer (bytes) |
| **Canonical values** | `16` `20` `28` `32` `48` `64` `128` |
| **Implementation note** | SHAKE128 provides 128-bit security for any output ≥32 bytes. BLAKE3 default 32 bytes. For MAC output truncation: minimum 128 bits recommended. |
| **Used in** | BLAKE3, SHAKE128, SHAKE256, KMAC128, KMAC256, cSHAKE128, cSHAKE256 |

---


### `{outputLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Variable output length (BLAKE3 / XOF) |
| **Description** | Requested output length in bytes for variable-output functions like BLAKE3 or SHAKE used standalone. |
| **Type** | integer (bytes) |
| **Canonical values** | `16` `32` `64` `128` |
| **Implementation note** | BLAKE3 default = 32 bytes (256 bits). SHAKE128 security = min(output_len/2, 128) bits. Longer outputs do not improve security beyond the capacity. |
| **Used in** | BLAKE3, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256 |

---


### `{dkmLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Derived keying material length |
| **Description** | Total length of output keying material from SP 800-108 or SP 800-56C KDF, before splitting into individual keys. |
| **Type** | integer (bits) |
| **Canonical values** | `128` `192` `256` `384` `512` |
| **Implementation note** | SP 800-108: DKM must not exceed 2^32 × h bits (h = PRF output). Typically ≤512 bits covers all practical split-key scenarios. |
| **Used in** | SP800-108, SP800-56C |

---


### `{length}`

| Aspect | Detail |
|:---|:---|
| **Short** | Generic output / truncation length |
| **Description** | A truncation length or output size used in contexts where the algorithm supports variable output (CMAC truncation, UMAC variants). |
| **Type** | integer (bits) |
| **Canonical values** | `32` `64` `96` `128` |
| **Implementation note** | UMAC (RFC 4418) variants: UMAC-32, UMAC-64, UMAC-96, UMAC-128. CMAC output can be truncated but minimum 64 bits recommended. |
| **Used in** | CMAC, UMAC |

---


### `{parameterSetIdentifier}`

| Aspect | Detail |
|:---|:---|
| **Short** | PQC security parameter set |
| **Description** | Selects one of the discrete NIST-defined security parameter sets for post-quantum algorithms. Each set targets a different NIST security level. |
| **Type** | enumeration |
| **Canonical values** | `44` `65` `87` `512` `768` `1024` `128s` `128f` `192s` `192f` `256s` `256f` `FN-DSA-512` `FN-DSA-1024` |
| **Implementation note** | ML-DSA: 44=L2 (k×l=4×4), 65=L3 (k×l=6×5), 87=L5 (k×l=8×7) — the numbers encode the matrix dimensions used in key generation. ML-KEM: 512=L1 (k=2), 768=L3 (k=3), 1024=L5 (k=4). SLH-DSA: `s` suffix = small signatures / slower signing; `f` suffix = fast signing / larger signatures — this distinction is the subject of ongoing NIST requests for additional parameter sets (NIST PQC Forum, 87-message thread, Nov 2025). FN-DSA: 512=L1 (n=512, pk=897B, sig=666B), 1024=L5 (n=1024, pk=1793B, sig=1280B). |
| **Used in** | ML-DSA, ML-KEM, SLH-DSA, FN-DSA |

---

## 2. Mode & variant parameters

Parameters that select among structural variants or sub-primitive choices for an algorithm family.

---


### `{mode}`

| Aspect | Detail |
|:---|:---|
| **Short** | Block cipher mode of operation |
| **Description** | Defines how a block cipher is applied to a message longer than one block. Mode choice determines confidentiality properties, parallelism, and whether authentication is provided. |
| **Type** | enumeration |
| **Canonical values** | `ECB` `CBC` `CFB1` `CFB8` `CFB64` `CFB128` `OFB` `CTR` `XTS` `CTS` `GCM` `CCM` `OCB` `GCM-SIV` `SIV` `CTR-HMAC-SHA1` |
| **Implementation note** | ECB leaks block patterns — never use for >1 block. XTS for disk encryption. GCM/CCM/OCB provide AEAD. SIV nonce-misuse resistant. |
| **Used in** | AES, 3DES, DES, Blowfish, Twofish, CAMELLIA, ARIA, SEED, SM4, RC2, RC5, RC6, CAST5, CAST6, IDEA, Serpent, GOST38147 |

---


### `{mode}` (HPKE)

| Aspect | Detail |
|:---|:---|
| **Short** | HPKE operational mode |
| **Description** | Selects the HPKE authentication mode. Controls whether the sender identity is authenticated and whether a PSK is used. |
| **Type** | enumeration |
| **Canonical values** | `mode_base` `mode_psk` `mode_auth` `mode_auth_psk` |
| **Implementation note** | RFC 9180 §5 (Table 1): mode_base (0x00) — no sender auth, no PSK; mode_psk (0x01) — PSK authentication only; mode_auth (0x02) — KEM private-key sender auth; mode_auth_psk (0x03) — both. Not all KEMs support AuthEncap/AuthDecap (required by mode_auth and mode_auth_psk); DHKEM variants defined in RFC 9180 all support it. Most deployments use mode_base. |
| **Used in** | HPKE |

---


### `{symmetricCipher}`

| Aspect | Detail |
|:---|:---|
| **Short** | Symmetric cipher sub-component |
| **Description** | Names the symmetric cipher used within a hybrid or composite scheme (ECIES data encryption, PBES encryption). |
| **Type** | algorithm reference |
| **Canonical values** | `AES-128-GCM` `AES-256-GCM` `AES-128-CBC` `AES-256-CBC` `ChaCha20-Poly1305` `3DES-CBC` |
| **Implementation note** | ECIES traditionally uses AES-CBC + HMAC or AES-GCM. Modern recommendations: AES-256-GCM or ChaCha20-Poly1305. |
| **Used in** | ECIES, HPKE, PBES1, PBES2 |

---


### `{cipherAlgorithm}`

| Aspect | Detail |
|:---|:---|
| **Short** | Cipher for CMAC / key-wrap |
| **Description** | Identifies the block cipher used as the underlying primitive in CMAC, key-wrap, or other cipher-based constructions. |
| **Type** | algorithm reference |
| **Canonical values** | `AES-128` `AES-192` `AES-256` `3DES` `CAMELLIA-128` `CAMELLIA-256` `SM4` |
| **Implementation note** | CMAC (SP 800-38B) most commonly uses AES-128 or AES-256. Key-wrap (SP 800-38F) requires AES. |
| **Used in** | CMAC, AES-KW, AES-KWP, PBMAC1 |

---


### `{cipherAlgorithm}` (CTR_DRBG)

| Aspect | Detail |
|:---|:---|
| **Short** | Block cipher for CTR_DRBG |
| **Description** | Selects the block cipher used as the core of CTR_DRBG. Determines security strength, seed length, and block size. |
| **Type** | algorithm reference |
| **Canonical values** | `AES-128` `AES-192` `AES-256` `3DES` |
| **Implementation note** | SP 800-90Ar1 CTR_DRBG: AES-256 provides 256-bit security. 3DES deprecated. AES-128 provides 128-bit security. |
| **Used in** | CTR_DRBG |

---


### `{blockCipher}` (DRBG)

| Aspect | Detail |
|:---|:---|
| **Short** | Block cipher for Fortuna / Yarrow |
| **Description** | Selects the block cipher used in the output generation stage of Fortuna or Yarrow. |
| **Type** | algorithm reference |
| **Canonical values** | `AES-256` `Blowfish` `3DES` |
| **Implementation note** | Fortuna (Schneier-Ferguson) specifies AES as the primary cipher. AES-256 in counter mode for the generator block. |
| **Used in** | Fortuna, Yarrow |

---


### `{encryptionAlgorithm}`

| Aspect | Detail |
|:---|:---|
| **Short** | Encryption algorithm (PBES) |
| **Description** | Identifies the symmetric cipher used for encryption in PBES1 or PBES2 (password-based encryption schemes). |
| **Type** | algorithm reference |
| **Canonical values** | `AES-128-CBC` `AES-256-CBC` `AES-128-GCM` `AES-256-GCM` `3DES-CBC` `RC2-40-CBC` |
| **Implementation note** | PBES2 (RFC 8018): use AES-256-GCM or AES-256-CBC. RC2-40 and 3DES in PBES1 are deprecated. |
| **Used in** | PBES1, PBES2 |

---


### `{kem}`

| Aspect | Detail |
|:---|:---|
| **Short** | KEM identifier (HPKE) |
| **Description** | Identifies the Key Encapsulation Mechanism used in HPKE. Determines the asymmetric key exchange component. |
| **Type** | KEM identifier |
| **Canonical values** | `DHKEM(P-256,HKDF-SHA256)` `DHKEM(P-384,HKDF-SHA384)` `DHKEM(P-521,HKDF-SHA512)` `DHKEM(X25519,HKDF-SHA256)` `DHKEM(X448,HKDF-SHA512)` `ML-KEM-768` `ML-KEM-1024` |
| **Implementation note** | RFC 9180 §7.1 (Table 2) defines five DHKEM instantiations with two-byte IANA KEM IDs. X25519 (0x0020) is the most common; P-256 (0x0010) is used when FIPS compliance is required. Post-quantum hybrid KEMs (X25519+ML-KEM) are emerging in TLS 1.3 but are not part of RFC 9180 itself. |
| **Used in** | HPKE |

**RFC 9180 KEM identifier table (Table 2):**

| KEM ID | Name | Nsecret (B) | Nenc (B) | Npk (B) | Nsk (B) |
|:---|:---|:---|:---|:---|:---|
| 0x0010 | DHKEM(P-256, HKDF-SHA256) | 32 | 65 | 65 | 32 |
| 0x0011 | DHKEM(P-384, HKDF-SHA384) | 48 | 97 | 97 | 48 |
| 0x0012 | DHKEM(P-521, HKDF-SHA512) | 64 | 133 | 133 | 66 |
| 0x0020 | DHKEM(X25519, HKDF-SHA256) | 32 | 32 | 32 | 32 |
| 0x0021 | DHKEM(X448, HKDF-SHA512) | 64 | 56 | 56 | 56 |

Nenc = encapsulated key size (ephemeral public key sent to recipient). Npk = recipient public key size. Nsecret = shared secret length fed into the KDF. For P-256/384/521, public keys are uncompressed SEC 1 points (0x04 prefix + coordinates); for X25519/X448, public keys are the compressed Montgomery u-coordinate.

---


### `{otherBlockCipher}`

| Aspect | Detail |
|:---|:---|
| **Short** | Alternative cipher in ChaCha hybrid |
| **Description** | Identifies an alternative block cipher combined with ChaCha as the keystream cipher in a hybrid construction. |
| **Type** | algorithm reference |
| **Canonical values** | `AES` |
| **Implementation note** | ChaCha with AES (ChaCha-AES) is a theoretical construction combining the differential resistance of AES with the ARX speed of ChaCha. Not widely deployed. |
| **Used in** | ChaCha |

---

## 3. Hash & digest parameters

Parameters that identify a hash function or PRF used as a sub-component within a larger construction.

---


### `{hashAlgorithm}`

| Aspect | Detail |
|:---|:---|
| **Short** | Hash / digest algorithm identifier |
| **Description** | Identifies the underlying hash function used within a composite algorithm — for signing, MAC construction, KDF, or DRBG seeding. |
| **Type** | algorithm reference |
| **Canonical values** | `SHA-1` `SHA-224` `SHA-256` `SHA-384` `SHA-512` `SHA-512/224` `SHA-512/256` `SHA3-224` `SHA3-256` `SHA3-384` `SHA3-512` `SHAKE128` `SHAKE256` `SM3` `GOSTR3411` `BLAKE2b-256` `BLAKE2s-256` |
| **Implementation note** | SHA-1 deprecated for signatures (collision found). SHA-256 minimum for new designs. SHA-384/512 for high-security. SHA3 series for diversity. |
| **Used in** | HMAC, HKDF, PBKDF1, PBKDF2, scrypt, TLS-PRF, IKE-PRF, SP800-108, SP800-56C, RSASSA-PKCS1, RSASSA-PSS, ECDSA, DSA, ANSI-KDF, CTR_DRBG, HMAC_DRBG, Hash_DRBG, LMS, XMSS, SLH-DSA, ML-DSA, OPAQUE, SPAKE2, SRP |

---


### `{maskGenAlgorithm}`

| Aspect | Detail |
|:---|:---|
| **Short** | Mask generation function |
| **Description** | MGF used in RSA-OAEP and RSA-PSS. MGF1 (the standard) takes a hash function as parameter. Determines how the mask is derived from the seed. |
| **Type** | algorithm reference |
| **Canonical values** | `MGF1` `MGF1-SHA256` `MGF1-SHA384` `MGF1-SHA512` |
| **Implementation note** | RFC 8017 specifies MGF1 exclusively. The hash inside MGF1 can differ from the main hash — but using the same function is simplest and most common. |
| **Used in** | RSAES-OAEP, RSASSA-PSS |

---


### `{prfFunction}`

| Aspect | Detail |
|:---|:---|
| **Short** | PRF for SP 800-108 KDF |
| **Description** | The pseudorandom function used as the building block of the SP 800-108 counter/feedback/double-pipeline KDFs. |
| **Type** | algorithm reference |
| **Canonical values** | `HMAC-SHA256` `HMAC-SHA384` `HMAC-SHA512` `AES-CMAC` `KMAC128` `KMAC256` |
| **Implementation note** | SP 800-108r1 approves HMAC and CMAC-based PRFs. KMAC variants added in 2022 revision. |
| **Used in** | SP800-108 |

---


### `{auxFunction}`

| Aspect | Detail |
|:---|:---|
| **Short** | Auxiliary function (SP 800-56C) |
| **Description** | The auxiliary hash or MAC used in the one-step or two-step key derivation in SP 800-56C. |
| **Type** | algorithm reference |
| **Canonical values** | `H(SHA-256)` `H(SHA-384)` `H(SHA-512)` `HMAC-SHA256` `HMAC-SHA512` `KMAC128` `KMAC256` |
| **Implementation note** | SP 800-56Cr2 §4: "H-function" can be a hash function, HMAC, or KMAC. Selection affects domain separation. |
| **Used in** | SP800-56C |

---


### `{hashfun}` / `{nbits}` / `{treeHeight}`

| Aspect | Detail |
|:---|:---|
| **Short** | Hash-based signature structure params (LMS / XMSS / HSS / XMSS^MT) |
| **Description** | Parameters for stateful hash-based signatures (LMS, HSS, XMSS, XMSS^MT). Combine to define the hash function, hash output width (n bytes), Merkle tree height, and — for LMOTS/WOTS+ — the Winternitz parameter w. |
| **Type** | composite parameter set identifier |
| **Used in** | LMS, LMOTS, HSS, XMSS, XMSS^MT |

#### LMS hash function parameter sets (SP 800-208 §4, Table 1)

Four hash functions are approved, identified by hash algorithm and output width n:

| SP 800-208 identifier | Hash function | n (bytes) | Security strength | Quantum security |
|:---|:---|:---|:---|:---|
| `LMS_SHA256_M32` | SHA-256 (full) | 32 | 256-bit | 128-bit |
| `LMS_SHA256_M24` | SHA-256/192 (truncated to 192 bits) | 24 | 192-bit | 96-bit |
| `LMS_SHAKE_M32` | SHAKE256 with 256-bit output | 32 | 256-bit | 128-bit |
| `LMS_SHAKE_M24` | SHAKE256 with 192-bit output | 24 | 192-bit | 96-bit |

> **CNSA 2.0 note:** NSA recommends `LMS_SHA256_M24` (SHA-256/192) parameter sets for National Security Systems.

Five tree heights h are available for each hash function (SP 800-208 Table 1):

| Height identifier | h | Max one-time signatures | Use case |
|:---|:---|:---|:---|
| `H5` | 5 | 2^5 = 32 | Short-lived keys; testing; embedded devices |
| `H10` | 10 | 2^10 = 1 024 | General low-frequency signing |
| `H15` | 15 | 2^15 = 32 768 | Firmware update lifecycles |
| `H20` | 20 | 2^20 ≈ 1 048 576 | Long-lived code-signing roots |
| `H25` | 25 | 2^25 ≈ 33 554 432 | Very long-lived hierarchies |

Full LMS parameter set names combine hash and height, e.g. `LMS_SHA256_M32_H5` … `LMS_SHAKE_M24_H25` — **20 LMS parameter sets** total.

#### LMOTS parameter sets (SP 800-208 §3, Table 2)

Each LMS signature embeds one LMOTS (Leighton-Micali One-Time Signature) component. The Winternitz parameter w trades signature size for computation time:

| SP 800-208 identifier (n=32 example) | w | LMOTS sig size (n=32) | Signing/verif. ops |
|:---|:---|:---|:---|
| `LMOTS_SHA256_N32_W1` | 1 | 8 516 bytes | Fewest hash calls; largest sig |
| `LMOTS_SHA256_N32_W2` | 2 | 4 292 bytes | — |
| `LMOTS_SHA256_N32_W4` | 4 | 2 180 bytes | Default; balanced |
| `LMOTS_SHA256_N32_W8` | 8 | 1 124 bytes | Most hash calls; smallest sig |

The same four Winternitz values apply to all four hash functions (N24/N32 × SHA256/SHAKE), giving **16 LMOTS parameter sets** total.

LMOTS signature sizes above are from RFC 8554 §4.3 (type + n×(p+1) bytes). The full LMS signature size adds the Merkle authentication path: LMS_sig_size = 4 + LMOTS_sig + 4 + h×n bytes.

#### HSS (Hierarchical Signature Scheme — SP 800-208 §6, RFC 8554 §6)

HSS is a multi-level extension of LMS. An HSS key pair of L levels chains L LMS trees where each level's root key is signed by the level above. Maximum signing capacity = product of per-level capacities:

| HSS levels L | Max signatures | Notes |
|:---|:---|:---|
| 1 | 2^h (single LMS tree) | Equivalent to bare LMS |
| 2 | 2^(h₁ + h₂) | Typical: h₁=10, h₂=10 → 2^20 |
| 3–8 | Up to 2^(h₁+…+h_L) | Longer-lived hierarchies |

HSS public key = root LMS public key (4 + 4 + 16 + n bytes). HSS signature = concatenation of L (LMS signature + LMS public key) pairs.

#### XMSS parameter sets (SP 800-208 §7, RFC 8391)

XMSS uses WOTS+ one-time signatures. SP 800-208 approves the following parameter set families:

| Family prefix | Hash | n (bytes) | Security | Heights h |
|:---|:---|:---|:---|:---|
| `XMSS-SHA2_{h}_256` | SHA-256 | 32 | 128-bit PQ | 10, 16, 20 |
| `XMSS-SHA2_{h}_512` | SHA-512 | 64 | 256-bit (≥128 PQ) | 10, 16, 20 |
| `XMSS-SHAKE_{h}_256` | SHAKE128 (256-bit output) | 32 | 128-bit PQ | 10, 16, 20 |
| `XMSS-SHAKE_{h}_512` | SHAKE256 (512-bit output) | 64 | 256-bit | 10, 16, 20 |
| `XMSS-SHA2_{h}_192` | SHA-256/192 (n=24, SP 800-208 addition) | 24 | 96-bit PQ | 10, 16, 20 |
| `XMSS-SHAKE256_{h}_192` | SHAKE256/192 (n=24, SP 800-208 addition) | 24 | 96-bit PQ | 10, 16, 20 |

Example names: `XMSS-SHA2_10_256`, `XMSS-SHA2_20_512`, `XMSS-SHAKE256_10_192`. **18 XMSS parameter sets** in SP 800-208.

#### XMSS^MT parameter sets (SP 800-208 §8, RFC 8391)

XMSS^MT (multi-tree XMSS) uses d layers of XMSS trees with total hypertree height H = h′×d. Enables very large signing volumes while keeping per-signing computation bounded to d WOTS+ computations:

| Family prefix | Total height H | Layers d | Max signatures |
|:---|:---|:---|:---|
| `XMSSMT-SHA2_{H}/{d}_256` | 20, 40, 60 | 2, 4, 8 | 2^H |
| `XMSSMT-SHA2_{H}/{d}_512` | 20, 40, 60 | 2, 4, 8 | 2^H |
| `XMSSMT-SHAKE_{H}/{d}_256` | 20, 40, 60 | 2, 4, 8 | 2^H |
| `XMSSMT-SHAKE_{H}/{d}_512` | 20, 40, 60 | 2, 4, 8 | 2^H |
| `XMSSMT-SHA2_{H}/{d}_192` | 20, 40, 60 | 2, 4, 8 | 2^H |
| `XMSSMT-SHAKE256_{H}/{d}_192` | 20, 40, 60 | 2, 4, 8 | 2^H |

Example name: `XMSSMT-SHA2_20/2_256` (H=20, d=2, n=32).

> **Implementation note — SP 800-208 §5.3 hardware mandate:** LMS and XMSS private key state **shall** be managed within a hardware cryptographic module validated to FIPS 140-2/3 Level 3 or higher. The current index value (state) must be stored in nonvolatile memory **before** any signature is exported from the module. Signing outside a validated hardware module is non-compliant with SP 800-208.
>
> The security strength against quantum adversaries is 4n bits (half the classical 8n-bit strength, by Grover's algorithm). Choose n=32 parameter sets for ≥128-bit post-quantum security; n=24 provides only 96-bit quantum security.
>
> Note: SLH-DSA (FIPS 205) uses analogous but **stateless** internal parameters (`{n}`, `{h}`, `{d}`, `{a}`, `{k}`, `{w}`) that are not covered by this entry — see Section 9.

---

## 4. Curve & group parameters

Parameters that select the algebraic structure for asymmetric operations.

---


### `{ellipticCurve}`

| Aspect                  | Detail                                                                                                                                                                                |
|:---|:---|
| **Short**               | Named elliptic curve identifier                                                                                                                                                       |
| **Description**         | Selects the specific elliptic curve domain parameters. Determines security level, performance, and interoperability.                                                                  |
| **Type**                | curve identifier                                                                                                                                                                      |
| **Canonical values**    | `P-256` `P-384` `P-521` `secp256k1` `brainpoolP256r1` `brainpoolP384r1` `brainpoolP512r1` `Curve25519` `Curve448` `Ed25519` `Ed448` `BLS12-381` `SM2` `id-GostR3410-2001-CryptoPro-A` |
| **Implementation note** | P-256 dominant in TLS. secp256k1 in Bitcoin. Curve25519/x25519 for modern DH. Ed25519 for EdDSA. P-256 = 128-bit security, P-384 = 192-bit.                                           |
| **Used in**             | ECDSA, ECDH, ECIES, EdDSA, MQV, BLS, EC-ElGamal, SM2, ECMQV, J-PAKE, SPAKE2, OPAQUE                                                                                                   |

---


### `{namedGroup}`

| Aspect | Detail |
|:---|:---|
| **Short** | Named DH / TLS group identifier |
| **Description** | Selects a named finite-field or elliptic curve group for key exchange, as registered in IANA TLS Named Groups or RFC 7919. |
| **Type** | group identifier |
| **Canonical values** | `ffdhe2048` `ffdhe3072` `ffdhe4096` `ffdhe6144` `ffdhe8192` `x25519` `x448` `secp256r1` `secp384r1` `secp521r1` `brainpoolP256r1tls13` |
| **Implementation note** | TLS 1.3 mandates x25519 and secp256r1 as minimum. RFC 7919 ffdhe groups for FIPS-compliant DH. x448 for 224-bit security. |
| **Used in** | FFDH, J-PAKE, SRP, OPAQUE, SPAKE2, SPAKE2PLUS, HPKE |

---


### `{group}`

| Aspect | Detail |
|:---|:---|
| **Short** | PAKE group / curve identifier |
| **Description** | Identifies the algebraic group used in password-authenticated key exchange protocols. Can be a named elliptic curve or a named DH group. |
| **Type** | group identifier |
| **Canonical values** | `P-256` `P-384` `P-521` `x25519` `x448` `ristretto255` `decaf448` |
| **Implementation note** | OPAQUE and SPAKE2+ use ristretto255 or P-256. Ristretto255 eliminates cofactor issues on Curve25519. |
| **Used in** | OPAQUE, SPAKE2, SPAKE2PLUS, J-PAKE |

---

## 5. Authentication & tag parameters

Parameters related to authentication tags, AEAD construction identifiers, and MAC sub-components.

---


### `{tagLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Authentication tag length in bits |
| **Description** | Length of the authentication tag produced by an AEAD or MAC construction. Shorter tags reduce overhead but lower forgery resistance. |
| **Type** | integer (bits) |
| **Canonical values** | `32` `48` `64` `80` `96` `112` `128` |
| **Implementation note** | GCM/CCM standard: 128 bits (96 acceptable for constrained). GHASH truncation to 32 bits is weak. RFC 5116 requires ≥128 bits for most uses. |
| **Used in** | AES-GCM, AES-CCM, AES-OCB, AES-GCM-SIV, ChaCha20-Poly1305, HMAC, UMAC, KMAC, SM4-GCM |

---


### `{ivLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Initialisation vector length in bits |
| **Description** | Length of the IV or nonce. Critical for AEAD security — reusing an IV with the same key under GCM destroys confidentiality and authentication. |
| **Type** | integer (bits) |
| **Canonical values** | `64` `96` `128` `192` |
| **Implementation note** | AES-GCM standard IV = 96 bits. Longer IVs require GHASH derivation. XChaCha20 uses 192-bit nonce to enable random nonce generation safely. |
| **Used in** | AES-GCM, AES-CCM, AES-GCM-SIV, SM4-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 |

---


### `{mac}`

| Aspect | Detail |
|:---|:---|
| **Short** | MAC algorithm reference |
| **Description** | Identifies a MAC sub-component inside a composite scheme (ECIES, J-PAKE, PBES, HPKE AEAD). |
| **Type** | algorithm reference |
| **Canonical values** | `HMAC-SHA256` `HMAC-SHA384` `HMAC-SHA512` `AES-CMAC` `Poly1305` `GMAC-128` `KMAC128` |
| **Implementation note** | HPKE AEAD IDs: AES-128-GCM (0x0001), AES-256-GCM (0x0002), ChaCha20-Poly1305 (0x0003). |
| **Used in** | HPKE, ECIES, J-PAKE, SPAKE2, SPAKE2PLUS, OPAQUE, PBES1, PBMAC1 |

---


### `{macAlgorithm}`

| Aspect | Detail |
|:---|:---|
| **Short** | MAC algorithm (PBMAC1) |
| **Description** | The MAC algorithm used in PBMAC1 (password-based MAC, RFC 8018). Applies a password-derived key to produce a MAC tag. |
| **Type** | algorithm reference |
| **Canonical values** | `HMAC-SHA256` `HMAC-SHA512` |
| **Implementation note** | RFC 8018 §7: PBMAC1 uses PBKDF2 to derive the MAC key, then applies the MAC function. SHA-256 and SHA-512 variants are standard. |
| **Used in** | PBMAC1 |

---


### `{aead}`

| Aspect | Detail |
|:---|:---|
| **Short** | AEAD cipher identifier (HPKE) |
| **Description** | Selects the AEAD algorithm for HPKE symmetric encryption. Registered in IANA HPKE AEAD Identifiers. |
| **Type** | AEAD identifier |
| **Canonical values** | `AES-128-GCM` `AES-256-GCM` `ChaCha20-Poly1305` `Export-Only` |
| **Implementation note** | RFC 9180 §7.3 (Table 5) defines three AEAD algorithms plus the export-only mode. 0xFFFF (Export-Only) is used when HPKE is used solely for key derivation (via the Secret Export API) with no symmetric encryption. |
| **Used in** | HPKE |

**RFC 9180 AEAD identifier table (Table 5):**

| AEAD ID | Name | Nk (key, B) | Nn (nonce, B) | Nt (tag, B) |
|:---|:---|:---|:---|:---|
| 0x0001 | AES-128-GCM | 16 | 12 | 16 |
| 0x0002 | AES-256-GCM | 32 | 12 | 16 |
| 0x0003 | ChaCha20Poly1305 | 32 | 12 | 16 |
| 0xFFFF | Export-Only | N/A | N/A | N/A |

---

## 6. KDF & password parameters

Parameters controlling cost, memory hardness, and sub-components of key derivation and password hashing functions.

---


### `{kdf}`

| Aspect | Detail |
|:---|:---|
| **Short** | Key derivation function reference |
| **Description** | Names the KDF used as a sub-component of a composite protocol (HPKE, ECIES, PBES2, OPAQUE). Distinct from top-level KDF algorithms. |
| **Type** | algorithm reference |
| **Canonical values** | `HKDF-SHA256` `HKDF-SHA384` `HKDF-SHA512` `HKDF-SHA3-256` `ANSI-KDF-X9.42` `ANSI-KDF-X9.63` `SP800_56C_OneStep` `TLS12-PRF-SHA256` `TLS13-PRF-SHA256` |
| **Implementation note** | RFC 9180 §7.2 (Table 3) defines three HKDF KDF IDs with their Extract output lengths (Nh). The KDF used inside a DHKEM's ExtractAndExpand is the one associated with the KEM (not necessarily the ciphersuite KDF). |
| **Used in** | HPKE, ECIES, PBES2, J-PAKE, SPAKE2, SPAKE2PLUS, OPAQUE, X3DH |

**RFC 9180 KDF identifier table (Table 3):**

| KDF ID | Name | Nh (output, B) |
|:---|:---|:---|
| 0x0001 | HKDF-SHA256 | 32 |
| 0x0002 | HKDF-SHA384 | 48 |
| 0x0003 | HKDF-SHA512 | 64 |

---


### `{iterations}`

| Aspect | Detail |
|:---|:---|
| **Short** | KDF iteration / work factor count |
| **Description** | Number of pseudorandom function iterations. Higher = more expensive to brute-force. Must be tuned to hardware to maintain security margin. |
| **Type** | positive integer |
| **Canonical values** | `1` `1000` `10000` `100000` `600000` `1000000+` |
| **Implementation note** | NIST SP 800-132 (2023): minimum 600,000 iterations for PBKDF2-HMAC-SHA256. bcrypt cost factor: 12 minimum (2024). Argon2: iterations + memory together. |
| **Used in** | PBKDF1, PBKDF2, bcrypt, PBES1, PBES2 |

---


### `{memoryKiB}`

| Aspect | Detail |
|:---|:---|
| **Short** | Memory cost in kibibytes (Argon2) |
| **Description** | Amount of memory Argon2 occupies during hashing. Core parameter resisting GPU/ASIC attacks — higher memory = more expensive to parallelise. |
| **Type** | positive integer (KiB) |
| **Canonical values** | `65536` `262144` `1048576` `4194304` |
| **Implementation note** | OWASP 2023 recommendation: Argon2id m=19456 (19 MiB), t=2, p=1. High-security servers: m=65536+. Mobile: m=9216. |
| **Used in** | Argon2 |

---


### `{passes}`

| Aspect | Detail |
|:---|:---|
| **Short** | Time cost / pass count (Argon2) |
| **Description** | Number of Argon2 passes over the memory block. Increases time cost without increasing memory. |
| **Type** | positive integer |
| **Canonical values** | `1` `2` `3` `4` |
| **Implementation note** | Argon2id: t=1 with high memory is stronger than t=3 with low memory for same elapsed time. |
| **Used in** | Argon2 |

---


### `{parallelism}`

| Aspect | Detail |
|:---|:---|
| **Short** | Parallelism degree (Argon2) |
| **Description** | Number of parallel lanes in Argon2. Should match the number of CPU threads available to the attacker, not to the defender. |
| **Type** | positive integer |
| **Canonical values** | `1` `2` `4` |
| **Implementation note** | p=1 is standard for most deployments. Increasing p does not significantly improve security vs. increasing m. |
| **Used in** | Argon2 |

---


### `{saltLenBytes}`

| Aspect | Detail |
|:---|:---|
| **Short** | KDF/password hash salt length |
| **Description** | Length of the random salt prepended to the password before hashing. Prevents rainbow table attacks and ensures unique hashes for identical passwords. |
| **Type** | integer (bytes) |
| **Canonical values** | `8` `16` `32` |
| **Implementation note** | NIST SP 800-132: minimum 128 bits (16 bytes). 32 bytes recommended. Must be cryptographically random (from CSPRNG, not PRNG). |
| **Used in** | Argon2, PBKDF2, scrypt, bcrypt |

---


### `{N}`

| Aspect | Detail |
|:---|:---|
| **Short** | scrypt CPU/memory cost factor |
| **Description** | Primary work factor for scrypt. Must be a power of 2. Doubles both time and memory cost when doubled. |
| **Type** | power of 2 integer |
| **Canonical values** | `1024` `16384` `32768` `65536` `131072` `1048576` |
| **Implementation note** | Litecoin: N=1024. OWASP recommendation: N=32768 for web logins. High-security: N=1048576. RFC 7914. |
| **Used in** | scrypt |

---


### `{r}`

| Aspect | Detail |
|:---|:---|
| **Short** | scrypt block size factor |
| **Description** | Controls the block size in scrypt. Memory usage scales as 128×N×r bytes. Affects cache locality — r=8 is the standard. |
| **Type** | positive integer |
| **Canonical values** | `8` |
| **Implementation note** | r=8 is the de facto standard. Changing r mainly affects memory bandwidth vs. compute ratio. |
| **Used in** | scrypt |

---


### `{p}`

| Aspect | Detail |
|:---|:---|
| **Short** | scrypt parallelisation factor |
| **Description** | Number of independent scrypt mixing operations. Allows trading time for parallelism without reducing memory hardness. |
| **Type** | positive integer |
| **Canonical values** | `1` `2` `4` |
| **Implementation note** | p=1 standard. Increasing p linearly increases time cost. Does not affect memory per instance. RFC 7914. |
| **Used in** | scrypt |

---


### `{cost}`

| Aspect | Detail |
|:---|:---|
| **Short** | bcrypt cost / work factor |
| **Description** | Log2 of the number of bcrypt rounds. Each increment doubles the computation time. |
| **Type** | integer (log2 of rounds) |
| **Canonical values** | `10` `11` `12` `13` `14` `15` |
| **Implementation note** | Cost 12 = 4096 rounds (minimum 2024). Cost 14 = 16384 rounds for high-security. bcrypt input truncated at 72 bytes. |
| **Used in** | bcrypt |

---


### `{ksf}`

| Aspect | Detail |
|:---|:---|
| **Short** | Key-stretching function (OPAQUE) |
| **Description** | The password-hardening function within OPAQUE. Applied server-side to the OPRF output before key material is derived. |
| **Type** | algorithm reference |
| **Canonical values** | `Identity` `Scrypt` `Argon2id` `PBKDF2-SHA256` |
| **Implementation note** | The OPAQUE specification recommends Argon2id or scrypt as the KSF. Identity KSF = no stretching (testing only). KSF selection is per deployment. |
| **Used in** | OPAQUE |

---


### `{N_log2}`

| Aspect | Detail |
|:---|:---|
| **Short** | yescrypt CPU/memory cost (log2) |
| **Description** | Log2 of the N parameter in yescrypt, analogous to scrypt's N. yescrypt extends scrypt with additional parameters t (time mixing) and g (upgrade factor). |
| **Type** | integer (log2) |
| **Canonical values** | `10` `14` `15` `16` `17` `18` |
| **Implementation note** | yescrypt default: N_log2=14 (N=16384). PHC winner for servers: N_log2=17. Introduced in Linux /etc/shadow for modern password hashing. |
| **Used in** | yescrypt |

---


### `{t}` (yescrypt)

| Aspect | Detail |
|:---|:---|
| **Short** | yescrypt time mixing parameter |
| **Description** | Additional time parameter in yescrypt. t=0 gives scrypt-equivalent behaviour. t>0 adds cheap time without memory increase. |
| **Type** | non-negative integer |
| **Canonical values** | `0` `1` `2` |
| **Implementation note** | t=0 = pure scrypt. t=1 doubles time cost without doubling memory. Allows tuning compute vs. memory balance independently. |
| **Used in** | yescrypt |

---

## 7. Padding & IV parameters

Parameters specifying padding schemes and initialisation vector handling.

---


### `{padding}`

| Aspect | Detail |
|:---|:---|
| **Short** | Padding scheme identifier |
| **Description** | Specifies how plaintext is padded to a block boundary, or how RSA messages are padded before encryption/signing. |
| **Type** | enumeration |
| **Canonical values** | `PKCS7` `PKCS5` `ISO10126` `ANSIX923` `ZeroPad` `NoPad` `OAEP` `PSS` `PKCS1v15` |
| **Implementation note** | PKCS7 standard for block ciphers. PKCS1v15 for RSA signing/encryption (PSS preferred). No-padding only for CTR/OFB/stream modes. |
| **Used in** | AES-CBC, AES-ECB, CAMELLIA, ARIA, SEED, SM4, GOST38147, Blowfish, 3DES, RSAES-PKCS1, RSAES-OAEP, RSASSA-PKCS1, RSASSA-PSS |

---

## 8. Protocol & miscellaneous parameters

Construction-specific or protocol-level parameters that do not fit a general category.

---


### `{compressionRounds}` / `{finalizationRounds}`

| Aspect | Detail |
|:---|:---|
| **Short** | SipHash round counts |
| **Description** | SipHash is parameterised by the number of SipRound operations in its compression and finalization phases. Standard: SipHash-2-4. |
| **Type** | small positive integer pair |
| **Canonical values** | `2-4` `1-3` `4-8` |
| **Implementation note** | SipHash-2-4 (c=2, d=4) is the standard for hash tables. SipHash-4-8 for MACs. Halving rounds to 1-3 weakens the construction. |
| **Used in** | SipHash |

---


### `{SRP version}`

| Aspect | Detail |
|:---|:---|
| **Short** | SRP protocol version |
| **Description** | SRP-3 (original, RFC 2945) vs SRP-6 (revised, improved against server forgery). SRP-6a is the most widely deployed variant. |
| **Type** | enumeration |
| **Canonical values** | `3` `6` `6a` |
| **Implementation note** | SRP-6 fixes a 2-for-1 guessing attack in SRP-3. SRP-6a (augmented) is the standard in TLS-SRP (RFC 5054). SRP-3 considered obsolete. |
| **Used in** | SRP |

---

---

## 9. PQC internal parameters (FIPS 203 / 204 / 205 / 206)

These parameters are fixed by the algorithm's named parameter set and are not free-standing
CycloneDX pattern placeholders. They are documented here because they are essential for
implementation analysis, memory planning, hardware sizing, and understanding active
standardisation discussions on the NIST PQC Forum.

> **Convention:** parameters in this section use the notation `{name}(algorithm)` to
> distinguish same-letter parameters that have different meanings across algorithms.

---

### ML-DSA internal parameters (FIPS 204)


#### `{k}` and `{l}` (ML-DSA) — lattice matrix dimensions

| Aspect | Detail |
|:---|:---|
| **Short** | Rows (k) and columns (l) of the public matrix A |
| **Description** | The public matrix A in ML-DSA has dimensions k×l. The parameter set name encodes these directly: ML-DSA-65 means k=6, l=5. These values determine public key size, signature size, and working memory requirements. |
| **Type** | integer pair |
| **Implementation note** | Memory for the NTT of A scales as k×l×256×4 bytes. Relevant for constrained-device implementations discussed in the PQC forum "pure vs. pre-hash ML-DSA" and memory optimisation threads. |
| **Used in** | ML-DSA |

**Values by parameter set:**

| Parameter set | k | l | NIST level |
|:---|:---|:---|:---|
| ML-DSA-44 | 4 | 4 | 2 |
| ML-DSA-65 | 6 | 5 | 3 |
| ML-DSA-87 | 8 | 7 | 5 |

---


#### `{eta}` (ML-DSA) — secret key coefficient bound

| Aspect | Detail |
|:---|:---|
| **Short** | Coefficient range for secret key polynomials |
| **Description** | Secret key polynomials s₁ and s₂ are sampled uniformly from [−η, η]. Determines secret key size and the signing rejection-sampling rate. |
| **Type** | integer |
| **Values by parameter set** | ML-DSA-44: η=2. ML-DSA-65: η=4. ML-DSA-87: η=2. |
| **Implementation note** | A non-constant-time implementation of the SampleInBall algorithm is a known vulnerability class (NIST PQC Forum, Jan 2026). Constant-time handling of η-bounded coefficients is mandatory. |
| **Used in** | ML-DSA |

---


#### `{gamma1}` (ML-DSA) — masking polynomial range

| Aspect | Detail |
|:---|:---|
| **Short** | Range of the masking polynomial y coefficients |
| **Description** | Controls the size of the randomising mask polynomial y during signing. Coefficients of y are sampled from (−γ₁, γ₁]. |
| **Type** | integer (power of 2) |
| **Values by parameter set** | ML-DSA-44: γ₁=2¹⁷=131072. ML-DSA-65/87: γ₁=2¹⁹=524288. |
| **Implementation note** | Larger γ₁ → larger signature component z → lower rejection-sampling rate. Directly impacts signing performance and signature byte size. |
| **Used in** | ML-DSA |

---


#### `{gamma2}` (ML-DSA) — low-order rounding threshold

| Aspect | Detail |
|:---|:---|
| **Short** | Rounding threshold for hint vector computation |
| **Description** | Used when decomposing w = w₁·2γ₂ + w₀ to compute the hint vector h. Determines the number of hint bits in the signature. |
| **Type** | integer |
| **Values by parameter set** | ML-DSA-44: γ₂=(q−1)/88=95232. ML-DSA-65/87: γ₂=(q−1)/32=261888. |
| **Implementation note** | γ₂ affects signature size (number of hint bits ≤ ω) and verification cost. Fixed by FIPS 204. |
| **Used in** | ML-DSA |

---


#### `{tau}` (ML-DSA) — challenge polynomial weight

| Aspect | Detail |
|:---|:---|
| **Short** | Number of ±1 coefficients in the challenge polynomial c |
| **Description** | The challenge polynomial c has exactly τ non-zero coefficients, each ±1. Controls binding hardness and the acceptance probability of the rejection sampler. |
| **Type** | integer |
| **Values by parameter set** | ML-DSA-44: τ=39. ML-DSA-65: τ=49. ML-DSA-87: τ=60. |
| **Implementation note** | Constant-time handling of the τ non-zero positions generated by SampleInBall is a critical implementation requirement (NIST PQC Forum, Jan 2026). All implementations must sample these positions in constant time with respect to the secret key. |
| **Used in** | ML-DSA |

---


#### `{lambda}` (ML-DSA) — collision strength target

| Aspect | Detail |
|:---|:---|
| **Short** | Target collision-resistance strength in bits |
| **Description** | Determines the required width of the commitment hash (SHAKE output length = λ/4 bytes internally). Sets the core security level. |
| **Type** | integer (bits) |
| **Values by parameter set** | ML-DSA-44: λ=128. ML-DSA-65: λ=192. ML-DSA-87: λ=256. |
| **Implementation note** | Per the IETF LAMPS WG specification for CMS/ML-DSA: the external digest algorithm SHOULD produce a hash of at least 2λ bits for collision resistance. SHAKE256 is the internal hash; SHA-512 or SHAKE256 are the recommended external pre-hash choices. |
| **Used in** | ML-DSA |

---


#### `{omega}` (ML-DSA) — maximum hint bits

| Aspect | Detail |
|:---|:---|
| **Short** | Maximum number of non-zero entries in the hint vector h |
| **Description** | The hint vector h in an ML-DSA signature encodes rounding correction information. The parameter ω bounds the number of non-zero entries; any signature with more than ω hints is rejected. |
| **Type** | integer |
| **Values by parameter set** | ML-DSA-44: ω=80. ML-DSA-65: ω=55. ML-DSA-87: ω=75. |
| **Implementation note** | ω affects signature size: the hint is encoded using ω+k bytes in the signature. Per FIPS 204 Table 1. |
| **Used in** | ML-DSA |

---


#### `{beta}` (ML-DSA) — norm bound for signature acceptance

| Aspect | Detail |
|:---|:---|
| **Short** | Norm bound β = τ·η for the signature vector z check |
| **Description** | During verification, the infinity norm of the signature vector z is checked against β. Defined as β = τ·η. Any signature with ‖z‖∞ ≥ γ₁−β is rejected. |
| **Type** | integer |
| **Values by parameter set** | ML-DSA-44: β=78 (39×2). ML-DSA-65: β=196 (49×4). ML-DSA-87: β=120 (60×2). |
| **Implementation note** | Per FIPS 204 Table 1. β is a derived parameter (product of τ and η). |
| **Used in** | ML-DSA |

---


#### `{q}` (ML-DSA) — prime modulus

| Aspect | Detail |
|:---|:---|
| **Short** | The prime modulus for polynomial arithmetic in ML-DSA |
| **Description** | All polynomial arithmetic in ML-DSA is performed modulo q = 8380417 = 2²³ − 2¹³ + 1. This prime was chosen to enable efficient NTT (Number Theoretic Transform) computation since it supports 512th roots of unity. |
| **Type** | prime integer |
| **Value** | q = 8380417 |
| **Implementation note** | Per FIPS 204 §4. The value is the same across all ML-DSA parameter sets. Polynomial degree n = 256 is also fixed across all parameter sets. |
| **Used in** | ML-DSA |

---


#### ML-DSA size reference (FIPS 204 / RFC 9881)

> RFC 9881 (October 2025) specifies the encoding of ML-DSA public keys and signatures in X.509 PKIX certificates and CRLs. Key usage: `digitalSignature`, `nonRepudiation`, `keyCertSign`, `cRLSign`. Algorithm parameters MUST be absent. Pure ML-DSA only (HashML-DSA is excluded from PKIX).

| Parameter set | pk (bytes) | sk seed (bytes) | sk expanded (bytes) | sig (bytes) | NIST level |
|:---|:---|:---|:---|:---|:---|
| ML-DSA-44 | 1312 | 32 | 2560 | 2420 | 2 |
| ML-DSA-65 | 1952 | 32 | 4032 | 3309 | 3 |
| ML-DSA-87 | 2592 | 32 | 4896 | 4627 | 5 |

---

### ML-KEM internal parameters (FIPS 203)


#### `{k}` (ML-KEM) — module rank

| Aspect | Detail |
|:---|:---|
| **Short** | Number of polynomials in the module lattice |
| **Description** | The fundamental dimension parameter. Determines public key size (384·k+32 bytes), ciphertext size, and security level. |
| **Type** | integer |
| **Implementation note** | Shared secret is always 32 bytes regardless of k. ML-KEM-768 (k=3) is the recommended TLS 1.3 default per PQC forum consensus (Jan 2026). |
| **Used in** | ML-KEM |

**Values by parameter set:**

> RFC 9935 (March 2026) specifies ML-KEM encoding in X.509 PKIX certificates. Key usage: `keyEncipherment` only. Algorithm parameters MUST be absent. Private key: 64-byte seed (preferred; compact) or expanded decapsulation key. Shared secret: always 32 bytes.

| Parameter set | k | Encaps key (B) | Decaps key — expanded (B) | Ciphertext (B) | Shared secret (B) | NIST level |
|:---|:---|:---|:---|:---|:---|:---|
| ML-KEM-512 | 2 | 800 | 1632 | 768 | 32 | 1 |
| ML-KEM-768 | 3 | 1184 | 2400 | 1088 | 32 | 3 |
| ML-KEM-1024 | 4 | 1568 | 3168 | 1568 | 32 | 5 |

---


#### `{du}` and `{dv}` (ML-KEM) — ciphertext compression bits

| Aspect | Detail |
|:---|:---|
| **Short** | Per-coefficient compression width for ciphertext components u and v |
| **Description** | ML-KEM compresses ciphertext coefficients to reduce bandwidth. `du` bits per coefficient in the u vector; `dv` bits for the v scalar polynomial. Higher values = less compression = lower decryption failure rate. |
| **Type** | integer (bits per coefficient) |
| **Implementation note** | Compression loss contributes to the decryption failure probability δ ≈ 2⁻¹³⁹ for ML-KEM-512. Fixed by FIPS 203. Important for hardware implementations computing ciphertext buffer sizes. |
| **Used in** | ML-KEM |

**Values by parameter set:**

| Parameter set | du | dv |
|:---|:---|:---|
| ML-KEM-512 | 10 | 4 |
| ML-KEM-768 | 10 | 4 |
| ML-KEM-1024 | 11 | 5 |

---


#### `{eta1}` and `{eta2}` (ML-KEM) — noise distribution width

| Aspect | Detail |
|:---|:---|
| **Short** | Binomial distribution parameter for key generation and encryption noise |
| **Description** | Private key s and error e are sampled from the centred binomial distribution B_η. η₁ governs key generation noise; η₂ governs encryption noise. |
| **Type** | integer |
| **Implementation note** | ML-KEM-512 uses η₁=3 to compensate for the smaller module rank k=2, maintaining security against LWE attacks. |
| **Used in** | ML-KEM |

**Values by parameter set:**

| Parameter set | η₁ | η₂ |
|:---|:---|:---|
| ML-KEM-512 | 3 | 2 |
| ML-KEM-768 | 2 | 2 |
| ML-KEM-1024 | 2 | 2 |

---


#### `{q}` (ML-KEM) — prime modulus

| Aspect | Detail |
|:---|:---|
| **Short** | The prime modulus for polynomial arithmetic in ML-KEM |
| **Description** | All polynomial arithmetic in ML-KEM is performed modulo q = 3329. This prime was chosen because it is small (fits in 12 bits), supports efficient NTT (256th roots of unity exist modulo 3329), and provides good noise tolerance. |
| **Type** | prime integer |
| **Value** | q = 3329 |
| **Implementation note** | Per FIPS 203 §4. The value is the same across all ML-KEM parameter sets. Polynomial degree n = 256 is also fixed across all parameter sets. |
| **Used in** | ML-KEM |

---


#### ML-KEM size reference (FIPS 203)

| Parameter set | ek (bytes) | dk (bytes) | Ciphertext (bytes) | Shared secret (bytes) | NIST level |
|:---|:---|:---|:---|:---|:---|
| ML-KEM-512 | 800 | 1632 | 768 | 32 | 1 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 | 3 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 | 5 |

---

### SLH-DSA internal parameters (FIPS 205)


#### `{n}` (SLH-DSA) — security parameter in bytes

| Aspect | Detail |
|:---|:---|
| **Short** | Core hash output width and key element length |
| **Description** | The fundamental security parameter of SLH-DSA. All hash outputs, PRF keys, private/public key elements, and signature elements have length n bytes. |
| **Type** | integer (bytes) |
| **Values by parameter set** | 128-bit security sets (128s/128f): n=16. 192-bit sets (192s/192f): n=24. 256-bit sets (256s/256f): n=32. |
| **Implementation note** | Public key = 2n bytes. Private key = 4n bytes. Central to the NIST PQC forum discussion requesting additional SLH-DSA parameter sets (Nov 2025, 87 messages), which proposes new (n, h, d, a, k) combinations for constrained signing volumes. |
| **Used in** | SLH-DSA |

---


#### `{h}` and `{d}` (SLH-DSA) — hypertree height and layer count

| Aspect | Detail |
|:---|:---|
| **Short** | Total hypertree height h and number of XMSS layers d |
| **Description** | The hypertree consists of d layers of XMSS trees each of height h'=h/d. Total height h determines the maximum number of signatures per key pair (2^h). d affects signing time (d WOTS+ signatures per SLH-DSA signature). |
| **Type** | integer pair |
| **Implementation note** | The "smaller SPHINCS+" paper (Fluhrer/Dang, ePrint 2024/018, cited in PQC forum) shows that alternative (h, d, a, k) tuples can significantly reduce signature sizes for realistic maximum signing volumes without security loss, motivating the NIST request for additional parameter sets. |
| **Used in** | SLH-DSA |

**Values by parameter set (all 12 — SHA-2 and SHAKE variants share the same structural parameters):**

| Parameter set | h | d | h' = h/d | Max signatures |
|:---|:---|:---|:---|:---|
| SLH-DSA-SHA2-128s / SLH-DSA-SHAKE-128s | 63 | 7 | 9 | 2⁶³ |
| SLH-DSA-SHA2-128f / SLH-DSA-SHAKE-128f | 66 | 22 | 3 | 2⁶⁶ |
| SLH-DSA-SHA2-192s / SLH-DSA-SHAKE-192s | 63 | 7 | 9 | 2⁶³ |
| SLH-DSA-SHA2-192f / SLH-DSA-SHAKE-192f | 66 | 22 | 3 | 2⁶⁶ |
| SLH-DSA-SHA2-256s / SLH-DSA-SHAKE-256s | 64 | 8 | 8 | 2⁶⁴ |
| SLH-DSA-SHA2-256f / SLH-DSA-SHAKE-256f | 68 | 17 | 4 | 2⁶⁸ |

---


#### `{a}` (SLH-DSA) — FORS tree height

| Aspect | Detail |
|:---|:---|
| **Short** | Height of each FORS few-time signature tree |
| **Description** | Each FORS few-time signature uses k trees of height a. Together they cover a·k bits of the message digest. Larger a = larger FORS signature but greater multi-target attack resistance. |
| **Type** | integer |
| **Canonical values (across all FIPS 205 parameter sets)** | `6` `8` `9` `12` `14` |
| **Implementation note** | FORS signature size per instance = k·(a+1)·n bytes. The NIST PQC forum thread on additional SLH-DSA parameter sets specifically explores adjusting a and k to achieve smaller signatures for constrained signing volumes. |
| **Used in** | SLH-DSA |

---


#### `{k}` (SLH-DSA) — number of FORS trees

| Aspect | Detail |
|:---|:---|
| **Short** | Number of FORS tree instances per signature |
| **Description** | Together with a, determines FORS signature size and few-time security level. |
| **Type** | integer |
| **Values by parameter set** | 128s: k=14. 128f: k=33. 192s: k=17. 192f: k=33. 256s: k=22. 256f: k=35. (SHA-2 and SHAKE variants share these values.) |
| **Implementation note** | FORS signature size = k·(a+1)·n bytes. Reducing k while increasing a (or vice versa) for realistic 2^m maximum signing volumes is the subject of the Fluhrer/Dang paper and the PQC forum additional parameter sets request. |
| **Used in** | SLH-DSA |

---


#### `{w}` / `{lg_w}` (SLH-DSA) — Winternitz parameter

| Aspect | Detail |
|:---|:---|
| **Short** | Base-w encoding width for WOTS+ chains |
| **Description** | WOTS+ represents each n-byte message as base-w integers. Each integer requires a hash chain of length w−1. Larger w = fewer but longer chains. |
| **Type** | integer (w) or log₂(w) |
| **Values in FIPS 205** | All 12 parameter sets fix lg_w=4 (w=16) — not a free parameter. |
| **Implementation note** | With w=16, each n-byte message maps to 2n hex digits. The SLH-DSA WOTS+ is distinct from the WOTS+ in RFC 8391 / SP 800-208 — the Winternitz parameter is fixed rather than selectable. |
| **Used in** | SLH-DSA (WOTS+ component) |

---


#### `{h_prime}` (SLH-DSA) — individual XMSS tree height

| Aspect | Detail |
|:---|:---|
| **Short** | Height of each individual XMSS tree layer |
| **Description** | The hypertree in SLH-DSA is composed of d layers, each containing XMSS trees of height h' = h/d. Each XMSS tree authenticates 2^h' sub-trees or FORS key pairs at the bottom layer. |
| **Type** | integer |
| **Values by parameter set** | 128s: h'=9. 128f: h'=3. 192s: h'=9. 192f: h'=3. 256s: h'=8. 256f: h'=4. |
| **Implementation note** | h' = h/d is always an integer. Larger h' means fewer layers d but larger XMSS trees (more WOTS+ signatures computed per layer). The "s" (small) variants have larger h' and fewer layers, reducing signature size at the cost of slower signing. |
| **Used in** | SLH-DSA |

---


#### `{m}` (SLH-DSA) — message digest length

| Aspect | Detail |
|:---|:---|
| **Short** | Length of the FORS message digest in bytes |
| **Description** | The message digest is mapped to k values in the range [0, 2^a), plus a tree index and leaf index within the hypertree. The total digest length m (in bytes) must accommodate k·a bits for the FORS input plus the tree address bits. Defined per parameter set in FIPS 205 Table 1. |
| **Type** | integer (bytes) |
| **Values by parameter set** | 128s: m=30. 128f: m=34. 192s: m=39. 192f: m=42. 256s: m=47. 256f: m=49. |
| **Implementation note** | m is derived from the formula: m = floor((k·a + h − h/d + 7) / 8) effectively. The exact values are fixed by FIPS 205 Table 1. |
| **Used in** | SLH-DSA |

---


#### SLH-DSA complete parameter and size reference (FIPS 205)

All 12 parameter sets (SHA-2 and SHAKE variants share identical structural parameters and sizes):

| Parameter set | n | h | d | h' | a | k | lg_w | m | pk (B) | sk (B) | sig (B) | NIST level |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| SLH-DSA-\*-128s | 16 | 63 | 7 | 9 | 12 | 14 | 4 | 30 | 32 | 64 | 7856 | 1 |
| SLH-DSA-\*-128f | 16 | 66 | 22 | 3 | 6 | 33 | 4 | 34 | 32 | 64 | 17088 | 1 |
| SLH-DSA-\*-192s | 24 | 63 | 7 | 9 | 14 | 17 | 4 | 39 | 48 | 96 | 16224 | 3 |
| SLH-DSA-\*-192f | 24 | 66 | 22 | 3 | 8 | 33 | 4 | 42 | 48 | 96 | 35664 | 3 |
| SLH-DSA-\*-256s | 32 | 64 | 8 | 8 | 14 | 22 | 4 | 47 | 64 | 128 | 29792 | 5 |
| SLH-DSA-\*-256f | 32 | 68 | 17 | 4 | 9 | 35 | 4 | 49 | 64 | 128 | 49856 | 5 |

> Note: `*` stands for either `SHA2` or `SHAKE`. E.g. SLH-DSA-SHA2-128s and SLH-DSA-SHAKE-128s share all values above.

---

### FN-DSA / Falcon parameters (FIPS 206 IPD)


#### `{signingMode}` — pure vs. pre-hash signing

| Aspect | Detail |
|:---|:---|
| **Short** | Whether the message is hashed before signing (pure) or pre-hashed by the caller |
| **Description** | ML-DSA, SLH-DSA, and FN-DSA all support both a pure mode (the algorithm hashes the message internally using SHAKE) and a pre-hash mode (the caller supplies an external digest and its OID). The HashFN-DSA variant takes a pre-computed digest and a hash algorithm identifier. |
| **Type** | enumeration |
| **Canonical values** | `pure` `pre-hash` |
| **Pattern implication** | Analogous to `HashML-DSA[-{hashAlgorithm}]` and `HashSLH-DSA[-{hashAlgorithm}]` in CycloneDX. For FN-DSA the equivalent would be `FN-DSA-(512\|1024)[-(pre-hash[-{hashAlgorithm}])]`. |
| **Implementation note** | PQC forum thread "HashSLH-DSA / HashML-DSA and choice of hash function" (Jan 2026): SHAKE256 should be the default pre-hash; SHA-512 is acceptable for legacy CMS interoperability (IETF LAMPS WG CMS/ML-DSA specification). |
| **Used in** | ML-DSA, SLH-DSA, FN-DSA |

---


#### `{deterministicSigning}` (ML-DSA) — hedged vs. deterministic mode

| Aspect | Detail |
|:---|:---|
| **Short** | Whether signing injects additional randomness (hedged) or is fully deterministic |
| **Description** | FIPS 204 specifies both deterministic (signature = f(key, message)) and hedged (an additional 32-byte random value rnd is mixed in) signing modes. Hedged is the default and is more robust against fault attacks and weak RNGs. |
| **Type** | enumeration |
| **Canonical values** | `deterministic` `hedged` |
| **Pattern implication** | `ML-DSA-(44\|65\|87)[-(deterministic\|hedged)]` |
| **Implementation note** | Hedged mode requires a 32-byte random value from an approved DRBG per signing call. FIPS 204 §5.2 permits setting rnd=0 for deterministic mode but this must be handled explicitly. Deterministic ML-DSA implementations have been identified as a fault-injection vulnerability class (NIST PQC Forum, Jan 2026). |
| **Used in** | ML-DSA |

---


#### `{context}` — signing context string

| Aspect | Detail |
|:---|:---|
| **Short** | Optional application context bound cryptographically into the signature |
| **Description** | ML-DSA, SLH-DSA, and FN-DSA all accept an optional context string (0–255 bytes) that is bound into the signature, preventing cross-protocol signature reuse. Applies in both pure and pre-hash modes. |
| **Type** | byte string (0–255 bytes) |
| **Canonical values** | Application-defined. Empty string `""` is the default. |
| **Pattern implication** | `ML-DSA-(44\|65\|87)[-ctx]` — analogous to `Ed(25519\|448)[-(ph\|ctx)]`. CycloneDX does not yet expose this for ML-DSA/SLH-DSA/FN-DSA. |
| **Implementation note** | Context strings provide domain separation between different uses of the same key pair (e.g. TLS vs. S/MIME vs. code signing). For CMS deployments, the signedAttrs structure already provides equivalent binding, so the context string may be empty. |
| **Used in** | ML-DSA, SLH-DSA, FN-DSA |

---


#### `{floatingPointMode}` (FN-DSA) — IEEE 754 arithmetic compliance

| Aspect | Detail |
|:---|:---|
| **Short** | Whether the Falcon Gaussian sampler uses strict IEEE 754 floating-point arithmetic |
| **Description** | FN-DSA/Falcon uses FFT-based Gaussian sampling over NTRU lattices, relying on floating-point arithmetic. Non-IEEE-754-compliant execution (extended precision x87 mode, flush-to-zero, non-standard rounding) produces a distribution that deviates from the specification, potentially weakening or breaking security. |
| **Type** | enumeration |
| **Canonical values** | `ieee754-strict` `ieee754-relaxed` `integer-emulation` |
| **Implementation note** | This is a unique parameter class with no analogue in any other standardised algorithm. FIPS 206 is still in the Initial Public Draft (IPD) stage as of Q1 2026 and does not yet mandate a specific arithmetic model; ongoing implementation discussions (PQC forum, Dec 2025) concern whether IEEE 754 compliance or integer-only Gaussian sampling should be required for FIPS 140-3 validation. Integer emulation is slower but portable, deterministic, and verifiable without floating-point test infrastructure. |
| **Used in** | FN-DSA |

---


#### `{n}` (FN-DSA) — polynomial degree

| Aspect | Detail |
|:---|:---|
| **Short** | Degree of the NTRU polynomials |
| **Description** | FN-DSA operates over the polynomial ring Z_q[x]/(x^n + 1). The degree n determines the lattice dimension and thus the security level. |
| **Type** | integer (power of 2) |
| **Values by parameter set** | FN-DSA-512: n=512. FN-DSA-1024: n=1024. |
| **Implementation note** | n=512 targets NIST Level 1 (equivalent to AES-128). n=1024 targets NIST Level 5 (equivalent to AES-256). The FFT-based Gaussian sampler operates over dimension-n polynomials. |
| **Used in** | FN-DSA |

---


#### `{q}` (FN-DSA) — prime modulus

| Aspect | Detail |
|:---|:---|
| **Short** | The prime modulus for polynomial arithmetic in FN-DSA |
| **Description** | All polynomial arithmetic in FN-DSA is performed modulo q = 12289. This prime supports efficient NTT since q ≡ 1 (mod 2n) for n up to 1024. |
| **Type** | prime integer |
| **Value** | q = 12289 |
| **Implementation note** | Per FIPS 206. The value is the same for both FN-DSA-512 and FN-DSA-1024. The small modulus (14 bits) contributes to compact key and signature sizes compared to ML-DSA (q = 8380417). |
| **Used in** | FN-DSA |

---


#### `{sigma}` (FN-DSA) — Gaussian standard deviation

| Aspect | Detail |
|:---|:---|
| **Short** | Standard deviation of the discrete Gaussian distribution used in signing |
| **Description** | During signing, FN-DSA samples a short vector from a discrete Gaussian distribution with standard deviation σ. The signature norm is checked against a bound derived from σ. |
| **Type** | floating-point constant |
| **Values by parameter set** | FN-DSA-512: σ ≈ 165.736617183. FN-DSA-1024: σ ≈ 168.388571447. |
| **Implementation note** | The Gaussian sampler is the most implementation-sensitive component of FN-DSA, requiring strict IEEE 754 double-precision floating-point arithmetic (see `{floatingPointMode}`). The signature acceptance bound is ‖(s₁, s₂)‖² ≤ ⌊β²⌋ where β² = (1.8962236 · σ)² · 2n. Incorrect floating-point behaviour can produce a biased distribution, leaking the secret key. |
| **Used in** | FN-DSA |

---


#### FN-DSA size reference (FIPS 206 IPD)

| Parameter set | n | q | pk (bytes) | sk (bytes) | sig (bytes, max) | NIST level |
|:---|:---|:---|:---|:---|:---|:---|
| FN-DSA-512 | 512 | 12289 | 897 | 1281 | 666 | 1 |
| FN-DSA-1024 | 1024 | 12289 | 1793 | 2305 | 1280 | 5 |

> Note: FN-DSA signature sizes are variable; the values above represent the expected maximum
> sizes in practice. Actual signatures may be slightly smaller due to compression.

---

### Cross-cutting PQC hybrid parameters


#### `{hybridKemCombiner}` — combination method for hybrid KEM shared secrets

| Aspect | Detail |
|:---|:---|
| **Short** | How the classical and PQC shared secrets are combined in a hybrid KEM |
| **Description** | Hybrid KEMs pair a classical key exchange (X25519 or P-256) with ML-KEM. The two resulting shared secrets must be combined into a single final secret. The combination method affects protocol binding and security. |
| **Type** | enumeration |
| **Canonical values** | `concat` `xor` `HKDF` |
| **Pattern implication** | `DHKEM(X25519)+ML-KEM-768[-{hybridKemCombiner}]` |
| **Implementation note** | PQC forum thread "TLS1.3 hybrid implementation" (Jan 2026, Bas Westerbaan): the TLS working group settled on simple concatenation (`concat`) — the two shared secrets are concatenated and fed directly into the TLS 1.3 HKDF key schedule. No separate combiner is needed because the key schedule already provides binding. Defined in `draft-ietf-tls-hybrid-design`. |
| **Used in** | ML-KEM (hybrid TLS / HPKE deployments) |

---

### HQC parameters (NIST selection, spec v2025-08-22)

> **Primary source:** HQC submission team, *Hamming Quasi-Cyclic (HQC)*, specification document v2025-08-22, https://pqc-hqc.org. NIST selected HQC as a fifth PQC standard (code-based KEM) in March 2025; FIPS standard pending.

#### Overview

HQC is an IND-CCA2-secure Key Encapsulation Mechanism (KEM) whose security is based on the **Quasi-Cyclic Syndrome Decoding (QCSD)** problem — a variant of the decoding problem for random linear codes over F₂. Unlike many code-based schemes, HQC does not require the underlying code family to be indistinguishable from random codes, which simplifies security arguments.

HQC-PKE (the underlying public-key encryption scheme) achieves IND-CPA security under the 2-DQCSD-P and 3-DQCSD-PT problems. HQC-KEM is obtained by applying the **Salted Fujisaki-Okamoto (SFO⊥) transform** to HQC-PKE, yielding IND-CCA2 security in the random-oracle model.

#### Internal structure

HQC uses a **double-circulant [2n, n] code** with parity-check matrix (Iₙ | rot(h)) and a decodable **concatenated Reed-Muller / Reed-Solomon (RMRS) code C** for message encoding.

| Component | Detail |
|:---|:---|
| External code | Shortened Reed-Solomon code over F₂₅₆ (field polynomial: 1+α²+α³+α⁴+α⁸); k_e = 16/24/32 symbols for L1/L3/L5 |
| Internal code | First-order duplicated Reed-Muller RM(1,7) = [128, 8, 64], duplicated 3× (L1) or 5× (L3, L5) |
| Duplication | L1: [384, 8] L3: [640, 8] L5: [640, 8] |
| Decoding | Maximum-likelihood decoding on internal code (fast Hadamard transform); algebraic decoder (Berlekamp-Massey / Euclidean) on external RS code |

#### Hash functions and XOF

| Function | Instantiation | Purpose |
|:---|:---|:---|
| G, I | SHA3-512 | Key and shared-secret derivation |
| H, J | SHA3-256 | Challenge hash in FO transform |
| XOF | SHAKE256 | Pseudorandom expansion of seeds into vectors |

#### Parameter sets (Table 5 of HQC spec v2025-08-22)

| Parameter | HQC-128 (HQC-1) | HQC-192 (HQC-3) | HQC-256 (HQC-5) |
|:---|---:|---:|---:|
| NIST security category | 1 | 3 | 5 |
| n (block length) | 17 669 | 35 851 | 57 637 |
| n₁ (RS code length) | 46 | 56 | 90 |
| n₂ (RM code length) | 384 | 640 | 640 |
| k (message bits) | 128 | 192 | 256 |
| w = w_r = w_x (Hamming weight) | 66 | 100 | 131 |
| w_e (error vector weight) | 75 | 114 | 149 |
| DFR (decoding failure rate) | < 2⁻¹²⁸ | < 2⁻¹⁹² | < 2⁻²⁵⁶ |

#### Key and ciphertext sizes (Table 6 of HQC spec v2025-08-22)

| Size | HQC-128 (HQC-1) | HQC-192 (HQC-3) | HQC-256 (HQC-5) |
|:---|---:|---:|---:|
| Encapsulation key ek (bytes) | 2 241 | 4 514 | 7 237 |
| Decapsulation key dk — default (bytes) | 2 321 | 4 602 | 7 333 |
| Decapsulation key dk — compressed (bytes) | 32 | 32 | 32 |
| Ciphertext c (bytes) | 4 433 | 8 978 | 14 421 |
| Shared secret K (bytes) | 32 | 32 | 32 |

> The **compressed dk** format stores only `seed_KEM` (32 bytes); the full key pair can be re-derived from this seed. The **default dk** format stores `(ek_KEM; dk_PKE; σ; seed_KEM)` to avoid re-derivation during decapsulation.

#### Security notes

- Classical security: ISD (Information Set Decoding) attacks yield work factors ≥ 2¹²⁸/²¹⁹²/²⁵⁶.
- Quantum security: ISD with quantum speedup (Grover / quantum ISD variants) halves the exponent; security parameters are chosen conservatively to maintain ≥ 128/192/256 bit classical and ≥ 64/96/128 bit quantum security.
- The quasi-cyclic structure does not benefit ISD attacks beyond a small constant factor; the DOOM attack gives at most O(√n) gain.
- OIDs: none assigned yet; will be defined in the forthcoming FIPS standard.

---

## Summary table

| Parameter | Category | Type | Key algorithm families |
|:---|:---|:---|:---|
| `{keyLength}` | Size & length | integer (bits) | AES, RSA, DH, DES, RC-family |
| `{saltLength}` | Size & length | integer (bytes) | RSASSA-PSS |
| `{dkLen}` | Size & length | integer (bytes) | PBKDF1, PBKDF2, PBES |
| `{tagLenBytes}` | Size & length | integer (bytes) | BLAKE3, SHAKE, KMAC |
| `{outputLength}` | Size & length | integer (bytes) | BLAKE3, SHAKE, cSHAKE |
| `{dkmLength}` | Size & length | integer (bits) | SP800-108, SP800-56C |
| `{length}` | Size & length | integer (bits) | CMAC, UMAC |
| `{parameterSetIdentifier}` | Size & length | enumeration | ML-DSA, ML-KEM, SLH-DSA, FN-DSA |
| `{mode}` | Mode & variant | enumeration | AES, 3DES, all block ciphers |
| `{mode}` (HPKE) | Mode & variant | enumeration | HPKE |
| `{symmetricCipher}` | Mode & variant | algorithm ref | ECIES, HPKE, PBES |
| `{cipherAlgorithm}` | Mode & variant | algorithm ref | CMAC, AES-KW |
| `{cipherAlgorithm}` (DRBG) | Mode & variant | algorithm ref | CTR_DRBG |
| `{blockCipher}` (DRBG) | Mode & variant | algorithm ref | Fortuna, Yarrow |
| `{encryptionAlgorithm}` | Mode & variant | algorithm ref | PBES1, PBES2 |
| `{kem}` | Mode & variant | KEM identifier | HPKE |
| `{otherBlockCipher}` | Mode & variant | algorithm ref | ChaCha |
| `{hashAlgorithm}` | Hash & digest | algorithm ref | HMAC, HKDF, PBKDF2, ECDSA, DSA, LMS, XMSS, SLH-DSA… |
| `{maskGenAlgorithm}` | Hash & digest | algorithm ref | RSAES-OAEP, RSASSA-PSS |
| `{prfFunction}` | Hash & digest | algorithm ref | SP800-108 |
| `{auxFunction}` | Hash & digest | algorithm ref | SP800-56C |
| `{hashfun}/{nbits}/{treeHeight}` | Hash & digest | composite integers | LMS, LMOTS, XMSS, XMSSMT |
| `{ellipticCurve}` | Curve & group | curve identifier | ECDSA, ECDH, ECIES, EdDSA, BLS, SM2… |
| `{namedGroup}` | Curve & group | group identifier | FFDH, J-PAKE, SRP, SPAKE2, HPKE |
| `{group}` | Curve & group | group identifier | OPAQUE, SPAKE2, SPAKE2PLUS, J-PAKE |
| `{tagLength}` | Auth & tag | integer (bits) | AES-GCM, AES-CCM, HMAC, UMAC, KMAC |
| `{ivLength}` | Auth & tag | integer (bits) | AES-GCM, AES-CCM, ChaCha20-Poly1305 |
| `{mac}` | Auth & tag | algorithm ref | HPKE, ECIES, J-PAKE, OPAQUE |
| `{macAlgorithm}` | Auth & tag | algorithm ref | PBMAC1 |
| `{aead}` | Auth & tag | AEAD identifier | HPKE |
| `{kdf}` | KDF & password | algorithm ref | HPKE, ECIES, OPAQUE, X3DH |
| `{iterations}` | KDF & password | positive integer | PBKDF1, PBKDF2, bcrypt, PBES |
| `{memoryKiB}` | KDF & password | positive integer (KiB) | Argon2 |
| `{passes}` | KDF & password | positive integer | Argon2 |
| `{parallelism}` | KDF & password | positive integer | Argon2 |
| `{saltLenBytes}` | KDF & password | integer (bytes) | Argon2, PBKDF2, scrypt, bcrypt |
| `{N}` | KDF & password | power of 2 | scrypt |
| `{r}` | KDF & password | positive integer | scrypt |
| `{p}` | KDF & password | positive integer | scrypt |
| `{cost}` | KDF & password | integer (log2) | bcrypt |
| `{ksf}` | KDF & password | algorithm ref | OPAQUE |
| `{N_log2}` | KDF & password | integer (log2) | yescrypt |
| `{t}` (yescrypt) | KDF & password | non-negative integer | yescrypt |
| `{padding}` | Padding & IV | enumeration | AES-CBC, CAMELLIA, ARIA, SEED, RSA |
| `{compressionRounds}/{finalizationRounds}` | Protocol & misc | integer pair | SipHash |
| `{SRP version}` | Protocol & misc | enumeration | SRP |
| `{k}` (ML-DSA) | PQC internal | integer | ML-DSA |
| `{l}` (ML-DSA) | PQC internal | integer | ML-DSA |
| `{eta}` (ML-DSA) | PQC internal | integer | ML-DSA |
| `{gamma1}` | PQC internal | integer (power of 2) | ML-DSA |
| `{gamma2}` | PQC internal | integer | ML-DSA |
| `{tau}` | PQC internal | integer | ML-DSA |
| `{lambda}` | PQC internal | integer (bits) | ML-DSA |
| `{omega}` (ML-DSA) | PQC internal | integer | ML-DSA |
| `{beta}` (ML-DSA) | PQC internal | integer | ML-DSA |
| `{q}` (ML-DSA) | PQC internal | prime integer | ML-DSA |
| `{k}` (ML-KEM) | PQC internal | integer | ML-KEM |
| `{du}` | PQC internal | integer (bits) | ML-KEM |
| `{dv}` | PQC internal | integer (bits) | ML-KEM |
| `{eta1}` | PQC internal | integer | ML-KEM |
| `{eta2}` | PQC internal | integer | ML-KEM |
| `{q}` (ML-KEM) | PQC internal | prime integer | ML-KEM |
| `{n}` (SLH-DSA) | PQC internal | integer (bytes) | SLH-DSA |
| `{h}` (SLH-DSA) | PQC internal | integer | SLH-DSA |
| `{d}` (SLH-DSA) | PQC internal | integer | SLH-DSA |
| `{a}` (SLH-DSA) | PQC internal | integer | SLH-DSA |
| `{k}` (SLH-DSA) | PQC internal | integer | SLH-DSA |
| `{w}` / `{lg_w}` | PQC internal | integer | SLH-DSA |
| `{h_prime}` (SLH-DSA) | PQC internal | integer | SLH-DSA |
| `{m}` (SLH-DSA) | PQC internal | integer (bytes) | SLH-DSA |
| `{n}` (FN-DSA) | PQC internal | integer | FN-DSA |
| `{q}` (FN-DSA) | PQC internal | prime integer | FN-DSA |
| `{sigma}` (FN-DSA) | PQC internal | floating-point | FN-DSA |
| `{signingMode}` | PQC protocol | enumeration | ML-DSA, SLH-DSA, FN-DSA |
| `{deterministicSigning}` | PQC protocol | enumeration | ML-DSA |
| `{context}` | PQC protocol | byte string (0–255 B) | ML-DSA, SLH-DSA, FN-DSA |
| `{hybridKemCombiner}` | PQC protocol | enumeration | ML-KEM (hybrid TLS) |
| `{floatingPointMode}` | PQC protocol | enumeration | FN-DSA |

---

## Sources

### Registries and community resources

- [CycloneDX Cryptography Registry](https://cyclonedx.org/registry/cryptography/) — algorithm families and variant patterns
    - [cryptography-defs.json](https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.json) — machine-readable definitions (last updated 2026-02-24)
    - [cryptography-defs.schema.json](https://cyclonedx.org/schema/cryptography-defs.schema.json) — JSON Schema for validation
    - [CycloneDX specification repository](https://github.com/CycloneDX/specification) — full spec source
- [SPDX Cryptographic Algorithm List](https://github.com/spdx/cryptographic-algorithm-list) — algorithm identifiers for SBOM
    - [SPDX project overview](https://spdx.dev/about/overview/)
- [NIST PQC Forum](https://groups.google.com/a/list.nist.gov/g/pqc-forum) — official NIST mailing list for PQC standardisation discussions
    - [NIST PQC standardisation project](https://csrc.nist.gov/projects/post-quantum-cryptography)

### NIST FIPS standards (post-quantum)

- NIST FIPS 203 — ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
    - [CSRC landing page](https://csrc.nist.gov/pubs/fips/203/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf)
    - DOI: [10.6028/NIST.FIPS.203](https://doi.org/10.6028/NIST.FIPS.203)
- NIST FIPS 204 — ML-DSA (Module-Lattice-Based Digital Signature Standard)
    - [CSRC landing page](https://csrc.nist.gov/pubs/fips/204/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)
    - DOI: [10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)
- NIST FIPS 205 — SLH-DSA (Stateless Hash-Based Digital Signature Standard)
    - [CSRC landing page](https://csrc.nist.gov/pubs/fips/205/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf)
    - DOI: [10.6028/NIST.FIPS.205](https://doi.org/10.6028/NIST.FIPS.205)
- NIST FIPS 206 — FN-DSA (FFT over NTRU-Lattice-Based Digital Signature Algorithm / Falcon; **Initial Public Draft** — IPD submitted for Department of Commerce clearance August 2025; final standard expected late 2026 / early 2027)
    - [CSRC landing page](https://csrc.nist.gov/pubs/fips/206/ipd)
    - Interim reference: Falcon Round 3.1 specification at [falcon-sign.info](https://falcon-sign.info/)

### NIST Special Publications

- NIST SP 800-90Ar1 — Recommendation for Random Number Generation Using Deterministic Random Bit Generators (DRBGs)
    - [CSRC landing page](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
    - DOI: [10.6028/NIST.SP.800-90Ar1](https://doi.org/10.6028/NIST.SP.800-90Ar1)
- NIST SP 800-132 — Recommendation for Password-Based Key Derivation (PBKDF2)
    - [CSRC landing page](https://csrc.nist.gov/pubs/sp/800/132/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
    - Note: revision under development (announced 2023) to add Argon2 and scrypt
- NIST SP 800-208 — Recommendation for Stateful Hash-Based Signature Schemes (LMS, XMSS)
    - [CSRC landing page](https://csrc.nist.gov/pubs/sp/800/208/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf)
    - DOI: [10.6028/NIST.SP.800-208](https://doi.org/10.6028/NIST.SP.800-208)

### IETF RFCs

- IETF LAMPS WG — Use of ML-DSA in the Cryptographic Message Syntax (CMS)
    - Track via [IETF LAMPS WG documents](https://datatracker.ietf.org/wg/lamps/documents/) (draft-ietf-lamps-cms-ml-dsa or successor RFC)
- IETF CFRG — The OPAQUE Asymmetric PAKE Protocol
    - Track via [IETF CFRG documents](https://datatracker.ietf.org/wg/cfrg/documents/) (draft-irtf-cfrg-opaque or successor RFC)
- RFC 9180 — Hybrid Public Key Encryption (HPKE)
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc9180)
    - DOI: [10.17487/RFC9180](https://doi.org/10.17487/RFC9180)
- RFC 9106 — Argon2 Memory-Hard Function for Password Hashing
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc9106)
    - DOI: [10.17487/RFC9106](https://doi.org/10.17487/RFC9106)
- RFC 8554 — Leighton-Micali Hash-Based Signatures (LMS)
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc8554)
    - DOI: [10.17487/RFC8554](https://doi.org/10.17487/RFC8554)
- RFC 8391 — XMSS: eXtended Merkle Signature Scheme
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc8391)
    - DOI: [10.17487/RFC8391](https://doi.org/10.17487/RFC8391)
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA)
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc8032)
    - DOI: [10.17487/RFC8032](https://doi.org/10.17487/RFC8032)
- RFC 8017 — PKCS #1: RSA Cryptography Specifications Version 2.2
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc8017)
    - DOI: [10.17487/RFC8017](https://doi.org/10.17487/RFC8017)
- RFC 8018 — PKCS #5: Password-Based Cryptography Specification v2.1 (PBKDF2, PBES, PBMAC1)
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc8018)
    - DOI: [10.17487/RFC8018](https://doi.org/10.17487/RFC8018)
- RFC 7914 — The scrypt Password-Based Key Derivation Function
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc7914)
    - DOI: [10.17487/RFC7914](https://doi.org/10.17487/RFC7914)
- RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc5869)
    - DOI: [10.17487/RFC5869](https://doi.org/10.17487/RFC5869)
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
    - [rfc-editor.org](https://www.rfc-editor.org/info/rfc2104)
    - DOI: [10.17487/RFC2104](https://doi.org/10.17487/RFC2104)

### IETF Internet-Drafts (active)

- `draft-ietf-tls-hybrid-design` — Hybrid key exchange in TLS 1.3 (ML-KEM + classical KEM)
    - [Latest version on datatracker](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
    - [HTML rendering of current draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design)
- `draft-ietf-cose-falcon` — FN-DSA for JOSE and COSE
    - [Datatracker](https://datatracker.ietf.org/doc/draft-ietf-cose-falcon/)
- `draft-turner-lamps-cms-fn-dsa` — Use of FN-DSA in CMS
    - [Datatracker](https://datatracker.ietf.org/doc/draft-turner-lamps-cms-fn-dsa/)

### Research papers

- Fluhrer, S. and Dang, Q. (2024). *Smaller Sphincs+* — proposes alternative SLH-DSA parameter sets for reduced signing volumes; cited in NIST PQC forum additional parameter sets request thread
    - [IACR ePrint 2024/018](https://eprint.iacr.org/2024/018)
    - [PDF](https://eprint.iacr.org/2024/018.pdf)