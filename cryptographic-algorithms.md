# Cryptographic Algorithm Table

> Complete taxonomy of cryptographic algorithms, hash functions, MACs, KDFs, KEMs, signature schemes,
> and random number generators covered in this repository.
>
> **Columns:**
> - **Id** — machine-readable kebab-case identifier
> - **Name** — full name and common aliases
> - **Crypto Class** — category in the taxonomy
> - **OID** — ASN.1 Object Identifier (algorithm-level, where standardised; variant-level OIDs in References)
> - **Pattern** — representative CycloneDX pattern; `[a|b]` = enumeration choice, `{x}` = variable, `*` = wildcard
> - **References** — primary standards and specifications
>
> **Sources:** FIPS 140-3 · FIPS 180-4 · FIPS 186-5 · FIPS 197 · FIPS 198-1 · FIPS 202 · FIPS 203/204/205 ·
> FIPS 206 (IPD) · NIST SP 800-38 series · SP 800-56A/B/C · SP 800-57 · SP 800-90A/B/C · SP 800-108 ·
> SP 800-131A · SP 800-132 · SP 800-135 · SP 800-186 · SP 800-208 · BSI TR-02102-1 (2026-01) ·
> BSI AIS 20/31 v3 · RFC 5869 · RFC 7539 · RFC 8017 · RFC 8032 · RFC 8391 · RFC 8439 · RFC 8554 · RFC 9180 ·
> CycloneDX Cryptography Registry · SPDX Cryptographic Algorithm List

---

## Taxonomy

```
Cryptographic Algorithms
├── Symmetric
│   ├── Block Ciphers
│   │   ├── Approved  (AES, CAMELLIA, ARIA, SEED, SM4)
│   │   └── Legacy / Deprecated  (3DES, DES, Blowfish, Twofish, IDEA, CAST5, CAST6, RC2, RC5, RC6, Serpent, GOST-28147)
│   ├── Stream Ciphers  (ChaCha20, XChaCha20, RC4)
│   └── Block Cipher Modes
│       ├── AEAD  (GCM, CCM, OCB, GCM-SIV, SIV)
│       ├── Confidentiality only  (CBC, CTR, CFB, OFB, XTS)
│       ├── Key wrapping  (KW, KWP)
│       └── Disallowed  (ECB)
│
├── Hash Functions
│   ├── SHA-2 family  (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256)
│   ├── SHA-3 / Keccak  (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256)
│   ├── BLAKE family  (BLAKE2b, BLAKE2s, BLAKE3)
│   ├── National / regional  (SM3, GOSTR3411-2012)
│   └── Legacy / Deprecated  (SHA-1, MD5, MD4)
│
├── Message Authentication Codes (MAC)
│   ├── HMAC  (HMAC-SHA-*)
│   ├── Block-cipher MAC  (CMAC, GMAC, CBC-MAC)
│   ├── Keccak MAC  (KMAC128, KMAC256)
│   ├── Universal hash  (UMAC, Poly1305)
│   └── Authenticated encryption tag  (GCM tag via GMAC)
│
├── Asymmetric / Public-Key
│   ├── Encryption  (RSAES-OAEP, RSAES-PKCS1, ECIES)
│   ├── Digital Signatures — Classical
│   │   ├── RSA  (RSASSA-PSS, RSASSA-PKCS1)
│   │   ├── Elliptic curve  (ECDSA, EdDSA / Ed25519 / Ed448)
│   │   └── Finite field  (DSA)
│   ├── Digital Signatures — Stateful Hash-based  (LMS, LMOTS, XMSS, XMSS^MT)
│   └── Key Agreement  (ECDH, FFDH, HPKE, MQV, BLS)
│
├── Post-Quantum Cryptography
│   ├── KEM — Lattice  (ML-KEM / Kyber)
│   ├── KEM — Code-based  (HQC, FrodoKEM)
│   ├── Signatures — Lattice  (ML-DSA / Dilithium, FN-DSA / Falcon, HAWK)
│   ├── Signatures — Hash-based stateless  (SLH-DSA / SPHINCS+)
│   ├── Signatures — Multivariate  (MAYO, SNOVA, UOV / pqov, QR-UOV)
│   ├── Signatures — Code-based  (CROSS, LESS)
│   ├── Signatures — MPC-in-the-Head  (FAEST, SDitH, MQOM, Mirath, PERK, RYDE)
│   └── Signatures — Isogeny  (SQIsign, SQIsign2D)
│
├── Key Derivation Functions (KDF)
│   ├── General-purpose  (HKDF, SP800-108, SP800-56C, ANSI X9.42/X9.63)
│   ├── Password-based  (PBKDF2, bcrypt, scrypt, Argon2, yescrypt)
│   └── Protocol-specific  (TLS PRF, IKEv2 PRF)
│
└── Random Number Generators
    ├── TRNG / Entropy sources  (physical noise, OS APIs, hardware)
    ├── DRBG / CSPRNG — NIST SP 800-90A  (Hash_DRBG, HMAC_DRBG, CTR_DRBG)
    ├── DRBG / CSPRNG — Accumulator  (Fortuna, Yarrow)
    ├── DRBG / CSPRNG — Stream-cipher  (ChaCha20-DRNG)
    └── Non-cryptographic PRNG (statistical only)  (MT19937, Xoshiro, PCG, LCG)
```

---

## 1. Symmetric Block Ciphers

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `aes` | AES (Advanced Encryption Standard) · Rijndael | Symmetric block cipher | `2.16.840.1.101.3.4.1` (arc) | `AES-[128\|192\|256]-*` | FIPS 197; SP 800-38 series; SP 800-57 |
| `3des` | Triple DES · 3DES · TDEA | Symmetric block cipher (legacy) | `1.2.840.113549.3.7` | `3DES-*` | SP 800-131A Rev 2 (disallowed for enc after 2023); NIST IR 8214C |
| `des` | DES (Data Encryption Standard) | Symmetric block cipher (broken) | `1.3.14.3.2.7` | `DES-*` | FIPS 46-3 (withdrawn); SP 800-131A (disallowed) |
| `camellia` | Camellia | Symmetric block cipher | `1.2.392.200011.61.1.1.1` (arc) | `CAMELLIA-[128\|256]-*` | ISO/IEC 18033-3; BSI TR-02102-1 |
| `aria` | ARIA | Symmetric block cipher | `1.2.410.200004.1.1.1` (arc) | `ARIA-[128\|192\|256]-*` | Korean standard KS X 1213; RFC 5794 |
| `seed` | SEED | Symmetric block cipher | `1.2.410.200004.1.3` | `SEED-*` | Korean standard KS X 1213; RFC 4269 |
| `sm4` | SM4 · SMS4 | Symmetric block cipher | `1.2.156.10197.1.104` | `SM4-*` | GM/T 0002-2012; ISO/IEC 18033-3 |
| `blowfish` | Blowfish | Symmetric block cipher (deprecated) | — | `Blowfish-*` | Schneier 1993; 64-bit block — deprecated |
| `twofish` | Twofish | Symmetric block cipher | — | `Twofish-[128\|192\|256]-*` | AES finalist (1998) |
| `idea` | IDEA (International Data Encryption Algorithm) | Symmetric block cipher (deprecated) | `1.3.6.1.4.1.188.7.1.1.2` | `IDEA-*` | Lai & Massey 1991; BSI removed |
| `cast5` | CAST-128 · CAST5 | Symmetric block cipher (deprecated) | `1.2.840.113533.7.66.10` | `CAST5-*` | RFC 2144; 64-bit block |
| `cast6` | CAST-256 · CAST6 | Symmetric block cipher | — | `CAST6-[128\|192\|256]-*` | RFC 2612 |
| `rc2` | RC2 · ARC2 | Symmetric block cipher (disallowed) | `1.2.840.113549.3.2` | `RC2-*` | RFC 2268; SP 800-131A (disallowed) |
| `rc5` | RC5 | Symmetric block cipher (deprecated) | `1.2.840.113549.3.8` | `RC5-*` | Rivest 1994 |
| `rc6` | RC6 | Symmetric block cipher | — | `RC6-[128\|192\|256]-*` | AES finalist (1998) |
| `serpent` | Serpent | Symmetric block cipher | — | `Serpent-[128\|192\|256]-*` | AES finalist (1998) |
| `gost-28147-89` | GOST 28147-89 · Magma | Symmetric block cipher | `1.2.643.2.2.21` | `GOST-28147-*` | GOST R 34.12-2015; RFC 4357 |
| `grasshopper` | Grasshopper · Kuznyechik | Symmetric block cipher | `1.2.643.7.1.1.5.2` | `Grasshopper-*` | GOST R 34.12-2015; RFC 7801 |

---

## 2. Symmetric Stream Ciphers

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `chacha20` | ChaCha20 · ChaCha | Stream cipher | — | `ChaCha20-*` | RFC 8439; Bernstein 2008 |
| `xchacha20` | XChaCha20 (extended nonce) | Stream cipher | — | `XChaCha20-*` | draft-irtf-cfrg-xchacha; 192-bit nonce |
| `rc4` | RC4 · ARC4 · ARCFOUR | Stream cipher (disallowed) | — | `RC4-*` | RFC 7465 (banned in TLS); SP 800-131A (disallowed) |
| `salsa20` | Salsa20 | Stream cipher | — | `Salsa20-*` | Bernstein 2007; eSTREAM portfolio |
| `grain-128` | Grain-128AEAD | Stream cipher (lightweight) | — | `Grain-128-*` | ISO/IEC 29192-3 |

---

## 3. Block Cipher Modes

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `aes-ecb` | AES-ECB (Electronic Code Book) | Block cipher mode — disallowed | `2.16.840.1.101.3.4.1.1/21/41` | `AES-[128\|192\|256]-ECB` | SP 800-38A; FIPS 197 (disallowed for multi-block) |
| `aes-cbc` | AES-CBC (Cipher Block Chaining) | Block cipher mode — confidentiality | `2.16.840.1.101.3.4.1.2/22/42` | `AES-[128\|192\|256]-CBC` | SP 800-38A |
| `aes-ctr` | AES-CTR (Counter) | Block cipher mode — confidentiality | — | `AES-[128\|192\|256]-CTR` | SP 800-38A |
| `aes-cfb128` | AES-CFB128 (Cipher Feedback, 128-bit segment) | Block cipher mode — confidentiality | — | `AES-[128\|192\|256]-CFB128` | SP 800-38A |
| `aes-ofb` | AES-OFB (Output Feedback) | Block cipher mode — confidentiality | — | `AES-[128\|192\|256]-OFB` | SP 800-38A |
| `aes-xts` | AES-XTS (XEX Tweakable Block Cipher with Ciphertext Stealing) | Block cipher mode — storage only | — | `AES-[128\|256]-XTS` | SP 800-38E; IEEE 1619 |
| `aes-gcm` | AES-GCM (Galois/Counter Mode) | AEAD mode | `2.16.840.1.101.3.4.1.6/26/46` | `AES-[128\|192\|256]-GCM` | SP 800-38D; FIPS 197 |
| `aes-ccm` | AES-CCM (Counter with CBC-MAC) | AEAD mode | `2.16.840.1.101.3.4.1.7/27/47` | `AES-[128\|192\|256]-CCM` | SP 800-38C; RFC 3610 |
| `aes-gcm-siv` | AES-GCM-SIV (Nonce-Misuse Resistant) | AEAD mode | — | `AES-[128\|256]-GCM-SIV` | RFC 8452 |
| `aes-ocb` | AES-OCB (Offset Code Book) | AEAD mode | — | `AES-[128\|192\|256]-OCB` | RFC 7253; SP 800-38F |
| `aes-siv` | AES-SIV (Synthetic IV) | Deterministic AEAD | — | `AES-[128\|256]-SIV` | RFC 5297 |
| `aes-cfb1` | AES-CFB1 (Cipher Feedback, 1-bit segment) | Block cipher mode — confidentiality | — | `AES-[128\|192\|256]-CFB1` | SP 800-38A |
| `aes-cfb8` | AES-CFB8 (Cipher Feedback, 8-bit segment) | Block cipher mode — confidentiality | — | `AES-[128\|192\|256]-CFB8` | SP 800-38A |
| `aes-pcbc` | AES-PCBC (Propagating CBC) | Block cipher mode — legacy | — | `AES-[128\|192\|256]-PCBC` | —; error-propagating CBC variant; no NIST standard |
| `aes-cts` | AES-CTS (Ciphertext Stealing) | Block cipher mode — confidentiality | — | `AES-[128\|192\|256]-CTS` | SP 800-38A §E; avoids padding for CBC |
| `aes-kw` | AES-KW (Key Wrap) | Key wrapping | `2.16.840.1.101.3.4.1.5/25/45` | `AES-KW-[128\|192\|256]` | SP 800-38F; RFC 3394 |
| `aes-kwp` | AES-KWP (Key Wrap with Padding) | Key wrapping | — | `AES-KWP-[128\|192\|256]` | SP 800-38F; RFC 5649 |
| `3des-tkw` | 3DES-TKW (Triple-DES Key Wrap) | Key wrapping (legacy) | — | `3DES-TKW` | SP 800-38F §6.3; key-wrapping only; 3DES deprecated |
| `aes-eax` | AES-EAX | AEAD mode | — | `AES-[128\|192\|256]-EAX` | Bellare, Rogaway & Wagner 2003; no NIST standard |
| `aes-cwc` | AES-CWC (Carter-Wegman + CTR) | AEAD mode | — | `AES-[128\|192\|256]-CWC` | Kohno et al. 2004; largely superseded by GCM |
| `aes-iapm` | AES-IAPM (Integrity-Aware Parallelisable Mode) | AEAD mode (historical) | — | `AES-[128\|192\|256]-IAPM` | Jutla 2001; superseded by OCB/GCM |
| `aes-ff1` | AES-FF1 (Format-Preserving Encryption) | Format-preserving encryption | — | `AES-FF1-{radix}` | NIST SP 800-38G; FF1 algorithm |
| `aes-ff3-1` | AES-FF3-1 (Format-Preserving Encryption) | Format-preserving encryption | — | `AES-FF3-1-{radix}` | NIST SP 800-38G Rev 1; replaces FF3 after attack |
| `aes-lrw` | AES-LRW (Liskov-Rivest-Wagner) | Block cipher mode — tweakable | — | `AES-[128\|256]-LRW` | Liskov, Rivest & Wagner 2002; predecessor to XTS |
| `aes-xex` | AES-XEX (XEX — XOR-Encrypt-XOR) | Block cipher mode — tweakable | — | `AES-[128\|256]-XEX` | Rogaway 2004; basis of XTS mode |
| `aes-cmc` | AES-CMC (CBC-Mask-CBC) | Block cipher mode — wide-block | — | `AES-[128\|256]-CMC` | Halevi & Rogaway 2003 |
| `aes-eme` | AES-EME / AES-EME2 (Encrypt-Mix-Encrypt) | Block cipher mode — wide-block | — | `AES-[128\|256]-EME` | Halevi 2004; EME2 / EME* variants |
| `aes-hctr2` | AES-HCTR2 | Block cipher mode — wide-block (length-preserving) | — | `AES-[128\|256]-HCTR2` | Adiantum; Google 2018; storage on low-end devices |
| `chacha20-poly1305` | ChaCha20-Poly1305 | AEAD mode | — | `ChaCha20-Poly1305` | RFC 8439; BSI TR-02102-1 |
| `xchacha20-poly1305` | XChaCha20-Poly1305 | AEAD mode | — | `XChaCha20-Poly1305` | draft-irtf-cfrg-xchacha |
| `adiantum` | Adiantum (ChaCha12 + AES-HCTR2 + Poly1305) | Length-preserving AEAD mode (disk/storage) | — | `Adiantum-*` | Google 2018; RFC 9369; Android for ARMv7 devices |

---

## 4. Hash Functions

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `sha-1` | SHA-1 · SHA | Hash function (deprecated) | `1.3.14.3.2.26` | `SHA-1` | FIPS 180-4; SP 800-131A (disallowed for digital signatures) |
| `sha-224` | SHA-224 · SHA2-224 | Hash function | `2.16.840.1.101.3.4.2.4` | `SHA-224` | FIPS 180-4; SP 800-131A Rev 3 IPD (disallowed after 2030) |
| `sha-256` | SHA-256 · SHA2-256 | Hash function | `2.16.840.1.101.3.4.2.1` | `SHA-256` | FIPS 180-4; SP 800-57 |
| `sha-384` | SHA-384 · SHA2-384 | Hash function | `2.16.840.1.101.3.4.2.2` | `SHA-384` | FIPS 180-4; SP 800-57 |
| `sha-512` | SHA-512 · SHA2-512 | Hash function | `2.16.840.1.101.3.4.2.3` | `SHA-512` | FIPS 180-4; SP 800-57 |
| `sha-512-224` | SHA-512/224 | Hash function | `2.16.840.1.101.3.4.2.5` | `SHA-512-224` | FIPS 180-4 |
| `sha-512-256` | SHA-512/256 | Hash function | `2.16.840.1.101.3.4.2.6` | `SHA-512-256` | FIPS 180-4 |
| `sha3-224` | SHA3-224 · Keccak-224 | Hash function (SHA-3) | `2.16.840.1.101.3.4.2.7` | `SHA3-224` | FIPS 202 |
| `sha3-256` | SHA3-256 · Keccak-256 | Hash function (SHA-3) | `2.16.840.1.101.3.4.2.8` | `SHA3-256` | FIPS 202 |
| `sha3-384` | SHA3-384 · Keccak-384 | Hash function (SHA-3) | `2.16.840.1.101.3.4.2.9` | `SHA3-384` | FIPS 202 |
| `sha3-512` | SHA3-512 · Keccak-512 | Hash function (SHA-3) | `2.16.840.1.101.3.4.2.10` | `SHA3-512` | FIPS 202 |
| `shake128` | SHAKE128 | Extendable-output function (XOF) | `2.16.840.1.101.3.4.2.11` | `SHAKE128[-{outputLength}]` | FIPS 202 |
| `shake256` | SHAKE256 | Extendable-output function (XOF) | `2.16.840.1.101.3.4.2.12` | `SHAKE256[-{outputLength}]` | FIPS 202 |
| `cshake128` | cSHAKE128 (customisable SHAKE128) | Extendable-output function (XOF) | — | `cSHAKE128[-{outputLength}]` | NIST SP 800-185 |
| `cshake256` | cSHAKE256 (customisable SHAKE256) | Extendable-output function (XOF) | — | `cSHAKE256[-{outputLength}]` | NIST SP 800-185 |
| `blake2b` | BLAKE2b · BLAKE2b-256 · BLAKE2b-512 | Hash function | — | `BLAKE2b-{outputLength}` | RFC 7693 |
| `blake2s` | BLAKE2s · BLAKE2s-256 | Hash function | — | `BLAKE2s-{outputLength}` | RFC 7693 |
| `blake3` | BLAKE3 | Hash function / XOF | — | `BLAKE3[-{outputLength}]` | BLAKE3 spec 2020 |
| `sm3` | SM3 | Hash function | `1.2.156.10197.1.401` | `SM3` | GM/T 0004-2012; ISO/IEC 10118-3 |
| `gostr3411-2012` | GOST R 34.11-2012 · Streebog | Hash function | `1.2.643.7.1.1.2.2` (256) · `1.2.643.7.1.1.2.3` (512) | `GOSTR3411-2012-[256\|512]` | RFC 6986; GOST R 34.11-2012 |
| `md5` | MD5 | Hash function (broken) | `1.2.840.113549.2.5` | `MD5` | RFC 1321; SP 800-131A (disallowed) |
| `md4` | MD4 | Hash function (broken) | `1.2.840.113549.2.4` | `MD4` | RFC 1320 (disallowed) |
| `siphash` | SipHash · SipHash-2-4 | Keyed hash / PRF (non-cryptographic use only) | — | `SipHash-{outputLength}` | Aumasson & Bernstein 2012 |

---

## 5. Message Authentication Codes (MAC)

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `hmac` | HMAC | Keyed hash MAC | `1.2.840.113549.2.7` (HMAC-SHA-1 arc) | `HMAC[-{hashAlgorithm}]` | FIPS 198-1; RFC 2104; SP 800-107 |
| `hmac-sha1` | HMAC-SHA-1 | Keyed hash MAC | `1.2.840.113549.2.7` | `HMAC-SHA-1` | FIPS 198-1 (legacy use only) |
| `hmac-sha256` | HMAC-SHA-256 | Keyed hash MAC | `1.2.840.113549.2.9` | `HMAC-SHA-256` | FIPS 198-1; SP 800-57 |
| `hmac-sha384` | HMAC-SHA-384 | Keyed hash MAC | `1.2.840.113549.2.10` | `HMAC-SHA-384` | FIPS 198-1 |
| `hmac-sha512` | HMAC-SHA-512 | Keyed hash MAC | `1.2.840.113549.2.11` | `HMAC-SHA-512` | FIPS 198-1 |
| `hmac-sha3-256` | HMAC-SHA3-256 | Keyed hash MAC | — | `HMAC-SHA3-256` | FIPS 198-1; FIPS 202 |
| `hmac-sha3-384` | HMAC-SHA3-384 | Keyed hash MAC | — | `HMAC-SHA3-384` | FIPS 198-1; FIPS 202 |
| `hmac-sha3-512` | HMAC-SHA3-512 | Keyed hash MAC | — | `HMAC-SHA3-512` | FIPS 198-1; FIPS 202 |
| `aes-cmac` | AES-CMAC · OMAC1 | Block cipher MAC | `0.4.0.127.0.7.1.1.4.1.2` | `AES-CMAC[-{keyLength}]` | SP 800-38B; RFC 4493 |
| `kmac128` | KMAC128 | Keccak-based MAC | `2.16.840.1.101.3.4.2.19` | `KMAC128[-{outputLength}]` | NIST SP 800-185 |
| `kmac256` | KMAC256 | Keccak-based MAC | `2.16.840.1.101.3.4.2.20` | `KMAC256[-{outputLength}]` | NIST SP 800-185 |
| `poly1305` | Poly1305 · Poly1305-AES | One-time polynomial MAC | — | `Poly1305[-{cipherAlgorithm}]` | RFC 8439; Bernstein 2005 |
| `gmac` | GMAC (GCM used as MAC) | Block cipher MAC | — | `AES-[128\|192\|256]-GMAC` | SP 800-38D |
| `umac` | UMAC | Universal hash-based MAC | — | `UMAC-[32\|64\|96\|128]` | RFC 4418 |
| `cbc-mac` | CBC-MAC | Block cipher MAC (deprecated standalone use) | — | `CBC-MAC-*` | ANSI X9.19 (legacy) |

---

## 6. Asymmetric Encryption

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `rsaes-oaep` | RSAES-OAEP (RSA with Optimal Asymmetric Encryption Padding) | Asymmetric encryption | `1.2.840.113549.1.1.7` | `RSAES-OAEP-{keyLength}-{hashAlgorithm}` | RFC 8017; SP 800-131A |
| `rsaes-pkcs1` | RSAES-PKCS1-v1.5 | Asymmetric encryption (deprecated) | `1.2.840.113549.1.1.1` | `RSAES-PKCS1-{keyLength}` | RFC 8017 (deprecated for encryption) |
| `ecies` | ECIES (Elliptic Curve Integrated Encryption Scheme) | Asymmetric encryption | — | `ECIES-{curve}-{hashAlgorithm}` | SEC 1; ISO/IEC 18033-2 |

---

## 7. Digital Signatures — Classical

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `rsassa-pss` | RSASSA-PSS (RSA with Probabilistic Signature Scheme) | Digital signature | `1.2.840.113549.1.1.10` | `RSASSA-PSS-{keyLength}-{hashAlgorithm}` | RFC 8017; FIPS 186-5; SP 800-131A |
| `rsassa-pkcs1` | RSASSA-PKCS1-v1.5 | Digital signature (legacy) | `1.2.840.113549.1.1.5` (SHA-256) | `RSASSA-PKCS1-{keyLength}-{hashAlgorithm}` | RFC 8017; FIPS 186-5 (deprecated for new use) |
| `ecdsa` | ECDSA (Elliptic Curve Digital Signature Algorithm) | Digital signature | `1.2.840.10045.4.3.2` (P-256/SHA-256) | `ECDSA-{curve}-{hashAlgorithm}` | FIPS 186-5; SP 800-186; RFC 5758 |
| `eddsa` | EdDSA (Edwards-curve Digital Signature Algorithm) | Digital signature | `1.3.101.112` (Ed25519) · `1.3.101.113` (Ed448) | `EdDSA-(Ed25519\|Ed448)` | RFC 8032; FIPS 186-5 |
| `ed25519` | Ed25519 | Digital signature | `1.3.101.112` | `Ed25519` | RFC 8032; FIPS 186-5 |
| `ed448` | Ed448 · Ed448-Goldilocks | Digital signature | `1.3.101.113` | `Ed448` | RFC 8032; FIPS 186-5 |
| `dsa` | DSA (Digital Signature Algorithm) | Digital signature (deprecated) | `1.2.840.10040.4.1` | `DSA-{keyLength}-{hashAlgorithm}` | FIPS 186-4 (withdrawn 2023); SP 800-131A |
| `sm2` | SM2 (signature scheme) | Digital signature | `1.2.156.10197.1.501` | `SM2-*` | GM/T 0003-2012 |
| `gostr3410-2012` | GOST R 34.10-2012 · Grasshopper DSA | Digital signature | `1.2.643.7.1.1.3.2` | `GOSTR3410-2012-*` | RFC 7091; GOST R 34.10-2012 |

---

## 8. Digital Signatures — Stateful Hash-Based

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `lms` | LMS (Leighton-Micali Signatures) | Stateful hash-based signature | `1.2.840.113549.1.9.16.3.17` | `LMS-{hashAlgorithm}-H{treeHeight}` | RFC 8554; NIST SP 800-208 |
| `lmots` | LMOTS (Leighton-Micali One-Time Signatures) | One-time signature component of LMS | — | `LMOTS-{hashAlgorithm}-W{winternitz}` | RFC 8554; NIST SP 800-208 |
| `xmss` | XMSS (eXtended Merkle Signature Scheme) | Stateful hash-based signature | `0.4.0.127.0.15.1.1.13.0` (arc) | `XMSS-{hashAlgorithm}` | RFC 8391; NIST SP 800-208 |
| `xmss-mt` | XMSS^MT (multi-tree XMSS) | Stateful hash-based signature | — | `XMSSMT-{hashAlgorithm}` | RFC 8391; NIST SP 800-208 |

---

## 9. Key Agreement

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `ecdh` | ECDH (Elliptic Curve Diffie-Hellman) | Key agreement | `1.3.132.1.12` | `ECDH-{curve}` | SP 800-56A Rev 3; FIPS 186-5 |
| `x25519` | X25519 (ECDH over Curve25519) | Key agreement | `1.3.101.110` | `ECDH-Curve25519` | RFC 7748; SP 800-186 |
| `x448` | X448 (ECDH over Curve448) | Key agreement | `1.3.101.111` | `ECDH-Curve448` | RFC 7748; SP 800-186 |
| `ffdh` | FFDH (Finite Field Diffie-Hellman) | Key agreement | — | `FFDH-{groupName}` | SP 800-56A Rev 3; RFC 7919 |
| `hpke` | HPKE (Hybrid Public-Key Encryption) | Key agreement + encryption | — | `HPKE-{kemVariant}-{kdfVariant}-{aeadVariant}` | RFC 9180 |
| `mqv` | MQV (Menezes-Qu-Vanstone) | Authenticated key agreement | — | `MQV-{curve}` | SP 800-56A Rev 3 |
| `bls` | BLS (Boneh-Lynn-Shacham) pairing | Key agreement / signature | — | `BLS-{curve}` | IETF draft-irtf-cfrg-bls-signature |

---

## 10. Elliptic Curves and Named Groups

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `p-256` | P-256 · secp256r1 · prime256v1 | Elliptic curve | `1.2.840.10045.3.1.7` | `ECDH-P-256` / `ECDSA-P-256-*` | FIPS 186-5; SP 800-186 |
| `p-384` | P-384 · secp384r1 | Elliptic curve | `1.3.132.0.34` | `ECDH-P-384` / `ECDSA-P-384-*` | FIPS 186-5; SP 800-186 |
| `p-521` | P-521 · secp521r1 | Elliptic curve | `1.3.132.0.35` | `ECDH-P-521` / `ECDSA-P-521-*` | FIPS 186-5; SP 800-186 |
| `curve25519` | Curve25519 (Montgomery) | Elliptic curve | `1.3.101.110` | `ECDH-Curve25519` | RFC 7748; SP 800-186 |
| `curve448` | Curve448 · Curve448-Goldilocks (Montgomery) | Elliptic curve | `1.3.101.111` | `ECDH-Curve448` | RFC 7748; SP 800-186 |
| `ed25519-curve` | Ed25519 (Edwards) | Elliptic curve (signature) | `1.3.101.112` | `Ed25519` | RFC 8032 |
| `ed448-curve` | Ed448 (Edwards) | Elliptic curve (signature) | `1.3.101.113` | `Ed448` | RFC 8032 |
| `secp256k1` | secp256k1 (Bitcoin curve) | Elliptic curve | `1.3.132.0.10` | `ECDSA-secp256k1-*` | SEC 2; not NIST-approved |
| `brainpoolp256r1` | brainpoolP256r1 | Elliptic curve | `1.3.36.3.3.2.8.1.1.7` | `ECDH-brainpoolP256r1` | RFC 5639; BSI TR-02102-1 |
| `brainpoolp384r1` | brainpoolP384r1 | Elliptic curve | `1.3.36.3.3.2.8.1.1.11` | `ECDH-brainpoolP384r1` | RFC 5639; BSI TR-02102-1 |
| `brainpoolp512r1` | brainpoolP512r1 | Elliptic curve | `1.3.36.3.3.2.8.1.1.13` | `ECDH-brainpoolP512r1` | RFC 5639; BSI TR-02102-1 |
| `sm2-curve` | SM2 curve | Elliptic curve | `1.2.156.10197.1.301` | `SM2-*` | GM/T 0003-2012 |
| `bls12-381` | BLS12-381 | Pairing-friendly elliptic curve | — | `BLS-BLS12-381` | IETF draft-irtf-cfrg-bls-signature |
| `ristretto255` | ristretto255 (Curve25519, cofactor-1 abstraction) | Elliptic curve group | — | — | draft-irtf-cfrg-ristretto255-decaf448 |
| `decaf448` | decaf448 (Curve448, cofactor-1 abstraction) | Elliptic curve group | — | — | draft-irtf-cfrg-ristretto255-decaf448 |
| `ffdhe2048` | ffdhe2048 (RFC 7919 DH group) | Finite-field group | `1.3.101.100` | `FFDH-ffdhe2048` | RFC 7919; SP 800-56A |
| `ffdhe3072` | ffdhe3072 | Finite-field group | `1.3.101.101` | `FFDH-ffdhe3072` | RFC 7919 |
| `ffdhe4096` | ffdhe4096 | Finite-field group | `1.3.101.102` | `FFDH-ffdhe4096` | RFC 7919 |
| `ffdhe6144` | ffdhe6144 | Finite-field group | `1.3.101.103` | `FFDH-ffdhe6144` | RFC 7919 |
| `ffdhe8192` | ffdhe8192 | Finite-field group | `1.3.101.104` | `FFDH-ffdhe8192` | RFC 7919 |

---

## 11. Key Derivation Functions

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `hkdf` | HKDF (HMAC-based Key Derivation Function) | Key derivation function | — | `HKDF-{hashAlgorithm}` | RFC 5869; SP 800-56C Rev 2 |
| `sp800-108` | SP 800-108 KDF (counter / feedback / pipeline) | Key derivation function | — | `SP800-108-{mode}-{prf}` | NIST SP 800-108 Rev 1 |
| `sp800-56c` | SP 800-56C KDF (one-step / two-step) | Key derivation function | — | `SP800-56C-{mode}-{hashAlgorithm}` | NIST SP 800-56C Rev 2 |
| `ansi-x9-42` | ANSI X9.42 KDF | Key derivation function | — | `ANSI-KDF-X9.42-{hashAlgorithm}` | ANSI X9.42; SP 800-56A |
| `ansi-x9-63` | ANSI X9.63 KDF | Key derivation function | — | `ANSI-KDF-X9.63-{hashAlgorithm}` | ANSI X9.63; SEC 1 |
| `tls-prf-12` | TLS 1.2 PRF | Protocol-specific KDF | — | `TLS12-PRF-{hashAlgorithm}` | RFC 5246 |
| `tls-kdf-13` | TLS 1.3 HKDF | Protocol-specific KDF | — | `TLS13-HKDF-{hashAlgorithm}` | RFC 8446 |
| `ikev2-prf` | IKEv2 PRF | Protocol-specific KDF | — | `IKEv2-PRF-{hashAlgorithm}` | RFC 7296 |
| `ssh-kdf` | SSH Key Derivation | Protocol-specific KDF | — | `SSH-KDF-{hashAlgorithm}` | RFC 4253 |

---

## 12. Password-Based Key Derivation and Password Hashing

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `pbkdf1` | PBKDF1 | Password-based KDF (deprecated) | `1.2.840.113549.1.5.3` | `PBKDF1-{hashAlgorithm}` | RFC 8018 (deprecated) |
| `pbkdf2` | PBKDF2 | Password-based KDF | `1.2.840.113549.1.5.12` | `PBKDF2-{hashAlgorithm}` | RFC 8018; NIST SP 800-132 |
| `bcrypt` | bcrypt | Password hashing function | — | `bcrypt-{cost}` | Provos & Mazières 1999 |
| `scrypt` | scrypt | Memory-hard password hashing | — | `scrypt-{N}-{r}-{p}` | RFC 7914; NIST SP 800-132 |
| `argon2i` | Argon2i | Memory-hard password hashing (data-independent) | — | `Argon2i-*` | RFC 9106; PHC winner 2015 |
| `argon2d` | Argon2d | Memory-hard password hashing (data-dependent) | — | `Argon2d-*` | RFC 9106 |
| `argon2id` | Argon2id | Memory-hard password hashing (hybrid) | — | `Argon2id-*` | RFC 9106; recommended variant |
| `yescrypt` | yescrypt | Memory-hard password hashing | — | `yescrypt-*` | UNIX /etc/shadow; Linux PAM |

---

## 13. Post-Quantum: Key Encapsulation Mechanisms

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `ml-kem-512` | ML-KEM-512 · Kyber-512 | PQC KEM (lattice) — NIST Level 1 | `2.16.840.1.101.3.4.4.1` | `ML-KEM-512` | FIPS 203; SP 800-227 (draft) |
| `ml-kem-768` | ML-KEM-768 · Kyber-768 | PQC KEM (lattice) — NIST Level 3 | `2.16.840.1.101.3.4.4.2` | `ML-KEM-768` | FIPS 203; SP 800-227 (draft) |
| `ml-kem-1024` | ML-KEM-1024 · Kyber-1024 | PQC KEM (lattice) — NIST Level 5 | `2.16.840.1.101.3.4.4.3` | `ML-KEM-1024` | FIPS 203 |
| `hqc-128` | HQC-128 | PQC KEM (code-based) — NIST Level 1 | — (FIPS draft 2026) | `HQC-128` | NIST selection March 2025; FIPS draft expected 2026 |
| `hqc-192` | HQC-192 | PQC KEM (code-based) — NIST Level 3 | — | `HQC-192` | NIST selection March 2025 |
| `hqc-256` | HQC-256 | PQC KEM (code-based) — NIST Level 5 | — | `HQC-256` | NIST selection March 2025 |
| `frodokem-640` | FrodoKEM-640 · FrodoKEM-640-AES · FrodoKEM-640-SHAKE | PQC KEM (lattice, conservative) | — | `FrodoKEM-640-*` | FrodoKEM spec; CIRCL library |
| `frodokem-976` | FrodoKEM-976 | PQC KEM (lattice, conservative) | — | `FrodoKEM-976-*` | FrodoKEM spec |
| `frodokem-1344` | FrodoKEM-1344 | PQC KEM (lattice, conservative) | — | `FrodoKEM-1344-*` | FrodoKEM spec |

---

## 14. Post-Quantum: Digital Signatures — NIST Standardised

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `ml-dsa-44` | ML-DSA-44 · Dilithium2 | PQC signature (lattice) — NIST Level 2 | `2.16.840.1.101.3.4.3.17` | `ML-DSA-44[-hedged]` | FIPS 204 |
| `ml-dsa-65` | ML-DSA-65 · Dilithium3 | PQC signature (lattice) — NIST Level 3 | `2.16.840.1.101.3.4.3.18` | `ML-DSA-65[-hedged]` | FIPS 204 |
| `ml-dsa-87` | ML-DSA-87 · Dilithium5 | PQC signature (lattice) — NIST Level 5 | `2.16.840.1.101.3.4.3.19` | `ML-DSA-87[-hedged]` | FIPS 204 |
| `slh-dsa-sha2-128s` | SLH-DSA-SHA2-128s · SPHINCS+-SHA2-128s | PQC signature (hash-based stateless) — L1 small | `2.16.840.1.101.3.4.3.20` | `SLH-DSA-SHA2-128s` | FIPS 205 |
| `slh-dsa-sha2-128f` | SLH-DSA-SHA2-128f · SPHINCS+-SHA2-128f | PQC signature (hash-based stateless) — L1 fast | `2.16.840.1.101.3.4.3.21` | `SLH-DSA-SHA2-128f` | FIPS 205 |
| `slh-dsa-sha2-192s` | SLH-DSA-SHA2-192s | PQC signature — L3 small | `2.16.840.1.101.3.4.3.22` | `SLH-DSA-SHA2-192s` | FIPS 205 |
| `slh-dsa-sha2-192f` | SLH-DSA-SHA2-192f | PQC signature — L3 fast | `2.16.840.1.101.3.4.3.23` | `SLH-DSA-SHA2-192f` | FIPS 205 |
| `slh-dsa-sha2-256s` | SLH-DSA-SHA2-256s | PQC signature — L5 small | `2.16.840.1.101.3.4.3.24` | `SLH-DSA-SHA2-256s` | FIPS 205 |
| `slh-dsa-sha2-256f` | SLH-DSA-SHA2-256f | PQC signature — L5 fast | `2.16.840.1.101.3.4.3.25` | `SLH-DSA-SHA2-256f` | FIPS 205 |
| `slh-dsa-shake-128s` | SLH-DSA-SHAKE-128s | PQC signature — L1 small (SHAKE) | `2.16.840.1.101.3.4.3.26` | `SLH-DSA-SHAKE-128s` | FIPS 205 |
| `slh-dsa-shake-128f` | SLH-DSA-SHAKE-128f | PQC signature — L1 fast (SHAKE) | `2.16.840.1.101.3.4.3.27` | `SLH-DSA-SHAKE-128f` | FIPS 205 |
| `slh-dsa-shake-192s` | SLH-DSA-SHAKE-192s | PQC signature — L3 small (SHAKE) | `2.16.840.1.101.3.4.3.28` | `SLH-DSA-SHAKE-192s` | FIPS 205 |
| `slh-dsa-shake-192f` | SLH-DSA-SHAKE-192f | PQC signature — L3 fast (SHAKE) | `2.16.840.1.101.3.4.3.29` | `SLH-DSA-SHAKE-192f` | FIPS 205 |
| `slh-dsa-shake-256s` | SLH-DSA-SHAKE-256s | PQC signature — L5 small (SHAKE) | `2.16.840.1.101.3.4.3.30` | `SLH-DSA-SHAKE-256s` | FIPS 205 |
| `slh-dsa-shake-256f` | SLH-DSA-SHAKE-256f | PQC signature — L5 fast (SHAKE) | `2.16.840.1.101.3.4.3.31` | `SLH-DSA-SHAKE-256f` | FIPS 205 |
| `fn-dsa-512` | FN-DSA-512 · Falcon-512 | PQC signature (lattice/NTRU) — NIST Level 1 | `1.3.9999.3.6` (draft) | `FN-DSA-512` | FIPS 206 (IPD); final expected late 2026 |
| `fn-dsa-1024` | FN-DSA-1024 · Falcon-1024 | PQC signature (lattice/NTRU) — NIST Level 5 | `1.3.9999.3.7` (draft) | `FN-DSA-1024` | FIPS 206 (IPD); final expected late 2026 |

---

## 15. Post-Quantum: Round 2 Additional Signature Candidates

### Multivariate

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `mayo-1` | MAYO-1 | PQC signature (multivariate UOV) — L1 | — | `MAYO-1` | NIST PQC Round 2; pqc-forum |
| `mayo-2` | MAYO-2 | PQC signature (multivariate UOV) — L1 small | — | `MAYO-2` | NIST PQC Round 2 |
| `mayo-3` | MAYO-3 | PQC signature (multivariate UOV) — L3 | — | `MAYO-3` | NIST PQC Round 2 |
| `mayo-5` | MAYO-5 | PQC signature (multivariate UOV) — L5 | — | `MAYO-5` | NIST PQC Round 2 |
| `snova` | SNOVA | PQC signature (multivariate) | — | `SNOVA-*` | NIST PQC Round 2 |
| `uov` | UOV · pqov (Unbalanced Oil and Vinegar) | PQC signature (multivariate) | — | `UOV-*` | NIST PQC Round 2 |
| `qr-uov` | QR-UOV (Quotient Ring UOV) | PQC signature (multivariate) | — | `QR-UOV-*` | NIST PQC Round 2 |

### Lattice

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `hawk-512` | HAWK-512 | PQC signature (lattice, LIP) — L1 | — | `HAWK-512` | NIST PQC Round 2 |
| `hawk-1024` | HAWK-1024 | PQC signature (lattice, LIP) — L5 | — | `HAWK-1024` | NIST PQC Round 2 |

### Code-Based

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `cross` | CROSS (Codes and Restricted Objects Signature Scheme) | PQC signature (code-based) | — | `CROSS-*` | NIST PQC Round 2; NIST IR 8545 |
| `less` | LESS (Linear Equivalence Signature Scheme) | PQC signature (code-based) | — | `LESS-*` | NIST PQC Round 2 |

### MPC-in-the-Head / Symmetric

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `faest-128s` | FAEST-128s (VOLEitH, AES-based) | PQC signature (MPC-in-the-Head) | — | `FAEST-128s` | NIST PQC Round 2 |
| `faest-128f` | FAEST-128f | PQC signature (MPC-in-the-Head) | — | `FAEST-128f` | NIST PQC Round 2 |
| `faest-192s` | FAEST-192s | PQC signature (MPC-in-the-Head) | — | `FAEST-192s` | NIST PQC Round 2 |
| `faest-192f` | FAEST-192f | PQC signature (MPC-in-the-Head) | — | `FAEST-192f` | NIST PQC Round 2 |
| `faest-256s` | FAEST-256s | PQC signature (MPC-in-the-Head) | — | `FAEST-256s` | NIST PQC Round 2 |
| `faest-256f` | FAEST-256f | PQC signature (MPC-in-the-Head) | — | `FAEST-256f` | NIST PQC Round 2 |
| `sdith` | SDitH (Syndrome Decoding in the Head) | PQC signature (MPC-in-the-Head, code) | — | `SDitH-*` | NIST PQC Round 2 |
| `mqom` | MQOM-v2 (MQ on my Mind) | PQC signature (MPC-in-the-Head, multivariate) | — | `MQOM-*` | NIST PQC Round 2 |
| `mirath` | Mirath · MiRitH · MIRA (MinRank in the Head) | PQC signature (MPC-in-the-Head, rank) | — | `Mirath-*` | NIST PQC Round 2 |
| `perk` | PERK (Permuted Kernels) | PQC signature (MPC-in-the-Head, permutation) | — | `PERK-*` | NIST PQC Round 2 |
| `ryde` | RYDE (Rank Syndrome Decoding Equivalence) | PQC signature (MPC-in-the-Head, rank) | — | `RYDE-*` | NIST PQC Round 2 |

### Isogeny-Based

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `sqisign` | SQIsign (Special Quaternion Isogeny Signature) | PQC signature (isogeny) | — | `SQIsign-*` | NIST PQC Round 2; EUROCRYPT 2023 |
| `sqisign2d` | SQIsign2D (2-dimensional variant) | PQC signature (isogeny) | — | `SQIsign2D-*` | NIST PQC Round 2; ASIACRYPT 2024 |

---

## 16. Random Number Generators — NIST SP 800-90A DRBGs

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `hash-drbg-sha256` | Hash_DRBG-SHA-256 | DRBG (hash-based) | — | `Hash_DRBG-SHA-256` | NIST SP 800-90A Rev 1 |
| `hash-drbg-sha384` | Hash_DRBG-SHA-384 | DRBG (hash-based) | — | `Hash_DRBG-SHA-384` | NIST SP 800-90A Rev 1 |
| `hash-drbg-sha512` | Hash_DRBG-SHA-512 | DRBG (hash-based) | — | `Hash_DRBG-SHA-512` | NIST SP 800-90A Rev 1 |
| `hash-drbg-sha1` | Hash_DRBG-SHA-1 | DRBG (hash-based, legacy) | — | `Hash_DRBG-SHA-1` | SP 800-90A Rev 1 (to be removed in Rev 2) |
| `hmac-drbg-sha256` | HMAC_DRBG-SHA-256 | DRBG (HMAC-based) | — | `HMAC_DRBG-SHA-256` | NIST SP 800-90A Rev 1 |
| `hmac-drbg-sha384` | HMAC_DRBG-SHA-384 | DRBG (HMAC-based) | — | `HMAC_DRBG-SHA-384` | NIST SP 800-90A Rev 1 |
| `hmac-drbg-sha512` | HMAC_DRBG-SHA-512 | DRBG (HMAC-based) | — | `HMAC_DRBG-SHA-512` | NIST SP 800-90A Rev 1 |
| `ctr-drbg-aes-128` | CTR_DRBG-AES-128 | DRBG (block cipher CTR) | — | `CTR_DRBG-AES-128` | NIST SP 800-90A Rev 1 |
| `ctr-drbg-aes-192` | CTR_DRBG-AES-192 | DRBG (block cipher CTR) | — | `CTR_DRBG-AES-192` | NIST SP 800-90A Rev 1 |
| `ctr-drbg-aes-256` | CTR_DRBG-AES-256 | DRBG (block cipher CTR) | — | `CTR_DRBG-AES-256` | NIST SP 800-90A Rev 1 |
| `ctr-drbg-3des` | CTR_DRBG-3DES | DRBG (legacy) | — | `CTR_DRBG-3DES` | SP 800-90A Rev 1 (to be removed in Rev 2) |
| `dual-ec-drbg` | Dual_EC_DRBG | DRBG — disallowed (backdoored) | — | `Dual_EC_DRBG` | SP 800-90A (withdrawn 2015); disallowed |

---

## 17. Random Number Generators — Accumulator-Based CSPRNGs

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `fortuna` | Fortuna | Accumulator-based CSPRNG | — | `Fortuna[-{blockCipher}][-{hashAlgorithm}]` | Ferguson & Schneier 2003; macOS /dev/random |
| `yarrow` | Yarrow | Accumulator-based CSPRNG (deprecated) | — | `Yarrow[-{blockCipher}][-{hashAlgorithm}]` | Kelsey, Schneier & Ferguson 1999 (superseded by Fortuna) |

---

## 18. Random Number Generators — Stream-Cipher-Based and OS APIs

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `chacha20-drng` | ChaCha20-DRNG (Linux kernel RNG) | CSPRNG (stream-cipher-based) | — | `ChaCha20-DRNG` | Linux kernel ≥ 4.8; /dev/urandom |
| `getrandom` | getrandom() syscall | OS entropy API | — | `getrandom()` | Linux ≥ 3.17; man 2 getrandom |
| `dev-urandom` | /dev/urandom | OS entropy API | — | `/dev/urandom` | Linux / macOS / BSD |
| `dev-random` | /dev/random | OS entropy API | — | `/dev/random` | Linux (= /dev/urandom since 5.6) / macOS |
| `bcryptgenrandom` | BCryptGenRandom | OS entropy API (Windows) | — | `BCryptGenRandom` | Windows CNG; CTR_DRBG-AES-256 internally |
| `getentropy` | getentropy() | OS entropy API | — | `getentropy()` | macOS ≥ 10.12; OpenBSD; glibc ≥ 2.25 |
| `rdrand` | RDRAND (Intel/AMD) | Hardware RNG | — | `RDRAND` | Intel SDM; use with OS-entropy mixing |
| `rdseed` | RDSEED (Intel/AMD) | Hardware entropy source | — | `RDSEED` | Intel SDM; raw conditioned entropy |
| `tpm-rng` | TPM RNG (TCG TPM 2.0) | Hardware RNG (trusted) | — | `TPM_RNG` | TCG TPM 2.0 specification |
| `rc4-prng` | RC4-PRNG · ARC4RANDOM (legacy) | CSPRNG (deprecated) | — | `RC4-PRNG` | BSD arc4random pre-2014 (replaced by ChaCha20) |

---

## 19. Non-Cryptographic PRNGs (Statistical Use Only)

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `mt19937` | Mersenne Twister (MT19937) | Non-cryptographic PRNG | — | `MT19937` | Matsumoto & Nishimura 1998; **not crypto-safe** |
| `xoshiro256` | Xoshiro256 (++/+/**) | Non-cryptographic PRNG | — | `Xoshiro(256\|512)(+\|++\|**)` | Blackman & Vigna 2018; **not crypto-safe** |
| `pcg` | PCG (Permuted Congruential Generator) | Non-cryptographic PRNG | — | `PCG-*` | O'Neill 2014; **not crypto-safe** |
| `lcg` | LCG (Linear Congruential Generator) | Non-cryptographic PRNG | — | `LCG-*` | Knuth 1968; **not crypto-safe** |
| `splitmix64` | SplitMix64 | Non-cryptographic PRNG | — | `SplitMix64` | Guy Steele et al.; **not crypto-safe** |

---

## 20. Padding and Encoding Schemes

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `oaep` | OAEP (Optimal Asymmetric Encryption Padding) | Padding scheme | — | `RSAES-OAEP-{keyLength}-{hashAlgorithm}` | RFC 8017; NIST SP 800-131A |
| `pss` | PSS (Probabilistic Signature Scheme) | Padding scheme | — | `RSASSA-PSS-{keyLength}-{hashAlgorithm}[-{saltLength}]` | RFC 8017; FIPS 186-5 |
| `pkcs1-v1-5` | PKCS#1 v1.5 padding | Padding scheme (deprecated for encryption) | — | `RSAES-PKCS1-{keyLength}` | RFC 8017 |
| `mgf1` | MGF1 (Mask Generation Function 1) | Mask generation function | — | `MGF1-{hashAlgorithm}` | RFC 8017 §B.2.1 |
| `pkcs7` | PKCS#7 padding | Padding scheme | — | — | RFC 5652 |

---

## 21. Composite and Hybrid Constructs

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `x25519mlkem768` | X25519+ML-KEM-768 hybrid KEM | Hybrid KEM (PQC + classical) | `1.3.9999.0.1` (draft) | `ECDH-X25519+ML-KEM-768` | IETF draft-kwiatkowski-tls-ecdhe-mlkem; Go 1.24+ TLS default |
| `x25519kyber768` | X25519+Kyber768 hybrid KEM (pre-standard) | Hybrid KEM (draft) | — | `ECDH-X25519+Kyber-768` | Cloudflare / Google deployment (pre-FIPS 203) |
| `p256mlkem768` | P-256+ML-KEM-768 hybrid KEM | Hybrid KEM | — | `ECDH-P-256+ML-KEM-768` | IETF TLS WG |
| `composite-sig` | Composite signature (classical + PQC) | Composite signature | — | `{classicalSig}+{pqcSig}` | IETF draft-ounsworth-pq-composite-sigs |

---

## 22. Additional Symmetric Block Ciphers (Historical / Legacy)

> Included for SPDX coverage. These ciphers appear in legacy software, forensic analysis, and SBOM scanning contexts but are not approved for new use.

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `3way` | 3-Way | Symmetric block cipher (historical) | — | `3Way-*` | Daemen 1994; 96-bit block |
| `tea` | TEA (Tiny Encryption Algorithm) | Symmetric block cipher (legacy) | — | `TEA-*` | Wheeler & Needham 1994; 64-bit block; broken |
| `xtea` | XTEA (eXtended TEA) | Symmetric block cipher (legacy) | — | `XTEA-*` | Wheeler & Needham 1997; patched TEA |
| `threefish` | Threefish | Symmetric block cipher (underlying Skein) | — | `Threefish-[256\|512\|1024]-*` | Ferguson et al. 2010; underlies Skein hash |
| `skipjack` | Skipjack | Symmetric block cipher (classified/historical) | — | `Skipjack-*` | NSA 1998 (declassified); 80-bit key; Clipper chip |
| `misty1` | MISTY1 | Symmetric block cipher (telecom) | `0.4.0.127.0.7.1.1.1.1.0` | `MISTY1-*` | Matsui 1997; basis of KASUMI (3GPP) |
| `kasumi` | KASUMI | Symmetric block cipher (3GPP) | — | `KASUMI-*` | 3GPP TS 35.202; derived from MISTY1; used in 2G/3G |
| `noekeon` | NOEKEON | Symmetric block cipher | — | `NOEKEON-*` | Daemen et al. 2000; NESSIE submission |
| `khazad` | Khazad | Symmetric block cipher | — | `Khazad-*` | Barreto & Rijmen 2000; NESSIE finalist |
| `shacal` | SHACAL | Symmetric block cipher (SHA-1 based) | — | `SHACAL-[1\|2]-*` | Handschuh & Naccache 2001; NESSIE |
| `fcrypt` | FC (Fast DES variant) | Symmetric block cipher (legacy) | — | `FCrypt-*` | —; DES-derived |
| `lucifer` | Lucifer | Symmetric block cipher (historical) | — | `Lucifer-*` | IBM 1970s; precursor to DES |
| `loki91` | LOKI91 | Symmetric block cipher (historical) | — | `LOKI91-*` | Brown et al. 1991 |
| `feal` | FEAL (Fast Data Encipherment Algorithm) | Symmetric block cipher (broken) | — | `FEAL-*` | Shimizu & Miyaguchi 1987; cryptanalyzed |
| `shark` | SHARK | Symmetric block cipher (historical) | — | `SHARK-*` | Daemen et al. 1996; precursor to Rijndael |
| `multi2` | MULTI2 | Symmetric block cipher (broadcast) | — | `MULTI2-*` | Hitachi; used in ISDB broadcast encryption |
| `cobra` | Cobra | Symmetric block cipher | — | `Cobra-*` | —; AES finalist era |
| `ice` | ICE (Information Concealment Engine) | Symmetric block cipher | — | `ICE-*` | Kwan 1997 |
| `juniper` | Juniper | Symmetric block cipher | — | `Juniper-*` | — |
| `nimbus` | Nimbus | Symmetric block cipher | — | `Nimbus-*` | — |
| `tcrypt` | TCrypt | Symmetric block cipher | — | `TCrypt-*` | — |
| `zipcrypt` | ZipCrypt | Symmetric encryption (ZIP legacy) | — | `ZipCrypt-*` | PKZIP legacy; cryptographically weak |

---

## 23. Additional Stream Ciphers (eSTREAM Portfolio and Telecom)

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `zuc` | ZUC (祖冲之) | Stream cipher (3GPP) | — | `ZUC-*` | 3GPP TS 35.221; 128-EEA3/128-EIA3; LTE/5G |
| `snow-3g` | SNOW 3G | Stream cipher (3GPP) | — | `SNOW-3G-*` | 3GPP TS 35.216; UEA2/UIA2; active in LTE |
| `snow-v` | SNOW-V | Stream cipher (5G candidate) | — | `SNOW-V-*` | Ekdahl et al. 2019; 5G candidate |
| `rabbit` | Rabbit | Stream cipher | — | `Rabbit-*` | Boesgaard et al. 2003; eSTREAM portfolio (SW) |
| `hc-128` | HC-128 | Stream cipher | — | `HC-128` | Wu 2004; eSTREAM portfolio (SW) |
| `hc-256` | HC-256 | Stream cipher | — | `HC-256` | Wu 2004; eSTREAM portfolio (SW) |
| `sosemanuk` | SOSEMANUK | Stream cipher | — | `SOSEMANUK-*` | Berbain et al. 2005; eSTREAM portfolio (SW) |
| `f8` | f8 (UMTS confidentiality) | Stream cipher mode (3GPP) | — | `f8-*` | 3GPP TS 35.201; uses KASUMI |
| `panama` | PANAMA | Hash / stream cipher (broken) | — | `PANAMA-*` | Daemen & Clapp 1998; broken |
| `seal` | SEAL (Software-Optimised Encryption Algorithm) | Stream cipher (legacy) | — | `SEAL-*` | Rogaway & Coppersmith 1994 |
| `quad` | QUAD | Stream cipher (multivariate) | — | `QUAD-*` | Berbain et al. 2006 |
| `sober` | SOBER / SOBER-128 | Stream cipher | — | `SOBER-*` | Rose 1998; eSTREAM candidate |
| `vmpc` | VMPC (Variably Modified Permutation Composition) | Stream cipher | — | `VMPC-*` | Zoltak 2004 |
| `wake` | WAKE (Word Auto Key Encryption) | Stream cipher | — | `WAKE-*` | Wheeler 1993 |
| `cmea` | CMEA (Cellular Message Encryption Algorithm) | Stream cipher (broken) | — | `CMEA-*` | CTIA standard; broken 1997 |
| `gea` | GEA (GPRS Encryption Algorithm) | Stream cipher (telecom, weak) | — | `GEA-[0\|1\|2\|3\|4\|5]-*` | 3GPP GPRS; GEA-1 intentionally weakened (2021 disclosure) |

---

## 24. Additional Hash Functions (Historical and Specialised)

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `md2` | MD2 | Hash function (broken) | `1.2.840.113549.2.2` | `MD2` | RFC 1319; SP 800-131A (disallowed) |
| `md6` | MD6 | Hash function (withdrawn) | — | `MD6-{outputLength}` | Rivest et al. 2008; SHA-3 candidate; withdrawn |
| `ripemd` | RIPEMD family | Hash function | `1.3.36.3.2.1` (RIPEMD-160) | `RIPEMD-[128\|160\|256\|320]` | ISO/IEC 10118-3 |
| `whirlpool` | Whirlpool | Hash function | `1.0.10118.3.0.55` | `Whirlpool` | ISO/IEC 10118-3; NESSIE |
| `tiger` | Tiger | Hash function | — | `Tiger-[128\|160\|192]` | Anderson & Biham 1996; 192-bit output |
| `skein` | Skein | Hash function / XOF | — | `Skein-[256\|512\|1024]-{outputLength}` | Ferguson et al. 2010; SHA-3 finalist; underlies BLAKE3 ideas |
| `haval` | HAVAL | Hash function | — | `HAVAL-{passes}-{outputLength}` | Zheng et al. 1992; variable output/passes |
| `mdc2` | MDC-2 | Hash function (Matyas-Meyer-Oseas) | `1.3.14.7.2.1.1` | `MDC-2` | ISO/IEC 10118-2 |
| `snerfu` | SNERFU | Hash function | — | `SNERFU-*` | — |
| `fnv1` | FNV-1 / FNV-1a (Fowler–Noll–Vo) | Non-cryptographic hash | — | `FNV1-[32\|64\|128]-*` | Fowler, Noll & Vo 1991; **not crypto-safe** |
| `fasthash` | FastHash | Non-cryptographic hash | — | `FastHash-*` | — |

---

## 25. Non-Cryptographic Checksums

> Not suitable for any security-relevant purpose. Included for SBOM scanning completeness.

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `crc32` | CRC-32 (Cyclic Redundancy Check) | Checksum (non-cryptographic) | — | `CRC-32` | ISO 3309; Ethernet; ZIP |
| `crc16` | CRC-16 | Checksum (non-cryptographic) | — | `CRC-16` | — |
| `adler32` | Adler-32 | Checksum (non-cryptographic) | — | `Adler-32` | RFC 1950; zlib |
| `fletcher` | Fletcher's Checksum | Checksum (non-cryptographic) | — | `Fletcher-[16\|32\|64]` | Fletcher 1982 |

---

## 26. Additional Asymmetric Schemes (Historical)

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `elgamal` | ElGamal | Asymmetric encryption / signature | `1.3.14.7.2.1.1` | `ElGamal-{keyLength}` | Taher ElGamal 1985; used in OpenPGP (RFC 4880) |
| `ntruencrypt` | NTRUEncrypt | Asymmetric encryption (lattice, historical) | — | `NTRUEncrypt-{paramSet}` | NTRU Cryptosystems 1996; patents in public domain (Security Innovation, 2017) |
| `rabin` | Rabin | Asymmetric encryption | — | `Rabin-{keyLength}` | Rabin 1979 |
| `blum-goldwasser` | Blum-Goldwasser | Asymmetric encryption (probabilistic) | — | `BlumGoldwasser-*` | Blum & Goldwasser 1984 |
| `luc` | LUC | Asymmetric encryption (Lucas sequence) | — | `LUC-{keyLength}` | Smith & Lennon 1993 |
| `xtr` | XTR | Asymmetric (compact DH variant) | — | `XTR-*` | Lenstra & Verheul 2000 |
| `srp` | SRP (Secure Remote Password) | Password-authenticated key exchange | — | `SRP-{version}-{hashAlgorithm}` | RFC 2945; RFC 5054 (TLS-SRP) |
| `mceliece` | McEliece | Asymmetric encryption (code-based, historical) | — | `McEliece-*` | McEliece 1978; basis for modern code-based PQC |

---

## 27. PKCS and Protocol Encoding Frameworks

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `pbes1` | PBES1 (Password-Based Encryption Scheme 1) | Password-based encryption (deprecated) | `1.2.840.113549.1.5.3` (arc) | `PBES1-{hashAlgorithm}-{cipherAlgorithm}` | RFC 8018 §6.1; deprecated in favour of PBES2 |
| `pbes2` | PBES2 (Password-Based Encryption Scheme 2) | Password-based encryption | `1.2.840.113549.1.5.13` | `PBES2-{kdfAlgorithm}-{encAlgorithm}` | RFC 8018 §6.2; PKCS#5 v2.1 |
| `pbe` | PBE (Password-Based Encryption, generic) | Password-based encryption framework | — | `PBE-*` | PKCS#5; RFC 8018 |
| `pkcs12` | PKCS#12 (PFX) | Key/certificate bundle format | `1.2.840.113549.1.12` | — | RFC 7292; certificate + private key containers |
| `x509` | X.509 | PKI certificate framework | `2.5.4` (arc) | — | ITU-T X.509; RFC 5280 |
| `cms` | CMS (Cryptographic Message Syntax) | Signed/encrypted message format | `1.2.840.113549.1.9.16` (arc) | — | RFC 5652 |
| `asn1` | ASN.1 (Abstract Syntax Notation One) | Encoding / serialisation framework | — | — | ITU-T X.680; DER/BER encoding of cryptographic structures |

---

## 28. Additional Password Hashing (Windows / System)

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `mscash` | MSCash (Domain Cached Credentials v1) | Password hashing (Windows) | — | `MSCash-*` | Windows NT/2000; MD4-based; weak |
| `mscash2` | MSCash2 (Domain Cached Credentials v2) | Password hashing (Windows) | — | `MSCash2-*` | Windows Vista+; PBKDF2-SHA1(10240 iterations); weak |

---

## 29. Additional Random Number Generators

| Id | Name | Crypto Class | OID | Pattern | References |
|:---|:---|:---|:---|:---|:---|
| `isaac` | ISAAC (Indirection, Shift, Accumulate, Add, Count) | PRNG (fast; not NIST-approved) | — | `ISAAC` | Jenkins 1996; fast non-cryptographic PRNG |
| `ansi-x931` | ANSI X9.31 PRNG | PRNG / RNG standard (legacy) | — | `ANSIX931-{blockCipher}` | ANSI X9.31 (withdrawn 2011; removed from FIPS 140-2 approved list 2016) |

---

## Summary Counts

| Category | Count |
|:---|:---|
| Symmetric block ciphers (approved + legacy) | 40 |
| Symmetric stream ciphers | 21 |
| Block cipher modes (inc. AEAD, FPE, tweakable) | 35 |
| Hash functions and XOFs | 34 |
| Non-cryptographic checksums | 4 |
| Message authentication codes | 15 |
| Asymmetric encryption and key exchange | 11 |
| Classical digital signatures | 9 |
| Stateful hash-based signatures | 4 |
| Key agreement algorithms | 7 |
| Named elliptic curves and groups | 20 |
| Key derivation functions | 9 |
| Password hashing (incl. Windows) | 10 |
| Password-based encryption frameworks | 3 |
| PKCS / protocol frameworks | 7 |
| PQC KEMs | 9 |
| PQC signatures — NIST standardised | 17 |
| PQC signatures — Round 2 candidates | 20 |
| NIST SP 800-90A DRBGs | 12 |
| Accumulator-based CSPRNGs | 2 |
| OS entropy APIs and hardware RNGs | 10 |
| Non-cryptographic PRNGs | 6 |
| Padding / encoding schemes | 5 |
| Composite / hybrid constructs | 4 |
| **Total** | **~314** |

---

## SPDX Coverage Notes

Cross-referenced against the [SPDX Cryptographic Algorithm List](https://github.com/spdx/cryptographic-algorithm-list/tree/main/yaml) (127 entries).

| Status | Count |
|:---|:---|
| SPDX entries covered | ~127 |
| Entries added solely for SPDX coverage (sections 22–29) | ~74 |
| Entries present in this table not in SPDX | ~167 (PQC, modes, curves, RNGs, KDFs) |

SPDX entries not mapped (no standard cryptographic definition found): `dcc`, `ssha` (salted SHA — implementation convention, not an algorithm), `blakex` (BLAKE umbrella — covered by BLAKE2/3).
