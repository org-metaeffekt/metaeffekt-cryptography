# Inventory of Implementations, Libraries and Runtimes

Curated catalogue of reference implementations, production-quality libraries, test-vector
repositories, and analysis tools tracked in `ae-cryptography-inventory.xlsx`.
Entries are grouped by role; each versioned row in the spreadsheet corresponds to one entry here.

---

## 1. PQC Reference Implementations

Official and near-official C implementations maintained by the algorithm submitters or by NIST.

### 1.1 CRYSTALS (ML-KEM / ML-DSA)

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| kyber | UNRELEASED | C + AVX2 | `ML-KEM-[512\|768\|1024]` | https://github.com/pq-crystals/kyber |
| dilithium | UNRELEASED | C + AVX2 | `ML-DSA-[44\|65\|87]-*` | https://github.com/pq-crystals/dilithium |

Official CRYSTALS reference implementations. NIST FIPS 203/204 were derived from these repos;
they track submission rounds via branches (`standard`, `master`) without formal releases.
For production use prefer `mlkem-native` / `mldsa-native`.

### 1.2 PQ Code Package (PQCP)

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| mlkem-native-1.0.0 | 1.0.0 | C90 + AArch64/AVX2 | `ML-KEM-[512\|768\|1024]` | https://github.com/pq-code-package/mlkem-c-aarch64 |
| mldsa-native | UNRELEASED | C90 | `ML-DSA-[44\|65\|87]-(hedged)` | https://github.com/pq-code-package/mldsa-c |
| slhdsa-c | UNRELEASED | C | `SLH-DSA-*` | https://github.com/pq-code-package/slhdsa-c |
| mlkem-libjade | UNRELEASED | Jasmin | `ML-KEM-[512\|768\|1024]` | https://github.com/formosa-crypto/libjade |

PQCP is the recommended migration target from PQClean. `mlkem-native` is C90-portable with
CBMC formal verification of functional correctness. `mldsa-native` is in alpha; `mlkem-libjade`
is formally verified at the Jasmin/EasyCrypt level.

### 1.3 SLH-DSA / SPHINCS+

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| sphincsplus | UNRELEASED | C | `SLH-DSA-*` | https://github.com/sphincs/sphincsplus |

No formal releases; rolls with submission-round commits.

### 1.4 FN-DSA / Falcon

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| falcon | UNRELEASED | C | `FN-DSA-[512\|1024]` | https://falcon-sign.info/ |
| falcon-py | UNRELEASED | Python | `FN-DSA-[512\|1024]` | https://github.com/tprest/falcon.py |

The primary C reference is distributed as a Round 3.1 zip from `falcon-sign.info` rather than
a GitHub tag. `falcon-py` is Thomas Prest's Python reference used for test-vector generation.
NTRU-related patents (Security Innovation) were placed in the public domain in March 2017.

### 1.5 HQC

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| hqc-5.0.0 | 5.0.0 | C | `HQC-[128\|192\|256]` | https://gitlab.com/pqc-hqc/hqc |
| hqc-4.0.0 | 4.0.0 | C | `HQC-[128\|192\|256]` | https://gitlab.com/pqc-hqc/hqc |
| hqc-py | UNRELEASED | Python | `HQC-[128\|192\|256]` | https://github.com/mjosaarinen/hqc-py |

HQC was selected by NIST on 11 March 2025 as the fifth PQC algorithm (code-based backup KEM).
A draft FIPS standard is expected in 2026, with finalisation in 2027. The v5.0.0 reference
implementation at `gitlab.com/pqc-hqc/hqc` is the current normative reference.
`hqc-py` by Markku-Juhani Saarinen provides FIPS-compatible test vectors.

---

## 2. Framework and Ecosystem Libraries

### 2.1 Open Quantum Safe (OQS)

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| liboqs-0.15.0 | 0.15.0 | C | `ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-*, HQC-*, MAYO-*, CROSS-*, UOV-*, SNOVA-*` | https://github.com/open-quantum-safe/liboqs |
| liboqs-0.14.0 | 0.14.0 | C | `ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-*, HQC-*, MAYO-*, CROSS-*, UOV-*, SNOVA-*` | https://github.com/open-quantum-safe/liboqs |
| oqs-provider-0.10.0-rc1 | 0.10.0-rc1 | C (OpenSSL provider) | `ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-*, HQC-*, MAYO-*, CROSS-*, UOV-*, SNOVA-*` | https://github.com/open-quantum-safe/oqs-provider |
| oqs-provider-0.9.0 | 0.9.0 | C (OpenSSL provider) | `ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-*, HQC-*, MAYO-*, CROSS-*, UOV-*, SNOVA-*` | https://github.com/open-quantum-safe/oqs-provider |

`liboqs-0.15.0` is the last release to support SPHINCS+ under its pre-FIPS name alongside
SLH-DSA. Future releases use the standardised SLH-DSA name exclusively.

`oqs-provider` ML-KEM, ML-DSA, and SLH-DSA are **disabled at runtime** when running against
OpenSSL >= 3.5.0, since OpenSSL 3.5.0 ships native support for those algorithms. oqs-provider
remains the route for experimental and candidate algorithms (MAYO, CROSS, UOV, SNOVA, etc.).

### 2.2 PQClean and pqm4

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| pqclean | UNRELEASED | C | `ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-[512\|1024]` | https://github.com/PQClean/PQClean |
| pqm4 | UNRELEASED | C + ARM | `ML-KEM-*, ML-DSA-*, SLH-DSA-*, FN-DSA-[512\|1024]` | https://github.com/mupq/pqm4 |

PQClean maintenance ended January 2026; the GitHub repository will be archived as read-only in
July 2026 (announced on the PQC forum). Migrate to the PQ Code Package (mlkem-native, mldsa-native).

`pqm4` is an ARM Cortex-M4 PQC benchmarking framework widely used for constrained-device evaluation.
It depends on PQClean sources and will require a migration path after the PQClean archive.

---

## 3. Round 2 Additional Signature Candidates

Implementations are at submission quality, not production quality. Many do not use semantic
version tags. The Round 2 tweak deadline was January 2025. NIST is evaluating candidates with
down-selection expected mid-to-late 2025 and a final standard potentially by 2026-2027
(NIST IR 8545). CROSS and MAYO are currently prioritised.

### 3.1 Multivariate-based

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| mayo-c | UNRELEASED | C | `MAYO-[1\|2\|3\|5]` | https://github.com/PQCMayo/MAYO-C |
| snova | UNRELEASED | C + AVX2 | `SNOVA-*` | https://github.com/PQCSNOVA/SNOVA |
| pqov | UNRELEASED | C | `UOV-*` | https://github.com/pqov/pqov |
| qr-uov | UNRELEASED | C | `QR-UOV-*` | https://github.com/qr-uov/qr-uov |
| mqom-v2 | UNRELEASED | C | `MQOM-*` | https://github.com/mqom/mqom |
| mirith-nist-submission | UNRELEASED | C | `Mirath-*` | https://github.com/mirith-nist-submission/mirith |

MAYO is an oil-and-vinegar variant; SNOVA, pqov (UOV), and QR-UOV are members of the
Oil-and-Vinegar family. Mirath is the result of the merger of MIRA and MiRitH (MinRank in the Head).

### 3.2 Lattice-based

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| hawk-sign | UNRELEASED | C | `HAWK-[512\|1024]` | https://github.com/hawk-sign/hawk |

HAWK is based on the Lattice Isomorphism Problem (LIP), designed by Ducas, Postlethwaite, Pulles,
and van Woerden. Uses NTRU lattices without the floating-point Gaussian sampler of Falcon.

### 3.3 Code-based

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| cross-implementation | UNRELEASED | C | `CROSS-*` | https://github.com/CROSS-signature/CROSS-implementation |
| less | UNRELEASED | C | `LESS-*` | https://github.com/less-sign/less |
| ryde | UNRELEASED | C | `RYDE-*` | https://github.com/ryde-signature/ryde |

CROSS (Codes and Restricted Objects Signature Scheme) and LESS (Linear Equivalence Signature
Scheme) are based on code equivalence problems. LESS, PERK, RYDE, and QR-UOV do not have
widely maintained public GitHub organisations as of Q1 2026; implementations are distributed
via algorithm websites and the NIST CSRC submission packages.

### 3.4 MPC-in-the-Head (MitH)

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| faest-ref | UNRELEASED | C | `FAEST-[128s\|128f\|192s\|192f\|256s\|256f]` | https://github.com/faest-sign/faest-ref |
| faest-avx-2.0.1 | 2.0.1 | C++ + AVX2 | `FAEST-[128s\|128f\|192s\|192f\|256s\|256f]` | https://github.com/faest-sign/faest-avx |
| sdith | UNRELEASED | C | `SDitH-*` | https://github.com/SDitH-team/SDitH |
| perk | UNRELEASED | C | `PERK-*` | https://github.com/perk-signature/perk |

FAEST (VOLEitH construction, AES-based witness) is at version 2.0.1 for the AVX2-optimised
implementation, matching the FAEST v2 specification. The reference C implementation (`faest-ref`)
tracks the same spec version without semantic tags. SDitH (Syndrome Decoding in the Head) is based
on the Hamming quasi-cyclic problem.

### 3.5 Isogeny-based

| Id | Version | Language | PQC patterns | URL |
|:---|:---|:---|:---|:---|
| sqisign-ec23 | UNRELEASED | C | `SQIsign-*` | https://github.com/SQISign/SQISign-EC-2023 |
| sqisign2d-west-ac24 | UNRELEASED | C | `SQIsign2D-*` | https://github.com/SQISign/SQISign2D-West-AC-2024 |

SQIsign (Supersingular Isogeny Signature) relies on isogeny-based hardness. `ec23` is the
EUROCRYPT 2023 C implementation; `ac24` is the improved ASIACRYPT 2024 variant.
Both are research-quality implementations.

---

## 4. Test-Vector, Tooling and Analysis Repositories

| Id | Version | Description | URL |
|:---|:---|:---|:---|
| acvp-server-1.1.0.41 | 1.1.0.41 | NIST ACVP-Server — CAVP test vectors for ML-KEM, ML-DSA, SLH-DSA | https://github.com/usnistgov/ACVP-Server |
| kat | UNRELEASED | NIST post-quantum-cryptography/KAT — XMSS and LMS KAT vectors | https://github.com/post-quantum-cryptography/KAT |
| draft-kwiatkowski-tls-ecdhe-mlkem | UNRELEASED | TLS hybrid KEM draft (X25519 + ML-KEM-768) — IETF reference implementation | https://github.com/post-quantum-cryptography/draft-kwiatkowski-tls-ecdhe-mlkem |
| sdith-parameters | UNRELEASED | SDitH parameter selection reference | https://github.com/sdith/sdith-parameters |
| kernel-pmu | UNRELEASED | XKCP/Kernel-PMU — PMU side-channel analysis tooling (cited in KyberSlash thread) | https://github.com/XKCP/Kernel-PMU |
| alteq-py | UNRELEASED | alteq-py — ALTEQ forgery demonstration (Saarinen, OFFICIAL COMMENT: ALTEQ) | https://github.com/mjosaarinen/alteq-py |
| slh-dsa-py | UNRELEASED | slh-dsa-py — SLH-DSA Python test-vector reference (Saarinen, FIPS 205 IPD) | https://github.com/mjosaarinen/slh-dsa-py |
| crystals-go | UNRELEASED | crystals-go — Go CRYSTALS implementation, ARCHIVED (KyberSlash patch applied, then retired) | https://github.com/cloudflare/circl |

`kernel-pmu` provides Linux PMU access from kernel modules; it was cited in the KyberSlash
(CVE-2023-49722) thread as tooling used to demonstrate cache-timing side channels.
`alteq-py` demonstrates a practical forgery against ALTEQ; included here as a documented
cryptanalysis artefact, not a production implementation.
`crystals-go` is archived — the KyberSlash vulnerability was patched but the repo was
subsequently retired in favour of CIRCL.

---

## 5. Production Cryptographic Libraries

Libraries in this section are suitable for production deployments. Version rows in the
spreadsheet record the latest and one previous stable release per major/minor series.

### 5.1 OpenSSL

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| openssl-3.6.1 | 3.6.1 | C | ML-KEM, ML-DSA, SLH-DSA (FIPS provider); default TLS 1.3 key-share X25519+ML-KEM-768 | https://github.com/openssl/openssl |
| openssl-3.5.0 | 3.5.0 | C | ML-KEM, ML-DSA, SLH-DSA first introduced as native FIPS-provider algorithms | https://github.com/openssl/openssl |

OpenSSL 3.5.0 is the first release with native (non-OQS) ML-KEM, ML-DSA, and SLH-DSA support
in the FIPS provider. Deploying oqs-provider against OpenSSL >= 3.5.0 disables those algorithms
in the provider to avoid duplication (see §2.1).

### 5.2 BoringSSL and AWS-LC

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| boringssl | UNRELEASED | C | ML-KEM; rolling snapshots (Chrome, Android, gRPC) | https://boringssl.googlesource.com/boringssl |
| aws-lc-1.71.0 | 1.71.0 | C | ML-KEM, ML-DSA; first open-source library with ML-KEM in FIPS 140-3 validation | https://github.com/aws/aws-lc |
| aws-lc-1.70.0 | 1.70.0 | C | ML-KEM, ML-DSA; FIPS 140-3 validated | https://github.com/aws/aws-lc |

BoringSSL is a Google-maintained OpenSSL fork used in Chrome, Android, and gRPC. It does not
follow semantic versioning; consumers pin a specific git commit. AWS-LC is an AWS fork of
BoringSSL with a FIPS 140-3 validation module; ML-KEM is the first PQC algorithm to appear
in that validated boundary.

### 5.3 Embedded TLS (Mbed-TLS, wolfSSL)

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| mbedtls-4.0.0 | 4.0.0 | C | ML-KEM-[512\|768\|1024]; ML-DSA on roadmap Q2 2026; parallel LTS 3.6.x branch | https://github.com/Mbed-TLS/mbedtls |
| mbedtls-3.6.5 | 3.6.5 | C | No PQC (classical algorithms only); LTS 3.6.x branch | https://github.com/Mbed-TLS/mbedtls |
| wolfssl-5.9.0 | 5.9.0 | C | ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205); CNSA 2.0 compliant | https://github.com/wolfSSL/wolfssl |
| wolfssl-5.8.4 | 5.8.4 | C | ML-KEM, ML-DSA, SLH-DSA (FIPS 203/204/205) | https://github.com/wolfSSL/wolfssl |

Mbed-TLS 4.0 and 3.6.x are maintained in parallel; 4.x is the API-breaking major release with
ML-KEM added; the 3.6.x LTS branch provides the stable ABI for existing integrations.
wolfSSL targets the CNSA 2.0 algorithm suite and is widely used in FIPS-certified embedded products.

### 5.4 GnuTLS / libgcrypt / Nettle

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| gnutls-3.8.12 | 3.8.12 | C | ML-KEM-768 (experimental, via liboqs or leancrypto); hybrid X25519+ML-KEM-768 TLS | https://gitlab.gnome.org/GNOME/gnutls |
| gnutls-3.7.6 | 3.7.6 | C | No PQC | https://gitlab.gnome.org/GNOME/gnutls |
| libgcrypt-1.12.1 | 1.12.1 | C | No PQC | https://gnupg.org/software/libgcrypt/ |
| libgcrypt-1.11.0 | 1.11.0 | C | No PQC | https://gnupg.org/software/libgcrypt/ |
| nettle-4.0.0 | 4.0.0 | C | No PQC | https://www.lysator.liu.se/~nisse/nettle/ |
| nettle-3.10.2 | 3.10.2 | C | No PQC | https://www.lysator.liu.se/~nisse/nettle/ |

This stack underlies much of the Linux ecosystem (GnuPG, GnuTLS, many RPM-based distributions).
None currently support PQC natively; ML-KEM in GnuTLS requires building with `--with-liboqs`
or `--with-leancrypto`. GnuTLS 3.8.x defaults the experimental hybrid key share to
X25519+ML-KEM-768 when PQC support is enabled.

### 5.5 Mozilla NSS

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| nss-3.122 | 3.122 | C | ML-KEM, ML-DSA | https://hg.mozilla.org/projects/nss |
| nss-3.121 | 3.121 | C | ML-KEM, ML-DSA | https://hg.mozilla.org/projects/nss |

NSS is the crypto and TLS library used by Firefox and many Linux distributions. ML-KEM support
ships in current Firefox releases; NSS follows a Mozilla-versioned release cadence independent
of Firefox version numbers.

### 5.6 Bouncy Castle (Java / C#)

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| bc-java-1.83 | 1.83 | Java | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, composite signatures | https://github.com/bcgit/bc-java |
| bc-java-1.82 | 1.82 | Java | ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, composite signatures | https://github.com/bcgit/bc-java |
| bc-csharp-2.6.2 | 2.6.2 | C# / .NET | ML-KEM, ML-DSA, SLH-DSA | https://github.com/bcgit/bc-csharp |
| bc-csharp-2.5.1 | 2.5.1 | C# / .NET | ML-KEM, ML-DSA, SLH-DSA (introduced in 2.5.0) | https://github.com/bcgit/bc-csharp |

Bouncy Castle is one of the most comprehensive PQC-capable JVM libraries. The Java version
additionally covers FN-DSA, HQC, and composite (classical + PQC) signature formats. The C#
implementation mirrors the Java PQC coverage with a slight release lag.

### 5.7 libsodium

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| libsodium-1.0.21 | 1.0.21 | C | No PQC | https://github.com/jedisct1/libsodium |
| libsodium-1.0.20 | 1.0.20 | C | No PQC | https://github.com/jedisct1/libsodium |

libsodium is a high-level, opinionated crypto library exposing X25519, Ed25519,
ChaCha20-Poly1305, Argon2id, and scrypt. No PQC algorithms are planned for the current API
design; users requiring PQC alongside libsodium-style ergonomics are directed to libsodium
wrappers layered on top of oqs or AWS-LC.

### 5.8 Crypto++ (C++)

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| cryptopp-8.9.0 | 8.9.0 | C++ | No PQC (last official release, Oct 2023) | https://github.com/weidai11/cryptopp |
| cryptopp-8.8.0 | 8.8.0 | C++ | No PQC | https://github.com/weidai11/cryptopp |

Crypto++ 8.9.0 (October 2023) is the last official release of the library. PQC is not in scope
for the current maintainership. Projects depending on Crypto++ for new deployments should
evaluate migration to OpenSSL 3.5+ or AWS-LC.

### 5.9 RustCrypto

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| rustcrypto-traits | UNRELEASED | Rust | AES, ChaCha20-Poly1305, SHA, HMAC, ECDH, EdDSA, ECDSA, HKDF, ML-KEM, ML-DSA, SLH-DSA | https://github.com/RustCrypto/traits |
| rustcrypto-kems | UNRELEASED | Rust | ML-KEM-[512\|768\|1024] (ml-kem 0.2.3) | https://github.com/RustCrypto/KEMs |

RustCrypto is a collection of independent Rust crates published to crates.io under individual
version numbers rather than a monorepo release. `ml-kem` (crates.io) is the ML-KEM FIPS 203
crate at version 0.2.3; `ml-dsa` and `slh-dsa` crates are available under RustCrypto/signatures
and RustCrypto/KEMs respectively.

### 5.10 Go standard library

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| go-stdlib-1.26.1 | 1.26.1 | Go | ML-KEM-768 (TLS default since 1.24), ML-DSA-[44\|65\|87]-* (added in 1.26) | https://pkg.go.dev/crypto |
| go-stdlib-1.25.8 | 1.25.8 | Go | ML-KEM-768 (TLS default); ML-DSA not yet included | https://pkg.go.dev/crypto |

The Go standard library `crypto` package has included X25519MLKEM768 as the default TLS 1.3
key-share algorithm since Go 1.24. ML-DSA was added in Go 1.26. Both are in `crypto/internal`
packages promoted to stable APIs. No cgo required; pure-Go implementations.

### 5.11 OpenJDK (JCA / JCE)

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| openjdk-26 | 26 | Java | ML-KEM-[512\|768\|1024], ML-DSA-[44\|65\|87]-* (native JCA); HPKE API GA | https://openjdk.org |
| openjdk-25 | 25 | Java | ML-KEM/ML-DSA APIs in incubating preview; HPKE not yet GA | https://openjdk.org |

OpenJDK 26 is expected to include ML-KEM and ML-DSA as GA JCA algorithm identifiers,
following the JEP track that began with incubating preview in JDK 25. The HPKE API was
introduced in JDK 26 under JEP 496. No external library dependency required; implementations
are in the JDK's native `sun.security` provider.

### 5.12 Google Tink

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| tink-java-1.21.0 | 1.21.0 | Java | ML-KEM-768/1024, ML-DSA-87, hybrid KEM (DHKEM+ML-KEM) | https://github.com/google/tink |
| tink-java-1.20.0 | 1.20.0 | Java | ML-KEM-768/1024, ML-DSA-87, hybrid KEM | https://github.com/google/tink |
| tink-go-2.6.0 | 2.6.0 | Go | ML-KEM-768/1024, ML-DSA-87 | https://github.com/google/tink |
| tink-go-2.5.0 | 2.5.0 | Go | ML-KEM-768/1024, ML-DSA-87 | https://github.com/google/tink |

Google Tink is an opinionated, high-level crypto API that intentionally exposes only
security-reviewed parameter combinations. PQC support is limited to the higher-security
parameter sets (ML-KEM-768/1024, ML-DSA-87) to prevent accidental use of weaker configurations.

### 5.13 Cloudflare CIRCL

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| circl-1.6.3 | 1.6.3 | Go | ML-KEM-[512\|768\|1024], ML-DSA-[44\|65\|87]-*, SLH-DSA-*, FrodoKEM-*, hybrid KEMs | https://github.com/cloudflare/circl |

CIRCL (Cloudflare Interoperable Reusable Cryptographic Library) is used in Cloudflare's
production TLS infrastructure. It is notable for including FrodoKEM (conservative
lattice-based KEM) and hybrid KEM constructions alongside the NIST-standardised algorithms.
The archived `crystals-go` (also in the spreadsheet) was a predecessor to the CRYSTALS
implementations now in CIRCL.

### 5.14 Python libraries (pyca/cryptography, PyCryptodome, PyNaCl)

| Id | Version | Language | PQC status | URL |
|:---|:---|:---|:---|:---|
| pyca-cryptography-46.0.6 | 46.0.6 | Python / C (OpenSSL backend) | ML-KEM, ML-DSA, SLH-DSA via OpenSSL >= 3.5 backend | https://github.com/pyca/cryptography |
| pyca-cryptography-45.0.7 | 45.0.7 | Python / C (OpenSSL backend) | PQC availability depends on OpenSSL backend version at runtime | https://github.com/pyca/cryptography |
| pycryptodome-3.23.0 | 3.23.0 | Python / C | No PQC | https://github.com/Legrandin/pycryptodome |
| pycryptodome-3.22.0 | 3.22.0 | Python / C | No PQC | https://github.com/Legrandin/pycryptodome |
| pynacl-1.6.2 | 1.6.2 | Python (libsodium bindings) | No PQC | https://github.com/pyca/pynacl |
| pynacl-1.5.0 | 1.5.0 | Python (libsodium bindings) | No PQC | https://github.com/pyca/pynacl |

`pyca/cryptography` inherits PQC support directly from its OpenSSL backend: applications using
OpenSSL >= 3.5.0 gain ML-KEM, ML-DSA, and SLH-DSA without any code changes, provided the
system's OpenSSL build includes the FIPS provider. PyCryptodome and PyNaCl have no PQC roadmap
items as of Q1 2026.

---

## 6. Remarks

1. **pq-crystals/kyber and pq-crystals/dilithium** — These are the official CRYSTALS reference
   implementations. NIST's FIPS 203/204 were derived from these but the repos themselves have
   not cut formal releases; they track the NIST submission rounds via branches (`standard`,
   `master`). For production use, prefer `mlkem-native` / `mldsa-native`.

2. **PQClean** — Maintenance ended January 2026; GitHub repository will be archived as read-only
   in July 2026 (announced on PQC forum). The recommended migration path is the PQ Code Package
   (mlkem-native, mldsa-native). Libraries depending on PQClean source should migrate now.

3. **oqs-provider** — ML-KEM, ML-DSA, and SLH-DSA are **disabled at runtime** when running
   against OpenSSL >= 3.5.0, since OpenSSL 3.5.0 ships native support for those algorithms.
   oqs-provider continues to be the route for experimental/candidate algorithms (MAYO, CROSS,
   UOV, SNOVA, etc.).

4. **liboqs 0.15.0** — This is the last liboqs release to support SPHINCS+ under its pre-FIPS name.
   Future releases will use the standardised name SLH-DSA exclusively. Projects referencing
   SPHINCS+ by name in algorithm identifiers should plan for a rename migration.

5. **HQC FIPS standardisation** — HQC was selected by NIST on March 11, 2025 as the fifth PQC
   algorithm (code-based backup KEM). A draft FIPS standard is expected in 2026, with finalisation
   in 2027. No FIPS number has been assigned yet. The v5.0.0 reference implementation at
   `gitlab.com/pqc-hqc/hqc` is the current normative reference.

6. **Round 2 additional signatures** — Implementations are at submission-quality, not production
   quality. Many do not use semantic version tags; the Round 2 tweak deadline was January 2025.
   NIST is evaluating additional signature candidates (CROSS, MAYO prioritised) with down-selection
   expected mid-to-late 2025 and final standard potentially by 2026-2027 (NIST IR 8545).
   LESS, PERK, RYDE, and QR-UOV do not have widely-found public GitHub organisations as of
   Q1 2026; implementations are distributed via their respective algorithm websites and the
   NIST CSRC submission packages.

7. **FAEST-avx v2.0.1** — The AVX2-optimised C++ implementation is at version 2.0.1, matching
   the FAEST v2 specification. The reference C implementation (`faest-ref`) tracks the same
   spec version but does not use semantic tags.

8. **Archive URL format** — For repos without formal tags, the `.../archive/refs/heads/main.tar.gz`
   URL always gives the current HEAD of the default branch. For tagged repos,
   `.../archive/refs/tags/{version}.tar.gz` gives the specific release.

9. **Mbed-TLS dual-branch maintenance** — Mbed-TLS 4.0.0 introduced breaking API changes alongside
   ML-KEM support. The 3.6.x LTS branch continues with security backports only; ML-DSA is planned
   for the 4.x line on the Q2 2026 roadmap, not for 3.6.x.

10. **AWS-LC FIPS 140-3 boundary** — AWS-LC 1.70.0+ is the first open-source library to include
    ML-KEM within a FIPS 140-3 validated cryptographic module boundary (AWS CAVP certificate).
    This makes it a reference point for organisations with FIPS compliance requirements that must
    also deploy ML-KEM.

11. **Go stdlib X25519MLKEM768 default** — Since Go 1.24 the TLS 1.3 implementation sends
    X25519MLKEM768 as the first key-share by default (draft-ietf-tls-hybrid-design). This is the
    same algorithm combination tracked in `draft-kwiatkowski-tls-ecdhe-mlkem` in the tooling
    section above.

12. **OpenJDK PQC roadmap** — JEP 496 (ML-KEM) and JEP 497 (ML-DSA) are targeting GA status
    in OpenJDK 26 (September 2026 release). JDK 25 exposed these as Preview APIs. Projects
    building on the JCA interface can adopt them via the incubating `jdk.security.jce` module
    in JDK 25 today.

13. **Cloudflare CIRCL and crystals-go** — `crystals-go` (archived) was a standalone Go
    implementation of CRYSTALS-Kyber and Dilithium. After the KyberSlash timing vulnerability
    was patched in that repo, Cloudflare retired it in favour of the CRYSTALS implementations
    now integrated into CIRCL. New Go projects should use CIRCL or the Go standard library.
