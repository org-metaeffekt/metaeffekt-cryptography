# Inventory of Implementations, Libraries and Runtimes

This directory catalogues real-world implementations of cryptographic algorithms — the
runtimes, libraries, and reference code that actually ship the algorithms described elsewhere
in this repository. It supports software composition analysis (SCA) and SBOM/CBOM workflows:
mapping an algorithm (or a registry / CycloneDX pattern) to the software that implements it,
and tracking the versions that are deployed in the field.

The catalogue lives in two spreadsheets. **The spreadsheets are the source of truth**; this
document explains their purpose, scope, and structure rather than duplicating their per-entry
contents (which would inevitably drift out of sync).

| File | Purpose |
|:---|:---|
| `ae-cryptography-asset-inventory.xlsx` | Asset inventory — the runtimes and libraries that implement cryptographic libraries or functions, each annotated with the algorithm patterns it supports. |
| `ae-cryptography-bom-inventory.xlsx` | Vulnerability-monitoring BOM — the same software expressed as components with CPE/PURL identifiers, for matching against vulnerability feeds. |

---

## Asset Inventory

Catalogues runtimes and libraries that implement cryptographic libraries or functions. The
`Patterns` column ties each entry to the algorithm-pattern vocabulary used by the YAML registry
and `cryptographic-algorithms.md`, so an entry can be resolved to the canonical algorithm
families it provides.

### Version Coverage

The asset inventory tracks the **last two major versions** of each library, and for **each**
of those majors the **latest available minor.patch** release. The preceding-major row is kept
**only while that major is still maintained** — EOL or superseded major lines are not tracked.
Libraries that have only ever had a single major line get a single row. Where a project cuts no
formal release, the `Version` is recorded as `UNRELEASED` and the relevant branch/tag is noted.

### Columns

| Column | Meaning |
|:---|:---|
| `Id` | Unique identifier: `name-version` (or just `name` when unversioned) |
| `Covered in CryptoBOM Dashboard` | Flag linking the entry to the BOM inventory |
| `Repository License` | SPDX licence expression |
| `Version` | Release version, or `UNRELEASED` / `N/A` |
| `URL` | Repository or project homepage |
| `Source Archive - URL` | Direct download for the tracked version (per-project scheme — GitHub tag tarball, project FTP, crates.io, etc.; not unified) |
| `Description` | One-line description including algorithm scope and language |
| `Version Status` | Tag/date or release-status detail |
| `Status` | `stable` / `previous` / `active` / `lts` / `retired` / `outdated code`, or empty |
| `Patterns` | Algorithm patterns the entry supports (registry / CycloneDX notation) — the join key to the algorithm catalogue |
| `Comments` | Free-text notes |
| `Patent References` | Relevant patent notes |

---

## BOM Inventory

The same runtimes and libraries, scoped for **vulnerability monitoring**: each component carries
CPE and PURL identifiers (plus inapplicable/proposed-identifier columns) so it can be matched
against vulnerability feeds such as the NVD.

### Version Coverage

The BOM inventory tracks only the **latest major.minor** line of each component, and within it
two rows — the **`.0`** release and the **latest available patch** (e.g. for a current `4.1.x`
line: `4.1.0` and `4.1.<latest>`), giving a version range for vulnerability matching.

Curation rules keep the BOM focused on what is actually deployed and what feeds report against:

- drop variants whose fixes have been upstreamed into the mainline;
- exclude reference implementations (not production-deployed; feeds will not distinguish them
  from the main project);
- do not track superseded major release lines.

---

## What is covered

The asset inventory spans the following categories (the spreadsheet holds the concrete entries
and versions):

- **Post-quantum reference implementations** — CRYSTALS (ML-KEM / ML-DSA), SLH-DSA / SPHINCS+,
  FN-DSA / Falcon, HQC, and the PQ Code Package (mlkem-native, mldsa-native, slhdsa-c).
- **PQC frameworks and tooling** — Open Quantum Safe (liboqs, oqs-provider), PQClean, pqm4,
  test-vector servers (ACVP, KAT), and the NIST Round 2 additional-signature candidates.
- **Production cryptographic libraries and runtimes** — OpenSSL, BoringSSL, AWS-LC (+ aws-lc-rs),
  Botan, Mbed-TLS, wolfSSL, GnuTLS / libgcrypt / Nettle, NSS, Bouncy Castle (Java / C#),
  libsodium, Crypto++, RustCrypto, ring, SymCrypt, HACL* / EverCrypt, the Go standard library
  and golang.org/x/crypto, OpenJDK, .NET, Google Tink, Cloudflare CIRCL, swift-crypto, Conscrypt,
  the Python libraries (pyca/cryptography, PyCryptodome, PyNaCl), and gost-engine.
- **Lightweight, regional, and protocol cryptography** — Ascon (NIST SP 800-232), the Chinese
  SM-series via GmSSL, PAKE (SPAKE2 / SPAKE2+, OPAQUE), and 3GPP/telecom algorithms (osmocom,
  open5gs).
- **Classical and historical coverage** — standalone reference implementations, OS entropy
  sources, and (non-cryptographic) PRNGs, tracked for SBOM-scanning completeness.

For the authoritative, version-accurate listing — including the algorithm patterns each entry
supports — consult `ae-cryptography-asset-inventory.xlsx` directly.
