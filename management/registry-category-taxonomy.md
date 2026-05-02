# Registry Category Taxonomy

> [!NOTE]
> Specification for the proposed `category:` field on registry algorithm entries. The
> field carries a path-valued functional taxonomy aligned with the section
> structure of `cryptographic-algorithms.md`. Companion to `registry-design-v2.md`.

## Purpose

Add a single optional field `category:` to algorithm entries in `cr-*.yaml`. Its
value is a `/`-separated path expressing the algorithm's *function*. Multiple
consumers (Summary Counts table, top-level dashboards, future tooling) derive
their views from this single field via prefix queries.

This is **functional taxonomy only**. Standardisation lineage (Round 2
candidate vs NIST-standardised vs broken vs legacy) is an orthogonal axis and
will be carried by a separate field — see [Deferred Decisions](#deferred-decisions).

## Field Definition

| Field | Type | Cardinality | Vocabulary |
|:---|:---|:---|:---|
| `category` | string (`/`-separated path) | optional, single value | controlled (see [Vocabulary](#vocabulary)) |

Single primary category per entry — no `categories:` list. When an algorithm
could arguably belong to two branches, the deeper path captures the secondary axis
(e.g. AES-GCM is `symmetric/block-cipher/mode/aead`, which a query for either
`symmetric/block-cipher/mode**` or `**/aead` will find).

Composite entries (`type: composite`) do not carry `category:`. The composite's
function is implicit in its `protocol:` and `subType:` fields.

## Vocabulary

The vocabulary is derived from the section structure of
`cryptographic-algorithms.md`. Each branch corresponds to a markdown section
(or a clearly-bounded subsection); each leaf is a category assignable to a
concrete YAML entry.

```
symmetric/
  block-cipher                       # §1  AES, 3DES, Camellia, Magma, ...
  block-cipher/mode                  # §3  generic block-cipher mode-of-operation
  block-cipher/mode/aead             # §3  AEAD modes (GCM, CCM, OCB, Ascon-AEAD128, ...)
  block-cipher/mode/fpe              # §3  format-preserving encryption modes (FF1, FF3-1)
  block-cipher/mode/tweakable        # §3  tweakable-block-cipher modes (XTS, ...)
  stream-cipher                      # §2  ChaCha20, Salsa20, RC4, ZUC, SNOW, A5, EEA/EIA, ...

hash/
  cryptographic                      # §4  SHA-2, SHA-3, BLAKE2/3, GOSTR3411, ...
  cryptographic/xof                  # §4  SHAKE, cSHAKE, KMACXOF, TupleHash, ParallelHash
  non-cryptographic                  # §23 Adler, CRC, ...

mac                                  # §5  HMAC, AES-CMAC, KMAC, Poly1305, GMAC, ...

asymmetric/
  encryption                         # §6  RSA-OAEP, RSAES-PKCS1, ECIES, DLIES, SM2, ...
  kem                                # §6  ML-KEM, HQC, FrodoKEM, NTRU, BIKE, ...
  signature/stateless                # §7  ECDSA, EdDSA, RSA-PSS, ML-DSA, SLH-DSA, FN-DSA, SM2/SM9, GOSTR3410, ...
  signature/stateful                 # §8  LMS, LMS/HSS, XMSS, XMSSMT
  key-agreement                      # §9  ECDH, FFDH, X25519/X448, MQV, SPAKE2+, OPAQUE-3DH, MLS, SRTP

hpke                                 # §6  HPKE ciphersuites (DHKEM-* families)

curve                                # §10 named elliptic curves and groups (P-256, X25519, ristretto255, BLS12-381, ...)

kdf                                  # §11 HKDF, SP 800-108, SP 800-56C, ANSI X9.42/X9.63, TLS/IKEv2/SSH PRFs, MGF1, CatKDF, KeyCombine
kdf/password                         # §12 PBKDF1/2, Argon2, scrypt, bcrypt, yescrypt, MSCash
kdf/pbe                              # §11 PBES1/2 (password-based encryption frameworks)

framework                            # §25 PKCS / protocol encoding frameworks (PKCS#1/7/8/12, CMS, ASN.1)

rng/
  drbg                               # §14 SP 800-90A DRBGs (Hash/HMAC/CTR), Dual_EC_DRBG
  csprng                             # §15 Fortuna, Yarrow (accumulator-based)
  csprng/stream-cipher               # §16 ChaCha20-RNG and similar
  os-entropy                         # §16 /dev/urandom, getrandom, BCryptGenRandom, getentropy
  hardware                           # §16 RDRAND, RDSEED, TPM_RNG
  non-crypto                         # §17 MT19937, PCG, LCG, Xoshiro/Xoroshiro, ISAAC, A5/1, A5/2

padding                              # §18 OAEP, PKCS1, PSS, padding/encoding schemes

composite                            # §19 composite-sig, x25519kyber768, p256mlkem768, Composite ML-DSA (LAMPS)
```

## Query Examples

The Summary Counts table in `cryptographic-algorithms.md` becomes a set of
prefix queries against `category`. The `**` notation means "this prefix or any
deeper path".

| Summary Counts row | Query |
|:---|:---|
| Symmetric block ciphers | `category = symmetric/block-cipher` (exact, excluding `/mode**`) |
| Block cipher modes | `category STARTSWITH symmetric/block-cipher/mode` |
| Symmetric stream ciphers | `category = symmetric/stream-cipher` |
| Hash functions and XOFs | `category STARTSWITH hash/cryptographic` |
| Non-cryptographic checksums | `category = hash/non-cryptographic` |
| MACs | `category = mac` |
| KEM and asymmetric Encryption | `category IN {asymmetric/encryption, asymmetric/kem}` |
| HPKE ciphersuites | `category = hpke` |
| Digital Signatures, stateless | `category = asymmetric/signature/stateless` |
| Digital Signatures, stateful | `category = asymmetric/signature/stateful` |
| Key agreement | `category = asymmetric/key-agreement` |
| Named curves and groups | `category = curve` |
| KDFs (excluding password) | `category = kdf` |
| Password hashing | `category = kdf/password` |
| Password-based encryption | `category = kdf/pbe` |
| PKCS / protocol frameworks | `category = framework` |
| DRBGs | `category = rng/drbg` |
| Accumulator-based CSPRNGs | `category STARTSWITH rng/csprng` |
| OS entropy + hardware RNGs | `category IN {rng/os-entropy, rng/hardware}` |
| Non-cryptographic PRNGs | `category = rng/non-crypto` |
| Padding / encoding | `category = padding` |
| Composite / hybrid | `category = composite` |

PQC-specific Summary rows ("PQC KEMs — standardised", "PQC signatures — Round 2
candidates", etc.) become **compound queries** that combine `category` with the
to-be-defined lifecycle field. Those queries are listed in the lifecycle
companion spec and are not derivable from `category` alone.

## Worked Examples

```yaml
- id: "AES"
  category: "symmetric/block-cipher"

- id: "AES-GCM"
  category: "symmetric/block-cipher/mode/aead"

- id: "AES-XTS"
  category: "symmetric/block-cipher/mode/tweakable"

- id: "ChaCha20"
  category: "symmetric/stream-cipher"

- id: "SHA-256"
  category: "hash/cryptographic"

- id: "SHAKE-128"
  category: "hash/cryptographic/xof"

- id: "CRC-32"
  category: "hash/non-cryptographic"

- id: "HMAC"
  category: "mac"

- id: "RSA-OAEP"
  category: "asymmetric/encryption"

- id: "ML-KEM-768"
  category: "asymmetric/kem"

- id: "HQC-128"
  category: "asymmetric/kem"

- id: "ECDSA"
  category: "asymmetric/signature/stateless"

- id: "ML-DSA-65"
  category: "asymmetric/signature/stateless"

- id: "LMS"
  category: "asymmetric/signature/stateful"

- id: "ECDH"
  category: "asymmetric/key-agreement"

- id: "P-256"
  category: "curve"

- id: "HKDF"
  category: "kdf"

- id: "Argon2id"
  category: "kdf/password"

- id: "PBES2"
  category: "kdf/pbe"

- id: "CTR_DRBG"
  category: "rng/drbg"

- id: "Fortuna"
  category: "rng/csprng"

- id: "/dev/urandom"
  category: "rng/os-entropy"

- id: "RDRAND"
  category: "rng/hardware"

- id: "MT19937"
  category: "rng/non-crypto"

- id: "OAEP"
  category: "padding"

- id: "x25519mlkem768"
  category: "composite"
```

## Deferred Decisions

These are intentionally not specified here; they belong to separate companion
specs and will be added in follow-up passes.

- **Lifecycle field.** Standardisation lineage (`standardised | selected |
  candidate | broken | …`) is an independent axis and will be specified
  separately. Its interaction with the existing per-authority `nist.status` /
  `bsi.status` / `cnsa.*` blocks needs analysis to avoid redundant
  categorisation.
- **§20–§27 historical / legacy mapping.** The markdown's "Additional /
  legacy / historical" sections (§20 legacy block ciphers, §21 eSTREAM
  portfolio, §22 legacy hashes, §24 historical asymmetric, §26 Windows
  password hashing, §27 legacy RNGs) currently group entries by *function +
  legacy-status*. Under this `category` taxonomy alone they dissolve into their
  function categories; the legacy/historical axis would be carried by the
  lifecycle field above. Mapping to be finalised once the lifecycle vocabulary
  is settled.
- **Multi-category support.** Currently single-category per entry. If review
  of the vocabulary surfaces genuinely dual-classifiable algorithms whose
  secondary category isn't capturable via path depth, a `categories: [list]`
  extension can be
  introduced — but the goal is to avoid this.

## Implementation Plan (when adopted)

1. Add `category:` to the YAML schema documentation (`registry/README.md`).
2. Add `category` field handling to `RegistryEntry.java` (Lombok-derived
   `getCategory()` accessor — single-line change; no Java keyword collision).
3. Annotate the 342 algorithm entries across the 9 algorithm files. Order:
   (a) `cr-symmetric-ciphers.yaml` (78 entries, broadest variety) as the
   pilot; review the assignments before continuing. (b) hash/MAC files. (c)
   asymmetric/PQC. (d) KDF/RNG. (e) cdx/spdx alternatives.
4. Add `check_category_vocabulary` to `validate_consistency.py` — every
   `category:` value must be in the controlled vocabulary; emit drift signals
   when entries gain or lose `category:` annotation.
5. Once all 342 entries are annotated, replace the manually maintained
   Summary Counts table in `cryptographic-algorithms.md` with an `<!--
   AUTOGEN:BEGIN summary-counts -->` block driven by category queries.
6. Retire the interim `check_summary_counts` drift detector or repurpose it
   as a redundant cross-check against the autogenerated table.
