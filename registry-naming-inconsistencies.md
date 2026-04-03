# Naming Ambiguities and Inconsistencies

Cross-reference of naming conventions between the CycloneDX cryptography registry
(`cryptography-defs.json`), the SPDX cryptographic algorithm list, this repository's
markdown taxonomy (`cryptographic-algorithms.md`), and the YAML validation registry
(`algorithms.yaml`).

Each entry describes a concrete inconsistency, its impact on tooling interoperability,
and a recommendation.

---

## 1. RSA Naming: Scheme vs Operation Split

| Source | Signature | Encryption |
|--------|-----------|------------|
| CycloneDX | `RSA-PSS[-...]`, `RSA-PKCS1-1.5[-...]` | `RSA-OAEP[-...]`, `RSA-PKCS1-1.5[-...]` |
| This repo | `RSASSA-PSS-{keyLength}-{hash}`, `RSASSA-PKCS1-{keyLength}-{hash}` | `RSAES-OAEP-{keyLength}-{hash}`, `RSAES-PKCS1-{keyLength}` |
| PKCS #1 / RFC 8017 | RSASSA-PSS, RSASSA-PKCS1-v1_5 | RSAES-OAEP, RSAES-PKCS1-v1_5 |

**Issue:** CycloneDX uses the short prefix `RSA-` and distinguishes sign/encrypt by
the padding scheme name alone (`PSS` = sign, `OAEP` = encrypt). The RFC 8017 names
(`RSASSA-`, `RSAES-`) encode the operation in the prefix. The CycloneDX pattern
`RSA-PKCS1-1.5` is ambiguous — it could be either sign or encrypt.

**Impact:** A validator using RSASSA/RSAES prefixes will not match CycloneDX patterns
with `RSA-` prefix and vice versa. The PKCS1-v1.5 ambiguity means a CBOM entry
cannot distinguish signature from encryption without additional context.

**Recommendation:** Accept both forms; map `RSA-PSS` to `RSASSA-PSS` and `RSA-OAEP`
to `RSAES-OAEP` as aliases. For `RSA-PKCS1-1.5`, require the consuming tool to
disambiguate via the CycloneDX `cryptoProperties.algorithmProperties.primitive` field.

---

## 2. Separator Convention: Dash vs Underscore

| Pattern family | CycloneDX | This repo |
|----------------|-----------|-----------|
| SP 800-108 KDF | `SP800_108_(CounterKDF\|...)` | `SP800-108-{mode}-{prf}` |
| SP 800-56C KDF | `SP800_56C_OneStep[...]` | `SP800-56C-{mode}-{hash}` |
| IKE PRF | `IKE_PRF_DERIVE[-{hash}]` | `IKEv2-PRF-{hash}` |
| IKE2 PRF | `IKE2_PRF_PLUS_DERIVE[-{hash}]` | `IKEv2-PRF-{hash}` |
| GOST 28147 | `GOST38147[-{mode}]` | `GOST-28147-*` |
| GOST MAC | `GOST38147_MAC` | *(not separately registered)* |
| GOST HMAC | `GOSTR3411_HMAC` | *(not separately registered)* |

**Issue:** CycloneDX uses underscores as intra-name separators (`SP800_108_CounterKDF`),
while this repository and most standards literature use dashes (`SP800-108`). Because
the ANTLR4 grammar treats underscores as part of the NAME token and dashes as structural
separators, `SP800_108_CounterKDF` parses as a single NAME token whereas
`SP800-108-CounterKDF` parses as three dash-separated segments.

**Impact:** A pattern written in one convention cannot be matched against a registry
using the other convention without normalisation. Validators must either normalise
underscores to dashes before parsing, or register both forms.

**Recommendation:** Define a canonical form using dashes (consistent with the
CycloneDX algorithm name field and NIST document numbers). Provide underscore
variants as aliases in the registry or apply a pre-parse normalisation step.

---

## 3. EdDSA / Ed25519 / Ed448: Curve-in-Name vs Curve-as-Parameter

| Source | Pattern |
|--------|---------|
| CycloneDX | `Ed(25519\|448)[(ph\|ctx)]` |
| This repo | `EdDSA-(Ed25519\|Ed448)`, `Ed25519`, `Ed448` |
| IETF RFC 8032 | Ed25519, Ed448 (no generic "EdDSA" identifier) |

**Issue:** CycloneDX uses `Ed` as a two-character prefix with a required choice group
for the curve (`Ed(25519|448)`), making the curve part of the name token. This repo
registers three separate families: `EdDSA` (with curve as parameter), `Ed25519`, and
`Ed448` (as standalone fixed identifiers). The CycloneDX pattern also supports
`ph` and `ctx` variants (pre-hashing and context), which are not in this repo.

**Impact:** `Ed25519` matches the `Ed25519` family in this repo but not the CycloneDX
`Ed(25519|448)` pattern without expansion. `EdDSA-Ed25519` is a valid instance in this
repo but not a CycloneDX pattern.

**Recommendation:** Accept all three forms. Map `Ed25519` and `Ed448` as aliases for
`EdDSA-Ed25519` and `EdDSA-Ed448`. Add `ph` and `ctx` variants to the EdDSA segment
vocabulary.

---

## 4. Choice-in-Name vs Dash-Separated Family: SHAKE, KMAC, TupleHash

| Source | Pattern |
|--------|---------|
| CycloneDX | `SHAKE(128\|256)`, `KMAC(128\|256)`, `KMACXOF(128\|256)`, `TupleHash(128\|256)`, `ParallelHash(128\|256)` |
| This repo | `SHAKE128`, `SHAKE256`, `KMAC128`, `KMAC256` (separate families) |
| NIST SP 800-185 | KMAC128, KMAC256, TupleHash128, TupleHash256, etc. |

**Issue:** CycloneDX encodes the output length as a choice group appended directly to
the name without a dash separator: `SHAKE(128|256)`. In the ANTLR4 parse tree, `SHAKE`
is a NAME token followed by a choiceGroup `(128|256)`. This repo registers `SHAKE128`
and `SHAKE256` as separate families with no parameters. The NIST standard uses the
concatenated form (KMAC128, not KMAC-128).

**Impact:** `SHAKE(128|256)` does not match any family prefix in the registry because
`SHAKE` alone is not registered and the choice group is not part of the prefix. The
validator identifies no family for these patterns.

**Recommendation:** Register `SHAKE`, `KMAC`, `KMACXOF`, `TupleHash`, `TupleHashXOF`,
`ParallelHash`, and `ParallelHashXOF` as additional families with a single choice
segment. Alternatively, add a pre-parse expansion step that converts `SHAKE(128|256)`
to two patterns: `SHAKE128`, `SHAKE256`.

---

## 5. SHA Family: Dash Position and Choice Scope

| Source | Pattern |
|--------|---------|
| CycloneDX | `SHA-(224\|256\|384\|512\|512/224\|512/256)` |
| This repo | `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA-512-224`, `SHA-512-256` (separate families) |
| NIST FIPS 180-4 | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 |

**Issue:** CycloneDX uses a single pattern `SHA-(224|256|...)` with a required choice
group after the `SHA-` prefix. This repo registers each SHA-2 variant as a separate
family. The validator finds `SHA` as a prefix token but no family matches because the
registered prefixes are `["SHA", "224"]`, `["SHA", "256"]`, etc. The choice group
prevents prefix matching.

**Impact:** The CycloneDX SHA pattern cannot be validated against the per-variant
registry entries without expanding the choice group first.

**Recommendation:** Add a generic `SHA` family covering the SHA-2 variants with a
choice segment, or implement choice-group expansion in the validator so that
`SHA-(224|256)` is tested as `SHA-224` and `SHA-256` individually.

---

## 6. GOST Algorithm Numbering: With and Without Year Suffix

| Source | Pattern |
|--------|---------|
| CycloneDX | `GOSTR3410`, `GOSTR3411` (no year) |
| This repo | `GOSTR3410-2012-*`, `GOSTR3411-2012-[256\|512]` |
| Russian standards | GOST R 34.10-2012, GOST R 34.11-2012 |

**Issue:** CycloneDX uses the compact form without a year suffix (`GOSTR3410`), while
this repo's taxonomy includes the year (`GOSTR3410-2012`) to distinguish the 2012
revision from the superseded 2001 and 1994 versions. Both forms are valid references
to the same algorithm.

**Impact:** Minor — resolved by registering both the base prefix and the year-qualified
prefix in the YAML registry.

**Recommendation:** Already addressed. Keep both registrations.

---

## 7. ECDH vs X25519/X448: Curve Namespace

| Source | Patterns |
|--------|----------|
| CycloneDX | `ECDH[E][-{ellipticCurve}]`, `x25519\|x448` |
| This repo | `ECDH-Curve25519`, `ECDH-Curve448`, `ECDH-P-256`, etc. |
| IETF | X25519 (RFC 7748), ECDH (generic) |

**Issue:** CycloneDX registers `x25519` and `x448` as top-level standalone names (pipe-
separated, lowercase) distinct from the generic `ECDH` pattern. This repo subsumes them
under the `ECDH` family with `Curve25519` and `Curve448` as curve parameter values.
The CycloneDX `ECDH[E]` pattern includes an optional `E` suffix for ephemeral mode,
which this repo does not model.

**Impact:** A CBOM entry using `x25519` will not match the `ECDH-Curve25519` pattern.
Lowercase `x25519` vs `X25519` is also a case sensitivity issue.

**Recommendation:** Register `X25519` and `X448` as standalone families (aliases for
`ECDH-Curve25519` and `ECDH-Curve448`). Add `E` (ephemeral) as an optional segment
to the `ECDH` family. Establish case-insensitive matching or normalise to uppercase.

---

## 8. SM2: Operation Split vs Monolithic Family

| Source | Patterns |
|--------|----------|
| CycloneDX | `SM2[-256]`, `SM2-(ENC\|ENCRYPTION)[-256]`, `SM2-(KEX\|KEYEXCHANGE\|...)[-256]` |
| This repo | `SM2-*` (single family, no operation distinction) |

**Issue:** CycloneDX splits SM2 into three patterns: bare `SM2` (signature), `SM2-ENC`
(encryption), and `SM2-KEX` (key exchange), each with an optional `-256` suffix. This
repo uses a single `SM2` family with wildcard parameters.

**Impact:** Validation against the CycloneDX patterns requires distinguishing SM2
operations, which the single-family registration cannot do. The `-256` suffix (the
only SM2 curve size) adds no information but is syntactically present.

**Recommendation:** Add operation and curve segments to the SM2 family vocabulary, or
register `SM2-ENC`, `SM2-KEX` as separate families mirroring the CycloneDX split.

---

## 9. Case Sensitivity: RABBIT vs Rabbit, CAMELLIA vs Camellia

| Algorithm | CycloneDX | This repo (MD) | This repo (YAML) |
|-----------|-----------|-----------------|-------------------|
| Rabbit | `RABBIT` | `Rabbit-*` | `Rabbit` and `RABBIT` |
| Camellia | `CAMELLIA-(128\|...)` | `CAMELLIA-[128\|256]-*` | `CAMELLIA` |

**Issue:** CycloneDX uses all-uppercase for some algorithm names (`RABBIT`, `CAMELLIA`),
while conventional English capitalisation or mixed case is used elsewhere (`Rabbit`,
`Camellia`). The ANTLR4 grammar is case-sensitive by default.

**Impact:** `RABBIT` does not match a family registered as `Rabbit` without
case-insensitive matching. The YAML registry currently registers both forms for Rabbit
as a workaround.

**Recommendation:** Implement case-insensitive family matching in the validator, or
define a canonical casing convention and normalise input before matching. Registering
duplicate entries for each casing variant does not scale.

---

## 10. Composite Signature Naming: Dash-Concatenated vs Structured

| Source | Example |
|--------|---------|
| CycloneDX | *(not yet in registry)* |
| IETF draft-lamps | `MLDSA44-RSA2048-PSS-SHA256` |
| This repo | `MLDSA44-RSA2048-PSS-SHA256` |

**Issue:** Composite ML-DSA signatures from draft-ietf-lamps-pq-composite-sigs use a
flat dash-concatenated naming convention (`MLDSA44-RSA2048-PSS-SHA256`) where each
component (ML-DSA parameter set, RSA key length, padding scheme, hash) is joined by
dashes. This conflicts with the structured dash-separator grammar because "RSA2048"
is a single NAME token (no dash between "RSA" and "2048"), breaking the segment
boundary model used elsewhere.

**Impact:** The flat naming works because each composite variant is registered as a
fixed compound value. But it prevents structured decomposition — a validator cannot
extract "RSA key length = 2048" from the pattern without knowing the composite naming
convention.

**Recommendation:** Accept the IETF flat naming as-is for composite signatures. Register
each variant as a compound value under the `MLDSA44`, `MLDSA65`, `MLDSA87` families.
This is already implemented.

---

## 11. HPKE Mode Encoding

| Source | Pattern |
|--------|---------|
| CycloneDX | `HPKE[-(mode_base\|mode_psk\|mode_auth\|mode_auth_psk)]-{kem}-{kdf}-{aead}` |
| This repo | `HPKE-{kemVariant}-{kdfVariant}-{aeadVariant}` |
| RFC 9180 | mode: 0x00 (Base), 0x01 (PSK), 0x02 (Auth), 0x03 (AuthPSK) |

**Issue:** CycloneDX encodes the HPKE mode as a `mode_` prefixed underscore-separated
name inside an optional choice group. This repo uses variable placeholders without
the mode parameter. The underscore-containing values (`mode_base`, `mode_psk`) are
parsed as single NAME tokens in the grammar.

**Impact:** A validator checking HPKE patterns would need to recognise `mode_base` etc.
as valid mode values.

**Recommendation:** Add HPKE mode as a segment with the four RFC 9180 mode values.
Accept both underscore (`mode_base`) and dash (`mode-base`) forms.

---

## 12. AES-Wrap vs AES-KW: Duplicate Key-Wrapping Names

| Source | Pattern |
|--------|---------|
| CycloneDX | `AES[-(128\|192\|256)][-(KW\|KWP)]` and `AES[-(128\|192\|256)]-Wrap[-PKCS7]` |
| This repo | `AES-KW-[128\|192\|256]`, `AES-KWP-[128\|192\|256]` |
| NIST SP 800-38F | AES Key Wrap (KW), AES Key Wrap with Padding (KWP) |

**Issue:** CycloneDX registers both `AES-KW` and `AES-Wrap` as valid patterns for
the same NIST SP 800-38F algorithm. The `-Wrap` variant adds an optional `-PKCS7`
suffix not present in the `KW` variant.

**Impact:** Two different pattern strings refer to the same algorithm. A CBOM tool
using `AES-256-Wrap` and another using `AES-256-KW` are expressing the same thing
but will not match without alias mapping.

**Recommendation:** Designate `AES-KW` / `AES-KWP` as canonical (matching the NIST
abbreviations). Accept `AES-Wrap` as an alias.

---

## 13. TLS PRF Versioning

| Source | Patterns |
|--------|----------|
| CycloneDX | `TLS1-PRF[-RFC7627]`, `TLS12-PRF[-RFC7627][-{hash}]`, `TLS13-PRF[-{hash}]` |
| This repo | `TLS12-PRF-{hash}`, `TLS13-HKDF-{hash}` |

**Issue:** CycloneDX distinguishes TLS 1.0/1.1 PRF (`TLS1-PRF`) from TLS 1.2
(`TLS12-PRF`) and TLS 1.3 (`TLS13-PRF`). This repo uses `TLS12-PRF` and `TLS13-HKDF`
(reflecting that TLS 1.3 uses HKDF, not a standalone PRF). CycloneDX's `TLS13-PRF`
differs from this repo's `TLS13-HKDF` — same algorithm, different name.

**Impact:** `TLS13-PRF` does not match `TLS13-HKDF` without alias mapping. `TLS1-PRF`
is not registered in this repo at all.

**Recommendation:** Register `TLS1-PRF` as a deprecated family. Add `TLS13-PRF` as an
alias for `TLS13-HKDF`, or register both prefixes pointing to the same family.

---

## 14. Missing from CycloneDX Registry

The following algorithms are in this repository's taxonomy but **not** in the CycloneDX
`cryptography-defs.json` registry:

| Algorithm | This repo pattern | Notes |
|-----------|-------------------|-------|
| FN-DSA (Falcon) | `FN-DSA-[512\|1024]` | FIPS 206 IPD; expected after final publication |
| HQC | `HQC-[128\|192\|256]` | Selected March 2025; FIPS pending ~2027 |
| FrodoKEM | `FrodoKEM-[640\|976\|1344]-*` | NIST Round 3 alternate; not standardised |
| BIKE | `BIKE-[L1\|L3\|L5]` | NIST Round 4 not selected |
| Composite ML-DSA | `MLDSA44-RSA2048-PSS-SHA256` etc. | IETF draft; 18 variants |
| MAYO, HAWK, CROSS, etc. | Various | NIST Round 2 additional signature candidates |

---

## 15. Missing from This Repository

The following CycloneDX patterns have **no corresponding family** in this repo:

| CycloneDX pattern | Category | Notes |
|--------------------|----------|-------|
| `KMACXOF(128\|256)` | XOF MAC | NIST SP 800-185 |
| `TupleHash(128\|256)` | Hash | NIST SP 800-185 |
| `TupleHashXOF(128\|256)` | XOF | NIST SP 800-185 |
| `ParallelHash(128\|256)` | Hash | NIST SP 800-185 |
| `ParallelHashXOF(128\|256)` | XOF | NIST SP 800-185 |
| `PBMAC1[-{mac}][-{hash}][-{iter}][-{dkLen}]` | MAC KDF | PKCS #5 v2.1 |
| `X3DH[-{hash}]` | Key agreement | Signal protocol |
| `J-PAKE[-{group}][-{kdf}][-{mac}]` | PAKE | RFC 8236 |
| `ECMQV[-{curve}]` | Key agreement | NIST SP 800-56A |
| `FFMQV[-{group}]` | Key agreement | NIST SP 800-56A |
| `EC-ElGamal[-{curve}]` | Asymmetric enc | EC variant |
| `WOTSP-(SHA2\|SHAKE)` | One-time signature | Component of XMSS |
| `IKE_PRF_DERIVE[-{hash}]` | KDF | IKEv1/v2 |
| `IKE1_(PRF\|Extended)_DERIVE[-{hash}]` | KDF | IKEv1 |
| `IKE2_PRF_PLUS_DERIVE[-{hash}]` | KDF | IKEv2 |
| `x25519`, `x448` | Key agreement | RFC 7748 (lowercase) |
| `FFDH(E)[-{group}]` | Key agreement | With optional ephemeral flag |
| `SRP-3[-{hash}][-{group}]` | PAKE | SRP version 3 |
| `SRP-6[-{hash}][-{group}]` | PAKE | SRP version 6/6a |
| `BLS(13-381\|13-377\|BN254)` | Pairing curve | Specific curve choice |
| `AES-CTR-HMAC-SHA1[-96]` | AEAD composite | Non-standard |
| `AES-Wrap[-PKCS7]` | Key wrapping | Alias for AES-KW |
| `AES-XCBC_MAC[_96]` | MAC | RFC 3566 |
| `BLAKE2b-*-HMAC`, `BLAKE2s-*-HMAC` | MAC | BLAKE2 keyed mode |
| `SEED-128-(CCM\|GCM)` | AEAD | Korean standard |
| `SEED-128-*-HMAC-*` | Encrypt-then-MAC | Korean standard |
| `Salsa20-Poly1305` | AEAD | NaCl |

---

## Summary

| Category | Count |
|----------|-------|
| Naming convention conflicts (RSA, SP800, IKE, GOST separators) | 5 |
| Structural notation differences (choice-in-name, curve-in-name) | 4 |
| Case sensitivity issues | 1 |
| Duplicate names for same algorithm (AES-Wrap/KW, TLS13-PRF/HKDF) | 2 |
| Missing from CycloneDX registry | 6+ families |
| Missing from this repository | 25+ CycloneDX patterns |

The most impactful inconsistencies for CBOM tooling interoperability are items 1 (RSA
naming), 2 (dash vs underscore), 4 (choice-in-name), and 7 (ECDH/X25519 namespace).
These should be prioritised for resolution through either alias mapping in the
validation registry or upstream alignment with the CycloneDX specification maintainers.
