# Cryptographic Registry Ambiguities and Inconsistencies

Cross-reference of naming conventions between the CycloneDX cryptography registry
(`cryptography-defs.json`), the SPDX cryptographic algorithm list, this repository's
markdown taxonomy (`cryptographic-algorithms.md`), and the YAML validation registry (not yet published).

Each entry describes a concrete inconsistency, its impact on tooling interoperability,
and the current resolution status. Resolution mechanisms:

1. **Aliases** on canonical families — simple name remapping; emits `ALIAS_USED` warning
2. **Deprecated CycloneDX families** in `cr-cdx.yaml` — structural naming alternatives
   marked `status: deprecated` with a `note` explaining the preferred canonical form;
   emits `DEPRECATED_VALUE` warning with the rationale
3. **New CycloneDX families** in `cr-cdx.yaml` — algorithms only present in the
   CycloneDX registry with no canonical equivalent; no deprecation warning
4. **SPDX aliases** on canonical families — SPDX alternative names (rijndael, desede,
   sms4, chacha, kazumi, diffiehellman, dhe, tdes); emit `ALIAS_USED` warning
5. **Deprecated SPDX families** in `cr-spdx.yaml` — SPDX-specific identifiers that
   differ from canonical names; marked `status: deprecated` with rationale
6. **New SPDX families** in `cr-spdx.yaml` — SPDX entries with no canonical equivalent

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

**Resolution:** Aliases registered: `RSA-PSS` &rarr; `RSASSA-PSS`, `RSA-OAEP` &rarr;
`RSAES-OAEP`, `RSA-PKCS1` &rarr; `RSAES-PKCS1` / `RSASSA-PKCS1`. Validator emits
`ALIAS_USED` warning when the short form is used.

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

**Resolution:** Not yet aliased. Requires either a pre-parse normalisation step or
registering underscore variants as aliases.

---

## 3. EdDSA / Ed25519 / Ed448: Curve-in-Name vs Curve-as-Parameter

| Source | Pattern |
|--------|---------|
| CycloneDX | `Ed(25519\|448)[(ph\|ctx)]` |
| This repo | `EdDSA-(Ed25519\|Ed448)`, `Ed25519`, `Ed448` |
| IETF RFC 8032 | Ed25519, Ed448 (no generic "EdDSA" identifier) |

**Issue:** CycloneDX uses `Ed` as a two-character prefix with a required choice group
for the curve (`Ed(25519\|448)`), making the curve part of the name token. This repo
registers three separate families: `EdDSA` (with curve as parameter), `Ed25519`, and
`Ed448` (as standalone fixed identifiers). The CycloneDX pattern also supports
`ph` and `ctx` variants (pre-hashing and context), which are not in this repo.

**Impact:** `Ed25519` matches the `Ed25519` family in this repo but not the CycloneDX
`Ed(25519\|448)` pattern without expansion. `EdDSA-Ed25519` is a valid instance in this
repo but not a CycloneDX pattern.

**Resolution:** Not yet aliased. Would require registering `Ed25519` and `Ed448` as
aliases for `EdDSA` with appropriate curve inference, plus adding `ph` and `ctx`
variants to the EdDSA segment vocabulary.

---

## 4. Choice-in-Name vs Dash-Separated Family: SHAKE, KMAC, TupleHash

| Source | Pattern |
|--------|---------|
| CycloneDX | `SHAKE(128\|256)`, `KMAC(128\|256)`, `KMACXOF(128\|256)`, `TupleHash(128\|256)`, `ParallelHash(128\|256)` |
| This repo | `SHAKE128`, `SHAKE256`, `KMAC128`, `KMAC256` (separate families) |
| NIST SP 800-185 | KMAC128, KMAC256, TupleHash128, TupleHash256, etc. |

**Issue:** CycloneDX encodes the output length as a choice group appended directly to
the name without a dash separator: `SHAKE(128\|256)`. In the ANTLR4 parse tree, `SHAKE`
is a NAME token followed by a choiceGroup `(128\|256)`. This repo registers `SHAKE128`
and `SHAKE256` as separate families with no parameters. The NIST standard uses the
concatenated form (KMAC128, not KMAC-128).

**Impact:** `SHAKE(128\|256)` does not match any family prefix in the registry because
`SHAKE` alone is not registered and the choice group is not part of the prefix. The
validator identifies no family for these patterns.

**Resolution:** Not yet aliased. Requires either registering `SHAKE`, `KMAC`, etc. as
families with a choice segment, or implementing a pre-parse expansion step that converts
`SHAKE(128\|256)` to two patterns: `SHAKE128`, `SHAKE256`.

---

## 5. SHA Family: Dash Position and Choice Scope

| Source | Pattern |
|--------|---------|
| CycloneDX | `SHA-(224\|256\|384\|512\|512/224\|512/256)` |
| This repo | `SHA` with compound `variant` segment (1, 224, 256, 384, 512, 512-224, 512-256) |
| NIST FIPS 180-4 | SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 |

**Issue:** CycloneDX uses a single pattern `SHA-(224\|256\|...)` with a required choice
group after the `SHA-` prefix. The choice group notation (`(224\|256\|...)` without dash)
prevents the validator from matching the CycloneDX template pattern as a template.

**Resolution:** Resolved for instance validation. The canonical `SHA` family
(`cr-hash-functions.yaml`) uses a single family with `["SHA"]` as prefix and a compound
`variant` segment covering all output lengths including `1` (deprecated), `512-224`, and
`512-256`. Concrete instances like `SHA-256` and `SHA-512-224` are fully matched. The
CycloneDX template form `SHA-(224\|256\|...)` remains unparsable as a template due to
choice-in-name notation.

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

**Resolution:** Both base prefix (`GOSTR3410`, `GOSTR3411`) and year-qualified prefix
(`GOSTR3410-2012`, `GOSTR3411-2012`) are registered as separate families. The base
prefix matches when no year suffix is provided.

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

**Resolution:** `X25519` and `X448` registered as aliases for `ECDH`. Validator emits
`ALIAS_USED` warning and resolves to canonical family `ECDH`. Note: lowercase `x25519`
vs `X25519` remains a case-sensitivity issue (see item 9).

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

**Resolution:** Not yet aliased. Recommend adding operation and curve segments to the
SM2 family vocabulary, or registering `SM2-ENC`, `SM2-KEX` as separate families.

---

## 9. Case Sensitivity: RABBIT vs Rabbit

| Algorithm | CycloneDX | This repo |
|-----------|-----------|-----------|
| Rabbit | `RABBIT` | `Rabbit` |

**Issue:** CycloneDX uses all-uppercase for some algorithm names (`RABBIT`), while
conventional English capitalisation is used elsewhere (`Rabbit`). The ANTLR4 grammar
is case-sensitive by default.

**Resolution:** `RABBIT` registered as alias for canonical `Rabbit`. Validator emits
`ALIAS_USED` warning. Long-term recommendation: implement case-insensitive family
matching to avoid registering casing variants individually.

---

## 10. Composite Signature Naming: Dash-Concatenated vs Structured

| Source | Example |
|--------|---------|
| CycloneDX | *(not yet in registry)* |
| IETF draft-lamps | `MLDSA44-RSA2048-PSS-SHA256` |
| This repo | `MLDSA44-RSA2048-PSS-SHA256` |

**Issue:** Composite ML-DSA signatures use a flat dash-concatenated naming convention
where each component is joined by dashes. This prevents structural decomposition — a
validator cannot extract "RSA key length = 2048" from the pattern without knowing the
composite naming convention.

**Resolution:** Accepted as-is. Each composite variant is registered as a compound
value under the `MLDSA44`, `MLDSA65`, `MLDSA87` families.

---

## 11. HPKE Mode Encoding

| Source | Pattern |
|--------|---------|
| CycloneDX | `HPKE[-(mode_base\|mode_psk\|mode_auth\|mode_auth_psk)]-{kem}-{kdf}-{aead}` |
| This repo | `HPKE-{kemVariant}-{kdf}-{aeadVariant}` |
| RFC 9180 | mode: 0x00 (Base), 0x01 (PSK), 0x02 (Auth), 0x03 (AuthPSK) |

**Issue:** CycloneDX encodes the HPKE mode as `mode_` prefixed underscore-separated
names. This repo uses variable placeholders without the mode parameter.

**Resolution:** Not yet aliased. Recommend adding HPKE mode as a segment with the four
RFC 9180 mode values, accepting both underscore and dash forms.

---

## 12. AES-Wrap vs AES-KW: Duplicate Key-Wrapping Names

| Source | Pattern |
|--------|---------|
| CycloneDX | `AES[-(128\|192\|256)][-(KW\|KWP)]` and `AES[-(128\|192\|256)]-Wrap[-PKCS7]` |
| This repo | `AES-KW-[128\|192\|256]`, `AES-KWP-[128\|192\|256]` |
| NIST SP 800-38F | AES Key Wrap (KW), AES Key Wrap with Padding (KWP) |

**Issue:** CycloneDX registers both `AES-KW` and `AES-Wrap` as valid patterns for
the same NIST SP 800-38F algorithm.

**Resolution:** `AES-Wrap` registered as alias for canonical `AES-KW`. Validator emits
`ALIAS_USED` warning when `Wrap` form is used.

---

## 13. TLS PRF Versioning

| Source | Patterns |
|--------|----------|
| CycloneDX | `TLS1-PRF[-RFC7627]`, `TLS12-PRF[-RFC7627][-{hash}]`, `TLS13-PRF[-{hash}]` |
| This repo | `TLS12-PRF-{hash}`, `TLS13-HKDF-{hash}` |

**Issue:** CycloneDX uses `TLS13-PRF` while this repo uses `TLS13-HKDF` (reflecting
that TLS 1.3 uses HKDF, not a standalone PRF). `TLS1-PRF` (for TLS 1.0/1.1) is not
registered in this repo at all.

**Resolution:** `TLS13-PRF` registered as alias for canonical `TLS13-HKDF`. Validator
emits `ALIAS_USED` warning. `TLS1-PRF` is not yet registered (recommend adding as
a deprecated family).

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

The following CycloneDX patterns have **no corresponding family** in this repository's
validation registry. They are grouped by resolution status.

### 15.1 Resolved via Aliases

These patterns are matched through the alias mechanism on canonical families. The
validator identifies the canonical family and emits an `ALIAS_USED` warning.

| CycloneDX pattern | Alias resolves to | Notes |
|--------------------|-------------------|-------|
| `RSA-PSS[-{hash}][-{mgf}][-{salt}][-{keyLen}]` | `RSASSA-PSS` | RFC 8017 naming |
| `RSA-OAEP[-{hash}][-{mgf}][-{keyLen}]` | `RSAES-OAEP` | RFC 8017 naming |
| `RSA-PKCS1-1.5[-{hash}][-{keyLen}]` | `RSAES-PKCS1` / `RSASSA-PKCS1` | Ambiguous sign/encrypt |
| `x25519` | `ECDH` | RFC 7748 standalone name |
| `x448` | `ECDH` | RFC 7748 standalone name |
| `TLS13-PRF[-{hash}]` | `TLS13-HKDF` | CycloneDX naming |
| `AES-Wrap[-PKCS7]` | `AES-KW` | Duplicate wrapping name |
| `RABBIT` | `Rabbit` | Case variant |

### 15.2 Resolved via Deprecated CycloneDX Families (cr-cdx.yaml)

These patterns are now matched through dedicated CycloneDX-specific family entries in
`cr-cdx.yaml`. Families that duplicate a canonical entry are marked `status: deprecated`
with a `note` field explaining the preferred canonical name. The validator emits a
`DEPRECATED_VALUE` warning with the rationale included in the message.

**Deprecated alternatives** (canonical equivalent exists in another registry file):

| CycloneDX pattern | cdx family | Canonical family | Rationale |
|--------------------|------------|------------------|-----------|
| `Ed(25519\|448)` | `cdx:Ed` | `EdDSA`, `Ed25519`, `Ed448` | CycloneDX short form |
| `CMAC[-{cipher}][-{length}]` | `cdx:CMAC` | `AES-CMAC` | Prefer cipher-qualified form |
| `ECMQV[-{ellipticCurve}]` | `cdx:ECMQV` | `MQV` | CycloneDX EC-specific split |
| `FFMQV[-{group}]` | `cdx:FFMQV` | `MQV` | CycloneDX FF-specific split |
| `EC-ElGamal[-{ellipticCurve}]` | `cdx:EC-ElGamal` | `ElGamal` | CycloneDX EC variant |
| `SRP-3[-{hash}][-{group}]` | `cdx:SRP-3` | `SRP` | CycloneDX version-specific |
| `SRP-6[-{hash}][-{group}]` | `cdx:SRP-6` | `SRP` | CycloneDX version-specific |
| `SP800_108_CounterKDF[-...]` | `cdx:SP800_108_CounterKDF` | `SP800-108` | Underscore form |
| `SP800_108_FeedbackKDF[-...]` | `cdx:SP800_108_FeedbackKDF` | `SP800-108` | Underscore form |
| `SP800_108_DoublePipelineKDF[-...]` | `cdx:SP800_108_DoublePipelineKDF` | `SP800-108` | Underscore form |
| `SP800_108_KMAC[-...]` | `cdx:SP800_108_KMAC` | `SP800-108` | Underscore form |
| `SP800_56C_OneStep[-...]` | `cdx:SP800_56C_OneStep` | `SP800-56C` | Underscore form |
| `SP800_56C_TwoStep_*[-...]` | `cdx:SP800_56C_TwoStep_*` (3 variants) | `SP800-56C` | Underscore form |
| `IKE_PRF_DERIVE[-{hash}]` | `cdx:IKE_PRF_DERIVE` | `IKEv2-PRF` | Underscore form |
| `IKE1_PRF_DERIVE[-{hash}]` | `cdx:IKE1_PRF_DERIVE` | `IKEv2-PRF` | Underscore form |
| `IKE1_Extended_DERIVE[-{hash}]` | `cdx:IKE1_Extended_DERIVE` | `IKEv2-PRF` | Underscore form |
| `IKE2_PRF_PLUS_DERIVE[-{hash}]` | `cdx:IKE2_PRF_PLUS_DERIVE` | `IKEv2-PRF` | Underscore form |
| `GOST38147[-{mode}]` | `cdx:GOST38147` | `GOST-28147` | CycloneDX compact form |
| `GOST38147_MAC` | `cdx:GOST38147_MAC` | `GOST-28147` | Underscore form |
| `GOSTR3411_HMAC` | `cdx:GOSTR3411_HMAC` | `HMAC` + `GOSTR3411` | Underscore form |
| `TLS1-PRF[-RFC7627]` | `cdx:TLS1-PRF` | *(none)* | TLS 1.0/1.1 deprecated per RFC 8996 |

**New families** (no canonical equivalent — not deprecated):

| CycloneDX pattern | cdx family | Notes |
|--------------------|------------|-------|
| `KMACXOF(128\|256)` | `cdx:KMACXOF128`, `cdx:KMACXOF256` | NIST SP 800-185 |
| `TupleHash(128\|256)` | `cdx:TupleHash128`, `cdx:TupleHash256` | NIST SP 800-185 |
| `TupleHashXOF(128\|256)` | `cdx:TupleHashXOF128`, `cdx:TupleHashXOF256` | NIST SP 800-185 |
| `ParallelHash(128\|256)` | `cdx:ParallelHash128`, `cdx:ParallelHash256` | NIST SP 800-185 |
| `ParallelHashXOF(128\|256)` | `cdx:ParallelHashXOF128`, `cdx:ParallelHashXOF256` | NIST SP 800-185 |
| `PBMAC1[-{mac}][-{hash}][-{iter}][-{dkLen}]` | `cdx:PBMAC1` | PKCS #5 v2.1 |
| `X3DH[-{hash}]` | `cdx:X3DH` | Signal protocol |
| `J-PAKE[-{group}][-{kdf}][-{mac}]` | `cdx:J-PAKE` | RFC 8236 |
| `WOTSP-(SHA2\|SHAKE)` | `cdx:WOTSP` | Winternitz OTS (XMSS component) |

### 15.3 Resolved via Family Consolidation and Segment Additions

These CycloneDX patterns were covered by consolidating per-variant families into
single families with parameter segments, or by adding controlled vocabulary segments
to existing canonical families.

**Family consolidation** (removed hardcoded parameters from family names):

| Before | After | File | Change |
|--------|-------|------|--------|
| `SHA-1`, `SHA-224`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA-512-224`, `SHA-512-256` (7 families) | `SHA` | cr-hash-functions.yaml | Single family with compound `variant` segment; SHA-1 marked deprecated |
| `CRC-32`, `CRC-16` (2 families) | `CRC` | cr-hash-functions.yaml | Single family with numeric `width` segment |
| `Adler-32` | `Adler` | cr-hash-functions.yaml | Single family with numeric `width` segment |
| `HC-128`, `HC-256` (2 families) | `HC` | cr-symmetric-ciphers.yaml | Single family with numeric `variant` segment |

**Segment additions** (no family rename, just vocabulary extensions):

| CycloneDX pattern | Family | Change |
|--------------------|--------|--------|
| `BLAKE2b-(160\|256\|384\|512)-HMAC` | `BLAKE2b` | Added `outputLength` segment (160/256/384/512) and `mode` segment with `HMAC` value |
| `BLAKE2s-(160\|256)-HMAC` | `BLAKE2s` | Added `outputLength` segment (160/256) and `mode` segment with `HMAC` value |
| `SEED-128-(CCM\|GCM)` | `SEED` | Added `keyLength` segment (128) and `mode` segment (ECB, CBC, CTR, OFB, CFB, GCM, CCM) |
| `AES-CTR-HMAC-SHA1[-96]` | `AES` | Added `CTR-HMAC-SHA1` as compound mode value (deprecated) |
| `AES-XCBC_MAC[_96]` | `AES` | Added `XCBC_MAC` and `XCBC_MAC_96` as mode values |
| `BLS(13-381\|13-377\|BN254)` | `BLS` | Added `curve` compound segment with `BLS12-381`, `BLS12-377`, `BN254` values |

### 15.4 Resolved via Standalone Families

These CycloneDX patterns use notation (choice groups appended without dash, optional
suffixes) that the grammar cannot decompose structurally. They are resolved by
registering each expanded concrete name as a **separate family** with its own prefix
and segment definitions.

Families that represent protocol-level variants of a canonical algorithm (ECDHE, FFDHE,
Ed25519ph/ctx) are in `cr-cdx.yaml` marked `status: deprecated` with a note pointing
to the canonical family. Families that already existed as canonical entries require no
additional registration.

| CycloneDX pattern | Families | File | Status |
|--------------------|----------|------|--------|
| `ECDH[E][-{ellipticCurve}]` | `cdx:ECDHE` | cr-cdx.yaml | Deprecated; prefer `ECDH` — ephemeral is a protocol property |
| `FFDH(E)[-{group}]` | `cdx:FFDHE` | cr-cdx.yaml | Deprecated; prefer `FFDH` — ephemeral is a protocol property |
| `Ed(25519\|448)[(ph\|ctx)]` | `cdx:Ed25519ph`, `cdx:Ed25519ctx`, `cdx:Ed448ph`, `cdx:Ed448ctx` | cr-cdx.yaml | Deprecated; prefer `Ed25519`/`Ed448` with context parameter |
| `SHAKE(128\|256)` | `SHAKE128`, `SHAKE256` | cr-hash-functions.yaml | Canonical; already existed |
| `KMAC(128\|256)` | `KMAC128`, `KMAC256` | cr-macs.yaml | Canonical; already existed |
| `[{hashAlgorithm}-]yescrypt[...]` | `yescrypt` | cr-kdfs.yaml | Canonical; already existed |
| `IKE1_(PRF\|Extended)_DERIVE` | `cdx:IKE1_PRF_DERIVE`, `cdx:IKE1_Extended_DERIVE` | cr-cdx.yaml | Deprecated; prefer `IKEv2-PRF` |

**Note:** The CycloneDX *template* patterns (e.g., `SHAKE(128\|256)`) still cannot be
validated as templates because the choice group is appended without a dash separator.
However, all *concrete instances* (e.g., `SHAKE128`, `FFDHE-ffdhe3072`, `Ed25519ph`)
are fully matched by the validator. The template notation gap is a CycloneDX grammar
convention issue, not a missing algorithm coverage issue.

---

## 16. SPDX Cryptographic Algorithm List Deviations

The SPDX cryptographic-algorithm-list (https://github.com/spdx/cryptographic-algorithm-list)
contains 127 algorithm identifiers. These use naming conventions that differ from both this
repository's canonical families and from CycloneDX. All 127 are now resolved through three
mechanisms: aliases on canonical families, deprecated SPDX families in `cr-spdx.yaml`, or
direct matches against existing canonical families.

### 16.1 Resolved via Aliases on Canonical Families

These SPDX identifiers are registered as aliases and produce an `ALIAS_USED` warning:

| SPDX identifier | Alias resolves to | Notes |
|-----------------|-------------------|-------|
| `rijndael` | `AES` | Original Rijndael name before NIST standardisation |
| `desede` | `3DES` | "DES-EDE" — standard Triple DES alternative |
| `tdes` | `3DES` | Common abbreviation |
| `sms4` | `SM4` | Chinese national standard identifier |
| `chacha` | `ChaCha20` | Generic ChaCha (always means ChaCha20 in practice) |
| `diffiehellman` | `FFDH` | Full Diffie-Hellman name |
| `dhe` | `FFDH` | Diffie-Hellman Ephemeral abbreviation |
| `kazumi` | `KASUMI` | Misspelling in the SPDX list (should be KASUMI) |

### 16.2 Resolved via Deprecated SPDX Families (cr-spdx.yaml)

These SPDX identifiers are registered as deprecated families with a `spdx:` prefix and a
`note` explaining the preferred canonical form:

**Generic unqualified names** (too broad to alias to a single canonical family):

| SPDX identifier | spdx family | Canonical equivalent(s) | Rationale |
|-----------------|-------------|------------------------|-----------|
| `shs` | `spdx:shs` | SHA | Secure Hash Standard — covers entire SHA family |
| `shax` | `spdx:shax` | SHA | Generic SHA — ambiguous which variant |
| `rsa` | `spdx:rsa` | RSASSA-PSS, RSAES-OAEP, etc. | Generic RSA — ambiguous sign vs encrypt |
| `cast` | `spdx:cast` | CAST5, CAST6 | Generic CAST — ambiguous which variant |
| `gost` | `spdx:gost` | GOST-28147, GOSTR3410, GOSTR3411 | Generic GOST — covers cipher, sig, and hash |
| `snow` | `spdx:snow` | SNOW-3G, SNOW-V | Generic SNOW — ambiguous which variant |
| `grain` | `spdx:grain` | Grain-128 | Generic Grain — only Grain-128 is standardised |
| `blake2` | `spdx:blake2` | BLAKE2b, BLAKE2s | Generic BLAKE2 — ambiguous which variant |
| `blakex` | `spdx:blakex` | BLAKE2b, BLAKE2s, BLAKE3 | Generic BLAKE — covers entire family |
| `keccak` | `spdx:keccak` | SHA3 | Keccak sponge — different padding than FIPS 202 SHA-3 |

**Variant names** (SPDX uses a different name for an existing canonical algorithm):

| SPDX identifier | spdx family | Canonical equivalent | Rationale |
|-----------------|-------------|---------------------|-----------|
| `dhies` | `spdx:dhies` | ECIES | DH Integrated Encryption Scheme |
| `salsa10` | `spdx:salsa10` | Salsa20 | Reduced-round (10-round) variant |
| `md160` | `spdx:md160` | RIPEMD | Short form for RIPEMD-160 |
| `tnepres` | `spdx:tnepres` | Serpent | Reversed byte-order implementation |
| `xtsea` | `spdx:xtsea` | XTEA | XTEA variant |
| `ssha` | `spdx:ssha` | SHA | Salted SHA — salting is usage, not algorithm |
| `umd5` | `spdx:umd5` | MD5 | Unicode MD5 |
| `usha` | `spdx:usha` | SHA | Unicode SHA |
| `gea0-x` | `spdx:gea0-x` | GEA | Generic GEA family |

**Encoding frameworks** (not cryptographic algorithms):

| SPDX identifier | spdx family | Notes |
|-----------------|-------------|-------|
| `pkcs12` | `spdx:pkcs12` | PKCS#12 key/certificate bundle format |
| `pkcs7` | `spdx:pkcs7` | PKCS#7 / CMS signed data format |
| `ASN1` | `spdx:ASN1` | ASN.1 encoding framework |
| `X509` | `spdx:X509` | X.509 PKI certificate framework |
| `cms` | `spdx:cms` | Cryptographic Message Syntax |

### 16.3 SPDX Entries with No Canonical Equivalent

These SPDX identifiers have no corresponding algorithm in the canonical registry or
in CycloneDX. They are registered in `cr-spdx.yaml` without deprecation:

| SPDX identifier | spdx family | Notes |
|-----------------|-------------|-------|
| `dcc` | `spdx:dcc` | Data Confidentiality Code |
| `ubi` | `spdx:ubi` | Universal Block cipher Interface (Skein/Threefish component) |
| `uffizi` | `spdx:uffizi` | Uffizi cipher |
| `uxn` | `spdx:uxn` | UXN cipher |

---

## Summary

| Category | Count | Status |
|----------|-------|--------|
| **CycloneDX** | | |
| Naming convention conflicts (RSA, AES-Wrap, TLS13, case) | 5 | Resolved via aliases |
| CycloneDX naming alternatives with canonical equivalent | 29 | Resolved via deprecated cdx families (cr-cdx.yaml) |
| CycloneDX-only families (no canonical equivalent) | 4 | Registered in cr-cdx.yaml (not deprecated): PBMAC1, X3DH, J-PAKE, WOTSP |
| Remaining CycloneDX template notation gaps | 0 | All instance patterns covered |
| **SPDX** | | |
| SPDX aliases on canonical families | 8 | rijndael, desede, tdes, sms4, chacha, diffiehellman, dhe, kazumi |
| SPDX deprecated alternatives (generic/variant names) | 24 | Resolved via deprecated spdx families (cr-spdx.yaml) |
| SPDX-only families (no canonical equivalent) | 4 | dcc, ubi, uffizi, uxn |
| Remaining SPDX unmatched identifiers | 0 | All 127 identifiers covered |
| **Structural** | | |
| Family consolidation (removed hardcoded parameters) | 4 | SHA, CRC, Adler, HC |
| Segment additions to existing families | 6 | BLAKE2 HMAC, SEED AEAD, AES compound modes, BLS curves |
| Standalone families for choice-in-name patterns | 7 | SHAKE/KMAC (canonical), ECDHE/FFDHE/Ed variants (deprecated cdx), yescrypt, IKE1 |
| Duplicate names for same algorithm | 2 | Resolved via aliases |
| Missing from CycloneDX registry | 6+ families | Upstream gap |

All CycloneDX and SPDX algorithm identifiers are now covered for **instance validation**.
The registry uses 324 families across 9 YAML files. Eight resolution mechanisms are in place:

1. **CycloneDX aliases** — RSA-PSS, X25519, AES-Wrap, RABBIT, TLS13-PRF
2. **SPDX aliases** — rijndael, desede, tdes, sms4, chacha, diffiehellman, dhe, kazumi
3. **Deprecated CycloneDX families** (`cr-cdx.yaml`) — 29 families for CycloneDX-specific
   naming (underscore separators, ECDHE/FFDHE, Ed25519ph/ctx, GOST compact forms)
4. **Deprecated SPDX families** (`cr-spdx.yaml`) — 24 families for SPDX-specific naming
   (generic names, variant names, encoding frameworks)
5. **New CycloneDX families** (`cr-cdx.yaml`) — 4 families only in CycloneDX
   (PBMAC1, X3DH, J-PAKE, WOTSP); TupleHash/ParallelHash/KMACXOF were moved to canonical files
6. **New SPDX families** (`cr-spdx.yaml`) — 4 families only in SPDX (dcc, ubi, uffizi, uxn)
7. **Family consolidation** — SHA, CRC, Adler, HC consolidated from per-variant to
   single families with parameter segments
8. **Standalone families** — concrete expanded names (SHAKE128, KMAC256, yescrypt)
   for choice-in-name patterns that cannot be structurally parsed
