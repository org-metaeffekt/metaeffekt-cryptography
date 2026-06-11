# Registry Lifecycle Taxonomy

> [!NOTE]
> Specification for the proposed `lifecycle:` field on registry algorithm
> entries. The field carries a standardisation-process-lineage indicator
> orthogonal to the functional `category:` field. Companion to
> [`registry-category-taxonomy.md`](registry-category-taxonomy.md) and
> [`registry-design-v2.md`](registry-design-v2.md).

## Purpose

Add a single mandatory field `lifecycle:` to algorithm entries in `cr-*.yaml`.
Its value classifies where the algorithm sits in formal standardisation
processes — independently of (a) what the algorithm *does* (that's
`category:`) and (b) any individual authority's current deployment
recommendation (that's `nist.status` / `bsi.status` / `cnsa.*`).

The motivating use case is the Summary Counts table in
`cryptographic-algorithms.md`, which currently distinguishes PQC entries by
standardisation lineage in rows such as:

- "PQC KEMs — standardised / selected" (`lifecycle ∈ {standardised, selected}`)
- "PQC KEMs — Round 3 notable non-standardised (incl. broken)" (`lifecycle ∈ {candidate, broken}`)
- "PQC signatures — NIST standardised" (`lifecycle = standardised`)
- "PQC signatures — Round 2 candidates" (`lifecycle = candidate`, with round
  detail in `remarks:`)
- "PQC signatures — Round 3 non-standardised / broken" (`lifecycle ∈ {candidate, broken}`)

Once `lifecycle:` is in place the PQC-specific Summary Counts rows become
compound queries (`category × lifecycle`) and the Summary Counts table can be
auto-generated end-to-end from YAML.

## Field Definition

| Field | Type | Cardinality | Vocabulary |
|:---|:---|:---|:---|
| `lifecycle` | string | **mandatory** on every algorithm entry, single value | controlled (see [Vocabulary](#vocabulary)) |

Single primary lifecycle per entry — no `lifecycles:` list. An algorithm has
*one* position in the standardisation pipeline at any given moment. When a
single SBOM identifier covers multiple algorithms in different lifecycle
states (e.g. `spdx:gost` covers GOST-28147 standardised + GOSTR3411
standardised + GOSTR3410 standardised; or `spdx:rsa` standardised), use the
`"unspecific"` sentinel matching the category convention.

Composite entries (`type: composite`) do not carry `lifecycle:`. The
composite's lifecycle is implicit in its `protocol:` version and the
lifecycles of its `components:`.

## Relationship to Other Fields

The `lifecycle:` field is **orthogonal** to three existing concepts that
overlap superficially:

| Field | Question it answers |
|:---|:---|
| `category:` | What does this algorithm *do*? (function) |
| `lifecycle:` | Where is this algorithm in the *standardisation process*? (lineage) |
| `authorities.<auth>.status:` | What is *this authority's current deployment recommendation*? (per-authority guidance) |
| `patternStatus:` | Is this entry the *canonical pattern* or a deprecated alias? (registry hygiene) |

Concrete demonstrations of the orthogonality:

- **AES is `lifecycle: standardised` and `nist.status: recommended`.** The
  algorithm is finalised (FIPS 197); NIST recommends it for deployment.
  Same lifecycle and per-authority status — they agree.
- **MD5 is `lifecycle: broken` and `nist.status: disallowed`.** The algorithm
  is cryptanalytically broken (lifecycle: terminal state of analysis); NIST
  disallows its use for new deployments (deployment recommendation). Same
  conclusion, different *reason* — lifecycle records the analysis fact;
  status records the policy decision.
- **HQC is `lifecycle: selected` and `nist.status: approved`.** Selected by
  NIST for standardisation in March 2025; final FIPS document pending. NIST
  approves the algorithm for deployment in advance of the final standard.
- **FN-DSA is `lifecycle: draft` and `nist.status: approved`.** FIPS 206 is
  in Initial Public Draft (IPD); NIST approves use with the caveat that the
  draft is subject to change.
- **SIKE is `lifecycle: broken` and `nist.status: broken`.** Cryptanalysis
  showed SIDH (and therefore SIKE) is fundamentally insecure during Round 4
  evaluation. Both fields point the same way.
- **DES is `lifecycle: withdrawn` and `nist.status: disallowed`.** FIPS 46
  was withdrawn in 2005; per-authority status records the deployment
  consequence.

The general rule: `lifecycle:` records *what happened in the standardisation
process*; per-authority `status:` records *what to do about it now*. They
often agree but they are separate facts and degrade differently — a previously
standardised algorithm whose standard has been withdrawn (`lifecycle:
withdrawn`) may still carry `nist.status: deprecated` for a transitional
period before becoming `nist.status: disallowed`.

## Vocabulary

```
standardised   # Final standard published by NIST FIPS, ISO/IEC, IETF Standards Track,
               # or equivalent top-tier body; remains in force
draft          # Published as a draft (FIPS IPD, IETF Internet-Draft, ISO DIS, ...);
               # final specification pending
selected       # Formally selected by a standards body for standardisation but
               # full specification not yet published (e.g. HQC selected by
               # NIST March 2025; FIPS document pending)
candidate      # Under active evaluation in a standards process (NIST PQC
               # competition rounds, NIST Lightweight Cryptography rounds,
               # IETF WG in-progress, ...)
withdrawn      # Formerly standardised but formally withdrawn (DES from FIPS 46,
               # ANSI X9.31 PRNG, ...). Distinguished from `broken` by being
               # an *administrative* outcome rather than an analytical one.
broken         # Cryptanalytically compromised — security materially broken
               # (SIKE, Rainbow, Picnic, GeMSS, MD5, RC4 prefix bias, ...).
               # Terminal state of analysis.
legacy         # Established by use, vendor practice, or academic publication
               # but never formally standardised by a top-tier body
               # (MT19937, LCG, RC2, Skipjack, ...). Distinguished from
               # `broken` by being non-standard rather than compromised, and
               # from `withdrawn` by having never been standardised.
unspecific     # Sentinel matching the category convention — used for SBOM
               # umbrella identifiers that span multiple lifecycle states
               # (rare; most umbrellas cover entries all of which are
               # standardised, in which case `standardised` is appropriate)
unknown        # Sentinel matching the category convention — identifier has
               # no documented standardisation history we can verify
```

## Worked Examples

```yaml
# Standardised mainstream algorithms (most of the registry)
- id: "AES"
  category: "symmetric/block-cipher"
  lifecycle: "standardised"

- id: "SHA-256"      # (parameter value within SHA family — illustrative)
  category: "hash/cryptographic"
  lifecycle: "standardised"

- id: "ChaCha20"
  category: "symmetric/stream-cipher"
  lifecycle: "standardised"          # RFC 8439

- id: "ML-KEM"
  category: "asymmetric/kem"
  lifecycle: "standardised"          # FIPS 203 (Aug 2024)

- id: "ML-DSA"
  category: "asymmetric/signature/stateless"
  lifecycle: "standardised"          # FIPS 204 (Aug 2024)

# Draft / pending finalisation
- id: "FN-DSA"
  category: "asymmetric/signature/stateless"
  lifecycle: "draft"                 # FIPS 206 IPD (Aug 2025; final pending)

# Selected for standardisation, specification pending
- id: "HQC"
  category: "asymmetric/kem"
  lifecycle: "selected"              # NIST selected March 2025; FIPS pending ~2027

# Active candidates
- id: "BIKE"
  category: "asymmetric/kem"
  lifecycle: "candidate"             # NIST PQC Round 3/4 (sub-axis in remarks)
  remarks:
    - "NIST PQC additional KEM Round 4 (2022 onwards)"

- id: "MAYO"
  category: "asymmetric/signature/stateless"
  lifecycle: "candidate"
  remarks:
    - "NIST PQC additional signature on-ramp Round 2 (2024)"

# Broken (cryptanalysed)
- id: "SIKE"
  category: "asymmetric/kem"
  lifecycle: "broken"                # SIDH/SIKE attack (Castryck-Decru 2022)

- id: "Rainbow"
  category: "asymmetric/signature/stateless"
  lifecycle: "broken"                # Beullens 2022

- id: "MD5"
  category: "hash/cryptographic"
  lifecycle: "broken"                # Wang et al. 2004; collision attacks practical

- id: "RC4"
  category: "symmetric/stream-cipher"
  lifecycle: "broken"                # AlFardan et al. 2013; biased outputs

# Withdrawn from formal standards
- id: "DES"
  category: "symmetric/block-cipher"
  lifecycle: "withdrawn"             # FIPS 46-3 withdrawn 2005

- id: "ANSIX931"
  category: "rng/non-crypto"
  lifecycle: "withdrawn"             # ANSI X9.31 PRNG withdrawn 2011

# Legacy / never standardised
- id: "MT19937"
  category: "rng/non-crypto"
  lifecycle: "legacy"                # Matsumoto-Nishimura 1997; academic standard, no formal body

- id: "LCG"
  category: "rng/non-crypto"
  lifecycle: "legacy"

- id: "RC2"
  category: "symmetric/block-cipher"
  lifecycle: "legacy"                # RFC 2268 Informational; never standards track

- id: "Lucifer"
  category: "symmetric/block-cipher"
  lifecycle: "legacy"                # Pre-DES IBM design; never formally adopted
```

## Query Examples for Summary Counts PQC Rows

Once `lifecycle:` is in place, the PQC-specific Summary Counts rows in
`cryptographic-algorithms.md` become compound queries:

| Summary Counts row | Query |
|:---|:---|
| PQC KEMs — standardised / selected | `category = asymmetric/kem AND lifecycle ∈ {standardised, selected, draft}` |
| PQC KEMs — Round 3 notable (incl. broken) | `category = asymmetric/kem AND lifecycle ∈ {candidate, broken}` |
| PQC signatures — NIST standardised | `category STARTSWITH asymmetric/signature AND lifecycle = standardised AND id ∈ PQC` |
| PQC signatures — Round 2 candidates | `category = asymmetric/signature/stateless AND lifecycle = candidate AND remarks MATCH "Round 2"` |
| PQC signatures — Round 3 non-standardised / broken | `category = asymmetric/signature/stateless AND lifecycle ∈ {candidate, broken}` |

The "Round 2 vs Round 3" distinction lives in `remarks:` for now — see
[Deferred Decisions](#deferred-decisions) below for the path-sub-axis
question.

## Deferred Decisions

These are intentionally not specified here; they belong to follow-up passes
once the v1 vocabulary has been exercised against real annotation:

- **NIST competition round granularity.** Currently `candidate` is a single
  leaf. A future enrichment could use path syntax to capture round
  identification (`candidate/pqc-round-2`, `candidate/pqc-round-3`,
  `candidate/lightweight-round-1`, ...). Decide once the simple flat
  vocabulary is in place and Summary Counts row mapping has stabilised.
- **`broken/standardised` vs `broken/candidate` distinction.** Some
  algorithms (MD5, RC4, DES) were once standardised and *then* broken; others
  (SIKE, Rainbow, Picnic) were broken during candidate evaluation and never
  reached standardisation. The flat `broken` value conflates these. Could be
  split as `broken/post-standardisation` vs `broken/candidate` if downstream
  queries need the distinction.
- **`de-facto-standard` for ubiquitously-deployed-but-not-formally-standardised
  primitives.** Examples: `/dev/urandom` (POSIX-tradition but no formal IETF
  spec for the algorithm), `BCryptGenRandom` (Windows API, no public spec).
  Currently these would be `legacy` which understates their adoption. Decide
  by use case: who needs to query "things every modern OS provides" vs
  "things never standardised"?
- **`historical` as a separate value distinct from `legacy`.** Some entries
  (Lucifer, Enigma, FEAL) predate the modern cryptography era and are
  registered for historical interest. Currently grouped with `legacy`; could
  be split if the "this is in our registry only for completeness" axis
  matters downstream.
- **Tie-in with `cryptographic-algorithms.md` §20–§27.** The markdown's
  "Additional / legacy / historical" sections are organised as
  *function + legacy-status*. Once both `category:` and `lifecycle:` are in
  place, those sections can dissolve into their function categories with the
  legacy axis carried by `lifecycle: legacy | withdrawn | broken`. Mapping
  to be finalised in a follow-up.

## Implementation Plan (when adopted)

1. Add `lifecycle:` to the YAML schema documentation
   (`ae-pattern-validator/src/main/resources/registry/README.md`).
2. Add `lifecycle` field handling to `RegistryEntry.java` (Lombok-derived
   `getLifecycle()` accessor — single-line change).
3. Annotate the 342 algorithm entries. Order:
   (a) PQC files first (`cr-pqc.yaml` 40 entries) — the motivating use case
   for the field; ensure the standardised/draft/selected/candidate/broken
   distinctions land cleanly before broader rollout.
   (b) Mainstream algorithms (`cr-symmetric-ciphers.yaml`, `cr-hash-functions.yaml`,
   `cr-macs.yaml`, `cr-asymmetric.yaml`, `cr-kdfs.yaml`) — mostly
   `standardised` with occasional `withdrawn` / `legacy` / `broken`.
   (c) RNGs (`cr-rngs.yaml`) — interesting mix of standardised DRBGs,
   legacy PRNGs, broken (Dual_EC_DRBG), withdrawn (ANSI X9.31).
   (d) SBOM alternatives (`cr-cdx.yaml`, `cr-spdx.yaml`) — typically
   inherit the lifecycle of their canonical referent.
4. Add `check_lifecycle_vocabulary` to `scripts/validate_consistency.py` —
   parallel to `check_category_vocabulary`; every algorithm entry must carry
   `lifecycle:` from the controlled vocabulary; report sentinel counts.
5. Extend `scripts/generate_status_tables_from_yaml.py` to emit a
   "Algorithm Lifecycle Distribution" autogen block (parallel to the
   category distribution table) inside the inner registry README.
6. Once both `category:` and `lifecycle:` are annotated across all 342
   entries, replace the manually maintained PQC-specific Summary Counts
   rows in `cryptographic-algorithms.md` with autogenerated content driven
   by compound `category × lifecycle` queries. Retain the markdown's
   non-PQC rows (which are markdown-row-granular and need separate
   handling — see `check_summary_counts` discussion in
   `content-update-plan.md` §8.4).
