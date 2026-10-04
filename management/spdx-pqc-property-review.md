# SPDX pqcClass Proposal Review (spdx/cryptographic-algorithm-list issue #73)

> [!NOTE]
> Ingested 2026-09-02. Review of the `pqcClass` property proposal posted to SPDX issue #73.
> The proposal is **WIP and not merged**; no change to this repository's registry is required
> today. This document records the proposal, our assessment, and the watch items that trigger
> work here if it lands.

## 1. Source

| Field | Value |
|:---|:---|
| Location | https://github.com/spdx/cryptographic-algorithm-list/issues/73#issuecomment-5267793501 |
| Author | `toscalix` |
| Posted | 2026-08-12; last edited 2026-08-26 |
| Status | WIP proposal, no PR yet |
| Self-declared caveats | "done with the help of AI"; "syntax is not perfect"; "examples require the review from experts"; "open questions need decisions" |
| Related issues | #68 (cryptoClass restructure), #72 (cryptoSubClass values), #43 (algorithm candidates) |

Prior group decisions cited in the proposal: **2026-04-22** — PQC is a *property*, not a
`cryptoClass`/`cryptoSubClass`. **2026-08-04** — the property is single-level, based on
mathematical characteristics, derived from NIST, with algorithm parameters deferred.

## 2. Proposal Summary

A new property `pqcClass`, cardinality `[0..1]`, placed after `cryptoSubClass`. Its presence
marks the algorithm as post-quantum; its absence means the algorithm is not post-quantum.
Values are Title-Case hyphenated, matching the `cryptoClass` convention:

| Value | Hardness cited in the proposal | Examples given |
|:---|:---|:---|
| `Lattice-Based` | LWE, Ring-LWE, Module-LWE, NTRU lattices | ML-KEM, ML-DSA, FN-DSA, FrodoKEM |
| `Code-Based` | decoding random linear codes (Goppa, quasi-cyclic) | Classic McEliece, HQC, BIKE |
| `Multivariate` | multivariate quadratic systems over finite fields | MAYO, UOV, SNOVA, Rainbow (broken) |
| `Hash-Based` | preimage and collision resistance | SLH-DSA (stateless), XMSS/LMS (stateful) |
| `Isogeny-Based` | isogenies between elliptic curves | SQIsign, CSIDH, SIKE (broken) |
| `MPC-in-the-Head` | "often symmetric primitives or other problems" | FAEST, Picnic, SDitH |

Two existing SPDX entries gain the property (`mceliece` → `Code-Based`, `ntruencrypt` →
`Lattice-Based`). Ten candidates from #43 are sketched as YAML: ML-KEM, ML-DSA, FN-DSA,
SLH-DSA, Classic McEliece, HQC, BIKE, MAYO, SQIsign, FAEST.

Five open questions are raised: (1) hybrids and non-fitting algorithms, (2) stateless versus
stateful, (3) OIDs bound to parameter sets rather than algorithms, (4) the existing
`commonkeySize`/`specifiedkeySize` inconsistency, (5) `Key-Exchange-Mechanism` being the only
available subclass for what are actually KEMs.

## 3. Assessment

### 3.1 What the Proposal gets right

**PQC as an orthogonal property.** Correct, and it matches this repository's model: our
mandatory `category:` field is function-first (`asymmetric/kem`,
`asymmetric/signature/stateless`), and quantum posture is deliberately *not* part of it.
Folding PQC into `cryptoClass` would have produced the same cardinality breakage we avoided.

**Question 5 is the strongest point in the proposal.** A KEM is not a key exchange. We already
separate `asymmetric/kem` from `asymmetric/key-agreement` in the category vocabulary, and the
distinction survives contact with 15 KEM entries. The proposal's preferred option (add
`Key-Encapsulation-Mechanism` in #72) is the right one.

**Question 2 is not a footnote.** The stateless/stateful split is deployment-critical, not
cosmetic: stateful schemes are approved only under the state-management regime of SP 800-208.
We model it as two distinct category leaves (`asymmetric/signature/stateful` carries LMS,
LMOTS, XMSS, XMSS^MT).

### 3.2 Findings

**F1. The value set mixes two orthogonal axes.** Five values name a *hardness assumption*;
`MPC-in-the-Head` names a *construction paradigm*. The paradigm is compatible with every
hardness family: SDitH is syndrome decoding (code-based), RYDE and Mirath are rank/code
problems, MQOM is multivariate, FAEST is AES, Picnic is LowMC. With cardinality `[0..1]` an
entry must discard one of the two facts. The proposal's own FAEST note ("a reader may find it
odd that an `Asymmetric-Key-Algorithm` gets its security from a symmetric cipher") is this
defect surfacing.

**F2. Six values do not cover the candidate space.** Group-action problems are a seventh
family: **ALTEQ** (alternating trilinear form equivalence) fits none of the six, and **LESS**
(linear code equivalence) is a group action over codes rather than a decoding problem. Both are
NIST additional-signature candidates and both are in our registry. Question 1's "add an
`Other` value" option is therefore not hypothetical — it is required before the first PR.

**F3. Absence semantics are unsafe for SBOM consumers.** "Its absence means the algorithm is not
post-quantum" collapses four distinct states into one: classical and quantum-vulnerable
(RSA), not applicable (AES-256 and SHA-3 are not PQC algorithms yet are not
quantum-broken), not yet classified (any entry the group has not revisited), and hybrid. The
consumer of an SBOM doing quantum-readiness triage reads the absent field as
"needs migration" and mis-flags every symmetric primitive in the inventory. A tri-state
quantum-posture property, separate from the mathematical taxonomy, avoids this; overloading one
optional field to mean both "is PQ" and "why it is PQ" does not.

**F4. Identity and assessment are conflated.** `pqcClass: Lattice-Based` on the legacy
`ntruencrypt` entry, and `Code-Based` on the generic 1978 `mceliece` entry, will be read as
"quantum-safe" — but neither is a deployable post-quantum scheme, and the SPDX list has no
lifecycle or status property to carry the caveat. The proposal states that `pqcClass` "does not
indicate whether the algorithm is secure, standardised, or recommended", which is the correct
intent, but intent is not machine-readable. This repository keeps the two layers apart on
purpose (`registries:` for identity, `authorities:`/`lifecycle:` for assessment); SPDX
currently has only the identity layer, so a family label is the *only* signal a tool can read.

**F5. Duplicate identity for one family.** Adding `classic-mceliece` while the generic
`mceliece` entry remains yields two identifiers for one family, with divergent metadata —
`mceliece` keeps `Public-Key-Cipher`, `classic-mceliece` gets `Key-Exchange-Mechanism`. We
handle exactly this class of SPDX identifier with the `unspecific` category sentinel
(`spdx:rsa`, `spdx:cast`). The proposal should state an explicit supersedes or alias relation.

**F6. Internal contradiction between §2 and §6.** §2 records the decision that "PQC algorithms
do not carry key-size or similar parameter properties at this stage", and §6 then puts
`specifiedkeySize` on all ten candidate YAML blocks.

**F7. The `specifiedkeySize` values are not key sizes.** `['128','192','256']` are NIST security
*categories* rendered as bit strings. The mapping is also wrong for two of the three lattice
schemes: ML-DSA-44/65/87 are Categories **2/3/5** (not 128/192/256), FN-DSA-512/1024 are
Categories **1/5** (the proposal lists two values, `['128','256']`, which happens to align only
by accident), ML-KEM-512/768/1024 are Categories **1/3/5**. Actual public keys range from
~800 bytes (ML-KEM-512) to over 1 MB (Classic McEliece), so no bit-length reading is
defensible. SLH-DSA is the single case where 128/192/256 are literal, because they appear in
the parameter-set names. Recommendation: carry the **parameter-set name** plus a
`nistSecurityCategory` in 1..5, and no key-length field for PQC.

**F8. Question 3 omits the option that works.** The proposal offers three choices — long OID
lists, one entry per parameter set, or "a structure that binds each OID to a parameter set" —
and treats the third as speculative future work. It is not: this repository implements it
today. OIDs are attached at the **parameter-value** level, so ML-KEM is one entry whose
`parameterSet` values 512/768/1024 each carry their own FIPS 203 OID
(`2.16.840.1.101.3.4.4.1/.2/.3`). The model holds across **406 algorithm entries and 658
unique OIDs** and preserves both "one algorithm, one entry" and exact OID resolution for
detection tooling. This is the most useful thing we can contribute to the thread.

**F9. The NIST provenance claim needs a citation.** "The six families come from the NIST
classification" is asserted without a document reference. The NIST additional-signature status
reports group candidates into more buckets than six and carry a residual bucket; the on-ramp
advanced to Round 3 with 9 candidates on 2026-05-14. The proposal should cite the specific IR
and table rather than the project landing page.

**F10. The property is named after its cohort, not its measurement.** `pqcClass` can only ever
apply to post-quantum algorithms, so the mathematical basis of RSA (integer factorisation), DH
(discrete logarithm) and ECC (ECDLP) stays unrecorded — or worse, half-recorded in
`cryptoSubClass`, where `Elliptic-Curve-Cryptography` sits next to `Digital-Signature` and
`Key-Exchange-Mechanism` as though a hardness family and a function were the same kind of
thing. The proposal's own SQIsign note ("`Digital-Signature` is right, but sqisign also works
on supersingular elliptic curves ... an entry cannot say it is both") is that collision
surfacing. A general `hardnessAssumption` property would fix both the PQC case and the
pre-existing `cryptoSubClass` category error. The group has decided otherwise; recording the
cost.

### 3.3 Proposed Response to the Group

1. **Split the property in two.** A tri-state quantum posture (`post-quantum` / `classical` /
   `hybrid`) answers Question 1 and closes the absence-semantics hole in F3; a separate
   hardness/family property answers "why". Either give the family property cardinality `[0..*]`
   or add `Other` — F1 and F2 both need it.
2. **Support Question 5 in #72, with a classical argument.** RSA-KEM (RFC 5990) is a
   pre-quantum KEM, so `Key-Encapsulation-Mechanism` is justified independently of PQC and does
   not read as a PQC-only concession.
3. **Parameters:** parameter-set name plus NIST security category 1..5; drop `specifiedkeySize`
   from the PQC examples (F6, F7).
4. **Offer the parameter-value OID model for Question 3** (F8), with ML-KEM and SLH-DSA as
   worked examples.
5. **Offer our PQC registry as a test corpus** — 49 entries against the six proposed values
   will surface F1 and F2 before the PR rather than after.

## 4. Cross-Check against this Repository

Our `cr-pqc.yaml` holds **49 entries**: 31 stateless signatures, 15 KEMs, 3 composites; by
lifecycle, 31 candidate, 5 standardised, 4 draft, 4 withdrawn, 3 broken, 1 selected, 1 legacy.
Stateful hash-based signatures (LMS, LMOTS, XMSS, XMSS^MT) live in `cr-asymmetric.yaml`.

All ten SPDX candidate identifiers already exist as canonical families here — ML-KEM, ML-DSA,
FN-DSA, SLH-DSA, ClassicMcEliece, HQC, BIKE, MAYO, SQIsign, FAEST — so if #43 lands, our SPDX
coverage work is alias mapping only, with no new canonical families.

Entries that stress the proposed six-value enum:

| Entry | Proposed value would be | Problem |
|:---|:---|:---|
| `ALTEQ` | none of the six | group-action-based (alternating trilinear forms) |
| `LESS` | `Code-Based`? | linear code *equivalence*, a group action, not decoding |
| `SDitH`, `RYDE`, `Mirath` | `MPC-in-the-Head` or `Code-Based` | both true; `[0..1]` discards one |
| `MQOM` | `MPC-in-the-Head` or `Multivariate` | both true |
| `FAEST` | `MPC-in-the-Head` | hardness is AES, i.e. symmetric; the paradigm is not the hardness |
| `CROSS` | `Code-Based` | restricted-error codes plus a Fiat-Shamir/ZK construction |
| `SQIsign2D` | `Isogeny-Based` | fine, but collides with `cryptoSubClass` per the proposal's own note |
| `HashML-DSA`, `HashSLH-DSA` | `Lattice-Based` / `Hash-Based` | pre-hash variants multiply the OID problem of Question 3 |

## 5. Watch Items

- [ ] **#73 merged** — `pqcClass` becomes a fourth SPDX metadata property after `cryptoClass`
      and `cryptoSubClass`. Metadata only; no new identifiers, no `cr-spdx.yaml` change, no
      coverage-test change. Record in `cryptographic-registry-inconsistencies.md` §16 only if
      the value assignments contradict our `category:`/`lifecycle:` assignments.
- [ ] **#72 adds `Key-Encapsulation-Mechanism`** — confirms our `asymmetric/kem` leaf; no action
      beyond a note in the mapping table.
- [ ] **#43 adds the ten candidates** — up to ten new SPDX identifiers requiring `spdx:` alias
      entries and `SpdxCoverageTest` cases. All ten map to existing canonical families.
- [ ] **`mceliece` versus `classic-mceliece`** — if both ship, the generic `mceliece` identifier
      becomes a candidate for the `unspecific` category sentinel.

## 6. Side Finding (unrelated to SPDX)

`cryptographic-algorithms.md:315-316` cites FN-DSA as "FIPS 206 (IPD)", which the currency note
of 2026-07-12 in `content-update-plan.md` §8.1 explicitly corrected: no FIPS 206 initial public
draft has been published. The `cr-pqc.yaml` `FN-DSA` entry carries `lifecycle: draft`. Both
should be re-checked against the lifecycle taxonomy in a separate pass; not touched here.
