# Architecture Decision Record: Cryptographic Registry v2

> Records the design decisions behind the v2 registry schema migration.
> For the full schema reference, see `ae-pattern-validator/src/main/resources/registry/README.md`.

## Context

The v1 registry modelled individual algorithms as "families" with a single
unqualified `status` field (e.g., `status: "approved"`). This caused three
problems:

1. **Ambiguous authority.** `status: "approved"` doesn't say approved *by whom*.
   NIST, BSI, and CNSA frequently disagree — AES-128 is approved by NIST but
   disallowed by CNSA; EdDSA is approved by NIST but not addressed by BSI.
   The single field forced a hidden prioritisation.

2. **No composition model.** TLS cipher suites, SSH algorithms, and X.509
   composite signatures combine multiple algorithms. The v1 registry couldn't
   express `TLS_AES_256_GCM_SHA384 = AES-256-GCM + HKDF-SHA-384`.

3. **Manual markdown curation.** Per-authority status lived in manually curated
   markdown tables (`cryptographic-algorithm-status.md`), not in the YAML.
   This produced recurring errors (wrong BSI section references, column swaps,
   stale data).

## Decisions

### 1. Per-Authority Status Model

Every status assessment is qualified by its authority. There is no unqualified
`status` field.

```yaml
authorities:
  nist: { status: "approved" }
  bsi: { status: "approved", source: "TR-02102-1 Table 3.1" }
  cnsa: { status: "disallowed", note: "CNSA mandates AES-256" }
```

An absent authority means "not checked." An authority entry with only `note`
(no `status`) means "checked; this authority does not cover this algorithm."

**Rationale:** Users in different regulatory contexts need different answers.
A composed status hides the disagreement and forces a prioritisation that
should be the user's decision.

### 2. Two Entry Types

| Type | Description |
|---|---|
| `algorithm` | Individual cryptographic primitive with prefix-based pattern matching |
| `composite` | Ordered list of algorithm pattern references |

Composites reference algorithms by pattern string (`"AES-256-GCM"`), resolved
by the existing `PatternValidator`. No new resolution syntax.

### 3. Semantic SubTypes

`subType` classifies entries without changing validation logic:

- **Algorithm:** `family`, `fixed`, `redirect`, `alias`
- **Composite:** `cipherSuite`, `supportedGroup`, `signatureScheme`, `sshKex`, `sshHostAuth`, `sshCipher`, `sshMac`, `compositeSignature`

### 4. `id` replaces `family`

The `family` field implied algorithm-only semantics. `id` is type-neutral and
serves as the unique identifier across the entire registry.

### 5. Configurable Authority on Validator

`PatternValidator`, `CertificateAnalyser`, and `CmsAnalyser` accept an
`authority` parameter (default: `"nist"`). The CLI exposes `--authority <id>`.
Status checks read from `getAuthorityStatus(authority)` — no hardcoded
authority in the validation path.

### 6. Composite Components as Patterns

Composites store an ordered `components` list of pattern strings:

```yaml
components:
  - "AES-256-GCM"
  - "HKDF-SHA-384"
```

Each component resolves through the existing validator. No roles, no structured
references — the order is implicit from the protocol's suite definition.

### 7. Curve-typed Parameters (2026-10-04)

**Decision:** the `ellipticCurve` parameter of EC algorithms is `type: "curve"` and is resolved
against the first-class `curve/*` entries instead of an inline value list. Curve OIDs and
curve postures live once, on the curve entry (or umbrella value); the EC algorithm entries
carry no curve OIDs. Redirect spellings (`secp256r1`, `prime256v1`, `ansip384r1`) are
deprecated curve entries with `preferredPattern`, so the canonical name wins and the
validator reports `PREFER_CANONICAL_PATTERN`. Algorithm-local names that are not curves
(ECDH `X25519`/`X448`) stay as inline values with their OIDs on the entry's `oidMap`.
`ValidationResult` exposes `curve`/`curveOid` next to the algorithm `oid`; the CBOM generator
writes the curve into CycloneDX 1.6 `algorithmProperties.curve`.

**Compatibility and combination posture (same day, after review):** resolving names against
the whole curve registry must not mean any algorithm composes with any curve. The parameter
declares `curveCategories` (structural forms the algorithm is defined on) and optionally a
closed `curves` list (SP 800-56A MQV); a resolvable but incompatible curve is the error
`INCOMPATIBLE_CURVE`. Posture is two-layered: the curve entry holds what is intrinsic to the
curve (security strength, SP 800-186 status), and the algorithm's inline values hold the
combination-specific authority statements — CNSA 2.0 "P-384 only" for ECDSA/ECDH, BSI
TR-02102-1 recommended curves per mechanism — overriding per authority.

**Rationale:** the curve registry grew to 202 entries while each EC algorithm enumerated
~17 curves, so `ECDSA-secp160r1-*` failed as an unknown value and 23 curve OIDs were duplicated
across ECDSA/ECDH and the curve file. One home per identifier; intrinsic curve facts on the
curve, combination facts on the algorithm's parameter.

## Status Vocabulary

| Status | Meaning |
|---|---|
| `mandatory` | Required by this authority |
| `recommended` | Preferred by this authority |
| `approved` | Acceptable for use |
| `conditional` | Allowed under the stated `condition` (2026-10-04: SP 800-186 Appendix H / IG C.A curves) |
| `transitional` | Acceptable until `until` |
| `not recommended` | IANA: not endorsed, not forbidden |
| `non-approved` | CMVP: not on an approved or allowed list; outside approved services only (added 2026-10-04) |
| `deprecated` | Migrate away; still functional |
| `disallowed` | Must not be used |
| `broken` | Cryptographically compromised |

Qualifiers on every authority block (2026-10-04): `basis` (`named` default / `rule` / `scope`),
`source`, `condition` (required for `conditional`), `until`, `note`. `basis: rule` marks a status
derived from a general rule the authority states (SP 800-131A strength thresholds) rather than a
per-object assessment; `basis: scope` marks the authority's default for unlisted objects.

## Migration Summary

| Phase | Change |
|---|---|
| 1 | `family:`→`id:`, `status:`→`authorities:`, added `type`/`subType`, class renames (`RegistryEntry`, `CryptographicRegistry`, `EntryMatch`) |
| 2 | Populated BSI (98 entries) and CNSA (34 entries) from verified sources |
| 3 | Generated `cr-tls.yaml` (170 composites) from IANA CSVs |
| 4 | Added `--authority` CLI flag; configurable authority on all validators |
| 5 | Added `cr-ssh.yaml` (25 composites), `cr-x509.yaml` (13 composites) |

## Current State

- 546 entries (338 algorithms + 208 composites) across 12 files
- 191 unique OIDs
- 786 tests passing
- 6 known authorities: `nist`, `bsi`, `cnsa`, `iana`, `ietf`, `cabf`
