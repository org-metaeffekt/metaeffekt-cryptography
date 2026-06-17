# Content Update Plan (consistency, integrity, and synchronisation)

> Plan for ensuring all artefacts in the metaeffekt-cryptography repository are consistent,
> complete, and synchronised. Covers markdown documents, YAML registry, ANTLR4 grammars,
> generated diagrams, inventory, glossary, test suite, and external registry alignment.

## Dependency Tree

```
Phase 1 (Registry ↔ Markdown Sync)
│ ├── 1.1 (Algorithm Coverage)        ── entry point; no dependencies
│ ├── 1.2 (Parameter Coverage)        ── depends on 1.1
│ ├── 1.3 (Status Sync)               ── depends on 1.1
│ └── 1.4 (OID Audit)                 ── depends on 1.1
│
├─► Phase 2 (External Registries)     ── may add families → feeds back to 1.1
│   ├── 2.1 (CycloneDX)
│   └── 2.2 (SPDX)
│
├─► Phase 3 (Tests and Reports)       ── depends on Phase 1 + Phase 2
│   ├── 3.1 (Missing Tests)
│   └── 3.2 (Test Report)             ── depends on 3.1
│
├─► Phase 4 (Glossary)                ── depends on Phase 1 (finalised names)
│   ├── 4.1 (Completeness)
│   └── 4.2 (Accuracy)
│
├─► Phase 5 (Inventory)               ── depends on Phase 1 (finalised families)
│   ├── 5.1 (Implementation Coverage)
│   └── 5.2 (README Sync)
│
├─► Phase 6 (Diagrams)                ── depends on Phase 1 (finalised parameters)
│   ├── 6.1 (Grammar Diagrams)
│   └── 6.2 (Parameter Set Diagrams)
│
└─► Phase 7 (Cross-File Consistency)  ── depends on ALL above phases
    ├── 7.1 (Number Sync)
    ├── 7.2 (Coverage Tables)
    ├── 7.3 (Cross-References)
    └── 7.4 (Naming Consistency)

Phase 8 (Improvements)                ── independent; can run last or in parallel
├── 8.1 (New Sources)                 ── independent
├── 8.2 (Markdown Structure)          ── depends on Phase 7
├── 8.3 (Compactness)                 ── depends on Phase 7
└── 8.4 (Tooling)                     ── independent

Phase 9 (Style Conventions)           ── independent; applies to all markdown files
├── 9.1 (Heading Capitalisation, Noun-Only Rule)
├── 9.2 (Em-Dashes in Headings, Avoided)
├── 9.3 (Bracketed Content, Lowercased)
├── 9.4 (Hyphenated Compounds in Noun Phrases)
├── 9.5 (Acronym and Proper Noun Preservation)
└── 9.6 (Verification and Enforcement)
```

**Critical Path:** 1.1 → 2.1/2.2 → 3.1 → 7 → 8.2/8.3

**Parallelisable:** Phases 4, 5, 6 can run in parallel once Phase 1.1 is complete.

---

## Phase 1: Registry and Markdown Synchronisation

> [!NOTE]
> The YAML registry and the markdown documents are the two authoritative representations of the same algorithm universe. This phase ensures they agree on what algorithms exist, what parameters they take, what their status is, and what OIDs identify them.

### 1.1 Algorithm Coverage Audit

> [!NOTE]
> Guarantee that the algorithm catalogue (markdown) and the machine-readable registry (YAML) enumerate exactly the same set of cryptographic algorithms — no entry exists in one without the other.

- [ ] Extract canonical (non-`cdx:`/`spdx:`) family names from YAML
- [ ] Diff against markdown `| Id |` column entries
- [ ] Check for markdown entries without a corresponding YAML family
- [ ] Reconcile counts across registry README, markdown summary, and actual YAML

### 1.2 Parameter/Segment Coverage Audit

> [!NOTE]
> Guarantee that every configurable parameter documented in the parameter taxonomy has a corresponding segment definition in the YAML registry, and every YAML segment is explained in the documentation — so users and tooling share the same parameter model.

- [ ] Extract all segment `name:` fields from YAML → check presence in parameter markdown
- [ ] Extract all `{placeholder}` from parameters markdown → check YAML segment exists
- [ ] Verify constraint rules (`min`, `max`, `rule`) are consistent between docs and YAML

### 1.3 Status Synchronisation

> [!NOTE]
> Ensure the security status (approved, deprecated, disallowed, broken) assigned to each algorithm and parameter value is consistent between the human-readable status document and the machine-readable YAML — preventing contradictory guidance.

- [ ] Cross-check family-level YAML `status:` against status tables
- [ ] Cross-check segment-value `status:` (e.g., SHA-1: deprecated) against tables
- [ ] Flag and resolve discrepancies

### 1.4 OID Completeness and Correctness

> [!NOTE]
> OIDs are the universal identifiers for algorithms in X.509 certificates, CMS structures, and CBOMs. Ensure all known OIDs are present, correctly assigned, and free of duplicates — so OID-based lookups and CBOM generation produce correct results.

- [ ] Extract all OIDs from YAML (family-level, segment-value, oidMap)
- [ ] Validate format, check for duplicates pointing to different families
- [ ] Cross-check against OIDs in `cryptographic-algorithms.md`
- [ ] Spot-check sample against authoritative sources (NIST CSOR, RFC OID arcs)

---

## Phase 2: External Registry Alignment

> [!NOTE]
> The repository must track the two primary SBOM cryptography registries (CycloneDX and SPDX) so that any algorithm identifier a user encounters in a CycloneDX CBOM or SPDX SBOM can be validated and mapped to a canonical family. This phase detects drift since the last synchronisation.

### 2.1 CycloneDX Crypto Registry

> [!NOTE]
> Ensure 100% coverage of the CycloneDX `cryptography-defs.json` vocabulary — every CycloneDX algorithm pattern must resolve to a canonical or `cdx:`-prefixed family in the YAML registry.

- [ ] Fetch latest `cryptography-defs.json` from GitHub
- [ ] Compare against `CycloneDxRegistryCoverageTest.java` test patterns
- [ ] Identify new algorithms added since last sync
- [ ] Update `cr-cdx.yaml`, tests, and coverage table if needed

### 2.2 SPDX Algorithm List

> [!NOTE]
> Ensure 100% coverage of the SPDX cryptographic algorithm list — every SPDX identifier must resolve to a canonical or `spdx:`-prefixed family.

- [ ] Fetch latest SPDX YAML from GitHub
- [ ] Compare against `SpdxCoverageTest.java`
- [ ] Update `cr-spdx.yaml`, tests, and coverage table if needed

---

## Phase 3: Tests and Reports

> [!NOTE]
> The test suite is the executable proof that the YAML registry is correct and complete. This phase ensures every algorithm family has test coverage and that the test report document reflects the actual test results.

### 3.1 Missing Tests

> [!NOTE]
> Identify YAML families that lack any test case — untested families may contain schema errors, incorrect segment definitions, or broken OID mappings that would only surface at runtime.

- [ ] Compare YAML families against test class coverage
- [ ] Add tests for families identified as untested
- [ ] Verify each test validates the longest/most-complete pattern per family

### 3.2 Test Report

> [!NOTE]
> Regenerate the test report document so it matches the actual test suite output — keeping the documented test statistics in sync with reality.

- [ ] Run `mvn test`, capture results
- [ ] Update `management/validator-test-report.md` counts and taxonomy breakdown

---

## Phase 4: Glossary

> [!NOTE]
> The glossary is the single reference for term definitions used across all documents. This phase ensures every acronym and technical term used in the repository is defined, and every definition is accurate — so readers never encounter undefined jargon.

### 4.1 Completeness

> [!NOTE]
> Identify terms used in the markdown documents that lack a glossary entry, particularly those introduced during recent ingestion sessions.

- [ ] Scan all markdown files for acronyms and technical terms
- [ ] Compare against `cryptographic-glossary.md` entries
- [ ] Add missing terms

### 4.2 Accuracy

> [!NOTE]
> Verify that existing glossary definitions are factually correct and reflect the current state of standardisation — catching stale references to draft names, withdrawn standards, or outdated status.

- [ ] Verify definitions against authoritative sources
- [ ] Check for stale info (pre-standardisation names, outdated status)
- [ ] Ensure internal cross-references are consistent

---

## Phase 5: Inventory

> [!NOTE]
> The inventory maps algorithms to real-world implementations (libraries, tools, hardware). This phase ensures every algorithm family has at least one known implementation reference and that the inventory data (versions, URLs, licences) remains current.

### 5.1 Implementation Coverage

> [!NOTE]
> Identify algorithm families in the YAML registry that have no corresponding implementation entry in the inventory — these are gaps that reduce the practical value of the knowledge base.

- [ ] Check which YAML families lack any implementation in the inventory
- [ ] Research and add missing implementations
- [ ] Verify existing entries are still current (versions, URLs, licences)

### 5.2 README and XLSX Sync

> [!NOTE]
> The inventory README and the XLSX spreadsheet are dual representations of the same data. Ensure they agree — preventing users from seeing different information depending on which file they consult.

- [ ] Verify `inventory/README.md` matches the XLSX
- [ ] Update XLSX to reflect any new entries or coverage added to the README (requires explicit instruction; provide reminde)
- [ ] Update stale entries in both README and XLSX

---

## Phase 6: Diagrams

> [!NOTE]
> Diagrams are visual documentation of the parameter taxonomy and RNG classification. They are generated deterministically from `scripts/generate_diagrams.py`, which emits SVG directly (no layout engine). This phase ensures the Python data structures reflect the current state of the parameter definitions and YAML registry — so the rendered SVGs remain a trustworthy visual reference.

### 6.1 Parameter Taxonomy Diagram

> [!NOTE]
> Verify the parameter taxonomy sections in `generate_diagrams.py` cover all algorithm families and parameters — especially PQC, Ascon, SM9, 3GPP, hybrid constructs, and any newly added sections.

- [ ] Review `build_parameters_diagram()` in `scripts/generate_diagrams.py`
- [ ] Check sections §1-§11 match `cryptographic-parameters.md` structure
- [ ] Verify PQC blocks are current (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC parameters)
- [ ] Verify parameter ordering follows logical/specification order per algorithm
- [ ] Re-render: `python3 scripts/generate_diagrams.py`

### 6.2 RNG Taxonomy Diagram

> [!NOTE]
> Verify the RNG classification in `generate_diagrams.py` covers all families from `cr-rngs.yaml`.

- [ ] Review `build_rng_diagram()` in `scripts/generate_diagrams.py`
- [ ] Verify all `cr-rngs.yaml` families are represented (CSPRNG, OS/hardware, non-crypto PRNGs, historical)
- [ ] Re-render: `python3 scripts/generate_diagrams.py`

### 6.3 Layout Constants

> [!NOTE]
> Adjust layout constants in `generate_diagrams.py` when the diagrams grow too tall, need wider parameter boxes, or require different color schemes. Deterministic layout means changes are reproducible.

- [ ] Tune `PARAM_WIDTH`, section column counts, or spacing constants as content grows
- [ ] Ensure both diagrams remain visually consistent (same parameter width, font sizes, color conventions)

---

## Phase 7: Cross-File Consistency

> [!NOTE]
> After all content changes in Phases 1-6, this phase performs a final sweep to ensure all documents cite consistent numbers, use consistent names, and reference valid section numbers — catching any inconsistencies introduced during the update process itself.

### 7.1 Number Synchronisation

> [!NOTE]
> Numbers (family counts, test counts, OID counts, inventory entries) are cited in multiple documents. Ensure they all agree — a single stale count undermines trust in the entire repository.

Reconcile these numbers across all documents:

| Metric | Sources to reconcile |
|:---|:---|
| Total YAML families | registry README, runtime log, top-level README, test report |
| Total markdown algorithms | `cryptographic-algorithms.md` summary table |
| Total tests | `management/validator-test-report.md`, CI output |
| Total OIDs | registry README vs runtime log — reconcile |
| CycloneDX coverage | test count, coverage notes in `cryptographic-algorithms.md` |
| SPDX coverage | test count, coverage notes in `cryptographic-algorithms.md` |
| Inventory entries | `inventory/README.md`, XLSX |

### 7.2 Coverage Tables

> [!NOTE]
> The CycloneDX and SPDX coverage tables in `cryptographic-algorithms.md` summarise alignment with external registries. Ensure the counts, coverage notes, and unmatched-entry lists reflect the current state after Phases 2 and 3.

- [ ] Update SPDX Coverage Notes section in `cryptographic-algorithms.md`
- [ ] Update CycloneDX Coverage Notes section in `cryptographic-algorithms.md`
- [ ] Verify counts match actual test results from Phase 3.2

### 7.3 Cross-Reference Validation

> [!NOTE]
> Documents reference each other's sections, source publications, and naming-inconsistency resolutions. Verify these references are still valid after all content changes — broken cross-references mislead readers.

- [ ] Check section number references between documents are valid
- [ ] Verify source citations match the primary sources list in `cryptographic-algorithm-status.md` header
- [ ] Check `cryptographic-registry-inconsistencies.md` reflects current resolution state

### 7.4 Naming Consistency

> [!NOTE]
> Algorithm names must be spelled identically across all files. Inconsistencies (e.g., "Chacha20" vs "ChaCha20", "SPHINCS+" vs "SLH-DSA") confuse readers and break search/grep workflows.

- [ ] Spot-check key names across all files (ChaCha20-Poly1305, SLH-DSA, ML-KEM, etc.)
- [ ] Ensure pre-standardisation names (Kyber, Dilithium, SPHINCS+, Falcon) are secondary references only

---

## Phase 8: Improvements

> [!NOTE]
> After achieving consistency, this phase proposes forward-looking improvements — new authoritative sources to ingest, structural simplifications to the markdown, compactness improvements, and tooling to prevent future drift.

### 8.1 New Data Sources to ingest

> [!NOTE]
> Identify authoritative publications that are referenced but not yet fully ingested, and new sources that would expand the knowledge base's coverage or currency.

> [!NOTE]
> **Currency verification (2026-06-11).** Web-checked the PQC standardisation
> state against the early-May ingestion; the registry is current. **FN-DSA**
> (FIPS 206) remains an Initial Public Draft, final expected late 2026 / early
> 2027 → `lifecycle: draft` correct. **HQC** (FIPS 207) remains selected, IPD
> expected early 2026 but not yet published, final 2027 → `lifecycle: selected`
> correct. **SP 800-57 Pt 1 Rev 6** remains an IPD (released 2025-12-05;
> comment period closed 2026-02-05); final not yet published. The only drift:
> the IETF LAMPS **composite-sigs** Internet-Draft advanced from `-15`
> (cited repo-wide) to `-19` (2026-04-21, still an I-D, progressing toward
> Proposed Standard). The composite-signature OID arc
> (`1.3.6.1.5.5.7.6.37–.53`) is draft-specific and was reassigned across
> revisions — **verify OID stability before re-citing**; do not bulk-bump the
> draft number without checking the OID assignments and composite list in `-19`.

| Source | Priority | Status | Rationale |
|:---|:---|:---|:---|
| ~~FIPS 140-3 IG~~ | — | **Ingested 2026-05-02** (cryptographic-glossary.md entry; companion reference to FIPS 140-3 validation programme) | Implementation guidance for FIPS 140 level requirements; shallow ingestion only — deeper integration with per-algorithm IG-section references deferred to a future pass |
| SP 800-57 Rev 6 IPD | Medium | Partially ingested (3 refs in algorithm-status); **re-verified 2026-06-11: still IPD, final pending** | December 2025 initial public draft; PQC key management — expand once final draft published |
| draft-ietf-lamps-pq-composite-sigs | Low | Cited at `-15` (February 2026); **latest `-19` (2026-04-21)** | Composite ML-DSA for X.509 PKIX; verify OID arc stability before bumping the cited draft number (OIDs are draft-specific) |
| ENISA "Post-Quantum Cryptography" Report (2024) | Medium | Partially ingested (referenced in PSK quantum mitigation, glossary) | EU PQC migration guidance; could deepen the governance file's EU section |
| NIST IR 8547 (PQC Migration) | Low | Ingested (March 2025) | Already cited; keep tracked for revisions |
| NIST SP 800-227 (KEM Usage) | Low | Ingested (September 2025) | Cited in glossary, parameters; verified current |
| ~~SP 800-52 Rev 2 (TLS)~~ | — | **Ingested 2026-05-01** (cryptographic-tls-cipher-suites.md §13; glossary entry) | TLS cipher suite guidelines for US federal use; integrated as authority column alongside IETF/IANA/BSI |
| ~~BSI TR-02102-2 v2026-01 (TLS)~~ | — | **Ingested 2026-05-01** (cryptographic-tls-cipher-suites.md §12; glossary entry) | Structured TLS-suite tables with `use up to` deadlines; quantum-migration anchor for 2032 |
| ~~SP 800-131A Rev 2~~ | — | **Ingested** (25 refs in algorithm-status) | Removed from list — fully integrated |
| ~~SP 800-56Ar3~~ | — | **Ingested** (17 refs in algorithm-status) | Removed from list — fully integrated |
| ~~RFC 3962 / 6649 / 8009 / 8429 / 4556 (Kerberos)~~ | — | **Ingested 2026-05-02** (cr-kerberos.yaml, 14 composites; protocol-status §7) | Kerberos enc-types, integrity, PKINIT KEX/transport with IETF/NIST/BSI overlay |
| ~~SP 800-57 Pt 3 Rev 1 §6 (Kerberos) / §8 (DNSSEC)~~ | — | **Ingested 2026-05-02** (cr-kerberos.yaml + cr-dnssec.yaml authority overlays) | Federal Kerberos and DNSSEC algorithm guidance integrated as `nist:` blocks per composite |
| ~~RFC 8624 / 8945 / 8080 (DNSSEC + TSIG)~~ | — | **Ingested 2026-05-02** (cr-dnssec.yaml, 18 composites; protocol-status §8) | DNSSEC zone-signing algorithms + TSIG MACs with IETF/NIST/BSI overlay |

### 8.2 Markdown Structure Review

> [!NOTE]
> Evaluate whether the current file organisation (12 markdown files at top level) is optimal or whether merges/splits would improve navigability and reduce maintenance burden.

**Current sizes (lines):**

| File | Lines | Decision |
|:---|---:|:---|
| `cryptographic-parameters.md` | 1813 | **Keep** — single coherent taxonomy; splitting would fragment the placeholder vocabulary |
| `cryptographic-glossary.md` | 1715 | **Keep** — alphabetical sections provide natural navigation |
| `random-number-generators.md` | 884 | **Keep separate** — RNGs are a coherent topic; merging into `cryptographic-algorithms.md` (847 lines) would create a 1700+ line file with two disjoint scopes |
| `cryptographic-algorithms.md` | 847 | **Keep** — primary algorithm catalogue, well-bounded scope |
| `cryptographic-algorithm-status.md` | 711 | **Keep** — §14 (SP 800-57 Strength Equivalence) is 162 lines and not yet a split candidate |
| `cryptographic-registry-inconsistencies.md` | 542 | **Keep separate** — substantial self-contained reference; making it an appendix of algorithms.md would obscure its purpose |
| `cryptographic-protocol-status.md` | 532 | **Keep** — distinct from algorithm-status.md by scope (protocol-level vs algorithm-level) |
| `cryptographic-tls-cipher-suites.md` | 370 | **Keep** — natural focus area for IANA-cited TLS work |
| `cryptographic-authority-inconsistencies.md` | 317 | **Keep** — auto-generated by `validate_consistency.py` |
| `cryptographic-governance.md` | 192 | **Keep** — clear regulatory-context scope |
| `README.md` | 144 | **Keep** — index |
| `cryptographic-status.md` | 7 | **Keep** — redirect stub maintained as breadcrumb after the algorithm/protocol split |

Conclusion: current structure is well-balanced; no structural changes recommended at this time. Re-evaluate when any single file exceeds ~2500 lines or when scope drift becomes evident.

### 8.3 Compactness Review

> [!NOTE]
> Identify and eliminate redundant content across files — duplicate paragraphs, overly verbose prose that could be tables, and scope overlaps between documents — keeping content compact yet complete.

**Findings (Q2 2026 review):**

- BSI references in `cryptographic-algorithm-status.md` (per-algorithm status with BSI deadlines) and `cryptographic-parameters.md` §10 (BSI parameter minimums) are scope-appropriate, not duplicate content. Each file references TR-02102-1 v2026-01 from a different angle.
- §12 "TLS / Protocol Quick-Reference" in `cryptographic-algorithm-status.md` is a brief 6-row table; full TLS coverage lives in `cryptographic-tls-cipher-suites.md` and `cryptographic-protocol-status.md`. Intentional summary, not duplication.
- Algorithm-status.md and protocol-status.md sections are disjoint (algorithm-level vs SSH/IPsec/CNSA/PKI/S-MIME/Kerberos/DNSSEC). No scope overlap.

**Scope contract (verified):**

| File | Scope |
|:---|:---|
| `cryptographic-algorithms.md` | What exists — algorithm catalogue with patterns, OIDs, references |
| `cryptographic-parameters.md` | What varies — parameter taxonomy, value ranges, constraints |
| `cryptographic-algorithm-status.md` | What to use — algorithm-level recommendations, status, migration timelines |
| `cryptographic-protocol-status.md` | What to use — protocol-specific deployment guidance |
| `cryptographic-tls-cipher-suites.md` | TLS deep-dive — IANA-cited cipher suite tables |
| `cryptographic-governance.md` | Why it matters — regulatory context, compliance drivers |
| `random-number-generators.md` | RNG deep-dive |
| `cryptographic-glossary.md` | Definitions |
| `cryptographic-registry-inconsistencies.md` | CycloneDX/SPDX naming deviations and resolutions |
| `cryptographic-authority-inconsistencies.md` | Auto-generated cross-authority divergence report |

Conclusion: scope boundaries are clean. No compactness work outstanding.

### 8.4 Tooling Improvements

> [!NOTE]
> Automate consistency checks so that future content changes are validated mechanically rather than relying on manual audits — shifting from periodic cleanup to continuous integrity.

**Implemented in `scripts/validate_consistency.py`:**

- [x] `check_family_count` — YAML family count vs README/markdown claims
- [x] `check_parameter_name_coverage` — extract `{placeholder}` from `cryptographic-parameters.md` and check YAML coverage
- [x] `check_oid_count` — OID count consistency across files
- [x] `check_authority_divergence` — auto-generates `cryptographic-authority-inconsistencies.md`
- [x] `check_heading_style` — Phase 9 capitalisation enforcement
- [x] `check_test_count` — test count sync between test report and main README
- [x] `check_oid_format` — OID syntax validation
- [x] `check_duplicate_families` — registry duplicate detection
- [x] `check_status_values` — status vocabulary enforcement
- [x] `check_deprecated_preferred_invariant` — preferredPattern flag invariants
- [x] `check_summary_counts` — Summary Counts total drift detector (recomputes total from `| `id` |` rows; ±5 tolerance against documented `**~NNN**`)
- [x] `check_category_vocabulary` — every algorithm entry's `category:` value (when present) must be in the controlled vocabulary defined in [`registry-category-taxonomy.md`](registry-category-taxonomy.md); reports annotation coverage informationally
- [x] `check_lifecycle_vocabulary` — every algorithm entry's `lifecycle:` value (when present) must be in the controlled vocabulary defined in [`registry-lifecycle-taxonomy.md`](registry-lifecycle-taxonomy.md); reports per-value counts
- [x] `check_markdown_only_oids` (validator check 15) — every OID in `cryptographic-algorithms.md` must be backed by the YAML registry or be on a small allowlist of verified contextual references (BLAKE2, SM2 curve, PKCS#12, CMS, composite arc parent, draft hybrid). Guards against fabricated/confabulated OIDs entering the catalogue without single-source-of-truth backing — added 2026-06-15 after the OID verification sweep that caught and corrected the bogus ffdhe `1.3.101.100–104` OIDs (an early-session confabulation that reinterpreted RFC 7919 TLS codepoints as an OID arc)

**Implemented schema enrichments:**

- [x] **Category taxonomy field** ([`registry-category-taxonomy.md`](registry-category-taxonomy.md)) — added **mandatory** path-valued `category:` field to every algorithm entry (342/342 = 100% annotated). Function-first hierarchy aligned with `cryptographic-algorithms.md` section structure (§1–§19); 26 leaf categories across 11 top-level branches (`symmetric/`, `hash/`, `mac`, `asymmetric/`, `hpke`, `kdf/`, `framework`, `rng/`, `composite`) plus two sentinel values: `"unspecific"` for polysemous identifiers that map to multiple canonical algorithms (`spdx:rsa`, `spdx:ubi`) and `"unknown"` for identifiers without a clear standard cryptographic mapping (`spdx:dcc`, `spdx:uffizi`, `spdx:uxn`). `RegistryEntry.java` carries the field; `cr-*.yaml` schema docs updated; `scripts/generate_status_tables_from_yaml.py` emits an autogenerated "Algorithm Category Distribution" table inside `ae-pattern-validator/src/main/resources/registry/README.md`. `check_category_vocabulary` (validator check 13) enforces presence + vocabulary on every algorithm entry.
- [x] **Lifecycle taxonomy field** ([`registry-lifecycle-taxonomy.md`](registry-lifecycle-taxonomy.md)) — added **mandatory** `lifecycle:` field to every algorithm entry (342/342 = 100% annotated), orthogonal to `category:`. Vocabulary captures standardisation-process state: `standardised | draft | selected | candidate | withdrawn | broken | legacy` plus `unspecific` / `unknown` sentinels matching category convention. Initial distribution: 187 standardised, 82 legacy, 27 candidate, 19 broken, 12 draft, 11 withdrawn, 3 unknown, 1 selected. `RegistryEntry.java` carries the field; schema docs updated; generator emits an autogenerated "Algorithm Lifecycle Distribution" table parallel to the category distribution. `check_lifecycle_vocabulary` (validator check 14) enforces presence + vocabulary.

**Implemented automation entry point:**

- [x] **On-demand check script** (`scripts/check.sh`) — bundles the fast Python checks (`validate_consistency.py` + `generate_status_tables_from_yaml.py --check`) and, with `--tests`/`--all`, the `mvn test` suite. Exits non-zero on any failure. This replaces the originally-planned GitHub Actions CI: the `ae-pattern-validator` submodule that holds the `cr-*.yaml` single source of truth is **not part of the external repository**, so cloud CI cannot check it out — the validator (reads `cr-*.yaml`), the generator, and `mvn test` would all fail or run only partially in GitHub Actions. Local on-demand checking is the supported workflow.

**Outstanding tooling candidates:**

- [ ] Auto-generate the full 27-row Summary Counts table in `cryptographic-algorithms.md` from YAML — blocked by the YAML/markdown counting-unit mismatch: Summary Counts counts markdown rows (curves, padding values, hash variants), whereas YAML categories label entries (curves and padding live as parameter values). Requires either expanding the YAML schema to entry-per-curve / entry-per-padding (registry shape change), or accepting the markdown Summary Counts as a separate view from the YAML category distribution. Drift detector via `check_summary_counts` is implemented as an interim measure. **PQC-row sub-case (investigated 2026-06-11):** the five PQC rows cannot be regenerated from `category × lifecycle` either — the rows track *markdown editorial section membership*, which diverges from `lifecycle:` (e.g. `frodokem-*` is `lifecycle: candidate` but sits in the "Standardised and selected KEMs" section; `fn-dsa-*` is `lifecycle: draft` but counted under "NIST standardised"), and the Round 2 / Round 3 split is not in the lifecycle vocabulary (deferred — see `registry-lifecycle-taxonomy.md` §Deferred Decisions). Faithful autogen needs one of: (a) round-granularity added to lifecycle plus a parameter-set instantiation-count rule, (b) redefinition of the rows along the pure lifecycle axis (changes published numbers), or (c) a markdown-internal row-count drift check (no lifecycle dependency). **Resolved 2026-06-12 (option b):** the five hand rows are consolidated into two catalogue-count rows (`Post-quantum KEMs` 31, `Post-quantum signatures` 62 — preserving the `~426` grand total) and a new autogenerated **"Post-Quantum Algorithm Counts by Lifecycle"** sub-table (markers `pqc-lifecycle-counts`) renders the YAML-faithful `category × lifecycle` breakdown (6 / 29 / 30 / 2 / 26 / 4; 97 parameter-set instantiations) via `render_pqc_lifecycle_counts()` in `generate_status_tables_from_yaml.py`. The 97 (YAML param-set instantiations) exceeds the 93 catalogue rows because the registry enumerates instantiations the catalogue prose collapses (Classic McEliece `f`-variants, FAEST `s`/`f` × levels); this divergence is documented in-table. The full 27-row Summary Counts autogen remains blocked for the non-PQC rows.
- [ ] Multi-category support for polysemous SBOM identifiers via optional `categories: [list]` extension if the `"unspecific"` sentinel proves too coarse for downstream tooling that needs the explicit fan-out (e.g. SBOM scanners that want to enumerate the canonical algorithms `spdx:rsa` covers). Currently 2 entries carry `"unspecific"`; 3 carry `"unknown"`.
- [ ] Auto-generate the per-file Registry Statistics table in `management/validator-test-report.md` from YAML on each `mvn test` run
- [ ] ~~CI hook (GitHub Actions)~~ — **not viable**: the validator submodule is not part of the external repository (see implemented `scripts/check.sh` above). Run `scripts/check.sh` locally instead.
- [ ] Optional local git hook (`core.hooksPath`) wrapping `scripts/check.sh` — deferred per maintainer preference for on-demand checking over commit/push-time enforcement (decision 2026-06-11).

---

## Phase 9: Style Conventions

> [!NOTE]
> Enforce consistent stylistic conventions across all markdown files in the repository so that authoring, review, and machine processing all assume the same rules. New content must conform; existing content is brought into conformance opportunistically.

### 9.1 Heading Capitalisation (noun-only rule)

> [!NOTE]
> Markdown headings follow a **strict noun-only** capitalisation rule (German-style) rather than English title case. **Only nouns are capitalised.** Adjectives — even when modifying a noun ("attributive adjectives") — are lowercased. The first content word of every heading is always capitalised regardless of its part of speech.

**Capitalise (strict noun-only rule):**

| Class | Treatment | Example |
|:---|:---|:---|
| **Nouns** (proper nouns, common nouns, noun adjuncts) | Always capital | `Hash Functions`, `Key Length`, `Summary Table`, `Block Cipher Modes` (Block, Cipher, Modes are all noun words) |
| **Gerunds** (verb form `-ing` acting as noun) | Capital (treated as nouns) | `Comparing Authorities`, `Hashing`, `Signing`, `Pairing-based` (Pairing is a gerund/noun) |
| **Acronyms** | Preserved as-is | `NIST`, `BSI`, `CNSA`, `IETF`, `PRNGs`, `KEM`, `MAC`, `XOF` |
| **Proper nouns and intentional-case names** | Preserved as-is | `ML-KEM`, `SHA-256`, `OpenSSL`, `eSTREAM`, `Diffie-Hellman`, `Weierstrass` |
| **First content word of heading** | Always capital regardless of part of speech | `Symmetric Encryption` (Symmetric is adj but first content word → capital); `Five Questions every Organization should be able to answer` (Five is a quantifier but first word) |

**Lowercase (strict noun-only rule):**

| Class | Treatment | Example |
|:---|:---|:---|
| **Adjectives** (even attributive, modifying a following noun) | lowercase | `specific Modes`, `quantum Transition`, `digital Signatures`, `elliptic Curves`, `cryptographic Inventory`, `historical Schemes`, `prime Curves`, `internal Parameters` |
| **Past participles acting as adjectives** | lowercase | `approved Algorithms`, `disallowed Modes`, `named Groups`, `standardised Algorithms` |
| **Verbs, modals, auxiliaries** | lowercase | `is`, `are`, `should`, `must`, `enables`, `excludes`, `retains`, `disagree` |
| **Predicate adjectives** (following a verb) | lowercase | `is urgent`, `is invisible`, `is involved` |
| **Adverbs** | lowercase | `always`, `mostly`, `never`, `more`, `most`, `not` |
| **Determiners, pronouns** | lowercase | `every`, `this`, `it`, `these`, `that`, `each` |
| **Articles** | lowercase | `a`, `an`, `the` |
| **Conjunctions** | lowercase | `and`, `but`, `or`, `nor`, `yet`, `so`, `than` |
| **Prepositions** (regardless of length) | lowercase | `at`, `by`, `for`, `in`, `of`, `on`, `to`, `with`, `from`, `per`, `across`, `between`, `during` |

**Worked example (the user's reference example):**

```
# Five Questions every Organization should be able to answer
  ─┬── ─┬─────── ─┬─── ─┬─────────── ─┬───── ─┬─ ─┬── ─┬─ ─┬────
   │    │         │     │             │      │   │   │    │
   │    │         │     │             │      │   │   │    └── verb           → lowercase
   │    │         │     │             │      │   │   └────── preposition    → lowercase
   │    │         │     │             │      │   └────────── adjective      → lowercase
   │    │         │     │             │      └────────────── verb           → lowercase
   │    │         │     │             └───────────────────── modal verb     → lowercase
   │    │         │     └─────────────────────────────────── noun           → CAPITAL
   │    │         └──────────────────────────────────────── determiner     → lowercase
   │    └─────────────────────────────────────────────── noun           → CAPITAL
   └────────────────────────────────────────────────── first word     → CAPITAL
```

**Adjective vs noun-adjunct discrimination:**

The most subtle case is distinguishing **noun adjuncts** (nouns functioning as modifiers) from **true adjectives**. Both modify a following noun, but they have different parts of speech:

| Phrase | Modifier | POS | Treatment |
|:---|:---|:---|:---|
| `Block Cipher Modes` | `Block`, `Cipher` | nouns | CAPITAL — both are noun words even though they function as modifiers |
| `Hash Functions` | `Hash` | noun | CAPITAL |
| `Key Length` | `Key` | noun | CAPITAL |
| `Algorithm Families` | `Algorithm` | noun | CAPITAL |
| `Security Strengths` | `Security` | noun | CAPITAL |
| `quantum Transition` | `quantum` | adjective | lowercase |
| `digital Signatures` | `digital` | adjective | lowercase |
| `elliptic Curves` | `elliptic` | adjective | lowercase |
| `specific Modes` | `specific` | adjective | lowercase |
| `cryptographic Inventory` | `cryptographic` | adjective | lowercase |

**Test:** can the modifier word stand alone as a noun? `Block` (a block of memory) yes — it's a noun used attributively. `quantum` (a quantum) — yes in physics, but in `quantum Transition` it functions as an adjective ("of a quantum nature"). When in doubt, look up the dictionary entry: if the primary part of speech is "noun", capitalise; if "adjective", lowercase.

**Section number prefixes are not part of capitalisation scope:**

```
### 13.5 Quantum Impact on security-strength Equivalence
    ─┬── ─┬───── ─┬──── ─┬ ─┬──────────────── ─┬─────────
     │    │       │      │   │                  │
     │    │       │      │   │                  └── noun           → CAPITAL
     │    │       │      │   └────────────────────── hyphenated adj → lowercase both halves
     │    │       │      └────────────────────────── preposition    → lowercase
     │    │       └─────────────────────────────── noun           → CAPITAL
     │    └─────────────────────────────────── adj, FIRST WORD  → CAPITAL
     └────────────────────────────────────── numeric prefix  → unchanged
```

### 9.2 Em-Dashes in Headings (avoid)

> [!NOTE]
> Em-dashes (`—`) in headings introduce a parsing ambiguity (where does the title end and the qualifier begin?) and complicate first-word treatment. Avoid them by restructuring the heading into one of the three forms below.

**Three options for converting em-dash headings:**

| Form | Use when | Example |
|:---|:---|:---|
| **Concatenate** | The two halves form a single noun phrase | `Block Cipher — Key Length` → `Block Cipher Key Length` |
| **Bracket** | The trailing text is a qualifier or descriptor | `PRNGs — Always disallowed for security use` → `PRNGs (always disallowed for security use)` |
| **Restructure** | The heading reads more naturally with the order swapped | `Digital Signatures — ML-DSA (FIPS 204)` → `ML-DSA Digital Signatures (FIPS 204)` |

When em-dashes appear inside parentheses, replace them with a semicolon:

| Before | After |
|:---|:---|
| `(SP 800-186, Appendix G — All Deprecated)` | `(SP 800-186, Appendix G; all deprecated)` |
| `(NIST SP 800-232 — Ascon)` | `(NIST SP 800-232; Ascon)` |

### 9.3 Bracketed Content (lowercase unless name, acronym, or acronym expansion)

> [!NOTE]
> Content inside parentheses is **lowercase**, regardless of whether the words would be capitalised outside the brackets. Exceptions: proper names, acronyms, standards identifiers, intentional-case algorithm/library names, **and acronym expansions** (the spelled-out form of an acronym written immediately before the bracket).

**Lowercased inside brackets:**

| Before | After |
|:---|:---|
| `(Statistical Use Only)` | `(statistical use only)` |
| `(Historical / Legacy)` | `(historical / legacy)` |
| `(Not Standardised)` | `(not standardised)` |
| `(Do Not Use)` | `(do not use)` |
| `(Three Levels)` | `(three levels)` |
| `(Active)` | `(active)` |
| `(Post-Quantum)` | `(post-quantum)` |
| `(Cross-Reference)` | `(cross-reference)` |
| `(NIST Selection, Spec v2025-08-22)` | `(NIST selection, spec v2025-08-22)` (NIST stays — acronym) |
| `(Windows / System)` | `(Windows / system)` (Windows stays — proper noun) |

**Preserved inside brackets (names, acronyms, identifiers):**

| Form | Reason |
|:---|:---|
| `(SP 800-131A Rev 2)` | Standards identifier |
| `(FIPS 203)` | Standards identifier |
| `(RFC 9142)` | Standards identifier |
| `(BSI TR-02102-1 §3.4)` | Standards identifier |
| `(ML-DSA)` | Algorithm name |
| `(pyca/cryptography, PyCryptodome, PyNaCl)` | Library names |
| `(BCryptGenRandom)` | API name |

**Acronym-expansion exception (capitalisation preserved):**

When the parenthetical immediately follows an acronym and provides the spelled-out expansion of that acronym, the expansion is capitalised word-by-word — each significant word in the expansion takes its first letter from the corresponding letter of the acronym, so the visual link `Acronym ↔ Expansion` is preserved.

| Form | Reason |
|:---|:---|
| `LCG (Linear Congruential Generator)` | Expansion of LCG — L, C, G match the initials |
| `PCG (Permuted Congruential Generator)` | Expansion of PCG |
| `KEM (Key Encapsulation Mechanism)` | Expansion of KEM |
| `KDF (Key Derivation Function)` | Expansion of KDF |
| `HKDF (HMAC-based Key Derivation Function)` | Expansion of HKDF |
| `MAC (Message Authentication Code)` | Expansion of MAC |
| `CSPRNG (Cryptographically Secure Pseudorandom Number Generator)` | Expansion of CSPRNG |
| `OQS (Open Quantum Safe)` / `Open Quantum Safe (OQS)` | Project name in either order |
| `HNDL (Harvest Now, Decrypt Later)` | Threat-model name in either order |

**How to tell an acronym expansion from generic descriptive content:** the expansion's word initials should align (in order) with the letters of the preceding acronym — `L`inear `C`ongruential `G`enerator → LCG. Function words (articles, prepositions, conjunctions) inside an expansion still follow normal lowercasing rules. If the bracketed content does not align this way, treat it as ordinary parenthetical content (§9.3 default — lowercase).

**Bidirectional rule:** the same exception applies when the order is reversed (`Expansion (ACRONYM)`), e.g. `Linear Congruential Generator (LCG)`. In that case, recognise that the parenthetical is *the acronym for* the preceding phrase and preserve the phrase's capitalisation.

### 9.4 Hyphenated Compounds

> [!NOTE]
> Hyphenated compounds use a **compound-cohesion rule**: when the compound contains at least one noun (or gerund-noun), **all parts of the compound are capitalised** as a single lexical unit. This applies whether the compound is the head of its phrase or modifies another noun.
>
> **Past participles override the cohesion rule**: when the compound contains a past participle (`based`, `provided`, `shared`, `standardised`), the past participle stays lowercase regardless of the other parts. Noun parts of the same compound still take capital from the noun rule itself.

**Decision flow:**

1. **Does the compound contain a past participle (`-based`, `-provided`, `-shared`, `-standardised`)?**
   → Past participle stays lowercase. Other parts follow their own POS (nouns capital, prefixes/adjectives lowercase except first-word rule).
2. **Else, does the compound contain a noun (or gerund)?**
   → All parts of the compound get capital (cohesion rule).
3. **Else** (compound has no noun and no past participle):
   → All parts lowercase. First-word rule still applies to the first letter of the first word.

**Examples — compound contains a past participle (rule 1, past participle lowercase):**

| Compound | POS breakdown | Result | Example heading |
|:---|:---|:---|:---|
| `Hash-based` | `Hash` noun · `based` past participle | `Hash-based` | `Stateful Hash-based Signatures` |
| `Stream-Cipher-based` | `Stream` + `Cipher` nouns · `based` past participle | `Stream-Cipher-based` | `Stream-Cipher-based CSPRNGs` |
| `Accumulator-based` | `Accumulator` noun · `based` past participle | `Accumulator-based` | `Accumulator-based CSPRNGs` |
| `OS-provided` | `OS` acronym noun · `provided` past participle | `OS-provided` | `OS-provided Entropy APIs` |
| `Pairing-based` | `Pairing` gerund-noun · `based` past participle | `Pairing-based` | `Pairing-based Cryptography` |
| `Pre-shared` | `Pre-` prefix · `shared` past participle | first word: `Pre-shared`; else: `pre-shared` | `Pre-shared Key (PSK) quantum Mitigation` |
| `Non-standardised` | `Non-` prefix · `standardised` past participle | first word: `Non-standardised`; else: `non-standardised` | `Notable non-standardised PQC Algorithms` |
| `NIST-standardised` | `NIST` acronym noun · `standardised` past participle | `NIST-standardised` | `NIST-standardised post-quantum digital Signatures` |

**Examples — compound contains a noun, no past participle (rule 2, cohesion applies):**

| Compound | POS breakdown | Result | Example heading |
|:---|:---|:---|:---|
| `Quick-Reference` | `Quick` adjective · `Reference` noun | `Quick-Reference` | `TLS / Protocol Quick-Reference` |
| `End-Entity` | `End` noun · `Entity` noun | `End-Entity` | `End-Entity Key Recommendations` |
| `Security-Strength` | `Security` noun · `Strength` noun | `Security-Strength` | `Quantum Impact on Security-Strength Equivalence` |
| `Top-Level` | `Top` adjective · `Level` noun | `Top-Level` | `Top-Level RNG Taxonomy` |
| `Cross-Reference` | `Cross-` prefix · `Reference` noun | `Cross-Reference` | `Cross-Reference Validation` |
| `Cross-File` | `Cross-` prefix · `File` noun | `Cross-File` | `Phase 7: Cross-File Consistency` |

**Examples — compound contains no noun and no past participle (rule 3, all lowercase except first word):**

| Compound | POS breakdown | Result | Example heading |
|:---|:---|:---|:---|
| `Cross-cutting` | `Cross-` prefix · `cutting` participle | first word: `Cross-cutting` | `Cross-cutting PQC hybrid Parameters` |
| `Non-cryptographic` | `Non-` prefix · `cryptographic` adjective | first word: `Non-cryptographic` | `Non-cryptographic PRNGs` |
| `Post-quantum` | `Post-` prefix · `quantum` adjective | first word: `Post-quantum` | `Post-quantum Cryptography` |

**Inside brackets (lowercased per §9.3):**

| Compound | Example |
|:---|:---|
| `post-quantum` | `(post-quantum)` |
| `cross-reference` | `(cross-reference)` |
| `low-order` | `(low-order rounding threshold)` |
| `hash-based` | `(hash-based)` |

### 9.5 Acronym and Proper Noun Preservation

> [!NOTE]
> Acronyms, algorithm names, and proper nouns retain their canonical capitalisation in **all** positions (headings, brackets, prose). Capitalisation rules must not "correct" intentional non-standard casing.

**Always preserved as-is:**

| Class | Examples |
|:---|:---|
| **Acronyms** | `PRNGs`, `KEM`, `MAC`, `XOF`, `DRBG`, `AEAD`, `OID`, `MGF`, `IETF`, `NIST`, `BSI`, `CNSA`, `CABF`, `IPsec`, `MODP`, `ECP`, `FORS`, `WOTS`, `XMSS`, `LMS`, `HSS`, `QKD` |
| **Algorithm names with intentional case** | `eSTREAM`, `cSHAKE`, `bcrypt`, `scrypt`, `yescrypt`, `secp256r1`, `brainpoolP256r1`, `mceliece460896/f`, `ssh-ed25519`, `chacha20-poly1305@openssh.com` |
| **Library / vendor names** | `pyca/cryptography`, `liboqs`, `OpenSSL`, `BoringSSL`, `GmSSL`, `wolfSSL`, `metæffekt`, `Bouncy Castle` |
| **OS API names** | `BCryptGenRandom`, `getrandom`, `getentropy`, `dev-random`, `dev-urandom`, `RDRAND`, `RDSEED` |
| **Standards identifiers** | `FIPS 203`, `SP 800-131A Rev 2`, `RFC 9142`, `TR-02102-1`, `BSI AIS 20/31` |
| **Mathematician / inventor names in proper nouns** | `Diffie-Hellman`, `Merkle`, `Schnorr`, `ElGamal`, `Lamport`, `Falcon` |

### 9.6 Verification and Enforcement

- [ ] Run `grep -nE '^#+' *.md inventory/README.md ae-pattern-validator/**/*.md management/*.md` after any heading edit to spot-check capitalisation
- [ ] Verify no em-dashes remain in headings: `grep -nE '^#+ .*—' *.md inventory/README.md ae-pattern-validator/**/*.md management/*.md` should return nothing
- [ ] When adding new headings, follow the lookup table in §9.4 for hyphenated compounds and §9.5 for preserved-case names
- [ ] Consider adding a tooling check (Phase 8.4) that flags lowercase nouns and rogue em-dashes in markdown headings, exempting the acronym/identifier list in §9.5

---

## Verification

After each phase:
```bash
cd ae-pattern-validator && mvn test
# All tests must pass
```

Final verification checklist:
- [ ] `grep -c 'family:' cr-*.yaml` total matches registry README
- [ ] Summary counts in `cryptographic-algorithms.md` are accurate
- [ ] No broken cross-references between documents
- [ ] `management/validator-test-report.md` matches actual test output
- [ ] OID count in registry README matches runtime log
