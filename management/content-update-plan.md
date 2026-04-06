# Content Update Plan — Consistency, Integrity, and Synchronisation

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

### 8.1 New Data Sources to Ingest

> [!NOTE]
> Identify authoritative publications that are referenced but not yet fully ingested, and new sources that would expand the knowledge base's coverage or currency.

| Source | Priority | Rationale |
|:---|:---|:---|
| SP 800-131A Rev 2 | High | Algorithm transition schedules — heavily referenced but not yet ingested |
| SP 800-56Ar3 | Medium | Partially ingested (§5.2 key establishment schemes) |
| SP 800-52 Rev 2 (TLS) | Medium | TLS cipher suite guidelines; would expand §11 |
| BSI TR-02102-2 (TLS) | Medium | TLS recommendations; companion to already-ingested TR-02102-1/3/4 |
| FIPS 140-3 IG | Low | Implementation guidance for FIPS 140 level requirements |
| SP 800-57 Rev 6 IPD | Low | December 2025 initial public draft; PQC key management |

### 8.2 Markdown Structure Review

> [!NOTE]
> Evaluate whether the current file organisation (7 markdown files) is optimal or whether merges/splits would improve navigability and reduce maintenance burden. Also review chapter ordering within each file.

- [ ] Evaluate merging `random-number-generators.md` into `cryptographic-algorithms.md` (RNGs already §16-§19 there)
- [ ] Evaluate whether `cryptographic-registry-inconsistencies.md` should become an appendix of `cryptographic-algorithms.md`
- [ ] Check `cryptographic-governance.md` for updates needed after all ingestion work
- [ ] Consider splitting `cryptographic-algorithm-status.md` §13-§21 (SP 800-57 / protocol-specific) into a separate file if it grows further
- [ ] Review chapter ordering within each markdown file for logical flow

### 8.3 Compactness Review

> [!NOTE]
> Identify and eliminate redundant content across files — duplicate paragraphs, overly verbose prose that could be tables, and scope overlaps between documents — keeping content compact yet complete.

- [ ] Check for duplicate content between `cryptographic-algorithm-status.md` and `cryptographic-parameters.md` (BSI migration timeline appears in both)
- [ ] Identify verbose prose sections that could become tables
- [ ] Ensure each file has a clear, non-overlapping scope:

| File | Scope |
|:---|:---|
| `cryptographic-algorithms.md` | What exists — algorithm catalogue with patterns, OIDs, references |
| `cryptographic-parameters.md` | What varies — parameter taxonomy, value ranges, constraints |
| `cryptographic-algorithm-status.md` | What to use — recommendations, status, migration timelines |
| `cryptographic-governance.md` | Why it matters — regulatory context, compliance drivers |
| `random-number-generators.md` | RNG deep-dive (candidate for merge) |
| `cryptographic-glossary.md` | Definitions |
| `cryptographic-registry-inconsistencies.md` | CycloneDX/SPDX naming deviations and resolutions |

### 8.4 Tooling Improvements

> [!NOTE]
> Automate consistency checks so that future content changes are validated mechanically rather than relying on manual audits — shifting from periodic cleanup to continuous integrity.

- [ ] Consider a CI script that validates YAML family count matches README/markdown claims
- [ ] Consider a script that extracts all `{placeholder}` from `cryptographic-parameters.md` and checks YAML coverage
- [ ] Consider generating the summary counts table in `cryptographic-algorithms.md` from YAML rather than maintaining manually

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
