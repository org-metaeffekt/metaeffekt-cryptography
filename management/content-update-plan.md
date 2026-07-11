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

> [!NOTE]
> **Two inventories.** The repository maintains two complementary spreadsheets in `inventory/`, both keyed by runtime/library but scoped and versioned differently:
>
> | Inventory | File | Scope | Version coverage |
> |:---|:---|:---|:---|
> | **Asset inventory** | `ae-cryptography-asset-inventory.xlsx` (mirrored by `inventory/README.md`) | Runtimes and libraries that implement cryptographic libraries or functions | The **last two major versions**; for **each** major, the **latest available minor.patch** release (up to two version rows per library — newest release of the current major and of the preceding major). The preceding-major row is added **only while that major is still maintained** — EOL / superseded major lines are not tracked. Libraries that have only ever had one major line get a single row. |
> | **BOM inventory** | `ae-cryptography-bom-inventory.xlsx` | The same runtimes and libraries, scoped for vulnerability monitoring (CPE/PURL mapping) | Only the **latest major.minor** line; within it the **`.0`** release **and** the **latest available patch** (e.g. for a current `4.1.x` line: `4.1.0` and `4.1.<latest>`) |
>
> BOM curation rules also apply: drop variants whose fixes have been upstreamed, exclude reference implementations (not production-deployed; NVD will not distinguish them), and do not track superseded major lines.

> [!NOTE]
> **Column schemas differ and must be preserved.** Each inventory has its own column set and formatting. Updates must keep the existing columns (order and headers) intact and fill the cells for every applicable column of a new or revised row — do not drop, reorder, or leave schema columns unpopulated where a value applies.
>
> - **Asset inventory** (`ae-cryptography-asset-inventory.xlsx`, 12 columns): `Id` · `Covered in CryptoBOM Dashboard` · `Repository License` · `Version` · `URL` · `Source Archive - URL` · `Description` · `Version Status` · `Status` · `Patterns` · `Comments` · `Patent References`.
> - **BOM inventory** (`ae-cryptography-bom-inventory.xlsx`, component sheet, 10 columns): `Id` · `Component` · `Version` · `AID-CryptoBOM` · `Type` · `Inapplicable CPE URIs` · `Additional CPE URIs` · `Inapplicable PURLs` · `Proposed CPE` · `Proposed Inapplicable CPE URIs`.
>
> `Id` convention is `name-version` (or `name` when unversioned). The asset inventory's `Patterns` column carries the registry algorithm patterns (the join key to the YAML families for 5.1 coverage); its `Covered in CryptoBOM Dashboard` flag cross-links to the BOM inventory.

### 5.1 Implementation Coverage

> [!NOTE]
> Identify algorithm families in the YAML registry that have no corresponding implementation entry in the inventory — these are gaps that reduce the practical value of the knowledge base.

- [ ] Check which YAML families lack any implementation in the inventory
- [ ] Research and add missing implementations
- [ ] Verify existing entries are still current (versions, URLs, licences)

### 5.2 README and XLSX Sync

> [!NOTE]
> `inventory/README.md` and the asset-inventory XLSX (`ae-cryptography-asset-inventory.xlsx`) are dual representations of the same data. Ensure they agree — preventing users from seeing different information depending on which file they consult. The BOM XLSX (`ae-cryptography-bom-inventory.xlsx`) is a separate, vulnerability-monitoring view derived from the same library set under the version rules above.

- [ ] Verify `inventory/README.md` matches the asset-inventory XLSX
- [ ] Verify the BOM XLSX reflects the asset inventory under the BOM version/curation rules (latest major.minor: `.0` + latest patch)
- [ ] Update XLSX files to reflect any new entries or coverage added to the README (requires explicit instruction; provide reminder)
- [ ] Update stale entries in `inventory/README.md` and both XLSX files

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
| ~~TCG Algorithm Registry (Family "2.0" Level 00 Rev 1.35)~~ | — | **Ingested 2026-07-01** (cryptographic-glossary.md entry; `tcg:` identity overlay + `tcg` authority in the YAML registry) | TPM 2.0 algorithm-identifier registry (`TPM_ALG_ID` / `TPM_ECC_CURVE`). Modelled in two layers: (1) **identity** — a `tcg:` overlay (registry/identifier/value) parallel to `iana:`; (2) **posture** — `tcg` is a first-class **authority** (registered like nist/bsi/cnsa; `--authority tcg`), mapping **TCG Legacy → `deprecated`** and **TCG Standard → `approved`** (Assigned → no posture). Curves and block-cipher modes are first-class entries (`cr-ecc-curves.yaml`, category `curve`; generic modes in `cr-symmetric-ciphers.yaml`) so each identifier lives once; SHA/SHA3 ids sit on the umbrella `variant` values. Not mapped: TCG-internal object types (`KEYEDHASH`/`NULL`/`SYMCIPHER`/`XOR`) and bare key-type tags (`RSA`/`ECC`). Human-readable TCG column in the status-comparison tables deferred. Verified on JDK 17: 809 tests green, all consistency checks pass. Rev 1.35 (18 Feb 2025) marks 3DES and SHA-1 as TCG Legacy |
| ~~DMTF DSP0274 SPDM v1.3.0~~ | — | **Ingested 2026-07-03** (glossary entry; `cr-spdm.yaml` composite registry; cryptographic-protocol-status.md §9) | DMTF Security Protocol and Data Model (hardware attestation/authentication). Full-parity protocol ingestion (matches TLS/SSH/IPsec/Kerberos/DNSSEC): new **`cr-spdm.yaml`** — 31 composite entries (12 asym-sig, 7 hash, 7 DHE groups, 4 AEAD, 1 key schedule) from DSP0274 §10.4, generated by `generate_protocol_composites.py` (`SPDM_ENTRIES`) with `nist:` posture overlays; 6 new `spdm*` composite subTypes. Auto-discovered by the Java loader/validator/generator (no hardcoded-list edits — payoff from the discovery unification). `cryptographic-protocol-status.md §9` covers the negotiable registries + the 6 SPDM certificate OIDs (`id-DMTF-spdm` arc `1.3.6.1.4.1.412.274.*`, verified from the spec). SPDM reuses TCG `TPM_ALG_*` identifiers. Verified on JDK 17: 812 tests green, all 19 consistency checks pass |
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
- [x] `check_spdx_oid_consistency` (validator check 16) — every SPDX identifier that publishes an upstream OID (vendored in `SPDX_ENTRY_OIDS`) must map, through its `spdx:` alias's `preferredPattern`, to a canonical family whose registry OID equals the SPDX-declared OID. OID-keyed reconciliation independent of name/filename — guards against alias mis-mappings where the SPDX entry's OID and its mapped algorithm disagree (e.g. the historical `spdx:gost` → GOST-28147 at OID `1.2.643.2.2.21`, whereas the SPDX id is `gostr3412-2015` → Magma at OID `1.2.643.7.1.1.5.1`)

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

### 8.5 Data Model Evolution: Three-Layer Model (Concept)

> [!NOTE]
> **Status: concept captured for later; not scheduled.** Recorded 2026-07-11 from a design discussion. Deferred pending further exploration before any commitment. The grammar and canonical pattern model are **not** in question here — this concerns only *how facts and relationships about algorithms are organised*.

**Framing — three conceptual concerns, two mechanisms.** The registry currently conflates several distinct kinds of knowledge on the same YAML nodes. Separating them yields three conceptual layers:

1. **Identification** — *what is this and what is it called?* The grammar + canonical pattern tree (the valid subjects), plus identity resolution: aliases/synonyms and cross-registry identifiers (`oid`, TCG `TPM_ECC_*` id, IANA number) all resolving to one canonical subject. This is the **subject vocabulary** everything else references.
2. **Assertions (attributes)** — *what is true / said about this one thing?* `subject → literal`: authority status × context, references, provenance.
3. **Relationships (edges)** — *how does this thing relate to other things?* `subject → subject`: `based-on`, `supersedes`, `equivalent-to`, … (see [§8.5.1](#851-relationship-graph-layer-3)).

Layers 2 and 3 share **one substrate** — pattern-keyed triples with referential integrity, provenance (`source`/`asOf`), context, and the "derive all views" principle. They differ only in whether the object is a **literal** (2) or **another subject** (3) — exactly the RDF/OWL *datatype-property* vs *object-property* distinction. So the design is **3 concerns to reason about, 2 stores to build**: the identity foundation (1), and the triple layer hosting both attribute-assertions (2) and relationship-edges (3). Naming three keeps the thinking clear; collapsing 2+3 into one mechanism keeps the implementation honest.

**Diagnosis (why separate at all).** Today assertions are *attached directly to structure at any level*, so no fact has a single canonical home and the same fact is restated in multiple places and drifts; and inter-entry relationships (Layer 3) have no structured home at all (only composite `components:`), so they live as prose. Evidence accumulated across ingestion sessions:

- **Restated assessments contradict.** SPDM composites were hand-authored with a NIST status (`ECDSA-P-384 → approved`) that contradicted the canonical value-level assessment (`transitional`, until 2035). Every protocol composite (TLS/SSH/IPsec/Kerberos/DNSSEC/SPDM) re-states authority assessments of algorithms already assessed on the canonical entries.
- **Context collisions force duplication.** `ECDSA-P-256` is `nist: disallowed` for *signatures* but `nist: recommended` for *key agreement*; the current model can only express this by duplicating the curve across usage contexts (per composite).
- **Taxonomy and counts live in N places.** The category vocabulary lived in three hand-maintained trees (validator set, doc tree, ASCII tree — now guarded by checks 18/19); entry counts live in ~five (guarded by check 12). The consistency checks are largely a **band-aid for missing referential integrity**.
- **Relationships are prose-only.** Family-level semantic edges — "ML-KEM based on Kyber", "AES supersedes 3DES", "Edwards25519 birationally equivalent to Curve25519" — appear across the markdown as free text (mined counts: "based on" ×45, "superseded" ×32, "truncated" ×27, "variant of" ×16, "derived from" ×16, "equivalent to" ×8, …) but are not navigable or queryable. The only structured inter-entry relationship in the registry is composite `components:`.

**Proposed reorganisation.** Keep the grammar + pattern tree as the identity layer. Lift the *assertional* fields into a first-class **assertion layer** — statements that *reference* a canonical pattern rather than being embedded in it:

```
(subject:  <canonical pattern or pattern-glob>,   e.g. "ECDSA-P-384-*"
 predicate: authority-status | identifier | reference,
 object:   <value>,                               e.g. "transitional"
 context:  <usage>,                               e.g. "signature" (vs "key-agreement")
 source:   <document>,                            e.g. "SP 800-131A Rev 2"
 asOf:     <date>)
```

Everything else — protocol composites, status tables, the §10 catalogue, distribution tables, dashboards — becomes a **derived projection** over (pattern tree + assertions). Structure = schema for subjects; assertions = the data; markdown / composite-YAML / CBOM = queries.

**The identity / assessment line.** `oid` and the `tcg` *identity* overlay (`registry`/`identifier`/`value`) are structural ("what this thing is") and stay on the pattern tree. `authorities.*.status` and the `tcg` *authority* posture are assertional ("what an authority says about it") and move to the assertion layer. Precedent already exists: the TCG ingestion split exactly this way (`tcg:` identity overlay vs `authorities.tcg` posture) — evidence the distinction is real and the model is half there.

**Benefits (each maps to a pain we actually hit):**

- Single canonical home per fact → the SPDM-parity class of contradiction becomes *structurally impossible*; composites carry no overlays, they *inherit* via `(component-pattern, context)`.
- `context` as a first-class dimension → signature-vs-key-agreement is two assertions, not two duplicated entries.
- Provenance (`source` + `asOf`) is structural → the anti-confabulation discipline and "re-verify when the upstream doc revises" become queryable reports, not memory.
- Referential integrity by construction → checks 12/18/19 and much of the count/taxonomy-drift surface collapse into "does every subject parse against the grammar" + "is every referenced authority/source known".
- **Identification becomes independently verifiable.** Separating the layers lets the prefix-parameter-sequence parse be validated on its own, decoupled from the assessments layered on top.
- **Assertions can use the pattern approach themselves.** A subject may be a **pattern-glob / placeholder expression** (e.g. `ECDSA-P-384-*`, `AES-256-*`), so a single recommendation applies across a family — and **general rules** (e.g. "RSA < 3000-bit → BSI disallowed", "PKCS#1 v1.5 signatures → deprecated") become expressible as parametric assertions rather than enumerated per-instance copies.

**Costs / non-goals.** Not a graph-database product, not abandoning human-readable YAML authoring, not touching the grammar or canonical naming. Trade-off: a normalised assertion store is less browseable than per-taxonomy YAML and needs authoring/query tooling.

**Migration path (incremental, not big-bang).** Extract the assertional fields (`authorities`/`nist`/`bsi`/`ietf`, `references`, per-composite overlays) into a pattern-keyed assertion layer with `context` + `source`; keep the current embedded YAML as a **generated view** of that layer during transition (so the Java validator and tests are unchanged on day one); then flip protocol composites and status tables to derive from assertions. Proof-of-concept scope: one protocol (SPDM is the natural candidate — its overlays are already the clearest duplication).

#### 8.5.1 Relationship Graph (Layer 3)

> [!NOTE]
> A typed directed graph of **family-level** semantic edges between entries — the same triple substrate as the assertion layer, but with an **entry-valued object** (`subject → subject`). Distinct from aliases (Layer 1: "same thing, different name") and from composite `components:` (instance-level "uses"); this captures the family-level relationships that today have no structured home.

**Proposed predicate vocabulary** (small and typed — deliberately *no* free-form "relates-to", which would turn a useful graph into noise):

| Predicate | Meaning | Examples in the data | Kind |
|:---|:---|:---|:---|
| `uses` / `built-on` | X operationally depends on Y | HMAC → hash; ECDSA → curve; HKDF → HMAC; Ed25519 → Curve25519 | structural |
| `based-on` / `derived-from` | X's design descends from Y | SHAKE/SHA-3 ← Keccak; XChaCha20 ← ChaCha20 ← Salsa20; Argon2i/d/id ← Argon2 | structural |
| `truncation-of` | X is a truncated Y | SHA-224 ← SHA-256; SHA-512/256 ← SHA-512 | structural |
| `equivalent-to` (symmetric) | same math object, different form | W-25519 ≡ Curve25519 ≡ Edwards25519; ristretto255 built-on Curve25519 | structural |
| `supersedes` / `superseded-by` (inverse pair) | migration direction | AES ⇒ 3DES/DES; SHA-256 ⇒ SHA-1; ML-KEM ⇒ RSA/ECDH (PQC) | **sourced** (which authority mandates the migration) |
| `standardized-from` / `formerly` | naming provenance | ML-KEM ← Kyber; ML-DSA ← Dilithium; SLH-DSA ← SPHINCS+; FN-DSA ← Falcon | structural |

**Design decisions this layer needs:**

- **Family-level granularity** — edges attach to the family entry (`ML-KEM based-on Kyber`), not per parameter instance.
- **Declare canonical direction; derive inverses** — store `supersedes`, derive `superseded-by`; `equivalent-to` is symmetric.
- **Structural vs sourced** — `truncation-of` / `equivalent-to` are objective facts; `supersedes` (migration) carries a `source` (same identity/assessment line as Layer 2).
- **No overlap with existing mechanisms** — `components:` already covers instance-level "uses" for composites; aliases cover name-synonyms.

**Value:** navigable queries ("what supersedes SHA-1?", "all Curve25519 representations", "what is ML-KEM based on?"); **PQC migration paths become queryable**; the "based on"/"superseded" prose scattered across markdown gets a single source and can be *generated*; can drive the dependency diagrams; enables consistency rules (if X supersedes Y, Y's lifecycle should be lower). **Caution:** keep the vocabulary tight — only encode edges with real value (migration, equivalence, standardization provenance, key construction).

#### 8.5.2 Open Questions

- [ ] **The further aspect to explore first** (flagged by maintainer 2026-07-11, before committing to this direction) — *to be elaborated*.
- [ ] Where exactly to draw the identity/assessment line for borderline fields (`lifecycle` — arguably a standardisation-*fact* with provenance, so possibly assertional; `category` — structural).
- [ ] Glob/placeholder semantics for assertion subjects: precedence and conflict resolution when a specific-pattern assertion and a family-glob assertion both match (most-specific-wins, like longest-prefix matching?).
- [ ] Authoring ergonomics: how maintainers write/review assertions and relationship edges without losing the diff-friendliness of the current per-file YAML.
- [ ] Relationship-layer scope guard: which edge types earn their keep vs. add noise; whether `uses` (Layer 3, family-level) is worth encoding given `components:` already covers instance-level composition.

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
