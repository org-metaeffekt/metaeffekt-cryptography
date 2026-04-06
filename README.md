# {metæffekt} Cryptography

Aggregates information on cryptographic algorithms, random number generators, and associated parameters. 
Covers a pattern-based approach for the evaluation of algorithms and generators.

> [!WARNING]  
> The content in this repository is aggregated with artificial intelligence (Claude and partially Gemini). 
> There is absolutely no claim on completeness and correctness. All usages are at your own risk.

## Introduction

Cryptography is a key asset of modern software. It supports protecting data (confidentiality, integrity, authenticity)
as well as functional authority (grants, claims).

Modern software systems depend on a rich and evolving ecosystem of cryptographic algorithms and protocols. Symmetric
ciphers such as AES protect data at rest and in transit; asymmetric schemes based on RSA, elliptic curves, or lattices
underpin key exchange, digital signatures, and certificate infrastructure; hash functions provide the integrity backbone
of everything from version control to blockchain ledgers. Together these primitives form layered security architectures
that guard communications, authenticate identities, authorise access, and establish provenance across distributed
systems.

The choice of cryptographic algorithm is never purely academic. It carries concrete engineering consequences:
performance budgets, key and signature sizes, hardware acceleration availability, side-channel exposure, and
compatibility with standards such as FIPS 140-3, ETSI, or the Common Criteria. At the same time, the threat landscape
evolves continuously. Cryptanalytic breakthroughs, implementation flaws, and emerging computational paradigms — most
notably large-scale quantum computing — periodically invalidate previously secure primitives and force ecosystem-wide
migrations.

Quantum computing poses a structural threat to the public-key algorithms that underpin most of today's internet
security. Shor's algorithm can break RSA and elliptic-curve discrete-logarithm schemes in polynomial time on a
sufficiently powerful quantum computer. In response, NIST concluded a multi-year standardisation process in 2024,
publishing FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) as the first post-quantum cryptography (PQC)
standards, with FN-DSA (Falcon) and HQC following. Organisations must now plan and execute migrations from classical to
quantum-resistant algorithms before cryptographically relevant quantum computers become available — a transition
complicated by the sheer breadth and depth of cryptographic usage across modern software stacks.

Effective governance of cryptographic assets therefore requires systematic visibility into what algorithms are deployed,
where, in which versions, and under which configurations. Without this inventory — commonly pursued through Software
Bill of Materials (SBOM) practices and cryptographic agility frameworks — organisations cannot assess their exposure,
prioritise remediation, or demonstrate compliance. Identifying, classifying, and tracking cryptographic algorithms at
the software-component level is the prerequisite for any meaningful migration or risk management programme.

## Purpose

This repository aggregates information on cryptographic materials. It tries to convey and
explain the complexity of the domain. It is intended to foster discussion on how to collaboratively 
organize this data and make it usable to all concerned parties.

For a summary of questions tried to answer see [cryptographic-governance.md](cryptographic-governance.md).

## License

Please note that this content is based on public data sources. Primarily:

* https://github.com/spdx/cryptographic-algorithm-list (Creative Commons Zero Universal 1.0)
* https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.json (Apache License 2.0)
* https://groups.google.com/a/list.nist.gov/g/pqc-forum (individual copyrights, licenses and trademarks apply)
* [NIST FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf) (ML-KEM), [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf) (ML-DSA), [FIPS 205](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf) (SLH-DSA), [FIPS 206 IPD](https://csrc.nist.gov/pubs/fips/206/ipd) (FN-DSA) — public domain
* [NIST SP 800-57 Part 1 Rev 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf), [SP 800-57 Part 2 Rev 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt2r1.pdf), [SP 800-57 Part 3 Rev 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf), [SP 800-131A Rev 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf) — public domain
* [NIST SP 800-56A Rev 3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf) — *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*, April 2018 — public domain
* [NIST SP 800-186](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf) — *Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters*, February 2023 — public domain
* [NIST SP 800-208](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf) — *Recommendation for Stateful Hash-Based Signature Schemes*, October 2020 — public domain
* [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) — *Ascon-Based Lightweight Cryptography Standards*, 2023 — public domain
* [BSI TR-02102-1](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.html) v2026-01, [TR-02102-2](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-2.html) v2026-01, [TR-02102-3](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-3.html) v2026-01, [TR-02102-4](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-4.html) v2026-01 — public domain
* [NSA Cybersecurity Advisory PP-22-1338](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF): *Announcing the Commercial National Security Algorithm Suite 2.0* (CNSA 2.0), September 2022, Version 1.0 — public domain
* [ENISA — *Post-Quantum Cryptography: Current state and quantum mitigation*](https://www.enisa.europa.eu/publications/post-quantum-cryptography-current-state-and-quantum-mitigation), v2, May 2021. Authors: Ward Beullens et al. DOI: [10.2824/92307](https://doi.org/10.2824/92307). © European Union Agency for Cybersecurity (ENISA), 2021 (reproduction authorised, source acknowledged).
* [RFC 9180](https://www.rfc-editor.org/info/rfc9180) — *Hybrid Public Key Encryption (HPKE)*, February 2022 — IETF (Revised BSD License)
* [RFC 9881](https://www.rfc-editor.org/info/rfc9881) — *Internet X.509 Public Key Infrastructure — Algorithm Identifiers for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)*, October 2025 — IETF (Revised BSD License)
* [RFC 9935](https://www.rfc-editor.org/info/rfc9935) — *Internet X.509 Public Key Infrastructure — Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)*, March 2026 — IETF (Revised BSD License)
* [draft-ietf-lamps-pq-composite-sigs-15](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) — *Composite ML-DSA for use in X.509 Public Key Infrastructure*, February 2026 — IETF Internet-Draft (work in progress); (Revised BSD License)
* [NIST IR 8545](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8545.pdf) — *Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process*, March 2025 — public domain
* HQC submission team — *Hamming Quasi-Cyclic (HQC)*, specification document v2025-08-22, [pqc-hqc.org](https://pqc-hqc.org) (individual authors; code in the public domain)

The aggregation and enhancement of the content are provided under Creative Commons BY-SA 4.0, 
Copyright (c) 2026 metaeffekt GmbH.

## Disclaimer

The content in this repository is ingested with artificial intelligence (Claude and partially Gemini). There is
absolutely no claim on completeness and correctness. All usages are at your own risk.

All company names, organization names, license names, algorithm names, method names, and product names mentioned in 
this documentation are used for identification purposes only. A trademark is explicitly identified as registered or
unregistered trademark only if required by the license terms.

If you see any infringement of terms and conditions in this metadata-level aggregation. Please report immediately such
that adjustments can be applied accordingly.

## Content

- **[cryptographic-governance.md](cryptographic-governance.md)** — Framing document for the governance challenge: five questions every organization should be able to answer about its cryptographic posture, why the quantum transition makes inventory urgent now, what a Cryptography Bill of Materials enables, and the scale of the taxonomy required to make it meaningful. Starting point for non-technical stakeholders and outreach.

- **[cryptographic-algorithms.md](cryptographic-algorithms.md)** — Algorithm table covering the full taxonomy: symmetric ciphers, block cipher modes, hash functions, MACs, asymmetric encryption, classical signatures, stateful hash-based signatures, post-quantum KEMs and signatures (NIST standardised + Round 2 candidates), KDFs, password hashing, DRBGs, OS entropy APIs, and non-cryptographic PRNGs. Each row includes id, name, crypto class, OID, CycloneDX pattern example, and references.

- **[cryptographic-parameters.md](cryptographic-parameters.md)** — Catalogue of cryptographic algorithms grouped by family (symmetric, asymmetric, hash, MAC, KDF, KEM, signature). Each entry covers purpose, parameter sets, security levels, FIPS/NIST standardisation status, and CycloneDX algorithm pattern strings used in SBOM tooling. PQC entries (ML-KEM, ML-DSA, SLH-DSA, FN-DSA) include full parameter tables with public-key, secret-key, ciphertext, and signature sizes in bytes.

- **[random-number-generators.md](random-number-generators.md)** — Catalogue of deterministic and non-deterministic random number generators (DRBGs and TRNGs). Covers SP 800-90A/B/C families, OS entropy sources, and platform-specific APIs. Each entry lists construction type, security strength, seeding requirements, and CycloneDX RNG pattern strings.

- **[cryptographic-status.md](cryptographic-status.md)** — Status on algorithms and key-length choices derived from NIST SP 800-57 Part 1 Rev 5, SP 800-131A Rev 2, BSI TR-02102-1 through -4, NSA CNSA 2.0, and related standards. Organises algorithms by security strength tier, highlights deprecated and disallowed primitives, and cross-references the FIPS post-quantum standards. Includes security strength equivalence tables (SP 800-57 Table 2), SSH recommendations (BSI TR-02102-4), IPsec/IKEv2 recommendations (BSI TR-02102-3), and CNSA 2.0 algorithm requirements and migration timeline.

- **[glossary.md](glossary.md)** — Plain-language explanations of all terms and abbreviations used across this repository, written for readers without a mathematics background. Covers cryptographic primitives, protocol concepts, standardisation bodies, post-quantum terminology, and SBOM/CycloneDX notation. Includes an abbreviation quick-reference table.

## Inventory of Implementations

- **[inventory/README.md](inventory/README.md)** — Curated list of reference implementations, production-quality libraries, test-vector repositories, and analysis tools. Covers NIST-standardised PQC algorithms (FIPS 203/204/205, FIPS 206 IPD, HQC), Round 2 additional signature candidates, ecosystem libraries, Ascon lightweight crypto (NIST SP 800-232), Chinese national standards (SM9 via GmSSL), password-authenticated key exchange (SPAKE2/SPAKE2+, OPAQUE), and 3GPP authentication algorithms (MILENAGE, TUAK, A5/x). Includes source-download archive URLs for each entry.

- **[inventory/ae-cryptography-inventory.xlsx](inventory/ae-cryptography-inventory.xlsx)** — Structured inventory of cryptographic libraries and implementations in spreadsheet form (99 entries). Each row records the library identifier, version, repository URL, source-download archive URL, description, version status, repository licence (SPDX expression), CycloneDX algorithm patterns supported, and patent references. Intended as a machine-readable companion to the narrative documents above.

## Pattern Validator

- **[ae-pattern-validator/](ae-pattern-validator/)** — Maven-based Java 17 module (Bouncy Castle 1.83, Spring Boot 4.1.0-M4) that validates cryptographic algorithm patterns, X.509 certificates, CMS/PKCS#7 structures, and CycloneDX CBOM files. Generates CycloneDX 1.6 CBOM JSON from certificate and CMS analysis. Registry: 324 algorithm families, 9 taxonomy files, 178 unique OIDs, full CycloneDX + SPDX coverage. CLI modes: `--cert`, `--cms`, `--cbom`, `--generate-cbom`, `--oid`, pattern instance/template validation. Build: `cd ae-pattern-validator && mvn clean verify`. (NOT YET PUBLISHED; UNDER EVALUATION)

- **[cryptographic-registry-inconsistencies.md](cryptographic-registry-inconsistencies.md)** — Cross-reference of naming ambiguities and inconsistencies between the CycloneDX cryptography registry, the SPDX algorithm list, and this repository's taxonomy. Documents 16 concrete issues with eight resolution mechanisms. All CycloneDX and SPDX instance patterns are covered.

- **[management/validator-test-report.md](management/validator-test-report.md)** — Test statistics for the pattern validator: 769 tests across 15 test classes covering instance validation by taxonomy, template/constraint validation, CycloneDX coverage (213 tests), SPDX coverage (169 tests), X.509 certificate analysis (5 tests), CMS analysis (7 tests), CBOM validation (8 tests), and CBOM generation (4 tests). Registry: 324 families, 9 files, 178 unique OIDs.

- **[management/content-update-plan.md](management/content-update-plan.md)** — Content consistency, integrity, and synchronisation plan across all repository artefacts.

## Grammars

The grammars are fully experimental. An update grammar covering both algorithms and
RNGs is currently under evaluation in the unpublished parts.

- **[grammar/AlgorithmPattern.g4](grammar/AlgorithmPattern.g4)** — ANTLR4 grammar for parsing CycloneDX cryptographic algorithm pattern strings. Handles variable placeholders (`{x}`), required-choice groups (`(a|b)`), optional components (`[x]`), wildcards (`*`), and enumeration brackets (`[v1|v2]`).

- **[grammar/RngPattern.g4](grammar/RngPattern.g4)** — ANTLR4 grammar extending `AlgorithmPattern` with constructs specific to RNG pattern strings: OS API path tokens, function-call notation (`Name()`), and multi-character operator tokens (`+`, `++`, `**`) as used in Xoshiro/Xoroshiro variant identifiers.

## Diagrams

- **[resources/cryptographic-parameters.svg](resources/cryptographic-parameters.svg)** — Cryptographic algorithm parameter taxonomy. §1–§8 general parameters (size, mode, hash, curve, auth, KDF, padding, protocol), §9 PQC internal parameters (ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, pre-hash variants), §10 lightweight & national standards (Ascon, SM9, 3GPP), §11 SP 800-57 key management, and hybrid/composite constructions. Each algorithm block lists its parameters in logical order with cross-cutting parameters (`{context}`, `{deterministicSigning}`) duplicated per block for self-contained readability.

- **[resources/random-number-generators.svg](resources/random-number-generators.svg)** — RNG classification: CSPRNG/DRBG (NIST SP 800-90A, accumulator-based, stream-cipher-based), OS entropy APIs, hardware RNG, non-cryptographic PRNGs, and historical/broken algorithms.

Both diagrams are generated from `scripts/generate_diagrams.py` — edit the Python data structures and re-run to regenerate. This replaces the previous draw.io diagrams which did not scale with frequent content changes.
