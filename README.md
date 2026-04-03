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

## License

Please note that this content is based on public data sources. Primarily:

* https://github.com/spdx/cryptographic-algorithm-list (Creative Commons Zero Universal 1.0)
* https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.json (Apache License 2.0)
* https://groups.google.com/a/list.nist.gov/g/pqc-forum (individual copyrights, licenses and trademarks apply)
* NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 IPD (FN-DSA) — public domain
* NIST SP 800-57 Part 1 Rev 5, SP 800-131A Rev 2 — public domain
* NIST SP 800-56A Rev 3 — *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography*, April 2018 — public domain
* NIST SP 800-186 — *Recommendations for Discrete Logarithm-Based Cryptography: Elliptic Curve Domain Parameters*, February 2023 — public domain
* NIST SP 800-208 — *Recommendation for Stateful Hash-Based Signature Schemes*, October 2020 — public domain
* NIST SP 800-232 — *Ascon-Based Lightweight Cryptography Standards*, 2023 — public domain
* BSI TR-02102-1 v2026-01, TR-02102-2 v2026-01, TR-02102-3 v2026-01, TR-02102-4 v2026-01 — public domain
* NSA Cybersecurity Advisory PP-22-1338: *Announcing the Commercial National Security Algorithm Suite 2.0* (CNSA 2.0), September 2022, Version 1.0 — public domain
* ENISA — *Post-Quantum Cryptography: Current state and quantum mitigation*, v2, May 2021. Authors: Ward Beullens et al. DOI: 10.2824/92307. © European Union Agency for Cybersecurity (ENISA), 2021 (reproduction authorised, source acknowledged).
* RFC 9180 — *Hybrid Public Key Encryption (HPKE)*, February 2022 — IETF (Revised BSD License)
* RFC 9881 — *Internet X.509 Public Key Infrastructure — Algorithm Identifiers for the Module-Lattice-Based Digital Signature Algorithm (ML-DSA)*, October 2025 — IETF (Revised BSD License)
* RFC 9935 — *Internet X.509 Public Key Infrastructure — Algorithm Identifiers for the Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)*, March 2026 — IETF (Revised BSD License)
* draft-ietf-lamps-pq-composite-sigs-15 — *Composite ML-DSA for use in X.509 Public Key Infrastructure*, February 2026 — IETF Internet-Draft (work in progress); (Revised BSD License)
* NIST IR 8545 — *Status Report on the Fourth Round of the NIST Post-Quantum Cryptography Standardization Process*, March 2025 — public domain
* HQC submission team — *Hamming Quasi-Cyclic (HQC)*, specification document v2025-08-22, https://pqc-hqc.org (individual authors; code in the public domain)
* and diverse public publications (such as special publications from NIST, FIPS and BSI guidance).

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

- **[inventory/ae-cryptography-inventory.xlsx](inventory/ae-cryptography-inventory.xlsx)** — Structured inventory of cryptographic libraries and implementations in spreadsheet form (93 entries). Each row records the library identifier, version, repository URL, source-download archive URL, description, version status, repository licence (SPDX expression), CycloneDX algorithm patterns supported, and patent references. Intended as a machine-readable companion to the narrative documents above.

## Pattern Validator

- **[ae-pattern-validator/](ae-pattern-validator/)** — Maven-based Java 17 module that validates CycloneDX and SPDX cryptographic algorithm pattern strings against a YAML-based controlled vocabulary registry. Combines an ANTLR4 structural grammar (`CryptographyPattern.g4`) with a data-driven validation registry of 303 algorithm families across 9 taxonomy files (141 with controlled vocabulary segments, 106 fixed identifiers, 56 wildcard), 159 OIDs with reverse lookup, and full CycloneDX + SPDX coverage (zero unmatched identifiers in either registry). Supports **instance** validation, **template** validation, underscore normalisation, OID resolution, and OID reverse lookup. CLI: `java -jar ae-pattern-validator-exec.jar AES-256-GCM`. Build: `cd ae-pattern-validator && mvn clean verify`. (NOT YET PUBLISHED; UNDER EVALUATION)

- **[registry-naming-inconsistencies.md](registry-naming-inconsistencies.md)** — Cross-reference of naming ambiguities and inconsistencies between the CycloneDX cryptography registry, the SPDX algorithm list, and this repository's taxonomy. Documents 16 concrete issues with eight resolution mechanisms: CycloneDX/SPDX aliases, deprecated CycloneDX/SPDX families, family consolidation, segment additions, standalone families, and new CycloneDX/SPDX-only families. All CycloneDX and SPDX instance patterns are now covered.

- **[validator-test-report.md](validator-test-report.md)** — Test statistics for the pattern validator: 698 tests across 11 test classes covering instance validation by taxonomy (symmetric, hash/MAC, asymmetric, PQC, KDF, RNG), template and constraint validation, full CycloneDX registry coverage (201 tests), and full SPDX coverage (159 tests). Includes registry statistics (303 families across 9 files, 159 OIDs).

## Grammars

The grammars are fully experimental.

- **[grammar/AlgorithmPattern.g4](grammar/AlgorithmPattern.g4)** — ANTLR4 grammar for parsing CycloneDX cryptographic algorithm pattern strings. Handles variable placeholders (`{x}`), required-choice groups (`(a|b)`), optional components (`[x]`), wildcards (`*`), and enumeration brackets (`[v1|v2]`).

- **[grammar/RngPattern.g4](grammar/RngPattern.g4)** — ANTLR4 grammar extending `AlgorithmPattern` with constructs specific to RNG pattern strings: OS API path tokens, function-call notation (`Name()`), and multi-character operator tokens (`+`, `++`, `**`) as used in Xoshiro/Xoroshiro variant identifiers.

## Diagrams

- **[resources/cryptographic-algorithms.drawio](resources/cryptographic-algorithms.drawio)** — Draw.io diagram visualising the CycloneDX cryptographic algorithm pattern grammar: notation legend (`{x}`, `[…]`, `(a|b)`), railroad pattern structure, grammar production rules, and a parameter taxonomy in ten sections — §1–§8 general parameters (size, mode, hash, curve, auth, KDF, padding, protocol), §9 PQC internal parameters (ML-DSA, ML-KEM, SLH-DSA, FN-DSA, HQC cross-cutting and pre-hash variants), and §10 lightweight & national standards (Ascon SP 800-232, SM9 GM/T 0044, 3GPP MILENAGE/TUAK/EEA/EIA).

- **[resources/random-number-generators.drawio](resources/random-number-generators.drawio)** — Draw.io diagram visualising the RNG pattern grammar (notation legend, identifier format, grammar production rules) and a classification hierarchy of random number generators (TRNG, CSPRNG/DRBG, non-cryptographic PRNG) as covered in `random-number-generators.md`. The CSPRNG section covers NIST SP 800-90A DRBGs, accumulator-based designs (Fortuna, Yarrow), stream-cipher-based generators (ChaCha20, SNOW 3G, ZUC), OS entropy APIs, and hardware RNG interfaces.
