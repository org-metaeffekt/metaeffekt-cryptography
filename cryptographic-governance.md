# The Cryptographic Governance Challenge

## Five Questions every Organization should be able to answer

Modern software systems depend on cryptography. Encryption protects data in transit and at rest.
Digital signatures establish authenticity and non-repudiation. Key exchange enables secure
communication between parties who have never met. Random number generators underpin the
unpredictability that security requires.

Yet most organizations cannot answer five basic questions about the cryptography they depend on:

1. **Which cryptographic algorithms are in use across our software portfolio — and where exactly?**
2. **Are any of those algorithms deprecated, disallowed, or scheduled for retirement?**
3. **Which systems will break or become insecure when quantum computers become cryptographically relevant?**
4. **What is the migration path for each affected algorithm, and what is the timeline?**
5. **Can we demonstrate compliance with the cryptographic requirements of our governing standards (FIPS, BSI TR-02102, CNSA 2.0, ETSI)?**

The inability to answer these questions is not a niche technical problem. It is a governance gap
with concrete consequences: security exposure, compliance failure, and — as the quantum transition
unfolds — an inability to protect data that must remain confidential for years or decades.

---

## Why this Gap exists

### Cryptography is everywhere, and mostly invisible

Cryptography is not concentrated in a few dedicated security components. It is distributed across
every layer of a modern software stack: transport protocols (TLS, SSH, IPsec), storage encryption,
code signing, certificate infrastructure, authentication systems, firmware update mechanisms, hardware
security modules, and third-party libraries that embed their own cryptographic dependencies.

A single application may invoke dozens of distinct algorithm configurations — often indirectly,
through frameworks and libraries whose cryptographic choices are opaque to the consuming team.

### The taxonomy is more complex than it appears

"We use AES-256" is not an answer. The security of AES depends on the mode (GCM vs. ECB vs. CBC),
the key management practices, the authentication tag length, the IV generation strategy, and
whether the implementation is resistant to side-channel attacks. "We use RSA" leaves open the
key length, the padding scheme (PKCS#1 v1.5 vs. OAEP vs. PSS), and the hash function — all of
which have distinct security implications and deprecation timelines.

A complete cryptographic inventory must capture not just algorithm names but parameter
configurations: key lengths, hash functions, modes, curves, padding schemes. Without this
granularity, the inventory cannot support risk assessment or compliance demonstration.

### Standards bodies disagree — and move at different speeds

NIST, BSI (Germany), ANSSI (France), ETSI, and NSA each publish cryptographic recommendations.
They do not always agree. BSI TR-02102 permits algorithms that NIST has deprecated. CNSA 2.0
mandates algorithms for national security systems on a timeline more aggressive than general
NIST guidance. A European organization deploying software in regulated sectors must navigate
multiple, partially overlapping requirements simultaneously.

Without a structured cross-reference, compliance teams rely on manual interpretation of
multiple standards documents — a process that is slow, error-prone, and impossible to automate.

---

## The Quantum Transition makes this urgent

The threat from large-scale quantum computers is not speculative. It is a matter of timing.
Shor's algorithm, running on a sufficiently powerful quantum computer, breaks RSA, ECDH, ECDSA,
and all other public-key cryptography based on integer factorization or discrete logarithm
problems. These algorithms underpin the key exchange and digital signature infrastructure of
virtually all secure communication today.

NIST completed its post-quantum cryptography standardization process in 2024, publishing FIPS 203
(ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). A fifth algorithm, HQC (code-based KEM),
was selected in March 2025. Migration to these standards is not optional — it is a matter of when.

Two factors make early action necessary:

**Harvest Now, Decrypt Later.** Adversaries are collecting encrypted traffic today with the
intention of decrypting it once quantum computers become available. Any data that must remain
confidential for more than a few years is already at risk — regardless of when quantum computers
arrive. Organizations protecting long-lived secrets (health records, intellectual property,
national security data, financial records) cannot afford to wait.

**Migration takes longer than expected.** Replacing cryptographic primitives across a large
software portfolio is not a simple configuration change. It requires identifying every affected
component, testing algorithm replacements, updating key management infrastructure, coordinating
with external parties (certificate authorities, HSM vendors, protocol counterparts), and
re-validating compliance. Organizations that have not started inventorying their cryptographic
assets are already behind.

CNSA 2.0 sets a mandatory timeline for US national security systems: post-quantum algorithms
required for new systems by 2025, full migration by 2030–2033 depending on the algorithm class.
BSI TR-02102 sets comparable expectations for German federal systems. Organizations that discover
their exposure only when these deadlines arrive will face an impossible remediation task.

---

## What a Cryptographic Inventory enables

A structured cryptographic inventory — a Cryptography Bill of Materials (CBOM) — transforms
these five unanswerable questions into tractable operational problems.

**Visibility.** Knowing which algorithms are deployed where is the prerequisite for every
subsequent action. Without it, risk assessment is guesswork and migration planning is impossible.

**Prioritisation.** Not all cryptographic usage carries equal risk. A deprecated hash function
used for non-security checksums is a lower priority than RSA-2048 key exchange protecting
long-lived confidential communications. An inventory with algorithm-level granularity allows
organizations to triage and allocate remediation effort rationally.

**Compliance demonstration.** Regulators and auditors increasingly require evidence of
cryptographic posture. A machine-readable CBOM, aligned to CycloneDX or SPDX identifiers,
provides auditable, reproducible evidence of compliance with FIPS, CNSA 2.0, BSI TR-02102, or
ETSI requirements — without manual re-examination of source code or configuration files.

**Automated monitoring.** An inventory expressed in a standard format can be continuously
monitored against evolving algorithm recommendations. When a standard body deprecates an
algorithm or a critical vulnerability is disclosed, affected components can be identified
immediately rather than through manual audit.

**Migration planning.** With a complete inventory, migration from classical to post-quantum
algorithms can be scoped, sequenced, and tracked as an engineering programme rather than an
emergency response.

---

## The Scale of the Problem

The challenge is not just the breadth of cryptographic usage — it is the depth of the taxonomy
required to make that usage meaningful.

A complete reference must cover:

- **~40 symmetric block ciphers** across approved, deprecated, and disallowed categories
- **~35 block cipher modes**, each with distinct security properties and AEAD vs. confidentiality-only implications
- **~37 hash functions and XOFs**, spanning SHA-2, SHA-3, lightweight (Ascon), national standards (SM3, GOST), and broken legacy algorithms (MD5, SHA-1)
- **~15 MAC constructions** with differing key management and authentication guarantees
- **32 post-quantum signature parameter sets** (ML-DSA, HashML-DSA, SLH-DSA, HashSLH-DSA) plus 2 FN-DSA variants — each with different security levels, performance profiles, and OIDs
- **9 post-quantum KEM variants** — standardised, selected, and under migration guidance
- **12 random number generator families**, from NIST SP 800-90A DRBGs to OS entropy APIs to non-cryptographic PRNGs that must not be used for security purposes
- **Cross-cutting parameter dimensions**: key lengths, hash functions, curves, padding schemes, tag lengths, iteration counts — each affecting security strength independently

This taxonomy spans multiple dimensions simultaneously. An algorithm entry in a CBOM is not
a string like `"AES"` — it is a structured object describing key length, mode, authentication
parameters, and the specific implementation context. Tooling that cannot express this granularity
cannot support meaningful risk assessment.

---

## This Repository as a Foundation

This repository is an attempt to make that reference material available in a structured,
community-maintainable form. It cross-references:

- **CycloneDX CBOM pattern strings** — the machine-readable identifiers used in software bills of materials
- **SPDX algorithm identifiers** — the parallel vocabulary used in SPDX SBOM documents
- **ASN.1 OIDs** — the protocol-level identifiers embedded in certificates, CMS structures, and algorithm negotiation
- **NIST FIPS standards** — FIPS 140-3 approved algorithms, key length requirements, deprecation timelines
- **BSI TR-02102** — German federal algorithm recommendations (v2026)
- **NSA CNSA 2.0** — US national security system migration requirements
- **NIST SP 800-57 / SP 800-131A** — Algorithm transition timelines
- **Post-quantum standards** — FIPS 203/204/205 parameter tables, HQC specification, Round 4 selection rationale (NIST IR 8545)

The goal is not to replicate the authority of any of these sources, but to make their combined
implications navigable — so that a security engineer, a compliance officer, or a tooling
developer can find the answer to "what do I need to know about this algorithm?" without
consulting six separate documents.

This is a foundation, not a finished product. Cryptographic standards evolve continuously.
The value of this resource grows with the community that maintains it. If you are working on
cryptographic governance, CBOM tooling, PQC migration, or standards development, contributions
and collaboration are welcome.

---

## Getting involved

The challenge of cryptographic governance is shared across industries, governments, and
standards bodies. No single organization can maintain this reference alone — and no single
organization should have to.

If you are:
- Developing SBOM or CBOM tooling and need a structured algorithm reference,
- Working on PQC migration and need a cross-standard status reference,
- Responsible for cryptographic compliance in a regulated sector,
- Contributing to standards at NIST, IETF, ETSI, BSI, or ISO,
- Building static analysis or software composition analysis tools, or

then this repository is intended as common infrastructure for your work, and your expertise
is what keeps it accurate and complete.

See [README.md](README.md) for the full content overview and licensing information.
