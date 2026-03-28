# Inventory of Implementations, Libraries and Runtimes

## Remarks

1. **pq-crystals/kyber and pq-crystals/dilithium** — These are the official CRYSTALS reference
   implementations. NIST's FIPS 203/204 were derived from these but the repos themselves have
   not cut formal releases; they track the NIST submission rounds via branches (`standard`,
   `master`). For production use, prefer `mlkem-native` / `mldsa-native`.

2. **PQClean** — Maintenance ended January 2026; GitHub repository will be archived as read-only
   in July 2026 (announced on PQC forum). The recommended migration path is the PQ Code Package
   (mlkem-native, mldsa-native). Libraries depending on PQClean source should migrate now.

3. **oqs-provider** — ML-KEM, ML-DSA, and SLH-DSA are **disabled at runtime** when running
   against OpenSSL ≥ 3.5.0, since OpenSSL 3.5.0 ships native support for those algorithms.
   oqs-provider continues to be the route for experimental/candidate algorithms (MAYO, CROSS,
   UOV, SNOVA, etc.).

4. **liboqs 0.15.0** — This is the last liboqs release to support SPHINCS+ under its pre-FIPS name.
   Future releases will use the standardised name SLH-DSA exclusively. Projects referencing
   SPHINCS+ by name in algorithm identifiers should plan for a rename migration.

5. **HQC FIPS standardisation** — HQC was selected by NIST on March 11, 2025 as the fifth PQC
   algorithm (code-based backup KEM). A draft FIPS standard is expected in 2026, with finalisation
   in 2027. No FIPS number has been assigned yet. The v5.0.0 reference implementation at
   `gitlab.com/pqc-hqc/hqc` is the current normative reference.

6. **Round 2 additional signatures** — Implementations are at submission-quality, not production
   quality. Many do not use semantic version tags; the Round 2 tweak deadline was January 2025.
   NIST is evaluating additional signature candidates (CROSS, MAYO prioritised) with down-selection
   expected mid-to-late 2025 and final standard potentially by 2026–2027 (NIST IR 8545).
   LESS, PERK, RYDE, and QR-UOV do not have widely-found public GitHub organisations as of
   March 2026; implementations are distributed via their respective algorithm websites and the
   NIST CSRC submission packages.

7. **FAEST-avx v2.0.1** — The AVX2-optimised C++ implementation is at version 2.0.1, matching
   the FAEST v2 specification. The reference C implementation (`faest-ref`) tracks the same
   spec version but does not use semantic tags.

8. **Archive URL format** — For repos without formal tags, the `.../archive/refs/heads/main.tar.gz`
   URL always gives the current HEAD of the default branch. For tagged repos,
   `.../archive/refs/tags/{version}.tar.gz` gives the specific release.