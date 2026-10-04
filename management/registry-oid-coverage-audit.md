# Registry OID Coverage Audit (2026-08-05)

> Audit of `ae-pattern-validator/.../registry/cr-*.yaml` against the **coverage mandate**:
> cover every algorithm ever seen (deprecated / retired / non-standard / pre-standard / broken)
> and capture every OID in the domain. Method: per-domain research (PQC, hash/MAC, symmetric,
> asymmetric/ECC) against BouncyCastle source, OQS `ALGORITHMS.md`, IETF-Hackathon
> `oid_mapping.md`, NIST CSOR, ISO 18033-2, and RFCs. Every OID below was read literally from a
> cited source — none fabricated. "No OID" = no authoritative assignment found.

## Headline

Baseline: **533 canonical families, 257 unique OIDs**. External catalogs (CycloneDX, SPDX) already
resolve fully. **OID coverage of classical crypto is strong** — curve, NIST P-curve, AES-mode,
HMAC-per-hash, and AEAD OIDs already resolve because they sit on the **functional entry**
(ECDSA / ECDH / AES / HMAC / ChaCha20), not the curve/hash entry. The dominant real gap is **PQC**:
~30 families with well-defined vendor/standard OIDs entirely absent. A small classical tail and a
few entirely-missing algorithms complete the list.

## P1: PQC OIDs (largest Gap, highest Value)

None of these families currently carry any OID; all have High-confidence cited OIDs. Model like the
pre-standard entries (multi-arc `oids:` lists; lifecycle `candidate`/`broken`/`withdrawn`).

**KEMs — BouncyCastle arc `1.3.6.1.4.1.22554.5.*` (+ ISO 18033-2 `1.0.18033.2.2.*` where noted):**

| Family | Arc | Leaves | Extra source |
|:---|:---|:---|:---|
| HQC | `22554.5.9.{1-3}` | 3 | NIST CSOR: none yet |
| FrodoKEM | `22554.5.2.{1-6}` | 6 | ISO `1.0.18033.2.2.7.*` (IETF-H) |
| ClassicMcEliece | `22554.5.1.{1-10}` | 10 | ISO `1.0.18033.2.2.6.*` |
| BIKE | `22554.5.8.{1-3}` | 3 | — |
| NTRU-HPS | `22554.5.5.{1,2,3,5}` | 4 | — |
| NTRU-HRSS | `22554.5.5.{4,6}` | 2 | — |
| LightSaber / Saber / FireSaber | `22554.5.3.{1-18}` | 18 | — |
| sntrup761 | `22554.5.7.2.2` | 1 | — |
| ntrulpr761 | `22554.5.7.1.2` | 1 | — |
| SIKE (broken) | `22554.5.4.{1-8}` | 8 | — |

**Signatures — BouncyCastle arc `1.3.6.1.4.1.22554.2.*` and/or OQS `1.3.9999.*` / `62245.*`:**

| Family | BC arc | OQS arc | Notes |
|:---|:---|:---|:---|
| Rainbow (broken) | `22554.2.9.{1-6}` | — | |
| Picnic | `22554.2.6.1.{1-12}`, `.6.2.{1-3}` | — | |
| HAWK | `22554.2.15.{1-3}` | — | |
| FAEST | `22554.2.12.{1-12}` | — | |
| SDitH | `22554.2.16.{1-12}` | — | |
| SQIsign | `22554.2.19.{1-3}` | — | 2-D variant SQIsign2D: no OID |
| QR-UOV | `22554.2.17.{1-12}` | — | |
| MAYO | `22554.2.10` (reserved, no leaves) | `1.3.9999.8.*` | OIDs live on OQS arc |
| SNOVA | `22554.2.11.{1-44}` | `1.3.9999.10-12.*` | two independent live arcs |
| UOV | `22554.2.14.{1-12}` | `1.3.9999.9.*` | two arcs |
| MQOM | `22554.2.13.{1-36}` | `1.3.9999.11.*` | two arcs |
| CROSS | (BC commented-out) | `1.3.6.1.4.1.62245.2.1.*` | OQS enterprise arc |

**Valid negatives (no OID exists — leave uncovered, note in remarks):** LESS, Mirath, PERK, RYDE,
ALTEQ, GeMSS, SQIsign2D.

**Historical PQC algorithms entirely absent from the registry, but with OIDs:**

| Algorithm | Round | OID (BC) |
|:---|:---|:---|
| NewHope | R2 KEM | `1.3.6.1.4.1.22554.3.1` |
| qTESLA | R2 sig | `1.3.6.1.4.1.22554.2.4` |
| AIMer | add-sig / KpqC | `1.3.6.1.4.1.22554.2.20.{1-6}` |
| SPHINCS-256 (2015) | pre-competition | `1.3.6.1.4.1.22554.2.1` |

## P2: Classical Primitives missing a standard OID

Family present, OID absent, standards/BC-sourced:

| Family | OID | Source |
|:---|:---|:---|
| GMAC (AES-GMAC) | `2.16.840.1.101.3.4.1.{9,29,49}` | RFC 9044 / NIST CSOR |
| BLAKE3 | `1.3.6.1.4.1.1722.12.2.3` (+`.3.8` = 256) | BC MiscObjectIdentifiers |
| HKDF | `1.2.840.113549.1.9.16.3.{28,29,30}` (SHA-256/384/512) | RFC 8619 |
| MGF1 | `1.2.840.113549.1.1.8` | PKCS#1 / RFC 8017 |
| XMSS-MT | `1.3.6.1.5.5.7.6.35` | RFC 9802 |
| PBKDF1 / PBES1 | `1.2.840.113549.1.5.{1,3,4,6,10,11}` | PKCS#5 |
| Blowfish | `1.3.6.1.4.1.3029.1.1.{1-4}` (ECB/CBC/CFB/OFB) | BC (cryptlib arc) |
| RC4 | `1.2.840.113549.3.4` (+PKCS#12 PBE `.1.12.1.1/.2`) | BC PKCSObjectIdentifiers |
| Skipjack | `2.16.840.1.101.2.1.1.4` (CMS SKIPJACK-CBC) | RFC 2876 |
| ZUC | `1.2.156.10197.1.800.{1-5}` (128-EEA3/EIA3/MAC/256…) | GmSSL / OSCCA |
| Tiger | `1.3.6.1.4.1.11591.12.2` (+HMAC-Tiger `1.3.6.1.5.5.8.1.3`) | GNU arc — **Medium** |
| AES-KWP | `2.16.840.1.101.3.4.1.{8,28,48}` | RFC 5649 (AES-KW `.5/.25/.45` already present) |
| 3DES-TKW | `1.2.840.113549.1.9.16.3.6` | RFC 3217 |

## P3: Optional national / vendor Extras (breadth)

| Item | OID | Source | Confidence |
|:---|:---|:---|:---|
| Serpent | `1.3.6.1.4.1.11591.13.2.*` (GNU) / Botan `25258.3.1` | BC GNUObjectIdentifiers | High / Med |
| Twofish | `1.3.6.1.4.1.25258.3.3` (+GCM/OCB/SIV) | Botan (vendor) | Medium |
| Threefish-512 (absent family) | `1.3.6.1.4.1.25258.3.2` | Botan | Medium |
| SM1 / SSF33 (absent families) | `1.2.156.10197.1.102.*` / `.103.*` | GmSSL/OSCCA | High |
| CAST3 (absent) | `1.2.840.113533.7.66.3` | Entrust arc | Medium |
| ElGamal | `1.3.6.1.4.1.3029.1.2.1` (cryptlib), `1.3.6.1.7.2.1.1` (Crypto++) | vendor only | Medium |
| ECIES | `1.3.132.1.{7,8}` | SEC1 (BC SECObjectIdentifiers) | High |
| MQV | `1.3.132.1.{3-6,13}` | SEC1 | High |
| GOST HMAC/IMIT | `1.2.643.2.2.10`, `1.2.643.7.1.1.4.{1,2}` | oid-info | High |
| HAS-160 (Korean) | `1.2.410.200004.1.2` | KISA | High |
| HMAC-SHA3-{224..512} | `2.16.840.1.101.3.4.2.{13-16}` | BC/CSOR (distinct from plain HMAC) | High |

## Redundancy finding (hygiene, not a coverage gap)

`HMACSHA1`, `HMACSHA256`, `HMACSHA384`, `HMACSHA512` are **duplicate** families — their OIDs
(`1.2.840.113549.2.{7,9,10,11}`) are already carried by the `HMAC` entry. Recommend collapsing them
into `HMAC` (or making them aliases) rather than adding OIDs. (Same pattern to check for `SHA224`
etc., though those legitimately carry distinct OIDs.)

## Confirmed NON-gaps (already resolve, do not re-add)

Curves (brainpool `1.3.36.3.3.2.8.1.1.*`, secp256k1 `1.3.132.0.10`, NIST P-256/384/521, X25519/X448
`1.3.101.110/.111`, Ed25519/Ed448 `.112/.113`), `id-ecPublicKey` `1.2.840.10045.2.1`, AES modes
(GCM/CCM/CBC/CTR-absent/KW `2.16.840.1.101.3.4.1.*`), HMAC-per-hash `1.2.840.113549.2.*`,
ChaCha20-Poly1305 AEAD `1.2.840.113549.1.9.16.3.18`, HSS/LMS CMS `1.2.840.113549.1.9.16.3.17` —
all present on functional entries (ECDSA / ECDH / AES / HMAC / ChaCha20 / LMS).

## Scale & plan

- **P1 (PQC):** ~30 families, ~300+ leaf OIDs (BC + OQS + ISO). Generatable like the pre-standard
  entries; the single highest-value, most mandate-aligned tranche.
- **P2 (classical tail):** ~13 families, ~40 OIDs.
- **P3 (national/vendor + absent algos):** optional breadth.

Raw source files cached under the session scratchpad (`BC.java`, `ALGORITHMS.md`, `oid_mapping.md`,
`bc-java/`) for re-verification. **Never fabricate OIDs — every addition must cite its source.**
