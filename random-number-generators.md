# Random Number Generators

> A structured reference for identifying, classifying, and parameterising
> random and pseudo-random number generators used in cryptographic systems.
>
> Sources: NIST SP 800-90A Rev 1, SP 800-90B, SP 800-90C, BSI AIS 20/31, CycloneDX Cryptography Registry,
> OS vendor documentation, and original algorithm specifications.
>
> **Note:** NIST SP 800-90A Rev 2 is in progress (pre-draft comment period closed November 2025).
> Planned changes include: removal of 3DES and SHA-1, addition of XOF_DRBG (SHAKE-based), SHA-3
> and Ascon options, and updated entropy requirements. No IPD published as of Q1 2026.
>
> Last updated: 2026-03-29

---

## Pattern Notation

This document adopts the CycloneDX pattern convention from the
[Cryptographic Algorithm Parameter Taxonomy](./cryptographic-parameters.md):

| Symbol | Meaning | Example |
|:---|:---|:---|
| `[]` | Optional parameter | `CTR_DRBG[-AES-256]` |
| `(a\|b)` | Required choice | `Hash_DRBG-(SHA-256\|SHA-512)` |
| `{x}` | Variable placeholder | `Fortuna[-{blockCipher}]` |
| `[-{x}]` | Optional variable | `HMAC_DRBG[-{hashAlgorithm}]` |

### RNG Identifier Format

The general pattern for identifying an RNG instance is:

```
RNG_Family[-{primitive}][-{securityStrength}][-{option}...]
```

where `{primitive}` names the underlying cryptographic function,
`{securityStrength}` is the target strength in bits, and `{option}` encodes
operational choices such as prediction resistance or derivation function use.

---

## 1. Top-Level RNG Taxonomy

```
RBG
├── TRNG  (True / Non-deterministic RNG)
│   ├── Physical noise source (thermal, shot noise, JFET, radioactive decay)
│   └── Non-physical noise source (OS interrupt timing, jitter-based)
│
├── CSPRNG  (Cryptographically Secure PRNG / DRBG)
│   ├── NIST SP 800-90A DRBGs
│   │   ├── Hash_DRBG[-{hashAlgorithm}]
│   │   ├── HMAC_DRBG[-{hashAlgorithm}]
│   │   └── CTR_DRBG[-{cipherAlgorithm}[-{keyLength}]][-noDF]
│   │
│   ├── Accumulator-based CSPRNGs
│   │   ├── Fortuna[-{blockCipher}][-{hashAlgorithm}]
│   │   └── Yarrow[-{blockCipher}][-{hashAlgorithm}]
│   │
│   ├── Stream-cipher-based CSPRNGs
│   │   ├── ChaCha20-DRNG  (Linux kernel, /dev/urandom since 4.8)
│   │   └── RC4-PRNG  (legacy ARC4RANDOM; deprecated)
│   │
│   ├── OS-provided entropy APIs
│   │   ├── getrandom()    (Linux ≥ 3.17)
│   │   ├── /dev/urandom   (Linux / macOS / BSD)
│   │   ├── /dev/random    (Linux; identical to /dev/urandom since 5.6)
│   │   ├── BCryptGenRandom (Windows; CTR_DRBG AES-256 internally)
│   │   └── getentropy()   (macOS / BSDs)
│   │
│   └── Hardware RNG interfaces
│       ├── RDRAND   (Intel/AMD; samples CTR_DRBG seeded by RDSEED)
│       ├── RDSEED   (Intel/AMD; direct hardware entropy, raw samples)
│       ├── TPM RNG  (TCG TPM 2.0; AES-based DRBG inside TPM)
│       └── HRNG     (dedicated hardware chip; varies by vendor)
│
└── PRNG  (Non-cryptographic, statistical only)
    ├── Mersenne Twister  (MT19937; fast, NOT crypto-safe)
    ├── Xorshift / Xoshiro family
    ├── PCG (Permuted Congruential Generator)
    └── LCG (Linear Congruential Generator; weakest)
```

---

## 2. NIST SP 800-90A DRBGs

The three approved DRBG mechanisms defined in NIST SP 800-90A Rev. 1.
All three share the same lifecycle: **Instantiate → Generate (→ Reseed) → Uninstantiate**.

### 2.1 Hash_DRBG

**Pattern:** `Hash_DRBG[-(SHA-1|SHA-224|SHA-256|SHA-384|SHA-512|SHA-512/256)]`

**Primitive:** Hash function (SHA-1 or SHA-2 family)

**Description:** Uses a hash function as its core one-way function.
The internal state consists of a value V (seed-length bytes) and a constant C.
Output generation uses iterative hashing of V; no block cipher or HMAC required.
Has a formal security proof for single-call output generation.

**Pattern examples:**
- `Hash_DRBG` — unspecified hash (implementation-defined)
- `Hash_DRBG-SHA-256` — SHA-256 as the underlying hash
- `Hash_DRBG-SHA-512` — SHA-512, supports 256-bit security strength

**Security strengths supported (SP 800-90A Rev 1, Table 2):**

| Hash function | Highest security strength (bits) | Seed length (bits) |
|:---|:---|:---|
| SHA-1 | 128 | 440 |
| SHA-224 | 192 | 440 |
| SHA-256 | 256 | 440 |
| SHA-384 | 256 | 888 |
| SHA-512 | 256 | 888 |
| SHA-512/256 | 256 | 440 |

**Max bits per request:** 2¹⁹ bits (524,288 bits)
**Reseed interval:** ≤ 2⁴⁸ generate calls

---

### 2.2 HMAC_DRBG

**Pattern:** `HMAC_DRBG[-(SHA-1|SHA-224|SHA-256|SHA-384|SHA-512)]`

**Primitive:** HMAC (keyed hash)

**Description:** Uses HMAC as its core update function. Internal state is a key K
and value V, both of hash output length. The update function
`HMAC_DRBG_Update(provided_data, K, V)` is called after every generate call.
HMAC_DRBG has a machine-verified security proof and is considered the
best-proven of the three SP 800-90A mechanisms.

**Pattern examples:**
- `HMAC_DRBG-SHA-256` — the most common deployment; 256-bit security
- `HMAC_DRBG-SHA-384` — 256-bit security; preferred when SHA-384 is used elsewhere in the system for consistency
- `HMAC_DRBG-SHA-512` — 256-bit security; larger internal state

**Security strengths supported (SP 800-90A Rev 1, Table 2):**

| HMAC function | Highest security strength (bits) |
|:---|:---|
| HMAC-SHA-1 | 128 |
| HMAC-SHA-224 | 192 |
| HMAC-SHA-256 | 256 |
| HMAC-SHA-384 | 256 |
| HMAC-SHA-512 | 256 |

**Max bits per request:** 2¹⁹ bits
**Reseed interval:** ≤ 2⁴⁸ generate calls

---

### 2.3 CTR_DRBG

**Pattern:** `CTR_DRBG[-(AES-128|AES-192|AES-256|3DES)][-noDF]`

**Primitive:** Block cipher in counter mode

**Description:** Uses a block cipher (AES or 3DES) in counter mode.
Internal state is a key K and counter V (both of block length).
Two variants exist: with a derivation function (DF) — recommended, processes
entropy of arbitrary length — and without DF (no_df), which requires the
entropy input to match the seed length exactly.

**Pattern examples:**
- `CTR_DRBG-AES-256` — AES-256, with derivation function (recommended)
- `CTR_DRBG-AES-128` — AES-128, with derivation function
- `CTR_DRBG-AES-256-noDF` — AES-256, no derivation function (not recommended)
- `CTR_DRBG-3DES` — 3DES (deprecated; 3DES is disallowed after 2023)

**Security strengths and seed lengths:**

| Cipher | Key length (bits) | Security strength (bits) | Seed length with DF (bits) |
|:---|:---|:---|:---|
| AES-128 | 128 | 128 | 256 |
| AES-192 | 192 | 192 | 320 |
| AES-256 | 256 | 256 | 384 |
| 3DES | 112 (effective) | 112 | 232 |

**Max bits per request:** 2¹⁹ bits
**Reseed interval:** ≤ 2⁴⁸ generate calls

**Note:** CTR_DRBG is the only SP 800-90A mechanism without a formal security
proof. It is the fastest and the basis of Windows `BCryptGenRandom` and Intel
platform firmware DRBGs. Do not use the `3DES` variant; it is deprecated.

---

### 2.4 Dual_EC_DRBG (withdrawn)

**Pattern:** `Dual_EC_DRBG` *(withdrawn — do not use)*

**Primitive:** Elliptic curve discrete logarithm

**Description:** Removed from SP 800-90A Rev. 1 (June 2015). Snowden documents
(2013) confirmed a deliberate NSA kleptographic backdoor via chosen elliptic
curve points (P and Q). Any implementation must be replaced immediately.

---

## 3. Accumulator-based CSPRNGs

### 3.1 Fortuna

**Pattern:** `Fortuna[-{blockCipher}[-{keyLength}]][-{hashAlgorithm}]`

**Primitive:** Block cipher (generator) + hash function (accumulator)

**Description:** Designed by Niels Ferguson and Bruce Schneier (*Practical Cryptography*, 2003).
Two-part architecture: a **generator** (AES-256-CTR, 256-bit key, rekeyed after every
2¹⁶ output blocks) and an **accumulator** (32 entropy pools P0–P31,
each a running SHA-256 hash state).
Pool Pi is included in a reseed only when the reseed counter r is divisible by 2ⁱ.
No entropy estimator required — a key design improvement over Yarrow.

**Pattern examples:**
- `Fortuna` — standard implementation (AES-256 + SHA-256, as specified)
- `Fortuna-AES-256-SHA-256` — explicit canonical form
- `Fortuna-Twofish-SHA-256` — alternative block cipher (non-standard)

**Fixed design parameters:**

| Parameter | Value | Notes |
|:---|:---|:---|
| Number of entropy pools | 32 (P0–P31) | Constant in specification |
| Pool hash function | SHA-256 | SHA-256 for pool accumulation and reseed key derivation |
| Generator cipher | AES-256-CTR | Key = 256 bits, counter = 128 bits |
| Generator key size | 256 bits | Rekeyed after each reseed |
| Max blocks per request | 2¹⁶ = 65,536 × 16 bytes = 1 MiB | Hard limit before rekey |
| Min pool-0 size before reseed | ≥ 64 bytes recommended | From *Cryptography Engineering* |
| Min interval between reseeds | ≥ 100 ms (software default) | Prevents trivial pool-exhaustion |
| Reseed pool selection | Pool Pi used iff 2ⁱ \| r | Where r = reseed counter |

**Deployed in:** macOS/iOS `/dev/random` (since macOS 10.15 / 2020),
FreeBSD kernel CSPRNG.

---

### 3.2 Yarrow

**Pattern:** `Yarrow[-{blockCipher}[-{keyLength}]][-{hashAlgorithm}]`

**Primitive:** Block cipher (generator) + hash function (accumulator)

**Description:** Predecessor to Fortuna. Designed by John Kelsey, Bruce Schneier,
and Niels Ferguson (1999). Uses two pools (fast and slow) with entropy
estimators per source. The entropy estimator requirement is the principal
weakness — it is difficult to implement correctly. Superseded by Fortuna for
all new deployments.

**Pattern examples:**
- `Yarrow-160` — SHA-1 accumulator + 3DES generator (original specification)
- `Yarrow-AES-256-SHA-256` — modern variant used in older macOS/iOS

**Fixed design parameters:**

| Parameter | Value |
|:---|:---|
| Entropy pools | 2 (fast, slow) |
| Reseed threshold (fast pool) | k × t bits (k sources, each contributing t bits) |
| Reseed threshold (slow pool) | Requires ≥ 2 sources each above threshold |
| Generator cipher | Triple-DES (original) or AES |
| Key size | 160 bits (Yarrow-160) |

**Note:** Yarrow is considered legacy. macOS replaced it with Fortuna in 2020.
Use Fortuna or a NIST DRBG for new designs.

---

## 4. Stream-Cipher-based CSPRNGs

### 4.1 ChaCha20-DRNG (Linux kernel)

**Pattern:** `ChaCha20-DRNG`

**Primitive:** ChaCha20 stream cipher in counter mode, seeded via BLAKE2s pool

**Description:** The Linux kernel random number generator since kernel 4.8
(2016). The input pool is a BLAKE2s hash state that accumulates entropy from
hardware interrupts, disk I/O, network timing, and hardware RNGs (RDRAND,
RDSEED, TPM). A base ChaCha20 CRNG is seeded from the pool; per-CPU secondary
ChaCha20 CRNGs are seeded from the base CRNG and serve `getrandom()`,
`/dev/urandom`, and in-kernel `get_random_bytes()`.

**Architecture:**

```
Noise sources (interrupts, I/O, RDRAND)
        │
        ▼
  Input pool (BLAKE2s state, one per system)
        │
        ▼ (once ≥ 256 bits of entropy accumulated)
  Base ChaCha20 CRNG  (256-bit key, rekeyed periodically)
        │
  ┌─────┴─────┐
  ▼           ▼
 CPU 0       CPU n   (per-CPU ChaCha20 CRNGs)
  │           │
  ▼           ▼
getrandom()  /dev/urandom  get_random_bytes()
```

**Key parameters:**

| Parameter | Value |
|:---|:---|
| CRNG key size | 256 bits (ChaCha20 key) |
| Input pool | BLAKE2s hash state |
| Entropy threshold for initialization | 256 bits |
| Per-CPU CRNG reseed interval | ~5 minutes (opportunistic) |
| RDRAND mixing | Yes — XORed into ChaCha20 state at every block |
| Blocking behaviour | `getrandom()` blocks only until initialization; never thereafter |

**OS interfaces and their behaviour:**

| Interface | Blocks? | Notes |
|:---|:---|:---|
| `getrandom()` (no flags) | At boot only | Recommended; identical to `/dev/urandom` once initialized |
| `/dev/urandom` | Never | Use this; same pool as `getrandom()` |
| `/dev/random` | At boot only (since Linux 5.6) | Identical to `/dev/urandom` on modern kernels |
| `get_random_bytes()` | Never | In-kernel API |

---

### 4.2 BCryptGenRandom (Windows)

**Pattern:** `BCryptGenRandom`

**Primitive:** CTR_DRBG-AES-256 internally; seeded from hardware entropy

**Description:** The Windows cryptographic RNG API. Internally uses
CTR_DRBG (AES-256) seeded from multiple entropy sources: CPU cycle counter,
memory addresses, system uptime, RDRAND (when available), and TPM.
All Windows crypto APIs (CryptGenRandom, RtlGenRandom, rand_s) route through
the same underlying CSPRNG.

**Key properties:**

| Property | Value |
|:---|:---|
| Underlying DRBG | CTR_DRBG-AES-256 |
| FIPS 140-3 validated | Yes (in BCryptPrimitives.dll) |
| Reseed on fork | Yes (address space randomisation) |
| Userspace API | `BCryptGenRandom()` (CNG) |
| Legacy API | `CryptGenRandom()` (CAPI, deprecated) |

---

## 5. Hardware RNG Interfaces

### 5.1 RDRAND (Intel / AMD x86-64)

**Pattern:** `RDRAND`

**Primitive:** CTR_DRBG-AES-128 (or AES-256 on newer microarchitectures),
seeded internally by RDSEED

**Description:** x86-64 instruction that returns output from an on-die
AES-CTR DRBG. The DRBG is automatically reseeded from the hardware entropy
source (thermal noise, metastability-based ring oscillator) via RDSEED.
Returns 16, 32, or 64-bit values per call.

**Key properties:**

| Property | Value |
|:---|:---|
| Instruction | `RDRAND` (16/32/64-bit variants) |
| Output | From AES-CTR DRBG (not raw entropy) |
| Internal DRBG | CTR_DRBG-AES-128 (Intel documentation); AES key size is implementation-defined and not publicly specified for all microarchitectures |
| Throughput (Skylake) | ~800 MB/s |
| Trust caveat | Must not be sole entropy source; combine with OS entropy |
| CPUID check | `CPUID.01H:ECX[30]` = 1 if RDRAND present |

**Security note:** RDRAND should never be used as the sole entropy source.
Combine with OS-provided entropy (`/dev/urandom`, `getrandom()`,
`BCryptGenRandom`) to mitigate potential implementation flaws or
deliberate weakening.

---

### 5.2 RDSEED (Intel / AMD x86-64)

**Pattern:** `RDSEED`

**Primitive:** Direct hardware entropy (conditioned raw noise)

**Description:** x86-64 instruction that returns samples directly from the
hardware entropy source, bypassing the on-die DRBG. Output is conditioned
(whitened) but reflects the underlying physical process. Suitable for seeding
software DRBGs. Slower than RDRAND; may fail (CF=0) if the hardware entropy
source has not yet accumulated a new sample.

**Key properties:**

| Property | Value |
|:---|:---|
| Instruction | `RDSEED` (16/32/64-bit variants) |
| Output | Conditioned hardware entropy (not DRBG output) |
| Failure mode | Returns CF=0 if entropy not ready; must retry |
| Throughput | Significantly lower than RDRAND |
| Use case | Seeding DRBGs; not for bulk output |
| CPUID check | `CPUID.(EAX=07H,ECX=0H):EBX[18]` = 1 if RDSEED present |

---

### 5.3 TPM RNG (TCG TPM 2.0)

**Pattern:** `TPM_RNG[-{tpmVersion}]`

**Primitive:** AES-based DRBG inside the TPM security boundary

**Description:** The Trusted Platform Module exposes a hardware RNG via the
`TPM2_GetRandom` command (TPM 2.0) or `TPM_GetRandom` (TPM 1.2). The RNG
operates inside the TPM's tamper-resistant boundary. The internal construction
varies by vendor but is typically a CTR_DRBG or similar NIST-approved mechanism
seeded from on-chip physical entropy.

**Key properties:**

| Property | Value |
|:---|:---|
| TPM 2.0 command | `TPM2_GetRandom` |
| Max bytes per call | 32 bytes (implementation may limit further) |
| FIPS 140-3 | Yes (for FIPS-validated TPMs) |
| Trust model | Hardware-isolated; separate entropy from CPU |
| Throughput | Low (≈ 10–50 KB/s depending on TPM) |

---

## 6. Non-cryptographic PRNGs

These generators produce statistically good output but are **not**
cryptographically secure. State is fully recoverable from a small number of
outputs. Never use for cryptographic keys, nonces, session tokens, or
any security-sensitive material.

### 6.1 Mersenne Twister (MT19937)

**Pattern:** `MT19937`

**State size:** 19,937 bits (624 × 32-bit words)
**Period:** 2¹⁹⁹³⁷ − 1

**Not cryptographically secure:** Full 624-word state is recoverable from
624 consecutive 32-bit outputs by solving a system of linear equations over GF(2).
Used in Python `random`, Ruby `Random`, PHP `rand()`, many game engines.

---

### 6.2 Xoshiro / Xorshift family

**Pattern:** `Xoshiro(256|512)(+|++|**)` or `Xorshift(64|128|plus)`

**State size:** 64–512 bits (algorithm-dependent)
**Period:** 2^(state_size) − 1

**Not cryptographically secure:** Simple linear feedback structure.
Extremely fast; used in language standard libraries (Rust `SmallRng`, JavaScript V8,
Julia `Base.GLOBAL_RNG`). Do not use for cryptographic purposes.

---

### 6.3 PCG (Permuted Congruential Generator)

**Pattern:** `PCG[-{stateSize}]`

**State size:** 64 or 128 bits
**Period:** 2⁶⁴ or 2¹²⁸

**Not cryptographically secure:** LCG-based with an output permutation that
improves statistical quality but does not provide cryptographic security.
Fast; excellent statistical properties. Used in game engines, simulation.

---

### 6.4 LCG (Linear Congruential Generator)

**Pattern:** `LCG[-{modulus}]`

**Not cryptographically secure:** Simplest PRNG form: Xₙ₊₁ = (aXₙ + c) mod m.
Output is trivially predictable from a single value. Never use for security.
`rand()` in many C standard library implementations is an LCG.

---

## 7. Parameter Taxonomy

Parameters governing RNG instantiation and operation, following the
CycloneDX `{placeholder}` convention.

---


### `{hashAlgorithm}` (DRBG)

| Aspect | Detail |
|:---|:---|
| **Short** | Hash function underlying Hash_DRBG or HMAC_DRBG |
| **Description** | Selects the hash function used as the DRBG's core one-way function. Determines the security strength and seed/state lengths. |
| **Type** | algorithm reference |
| **Canonical values** | `SHA-1` `SHA-224` `SHA-256` `SHA-384` `SHA-512` `SHA-512/256` |
| **Implementation note** | SHA-1 Hash_DRBG supports up to 128-bit security per SP 800-90A Rev 1 Table 2. However, SP 800-131A Rev 2 treats SHA-1-based DRBGs as transitional through 2030; use SHA-256 or higher for new deployments. |
| **Used in** | Hash_DRBG, HMAC_DRBG, Fortuna (accumulator), Yarrow (accumulator), Hash_df (derivation function in CTR_DRBG) |

**Values and corresponding security strengths:**

| Value | Highest security strength | Seed length |
|:---|:---|:---|
| `SHA-1` | 128 bits | 440 bits |
| `SHA-224` | 192 bits | 440 bits |
| `SHA-256` | 256 bits | 440 bits |
| `SHA-384` | 256 bits | 888 bits |
| `SHA-512` | 256 bits | 888 bits |
| `SHA-512/256` | 256 bits | 440 bits |

---


### `{cipherAlgorithm}` (CTR_DRBG)

| Aspect | Detail |
|:---|:---|
| **Short** | Block cipher underlying CTR_DRBG or the Fortuna/Yarrow generator |
| **Description** | Selects the block cipher used in counter mode as the DRBG core, or as the output generator in an accumulator-based CSPRNG. |
| **Type** | algorithm reference |
| **Canonical values** | `AES-128` `AES-192` `AES-256` `3DES` |
| **Implementation note** | The 3DES variant of CTR_DRBG has a 64-bit block, which causes the DRBG output to be distinguishable from random at 128+ bits of output per instantiation (birthday bound). Never use 3DES CTR_DRBG for new designs. AES-256 is the standard choice for FIPS 140-3 validation. |
| **Used in** | CTR_DRBG, Fortuna (generator), Yarrow (generator) |

**Values and properties:**

| Value | Key bits | Block bits | Security strength | Status |
|:---|:---|:---|:---|:---|
| `AES-128` | 128 | 128 | 128 bits | Current |
| `AES-192` | 192 | 128 | 192 bits | Current |
| `AES-256` | 256 | 128 | 256 bits | Current; recommended |
| `3DES` | 112 (effective) | 64 | 112 bits | Deprecated (NIST 2023) |

---


### `{securityStrength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Target security strength of the DRBG instantiation in bits |
| **Description** | The security strength requested at instantiation time. Must be ≤ the maximum security strength supported by the chosen algorithm and primitive. All output from that instantiation provides at most this many bits of security. |
| **Type** | integer (bits) |
| **Canonical values** | `112` `128` `192` `256` |
| **Implementation note** | NIST SP 800-57 recommends ≥ 128-bit security for new applications; 112 bits is a legacy minimum. For post-quantum resilience, 256-bit security is preferred. |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG, all SP 800-90A DRBGs |

---


### `{predictionResistance}`

| Aspect | Detail |
|:---|:---|
| **Short** | Whether the DRBG forcibly reseeds from a live entropy source before every generate call |
| **Description** | When enabled, the DRBG calls the entropy source immediately before producing output, preventing an adversary who compromised the DRBG state from predicting future output. Requires a live entropy source to be available at all times. |
| **Type** | boolean |
| **Canonical values** | `true` `false` |
| **Implementation note** | Prediction resistance = true guarantees forward security but imposes a live entropy source requirement and performance overhead. Most deployments use false with periodic reseeding instead. |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG (SP 800-90A option) |

---


### `{derivationFunction}`

| Aspect | Detail |
|:---|:---|
| **Short** | Whether CTR_DRBG uses a derivation function to process entropy input |
| **Description** | The derivation function (DF) allows CTR_DRBG to accept entropy of arbitrary length and compresses it into the seed length. Without DF (no_df mode), the entropy input must be exactly seed-length bits. The DF variant provides better security properties and is strongly recommended. |
| **Type** | boolean |
| **Canonical values** | `true` (with DF, recommended) `false` (no_df, not recommended) |
| **Pattern encoding** | `CTR_DRBG-AES-256` = with DF; `CTR_DRBG-AES-256-noDF` = without DF |
| **Implementation note** | The no_df variant is rarely used and provides degraded security properties. The ANSSI libdrbg project strongly discourages it. The FIPS CAVP test suite tests both variants separately. |
| **Used in** | CTR_DRBG only |

---


### `{reseedInterval}`

| Aspect | Detail |
|:---|:---|
| **Short** | Maximum number of generate calls before mandatory reseeding |
| **Description** | SP 800-90A mandates that a DRBG instance must be reseeded after a bounded number of generate calls (the reseed interval). This limits the total output produced from a single seed, protecting against state compromise and output predictability over very long sequences. |
| **Type** | positive integer (generate call count) |
| **Implementation note** | Implementations may use a shorter reseed interval for defence-in-depth. Some FIPS 140-3 profiles require shorter intervals. The Fortuna design replaces a fixed interval with pool-based automatic reseeding. |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG |

**Canonical values:**

| Mechanism | SP 800-90A maximum |
|:---|:---|
| Hash_DRBG | 2⁴⁸ |
| HMAC_DRBG | 2⁴⁸ |
| CTR_DRBG (any) | 2⁴⁸ |

---


### `{maxBitsPerRequest}`

| Aspect | Detail |
|:---|:---|
| **Short** | Maximum number of bits that can be requested in a single generate call |
| **Description** | SP 800-90A places a hard upper bound on bits per generate call to prevent excessive output from a single state and to limit the advantage an adversary gains between reseedings. |
| **Type** | integer (bits) |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG |

**Canonical values (SP 800-90A):**

| Mechanism | Maximum bits per request |
|:---|:---|
| Hash_DRBG | 2¹⁹ = 524,288 bits (65,536 bytes) |
| HMAC_DRBG | 2¹⁹ = 524,288 bits |
| CTR_DRBG | 2¹⁹ = 524,288 bits |

---


### `{personalizationString}`

| Aspect | Detail |
|:---|:---|
| **Short** | Optional caller-supplied string mixed into the DRBG seed at instantiation |
| **Description** | Provides application-level domain separation. Mixed into the initial seed to ensure two DRBG instances instantiated at the same time with the same entropy source produce independent output. Does not need to be secret but should be unique per instance (e.g. application name + PID + timestamp). |
| **Type** | byte string (variable length; SP 800-90A: max 2³² bits) |
| **Canonical values** | Application-defined. Empty string `""` is permitted. |
| **Implementation note** | Even a non-secret personalization string significantly improves the independence of multiple DRBG instances seeded from the same entropy source. NIST strongly recommends its use. |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG (all SP 800-90A DRBGs) |

---


### `{additionalInput}`

| Aspect | Detail |
|:---|:---|
| **Short** | Optional per-call additional data mixed into DRBG state at generate time |
| **Description** | An optional input string provided at each generate or reseed call. Mixes additional unpredictable data into the DRBG state without formal entropy credit. Provides defence-in-depth: even if the internal state is partially compromised, additional input from an independent source can partially recover security. |
| **Type** | byte string (variable length; SP 800-90A: max 2³² bits) |
| **Canonical values** | Application-defined. Empty string `""` is the common case. |
| **Implementation note** | For security-sensitive applications, supply high-entropy additional input at each generate call (e.g. a current timestamp XOR'd with a hardware counter). This is especially important in virtualised environments where VM snapshots can replay DRBG state. |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG (optional parameter at generate/reseed) |

---


### `{entropyInputLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Required length of the entropy input string fed to the DRBG |
| **Description** | The minimum number of bits of entropy that must be provided during instantiation or reseeding. Must be ≥ the requested security strength. For CTR_DRBG with no DF, must equal the seed length exactly. |
| **Type** | integer (bits) |
| **Implementation note** | SP 800-90B requires that each bit of entropy input contains at least H_min bits of min-entropy, measured by the 90B estimators. The raw bit count does not equal the entropy unless the source is validated. |
| **Used in** | All SP 800-90A DRBGs; SP 800-90B entropy source characterisation |

**Canonical values (minimum by security strength):**

| Security strength | Minimum entropy input |
|:---|:---|
| 112 bits | 112 bits |
| 128 bits | 128 bits |
| 192 bits | 192 bits |
| 256 bits | 256 bits |

---


### `{nonceLength}`

| Aspect | Detail |
|:---|:---|
| **Short** | Length of the nonce used during DRBG instantiation |
| **Description** | An additional seed input used at instantiation to ensure that two DRBG instances seeded from the same entropy source are independent. SP 800-90A requires the nonce to provide at least securityStrength/2 bits of entropy. |
| **Type** | integer (bits) |
| **Used in** | Hash_DRBG, HMAC_DRBG, CTR_DRBG |

**Canonical values:**

| Security strength | Minimum nonce length |
|:---|:---|
| 128 bits | 64 bits |
| 192 bits | 96 bits |
| 256 bits | 128 bits |

---


### `{minPoolSize}` (Fortuna)

| Aspect | Detail |
|:---|:---|
| **Short** | Minimum bytes that pool P0 must accumulate before a reseed is triggered |
| **Description** | Fortuna reseed control: the generator reseeds whenever pool P0 has accumulated at least minPoolSize bytes of events AND at least 100 ms have elapsed since the last reseed (to prevent denial-of-service via forced reseeds). This parameter trades reseed latency for attack resistance. |
| **Type** | integer (bytes) |
| **Canonical values** | `64` (recommended in *Cryptography Engineering*); minimum `32` |
| **Implementation note** | Ferguson and Schneier note that values below 32 bytes are inadvisable (too little entropy per reseed). Values larger than ~256 bytes delay recovery after state compromise without significant security benefit. |
| **Used in** | Fortuna |

---


### `{poolCount}` (Fortuna)

| Aspect | Detail |
|:---|:---|
| **Short** | Number of entropy accumulation pools |
| **Description** | Fortuna uses exactly 32 pools (P0–P31) in its standard specification. Pool Pi contributes to a reseed only when the reseed counter r is divisible by 2ⁱ. More paranoid implementations or very high-throughput systems could use more pools; fewer would reduce protection against injection attacks. |
| **Type** | positive integer |
| **Canonical values** | `32` (standard) |
| **Implementation note** | With 32 pools and reseeds limited to 10/second, pool P31 accumulates entropy for ~13 years between uses — sufficient for all practical deployments. |
| **Used in** | Fortuna |

---


### `{minEntropyBitsPerSample}` (entropy source, SP 800-90B)

| Aspect | Detail |
|:---|:---|
| **Short** | Estimated min-entropy per output bit from the noise source |
| **Description** | The fundamental characterisation metric for an SP 800-90B entropy source. Defined as H_min = −log₂(p_max) where p_max is the probability of the most likely output symbol. All 90B health test designs and conditioning component entropy credit calculations depend on this value. |
| **Type** | real number (bits per symbol) |
| **Canonical values** | Source-dependent; typical hardware entropy sources: 0.1–1.0 bits per sample (raw), approaching 1.0 bits per bit after conditioning. |
| **Implementation note** | SP 800-90B requires that the entropy estimate be validated using at least 10 of the 11 SP 800-90B estimators. The minimum of all estimates is used. At least 1,000,000 samples are required for validation. |
| **Used in** | SP 800-90B entropy source validation |

---


### `{conditioningComponent}` (entropy source, SP 800-90B)

| Aspect | Detail |
|:---|:---|
| **Short** | Post-processing function that increases entropy density of raw noise |
| **Description** | The conditioning component (CC) processes the noise source output to remove bias and correlation. A vetted CC (SHA-256, SHA-512, BLAKE2, AES-CBC-MAC) allows full entropy credit up to the hash output length. A non-vetted CC provides at most 1/2 the input length as entropy credit. |
| **Type** | algorithm reference |
| **Canonical values** | `SHA-256` `SHA-512` `BLAKE2s` `BLAKE2b` `AES-CBC-MAC` `None` (raw output, full estimator-based entropy credit only) |
| **Implementation note** | Using a vetted CC is strongly recommended. The Linux kernel uses BLAKE2s as its conditioning function for the input pool. |
| **Used in** | SP 800-90B entropy source design |

---


### `{rbgConstruction}` (SP 800-90C)

| Aspect | Detail |
|:---|:---|
| **Short** | The SP 800-90C RBG construction class |
| **Description** | SP 800-90C defines four classes of RBG construction, each specifying different requirements for entropy source availability, prediction resistance capability, and full-entropy output. |
| **Type** | enumeration |
| **Implementation note** | Most server and workstation deployments correspond to RBG2 or RBG3. Embedded systems with no live entropy source may only support RBG1. |
| **Used in** | SP 800-90C RBG construction specification |

**Canonical values and capabilities:**

| Value | Prediction resistance | Full-entropy output | Entropy source after init |
|:---|:---|:---|:---|
| `RBG1` | No | No | Not available |
| `RBG2(P)` | Yes (physical source) | Yes | Physical entropy source |
| `RBG2(NP)` | Yes (non-physical source) | Yes | Non-physical entropy source |
| `RBG3` | Yes | Yes | Any approved entropy source |
| `RBGC` | Root only | No | Parent RBGC in tree |

---

## 8. Summary Table

| Identifier pattern | Category | Primitive | FIPS 140-3 | Status |
|:---|:---|:---|:---|:---|
| `Hash_DRBG[-{hashAlg}]` | DRBG | Hash function | Approved | Current |
| `HMAC_DRBG[-{hashAlg}]` | DRBG | HMAC | Approved | Current; best-proven |
| `CTR_DRBG[-{cipherAlg}][-noDF]` | DRBG | Block cipher CTR | Approved | Current |
| `Dual_EC_DRBG` | DRBG (withdrawn) | Elliptic curve | Removed | **Never use** |
| `Fortuna[-{cipher}][-{hash}]` | Accumulator CSPRNG | Block cipher + hash | N/A | Current; OS standard |
| `Yarrow[-{cipher}][-{hash}]` | Accumulator CSPRNG | Block cipher + hash | N/A | Legacy; superseded |
| `ChaCha20-DRNG` | Stream CSPRNG | ChaCha20 | N/A | Current; Linux kernel |
| `BCryptGenRandom` | OS API / CTR_DRBG | AES-256 CTR | Approved | Current; Windows |
| `getrandom()` | OS API | ChaCha20 DRNG | N/A | Current; Linux recommended |
| `/dev/urandom` | OS API | ChaCha20 DRNG | N/A | Current; equivalent to getrandom |
| `RDRAND` | Hardware | AES CTR DRBG | N/A | Use with OS entropy |
| `RDSEED` | Hardware entropy | Conditioned noise | N/A | For seeding DRBGs |
| `TPM_RNG[-{version}]` | Hardware / DRBG | AES DRBG in TPM | Yes (FIPS TPMs) | Current |
| `MT19937` | PRNG (non-crypto) | LFSR | N/A | **Not crypto-safe** |
| `Xoshiro(256\|512)(**\|+\|++)` | PRNG (non-crypto) | XOR-shift | N/A | **Not crypto-safe** |
| `PCG[-{stateSize}]` | PRNG (non-crypto) | LCG + permutation | N/A | **Not crypto-safe** |
| `LCG[-{modulus}]` | PRNG (non-crypto) | Linear congruence | N/A | **Not crypto-safe** |

---

## 9. Parameter Summary Table

| Parameter | Category | Type | Used in |
|:---|:---|:---|:---|
| `{hashAlgorithm}` | Primitive | algorithm ref | Hash_DRBG, HMAC_DRBG, Fortuna, Yarrow |
| `{cipherAlgorithm}` | Primitive | algorithm ref | CTR_DRBG, Fortuna, Yarrow |
| `{securityStrength}` | Instantiation | integer (bits) | All SP 800-90A DRBGs |
| `{predictionResistance}` | Operational | boolean | All SP 800-90A DRBGs |
| `{derivationFunction}` | Construction | boolean | CTR_DRBG only |
| `{reseedInterval}` | Operational | positive integer | All SP 800-90A DRBGs |
| `{maxBitsPerRequest}` | Operational | integer (bits) | All SP 800-90A DRBGs |
| `{personalizationString}` | Instantiation | byte string | All SP 800-90A DRBGs |
| `{additionalInput}` | Per-call | byte string | All SP 800-90A DRBGs |
| `{entropyInputLength}` | Instantiation | integer (bits) | All SP 800-90A DRBGs |
| `{nonceLength}` | Instantiation | integer (bits) | All SP 800-90A DRBGs |
| `{minPoolSize}` | Reseed control | integer (bytes) | Fortuna |
| `{poolCount}` | Architecture | integer | Fortuna |
| `{minEntropyBitsPerSample}` | Entropy source | real (bits/symbol) | SP 800-90B sources |
| `{conditioningComponent}` | Entropy source | algorithm ref | SP 800-90B sources |
| `{rbgConstruction}` | Architecture | enumeration | SP 800-90C |

---

## 10. Sources

### NIST SP 800-90 Series

- NIST SP 800-90A Rev. 1 — Recommendation for Random Number Generation Using Deterministic Random Bit Generators
    - [CSRC landing page](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
    - DOI: [10.6028/NIST.SP.800-90Ar1](https://doi.org/10.6028/NIST.SP.800-90Ar1)
- NIST SP 800-90B — Recommendation for the Entropy Sources Used for Random Bit Generation
    - [CSRC landing page](https://csrc.nist.gov/pubs/sp/800/90/b/final)
    - [PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90B.pdf)
    - DOI: [10.6028/NIST.SP.800-90B](https://doi.org/10.6028/NIST.SP.800-90B)
- NIST SP 800-90C (3rd draft) — Recommendation for Random Bit Generator (RBG) Constructions
    - [CSRC landing page](https://csrc.nist.gov/pubs/sp/800/90/c/3pd/docs)
    - [PDF (3rd draft)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90C.pdf)

### Accumulator-based CSPRNG Specifications

- Ferguson, N. and Schneier, B. (2003). *Practical Cryptography*, Wiley.
    - [Fortuna chapter excerpt (Schneier.com)](https://www.schneier.com/wp-content/uploads/2015/12/fortuna.pdf)
- Ferguson, N., Schneier, B. and Kohno, T. (2010). *Cryptography Engineering: Design Principles and Practical Applications*, Wiley.
- Kelsey, J., Schneier, B. and Ferguson, N. (1999). *Yarrow-160: Notes on the Design and Analysis of the Yarrow Cryptographic Pseudorandom Number Generator*.
    - [Schneier.com](https://www.schneier.com/academic/yarrow/)
- Dodis, Y., Shamir, A., Stephens-Davidowitz, N. and Wichs, D. (2014). *How to Eat Your Entropy and Have It Too — Optimal Recovery Strategies for Compromised RNGs*.
    - [Schneier on Security commentary](https://www.schneier.com/blog/archives/2014/03/the_security_of_7.html)

### Linux Kernel RNG

- BSI (2022). *Documentation and Analysis of the Linux Random Number Generator v5.0*.
    - [BSI PDF](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Studies/LinuxRNG/LinuxRNG_EN_V5_0.pdf)
- Amossys (2023). *Linux RNG Architecture*.
    - [Blog post](https://www.amossys.fr/insights/blog-technique/linux-csprng-architecture/)
- Linux man page: random(7)
    - [man7.org](https://man7.org/linux/man-pages/man7/random.7.html)
- Filippo Valsorda (2020). *The Linux CSPRNG Is Now Good!*
    - [words.filippo.io](https://words.filippo.io/linux-csprng/)

### Hardware RNG

- Intel (2012). *Intel Digital Random Number Generator (DRNG) Software Implementation Guide*.
    - [Intel ARK / Software Developer Manual Vol. 1, §7.3](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-digital-random-number-generator-drng-software-implementation-guide.html)
- TCG (2019). *Trusted Platform Module Library Specification, Family "2.0" — Part 3: Commands*, §16.2 `TPM2_GetRandom`.
    - [TCG specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

### Security Analyses

- Woodage, J. and Shumow, D. (2019). *An Analysis of the NIST SP 800-90A Standard*.
    - [IACR ePrint 2018/349](https://eprint.iacr.org/2018/349)
- Wikipedia: NIST SP 800-90A
    - [en.wikipedia.org](https://en.wikipedia.org/wiki/NIST_SP_800-90A)
- Wikipedia: Fortuna PRNG
    - [en.wikipedia.org](https://en.wikipedia.org/wiki/Fortuna_(PRNG))
- Wikipedia: Yarrow algorithm
    - [en.wikipedia.org](https://en.wikipedia.org/wiki/Yarrow_algorithm)

### CycloneDX and SPDX (cross-reference)

- [CycloneDX Cryptography Registry](https://cyclonedx.org/registry/cryptography/) — CTR_DRBG, Hash_DRBG, HMAC_DRBG, Fortuna, Yarrow entries
- [CycloneDX cryptography-defs.json](https://github.com/CycloneDX/specification/blob/master/schema/cryptography-defs.json)
- [SPDX Cryptographic Algorithm List](https://github.com/spdx/cryptographic-algorithm-list)
