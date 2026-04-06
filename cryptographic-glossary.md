# Cryptographic Glossary

> Plain-language explanations of every term, abbreviation, and acronym used in this repository.
> Entries are sorted alphabetically. Mathematical details are kept to a minimum.
>
> Copyright (c) 2026 metaeffekt GmbH — Creative Commons BY-SA 4.0

---

## 0–9

**2TDEA — Two-Key Triple DES**
A variant of Triple DES using only two distinct 56-bit DES keys (K1, K2) in an encrypt-decrypt-encrypt sequence (K1-K2-K1). Provides at most 80 bits of security. Disallowed by NIST (SP 800-131A) for applying cryptographic protection; legacy processing only.

**3GPP — 3rd Generation Partnership Project**
The international standards body responsible for mobile telecommunications protocols (3G UMTS, 4G LTE, 5G NR). Specifies cryptographic algorithms for authentication (AKA, MILENAGE, TUAK) and confidentiality/integrity (SNOW 3G, ZUC, AES-based 128-EEA/EIA).

---

## A

**ACVP — Automated Cryptographic Validation Protocol**
A NIST testing service that automatically checks whether a cryptographic software implementation produces the correct outputs for a given set of inputs. Think of it as a standardised exam for crypto code.

**Additional Input**
An optional extra piece of data you can feed into a random number generator at every "generate" call. It does not count as formal entropy but mixes extra unpredictable data into the generator's internal state, giving some protection if the state has been partially compromised.

**AEAD — Authenticated Encryption with Associated Data**
An encryption mode that provides two guarantees in one operation: (1) the message is kept secret (confidentiality) and (2) any tampering can be detected (authenticity). "Associated data" is metadata (like a header) that is authenticated but not encrypted — a recipient can read it, but cannot alter it undetected. Examples: AES-GCM, ChaCha20-Poly1305.

**AES — Advanced Encryption Standard**
The world's most widely used symmetric block cipher, standardised by NIST in FIPS 197. A block cipher works on fixed-size chunks of data (128 bits) at a time, transforming them using a secret key. AES supports three key sizes: 128, 192, and 256 bits. The larger the key, the harder it is to brute-force. Used in virtually all encrypted communications, file encryption, and storage encryption.

**AES-GCM — AES in Galois/Counter Mode**
AES used in GCM mode, providing both encryption and authentication (an AEAD construction). The standard choice for TLS 1.3, SSH, and most modern protocols.

**AES-KW / AES-KWP — AES Key Wrap / Key Wrap with Padding**
A standardised way to encrypt (wrap) one cryptographic key inside another, so the key can be safely stored or transmitted. Used in XML encryption, CMS, and enterprise key management.

**AIS 20/31**
A BSI technical guideline defining requirements for random number generators in security modules. Version 3 (2022) classifies generators into functionality classes: DRG.2-4 for deterministic generators, PTG.2-3 for physical TRNGs, and NTG.1 for non-deterministic RBGs. Referenced in cryptographic module evaluations (Common Criteria, BSI certification).

**Adiantum**
A length-preserving encryption construction designed by Google (2018) for storage encryption on low-end devices lacking AES hardware acceleration. Internally combines ChaCha12 (a reduced-round ChaCha variant), AES-HCTR2 (a wide-block mode), and Poly1305 hashing. Used in Android for full-disk encryption on ARMv7 devices. Not an AEAD cipher — it provides confidentiality only, not authentication.

**Agility, Cryptographic**
The design property of a system that allows its cryptographic algorithms to be swapped out without redesigning the system. Important for migrating away from algorithms that are broken or deprecated.

**AKA — Authentication and Key Agreement**
The mutual authentication protocol used in 3GPP mobile networks (3G/4G/5G) between the SIM/USIM and the network. The authentication functions are typically implemented using MILENAGE (AES-based) or TUAK (Keccak-based).

**ANSSI — Agence Nationale de la Sécurité des Systèmes d'Information**
The French national cybersecurity agency. Publishes cryptographic recommendations and algorithm approvals for French government systems, comparable to BSI (Germany) and NIST (US).

**Argon2 (Argon2i, Argon2d, Argon2id)**
A modern password-hashing algorithm (RFC 9106) designed to resist brute-force attacks even on specialised hardware (GPUs, ASICs). It intentionally consumes a configurable amount of memory and time, making bulk password-cracking expensive. **Argon2id** is the recommended variant: it resists both timing side-channels and GPU attacks. Winner of the Password Hashing Competition (2015).

**ARIA**
A 128-bit block cipher standardised in South Korea, used in Korean government and financial applications.

**Ascon**
A family of lightweight cryptographic algorithms standardised by NIST in **NIST SP 800-232**. Designed for constrained environments (IoT, embedded systems) where AES and SHA-3 carry too much overhead. Based on a sponge-permutation construction. Four variants: **Ascon-AEAD128** (authenticated encryption with associated data, 128-bit key/tag/nonce), **Ascon-Hash256** (fixed 256-bit hash), **Ascon-XOF128** (extendable output, 128-bit security), **Ascon-CXOF128** (customisable XOF). All four variants are in the CycloneDX registry. Ascon was the winner of the NIST Lightweight Cryptography competition (2023).

**ASN.1 — Abstract Syntax Notation One**
A standard interface description language (ITU-T X.680) for defining data structures. In cryptography, ASN.1 is used to describe certificate formats (X.509), key encodings (PKCS#8), and algorithm identifiers (OIDs). DER and BER are the binary encoding rules used to serialize ASN.1 structures in certificates and signed messages.

**Authentication**
Verifying the identity of a sender or the integrity of data — confirming that a message truly came from who it claims to be from and has not been altered in transit.

**Authentication Tag**
A short value (typically 128 bits) appended to a message by an AEAD cipher. The recipient recomputes the tag and checks it matches; if the message or key is wrong, the tag will not match and the message is rejected.

**AVX2 — Advanced Vector Extensions 2**
A set of CPU instructions (available on Intel/AMD processors since ~2013) that allow processing multiple data values simultaneously. Cryptographic implementations using AVX2 can be significantly faster than plain C code.

---

## B

**bcrypt**
A password-hashing algorithm built on the Blowfish cipher. A "cost" parameter controls how many internal rounds are performed, so the algorithm can be tuned to remain slow as hardware improves. Cost 12 (= 4 096 rounds) is the 2024 minimum recommendation. Note: bcrypt truncates passwords at 72 bytes.

**BIKE — Bit Flipping Key Encapsulation**
A code-based post-quantum KEM that reached Round 4 of the NIST PQC standardisation process but was **not selected** (NIST IR 8545, March 2025). BIKE is based on the **QC-MDPC** (Quasi-Cyclic Moderate-Density Parity-Check) problem; IND-CPA security relies on the difficulty of decoding random QC-MDPC codes. During Round 4, a new structural weakness called the **gathering property** was discovered: a small but non-negligible fraction of BIKE private keys are "weak" in a way that causes the decapsulation algorithm to fail with probability ≥ 2⁻¹¹⁷ at NIST Level 1 — far above the required DFR bound of 2⁻¹²⁸. This defeats IND-CCA2 security for those keys. Fixing the issue would require increasing the ring size (r: 12 323 → 13 477, ~9% growth) and additional post-selection analysis. NIST judged the DFR analysis insufficiently mature for standardisation. Compared to HQC: BIKE key generation is 6–10× slower; decapsulation is 5–7× slower; public keys and ciphertexts are ~70%/~30% smaller than HQC. Available in liboqs.

**Birthday Bound / Birthday Attack**
An attack that exploits the fact that collisions in hash functions or counter values occur sooner than expected due to probability. Relevant for older 64-bit block ciphers (3DES, Blowfish): after approximately 2³² encrypted blocks (~32 GB of data), collisions become likely, leaking information. This is why AES (128-bit block) is required for large data volumes.

**BLAKE2 (BLAKE2b, BLAKE2s)**
A fast cryptographic hash function that is both faster than MD5 in software and more secure than SHA-2. BLAKE2b targets 64-bit platforms; BLAKE2s targets 32-bit and embedded systems.

**BLAKE3**
A newer hash function building on BLAKE2, adding parallel tree hashing and an extendable (variable-length) output. It is extremely fast and suitable for both hashing and key derivation.

**Block Cipher**
A symmetric encryption algorithm that encrypts data in fixed-size chunks ("blocks"), typically 128 bits. The same key must be used to encrypt and decrypt. Examples: AES, Camellia, 3DES.

**Block Size**
The fixed chunk size a block cipher operates on. AES has a 128-bit block size (16 bytes). Older ciphers like DES and 3DES have a 64-bit block size, which limits how much data can be safely encrypted with one key.

**BLS — Boneh-Lynn-Shacham Signature**
A digital signature scheme with the unique property that multiple signatures can be combined ("aggregated") into a single short signature. Widely used in blockchain protocols (Ethereum). Requires a special class of elliptic curve (pairing-friendly, e.g. BLS12-381).

**Blowfish**
An older 64-bit block cipher. Its small block size makes it vulnerable to the birthday attack for large data volumes. Superseded by AES and Twofish.

**Blum-Goldwasser**
A semantically secure probabilistic public-key encryption scheme based on the Blum-Blum-Shub CSPRNG and the quadratic residuosity assumption. Historically significant but not used in modern protocols.

**BSI — Bundesamt für Sicherheit in der Informationstechnik**
Germany's Federal Office for Information Security. Publishes algorithm recommendations (TR-02102 series) and standards for random number generators (AIS 20/31). A major authority alongside NIST for European deployments.

**BSI TR — BSI Technical Regulation**
A series of technical recommendations published by the German BSI. Key documents for cryptography: TR-02102-1 (cryptographic algorithms and key lengths), TR-02102-2 (TLS), TR-02102-3 (IPsec), TR-02102-4 (SSH). Updated annually; the current edition is TR-02102-1 (2026-01).

---

## C

**Camellia**
A 128-bit block cipher developed by NTT and Mitsubishi, approved by NIST, ISO, and ETSI. Performance and security are comparable to AES. Used in Japanese government and TLS deployments.

**CAST5 / CAST6**
Block ciphers used in OpenPGP and some TLS ciphersuites. Largely superseded by AES.

**CatKDF — Concatenation Key Derivation Function**
A KDF construction (NIST SP 800-56C) that derives key material by concatenating shared secrets and hashing. Used in hybrid PQC key combination (BSI TR-02102-1 §2.2) to merge a classical and a post-quantum shared secret into a single session key. Recommended with KMAC or HKDF.

**CAVP — Cryptographic Algorithm Validation Program**
A NIST program that validates cryptographic implementations through testing against known answer tests (KATs) and other validation procedures. A CAVP certificate demonstrates that a specific implementation produces correct outputs. CAVP is the testing component; CMVP (Cryptographic Module Validation Program) validates complete cryptographic modules under FIPS 140-3.

**CBC — Cipher Block Chaining**
A block cipher mode where each plaintext block is XOR-ed with the previous ciphertext block before encryption, so identical input blocks produce different output. Requires a random IV. Used in older TLS and still in file encryption; less preferred than AEAD modes for new designs.

**CBC-MAC**
A message authentication code computed using a block cipher in CBC mode. Vulnerable to certain extension attacks when used naively; CMAC is the safe standardised variant.

**CBOM — Cryptography Bill of Materials**
A structured inventory of all cryptographic assets (algorithms, keys, certificates, protocols) used in a software system. Typically expressed as a CycloneDX component with `cryptographicProperties`. Analogous to an SBOM for software dependencies.

**CBMC — C Bounded Model Checker**
A formal verification tool that can mathematically prove the correctness of C programs by exploring all possible execution paths up to a specified bound. Used by the PQ Code Package (mlkem-native) to verify functional correctness of PQC implementations.

**CCM — Counter with CBC-MAC**
An AEAD mode combining AES-CTR (for encryption) and AES-CBC-MAC (for authentication). Used in IEEE 802.15.4 (ZigBee/IoT) and TLS. Less flexible than GCM for online processing.

**CFB — Cipher Feedback Mode**
A block cipher mode that converts a block cipher into a stream cipher by encrypting the previous output. Rarely preferred over CTR mode for new designs.

**CFRG — Crypto Forum Research Group**
An IRTF (Internet Research Task Force) research group that develops cryptographic algorithms and protocols for eventual IETF standardisation. Responsible for work on Curve25519/X25519, EdDSA, HPKE, and post-quantum algorithm integration.

**C(ie,js) — Key Establishment Scheme Notation (SP 800-56A)**
A compact notation used in NIST SP 800-56A Rev.3 to categorise key establishment schemes by the number of ephemeral (e) and static (s) key contributions from each party (i = initiator, j = responder). For example: C(2e, 0s) means both parties contribute only ephemeral keys (full ephemeral, best forward secrecy); C(1e, 1s) means each party uses one ephemeral and one static key; C(0e, 2s) means both use only static keys (no forward secrecy). SP 800-56A Table 8 defines eleven named schemes covering ECC and FFC variants of each pattern.

**Cofactor**
An integer h associated with an elliptic curve. The order of the curve group = h × order of the main subgroup. Curves with cofactor h > 1 (Curve25519 h=8, Curve448 h=4, Edwards25519 h=8) require special handling during key agreement: the scalar must be multiplied by h (the "cofactor multiplication" step in the ECC CDH primitive) to avoid small-subgroup attacks. Prime-order Weierstrass curves (P-256, P-384, P-521) have h=1 and require no cofactor clearing.

**CNSA 2.0 — Commercial National Security Algorithm Suite 2.0**
NSA Cybersecurity Advisory PP-22-1338 (September 2022, Version 1.0) specifying which cryptographic algorithms are required for all National Security Systems (NSS). CNSA 2.0 mandates: ML-KEM-1024 / CRYSTALS-Kyber Level V (key establishment), ML-DSA-87 / CRYSTALS-Dilithium Level V (general signatures), LMS with SHA-256/192 recommended and XMSS (software/firmware signing — use immediately), AES-256 (symmetric encryption), and SHA-384 or SHA-512 (hashing). RSA, ECDH, ECDSA, and DH are deprecated upon mandate. SLH-DSA and FN-DSA are not included. Transition deadlines by system category range from 2025–2030 (software signing, networking) to 2033 (browsers, OS, legacy), with an overall NSM-10 deadline of 2035. Replaces CNSA 1.0 (CNSSP 15 Annex B), which required ECDH/ECDSA P-384, RSA-3072, DH-3072, SHA-384, and AES-256.

**Code Equivalence**
A mathematical problem where the task is to determine whether two error-correcting codes are equivalent under a permutation of coordinates. The hardness of this problem is the security basis for the LESS and CROSS post-quantum signature schemes.

**Common Criteria (CC)**
An international standard (ISO/IEC 15408) for evaluating the security properties of IT products and systems. Evaluation Assurance Levels (EAL 1-7) measure the rigor of evaluation. Relevant for cryptographic modules alongside FIPS 140-3.

**Composite Cryptographic Element**
A multi-algorithm scheme that combines multiple component algorithms of the same type (e.g. two signature algorithms) into a single cryptographic object presenting one public key and one signature value. An adversary must break **all** component algorithms simultaneously to compromise the system. The term is defined in RFC 9794. A composite algorithm is transparent at the protocol level — it appears as a single atomic algorithm identifier, enabling deployment in protocols that are not explicitly hybrid-aware. Contrast with explicit hybrid protocols (e.g. TLS hybrid key exchange) where the hybrid nature is visible to the protocol.

**Composite ML-DSA**
An IETF standard (draft-ietf-lamps-pq-composite-sigs-15, LAMPS WG, February 2026) defining 18 composite signature algorithms that combine ML-DSA (FIPS 204) with a traditional algorithm (RSA-PSS, RSA-PKCS#1v1.5, ECDSA, Ed25519, or Ed448). Each algorithm has a registered OID in the `1.3.6.1.5.5.7.6` arc. The signing process generates two independent component signatures (one ML-DSA, one traditional) serialised as a pair; verification requires both to succeed. Composite ML-DSA provides **EUF-CMA** (existential unforgeability) but not **SUF-CMA** (strong unforgeability); see those entries. Motivation: allows organisations to add post-quantum protection to existing PKIX infrastructure without replacing the traditional cryptography, reducing re-certification overhead. Security holds as long as either component algorithm remains unbroken.

**CROSS — Codes and Restricted Objects Signature Scheme**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on code equivalence problems. CROSS is one of the prioritised candidates alongside MAYO in the NIST additional signatures process.

**ChaCha20**
A stream cipher designed by Daniel Bernstein. Produces a keystream (pseudorandom bytes) that is XOR-ed with the plaintext. ChaCha20 is very fast on devices without hardware AES acceleration (mobile, IoT). Used in combination with Poly1305 authenticator.

**ChaCha20-Poly1305**
An AEAD construction combining ChaCha20 encryption and Poly1305 authentication. The standard alternative to AES-GCM in TLS 1.3, SSH, and WireGuard.

**ChaCha20-DRNG**
The random number generator built into the Linux kernel since version 4.8. Uses ChaCha20 as its output function, seeded from hardware interrupts and RDRAND via a BLAKE2s entropy pool.

**Classic McEliece**
A code-based post-quantum KEM using binary Goppa codes. NIST PQC Round 4 candidate (not selected for standardisation). Offers very small ciphertexts but extremely large public keys (~261 KB to ~1.3 MB depending on security level). ISO standardisation pending.

**Cipher**
General term for an algorithm that transforms data to keep it secret (encryption) or recover the original (decryption).

**Ciphertext**
The scrambled, unreadable form of data after encryption. Without the key, ciphertext appears as random noise.

**CMVP — Cryptographic Module Validation Program**
A joint US-Canadian program (NIST and CCCS) that validates complete cryptographic modules against the FIPS 140-3 standard. CMVP builds on CAVP (which validates individual algorithm implementations) by evaluating the module's physical security, key management, self-tests, and operational environment. A CMVP certificate is required for cryptographic modules used in US and Canadian federal systems.

**CMAC — Cipher-Based Message Authentication Code**
A MAC algorithm using a block cipher (typically AES) as its core. Defined in NIST SP 800-38B. An alternative to HMAC when AES hardware acceleration is available.

**CMP — Certificate Management Protocol**
A PKI protocol (RFC 4210) for certificate request, issuance, revocation, and key update between end entities and certificate authorities. One of three standard PKI enrollment protocols alongside EST and CMC.

**CMC — Certificate Management over CMS**
A PKI protocol (RFC 5272-5274) that wraps certificate requests and responses in CMS (PKCS#7) structures. Supports complex enrollment scenarios including key escrow and certificate batch operations.

**CMS — Cryptographic Message Syntax**
A standard format (RFC 5652) for wrapping data with cryptographic operations — signing, encrypting, or both. Used in S/MIME email and code-signing certificates. The IETF LAMPS working group is standardising ML-DSA (post-quantum signatures) for CMS.

**CNSA 1.0 — Commercial National Security Algorithm Suite 1.0**
The original NSA algorithm suite (CNSSP 15 Annex B) for National Security Systems. Required ECDH/ECDSA P-384, RSA-3072, DH-3072, SHA-384, and AES-256. Superseded by CNSA 2.0, which mandates post-quantum algorithms (ML-KEM-1024, ML-DSA-87) with transition deadlines of 2025-2035.

**Collision Resistance**
A property of hash functions: it should be computationally infeasible to find two different inputs that produce the same hash output. SHA-1 lost this property (2017 collision found); SHA-256 and SHA-3 remain collision-resistant.

**Compression Round / Finalization Round (SipHash)**
The two phases of SipHash's internal mixing: compression (processing each input block) and finalization (producing the output). SipHash is parameterised as SipHash-c-d where c and d are round counts; standard is SipHash-2-4.

**Confidentiality**
The guarantee that only authorised parties can read a message. Achieved by encryption.

**Constant-Time Implementation**
Code whose execution time does not depend on secret values (such as keys or private key components). Non-constant-time code can leak secrets through timing measurements — an attacker who can measure how long an operation takes can sometimes recover the secret key.

**Context String**
An optional application-defined byte string bound into a signature in ML-DSA, SLH-DSA, and FN-DSA. Different applications using the same key can choose distinct context strings so that a signature produced in one context cannot be reused in another.

**COSE — Concise Object Signing and Encryption**
A compact binary counterpart to JSON-based JOSE, designed for constrained IoT environments. Supports the same operations (signing, encryption, MAC) in a smaller encoding. FN-DSA integration is being standardised.

**Cost Factor (bcrypt / Argon2)**
A parameter that controls how expensive (time and/or memory) a password-hashing operation is. Increasing the cost by 1 roughly doubles the time required. This allows administrators to keep the algorithm slow as hardware improves.

**cSHAKE — Customisable SHAKE**
A variant of SHAKE (NIST SP 800-185) that accepts two additional inputs: a function-name string and a customisation string. These inputs provide built-in domain separation, ensuring that different applications using the same key or input produce independent outputs. cSHAKE128 and cSHAKE256 are the base building blocks for KMAC, TupleHash, and ParallelHash.

**CSPRNG — Cryptographically Secure Pseudorandom Number Generator**
A pseudorandom number generator whose output is indistinguishable from true randomness for any computationally bounded attacker, and whose internal state cannot be recovered from observing its outputs. Required for key generation, nonce generation, and all other security-sensitive random values.

**Cryptoperiod**
The time span during which a specific cryptographic key is authorised for use. Defined in NIST SP 800-57 Part 1 §5.3. Typical values: 1-3 years for signature keys, ≤2 years for symmetric encryption keys, one transaction for ephemeral key-agreement keys. Expired keys must be destroyed or archived per policy.

**CTR — Counter Mode**
A block cipher mode that turns the cipher into a stream cipher by encrypting successive counter values and XOR-ing the result with the plaintext. Parallelisable and efficient. Does not provide authentication on its own — combine with HMAC or use GCM/CCM instead.

**CTR_DRBG — Counter-Mode Deterministic Random Bit Generator**
A NIST SP 800-90A random number generator using a block cipher (AES or 3DES) in counter mode. The most widely deployed DRBG, used internally by Windows BCryptGenRandom and Intel RDRAND. The 3DES variant is deprecated.

**Curve25519 / X25519**
A modern elliptic curve designed by Daniel Bernstein optimised for speed and resistance to implementation errors. X25519 is the Diffie-Hellman key exchange using Curve25519. It is the default key-exchange algorithm in TLS 1.3.

**Curve448 / X448**
A larger elliptic curve providing approximately 224-bit security (compared to 128-bit for Curve25519). Used for higher-security applications.

**CycloneDX**
An open standard for Software Bills of Materials (SBOMs) maintained by OWASP. Its Cryptography Extension provides a structured way to document which cryptographic algorithms, key lengths, and modes are used in a software component.

---

## D

**Decryption**
The process of turning ciphertext back into readable plaintext using the correct key.

**DES — Data Encryption Standard**
A 56-bit block cipher, once the US government standard. Its short key length makes it trivially brute-forceable with modern hardware. Disallowed for all new uses.

**Deterministic Signing**
A signing mode where the signature depends only on the private key and the message — no randomness is injected at signing time. While this avoids the risk of a weak random number generator, it can be vulnerable to fault-injection attacks (artificially induced hardware errors).

**DFR — Decryption Failure Rate**
The probability that a ciphertext produced by the encapsulation algorithm cannot be correctly decapsulated by the legitimate recipient, even without any attacker involvement. For a KEM claiming λ-bit IND-CCA2 security, the DFR must be ≤ 2⁻λ; otherwise an adversary can probe for weak keys and distinguish the KEM from a random function. HQC achieves a DFR of 2⁻¹²⁸ / 2⁻¹⁹² / 2⁻²⁵⁶ for HQC-128/192/256 via its RMRS concatenated code. BIKE's DFR analysis was found insufficient during NIST Round 4 (gathering property weak keys push DFR to ≥ 2⁻¹¹⁷ at Level 1), which was the decisive reason BIKE was not selected.

**DLIES — Discrete Logarithm Integrated Encryption Scheme**
A public-key encryption scheme based on the discrete logarithm problem over finite fields. The DL analogue of ECIES. Combines DH key agreement with a KDF and symmetric authenticated encryption. Referenced in BSI TR-02102-1 §2.3.3 and ISO/IEC 18033-2.

**DNSSEC — Domain Name System Security Extensions**
A suite of IETF standards (RFC 4033-4035) that authenticate DNS responses using digital signatures. Prevents DNS spoofing and cache poisoning by allowing resolvers to verify that DNS records originate from the authoritative name server. Uses RSA or ECDSA signatures (TSIG for zone transfer authentication).

**DH — Diffie-Hellman Key Exchange**
The original protocol (1976) for two parties to establish a shared secret over an insecure channel without ever transmitting the secret itself. Think of it as mixing paint colours: each party has a secret colour, they share a common colour, and the shared result cannot be reverse-engineered. Superseded by ECDH for performance; use FFDH only when required by policy.

**Digest**
Another word for the output of a hash function — a fixed-length fingerprint of a message.

**Digital Signature**
A mathematical value computed from a message and a private key. Anyone with the matching public key can verify that (1) the message has not been altered and (2) only someone with the private key could have produced the signature.

**Domain Separation**
A technique ensuring that the same cryptographic key or primitive produces independent, unrelated outputs when used for different purposes. Achieved by prepending different labels or using different context strings. Prevents cross-protocol attacks.

**DRBG — Deterministic Random Bit Generator**
A random number generator that produces output deterministically from an initial seed. NIST SP 800-90A defines three approved mechanisms: Hash_DRBG, HMAC_DRBG, and CTR_DRBG. Once seeded with true entropy, a DRBG can produce arbitrarily many pseudorandom bits.

**DSA — Digital Signature Algorithm**
A US government signature standard (FIPS 186). Uses a discrete-logarithm problem over a finite field. Key sizes below 2048 bits are deprecated; superseded by ECDSA and EdDSA for new designs.

**Dual_EC_DRBG — Dual Elliptic Curve Deterministic Random Bit Generator**
A DRBG mechanism originally included in NIST SP 800-90A that used elliptic curve operations to generate pseudorandom output. Withdrawn from SP 800-90A Rev. 1 (June 2015) after Snowden documents (2013) confirmed a deliberate NSA kleptographic backdoor via the choice of default elliptic curve points. Must never be used. Its inclusion in RSA BSAFE via a $10M contract (Reuters, 2013) made it the most widely deployed backdoored random number generator in history.

**du / dv (ML-KEM compression)**
Parameters controlling how aggressively ciphertext components are compressed in ML-KEM. Higher values reduce compression (and therefore decryption failure probability) but increase ciphertext size. Fixed by the parameter set — implementers do not choose these.

---

## E

**EasyCrypt**
A formal verification framework for cryptographic proofs, used to verify the security of implementations written in the Jasmin programming language. The mlkem-libjade implementation in the PQ Code Package uses EasyCrypt-level proofs.

**ECB — Electronic Codebook Mode**
A block cipher mode where each block is encrypted independently with the same key. Identical plaintext blocks produce identical ciphertext blocks, which leaks patterns (the "ECB penguin" problem). Never use ECB for messages longer than one block.

**ECC CDH — Elliptic Curve Cofactor Diffie-Hellman**
The primitive underlying ECDH key establishment, as defined in NIST SP 800-56A Rev.3 §5.7.1.2. The shared secret Z is computed as Z = h·dA·QB, where dA is the private key, QB is the peer's public key, and h is the curve cofactor. For prime-order curves (P-256, P-384, P-521) with h=1, no cofactor multiplication is needed. For Curve25519 (h=8), Curve448 (h=4), and Edwards curves (h=8 and h=4), the cofactor multiplication clears the small-subgroup component, preventing small-subgroup attacks. The result Z is then passed to a KDF (SP 800-56C) before use as a symmetric key.

**ECDH — Elliptic Curve Diffie-Hellman**
A key-exchange algorithm performing Diffie-Hellman key agreement using elliptic curves rather than large integers. Achieves the same security as classical DH with much smaller keys (256 bits of ECDH ≈ 3072 bits of DH).

**ECDSA — Elliptic Curve Digital Signature Algorithm**
A widely used signature algorithm based on elliptic curves. Defined in FIPS 186-5. Requires a random nonce per signature — if the nonce is ever reused or weak, the private key can be recovered (PlayStation 3 vulnerability).

**EFS — Encrypting File System**
A Windows NTFS feature providing transparent file-level encryption using per-file symmetric keys (AES or 3DES) protected by user certificates. Key recovery is managed through a designated recovery agent.

**ECIES — Elliptic Curve Integrated Encryption Scheme**
A public-key encryption scheme combining ECDH (for key agreement), a KDF (for key derivation), a symmetric cipher, and a MAC. Allows encrypting a message to someone's public key without prior shared secret.

**EdDSA — Edwards-Curve Digital Signature Algorithm**
A modern signature scheme (RFC 8032) using twisted Edwards curves. Inherently deterministic (no per-signature random nonce needed), fast, and resistant to many implementation pitfalls. Two variants: Ed25519 (128-bit security, most common) and Ed448 (224-bit security).

**Elliptic Curve**
A mathematical structure used as the foundation of modern public-key cryptography (ECDH, ECDSA, EdDSA, ML-KEM hybrid). Elliptic curves allow very short keys (256 bits) to provide security equivalent to much larger RSA keys (3072 bits). The "hard problem" underlying their security is the Elliptic Curve Discrete Logarithm Problem.

**Encryption**
The process of transforming readable plaintext into unreadable ciphertext using a key, so that only authorised parties can recover the original.

**ElGamal**
A public-key encryption and signature scheme based on the discrete logarithm problem in finite fields. Introduced by Taher ElGamal in 1985. Historically used in PGP/GnuPG (encryption only); the signature variant is distinct from DSA.

**ENISA — European Union Agency for Cybersecurity**
The EU agency responsible for cybersecurity policy, guidance, and incident response. Publishes post-quantum cryptography migration guidance and cryptographic recommendations for EU member states.

**Entropy**
A measure of unpredictability or randomness. High-entropy data is difficult to guess. Cryptographic keys require high entropy; a key generated from a weak source (e.g., the current time) can be guessed quickly.

**Entropy Source**
A hardware or software component that collects unpredictable data (thermal noise, interrupt timing, disk seek times, etc.) to seed a random number generator.

**EST — Enrollment over Secure Transport**
A simple HTTPS-based protocol (RFC 7030) for X.509 certificate enrollment and re-enrollment. Designed as a modern, lightweight replacement for SCEP.

**ETSI — European Telecommunications Standards Institute**
A European standards body producing standards for telecommunications, electronic signatures, and quantum-safe cryptography. Works alongside 3GPP and CEN/CENELEC.

**EUF-CMA — Existential Unforgeability under Chosen-Message Attack**
The standard security notion for digital signature schemes. It states that an adversary with access to a signing oracle (the ability to request signatures on any messages of their choice) cannot produce a valid signature on any new message not previously signed — even after receiving polynomially many signatures. A signature scheme that achieves EUF-CMA is considered cryptographically secure for general use. ML-DSA, SLH-DSA, FN-DSA, LMS, and XMSS are all designed to achieve EUF-CMA. The "existential" qualifier means the adversary is allowed to choose which message to forge (the strongest form). See also **IND-CCA2** for the analogous notion for encryption.

---

## F

**FAEST**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on symmetric-key primitives and a technique called MPC-in-the-Head with VOLE (Vector Oblivious Linear Evaluation). Its security depends only on the security of AES, rather than on hard mathematical problems.

**Falcon / FN-DSA**
See **FN-DSA**.

**FFDH — Finite Field Diffie-Hellman**
Standard Diffie-Hellman key exchange using named finite-field groups (RFC 7919). Minimum recommended group: ffdhe2048 (2048-bit). Used when ECDH is not available (e.g. some legacy FIPS-constrained deployments).

**FIPS — Federal Information Processing Standards**
US government standards, published by NIST, defining requirements for cryptographic algorithms and security modules. Key publications: FIPS 140-3 (crypto module validation), FIPS 197 (AES), FIPS 198-1 (HMAC), FIPS 202 (SHA-3), FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 206 (FN-DSA).

**FIPS 140-3**
The current US government standard (and internationally recognised) for validating that a hardware or software cryptographic module meets security requirements. Systems handling classified or sensitive government data often require FIPS 140-3 validated cryptography.

**FIPS Provider**
In OpenSSL 3.x, a loadable module that contains only FIPS 140-3 validated cryptographic algorithm implementations. When the FIPS provider is loaded, OpenSSL restricts itself to approved algorithms and operates within the validated cryptographic module boundary. OpenSSL 3.5.0 added ML-KEM, ML-DSA, and SLH-DSA to the FIPS provider.

**FN-DSA — FFT over NTRU-Lattice-Based Digital Signature Algorithm**
The NIST name for the Falcon signature scheme. Based on lattice mathematics (NTRU) and uses Fast Fourier Transform computations. Produces the smallest signatures of the NIST PQC signature algorithms. Requires strict IEEE 754 floating-point arithmetic in the reference implementation; integer-only variants are under development for constrained platforms. **Status:** FIPS 206 is still in the Initial Public Draft (IPD) stage as of Q1 2026 — the IPD was submitted for Department of Commerce clearance in August 2025; the final standard is expected late 2026 or early 2027. FIPS 203 (ML-KEM), 204 (ML-DSA), and 205 (SLH-DSA) were published as final standards in August 2024.

**FN-DSA-512 / FN-DSA-1024**
The two parameter sets for FN-DSA: 512 targets 128-bit security (NIST Level 1); 1024 targets 256-bit security (NIST Level 5).

**FORS — Forest of Random Subsets**
An internal component of SLH-DSA that provides a "few-time" signature layer. It uses a forest of small Merkle trees; parameters a (tree height) and k (number of trees) together control how many bits of the message digest are covered and how large the signature component is.

**Fortuna**
A CSPRNG (Cryptographically Secure Pseudorandom Number Generator) architecture designed by Bruce Schneier and Niels Ferguson. It uses 32 entropy pools to accumulate randomness from multiple sources, and an AES-256 counter-mode generator to produce output. Used in macOS/iOS since 2020 and in FreeBSD. The design improves on Yarrow by eliminating the need for an entropy estimator.

**FISMA — Federal Information Security Modernization Act**
US legislation (P.L. 113-283, 2014) requiring federal agencies to implement information security programs. Drives FIPS 140 and SP 800-series compliance for all federal information systems.

**Fiat-Shamir Transform**
A generic technique for converting an interactive identification scheme (a "sigma protocol" or zero-knowledge proof) into a non-interactive digital signature scheme. The verifier's random challenge in the interactive protocol is replaced by the output of a cryptographic hash function applied to the message and the prover's commitment. The resulting signature scheme is secure in the random oracle model (ROM). Many PQC signature schemes use this approach: ML-DSA (Fiat-Shamir with aborts), FN-DSA (Falcon), and several NIST Round 2 additional signature candidates (SDitH, FAEST, CROSS, Mirath). Security in the stronger **QROM** (quantum-accessible random oracle model) requires additional care — see QROM.

**FO-Transform — Fujisaki-Okamoto Transform**
A generic technique for converting an IND-CPA-secure public-key encryption scheme (or a passively secure KEM) into an IND-CCA2-secure KEM. The transform works by hashing the randomness used for encryption into the key material, so that any decryption that fails to reproduce the expected ciphertext is rejected. First introduced by Fujisaki and Okamoto (1999). All NIST-standardised lattice KEMs use a variant of the FO-transform: ML-KEM uses the Hofheinz-Hövelmanns-Kiltz (HHK) modular variant with tightly provable security. The FO-transform enables tight security proofs in both the ROM and the QROM, which is why all NIST PQC KEM finalists adopted it.

**FrodoKEM**
A conservative lattice-based key encapsulation mechanism based on the plain Learning With Errors (LWE) problem rather than the structured (ring or module) variants used by ML-KEM. FrodoKEM has larger keys and ciphertexts but its security relies on a simpler, more well-studied mathematical problem. Not selected for NIST standardisation; available in the Cloudflare CIRCL library.

**Forward Secrecy (Perfect Forward Secrecy, PFS)**
A property of a key-exchange protocol where the compromise of a long-term private key does not allow decryption of past recorded sessions. Achieved by generating a fresh, ephemeral key pair for each session (as in ECDHE in TLS 1.3) and discarding it immediately afterwards.

---

## G

**GCM — Galois/Counter Mode**
An AEAD (Authenticated Encryption with Associated Data) block cipher mode combining AES-CTR encryption with GHASH authentication. The standard mode in TLS 1.3 and most modern secure protocols. The IV/nonce must never be reused with the same key — IV reuse completely breaks both confidentiality and authentication.

**GCM-SIV — GCM Synthetic IV**
A nonce-misuse-resistant variant of GCM. If a nonce is accidentally reused, GCM-SIV leaks that two messages are identical, but does not expose the plaintext or allow forgery (unlike standard GCM). Slightly slower than GCM.

**getrandom()**
A Linux system call (kernel 3.17+) for obtaining cryptographically random bytes. Recommended for new Linux code: it blocks only at very early boot until the system has collected enough entropy, and never blocks thereafter.

**GMAC — Galois Message Authentication Code**
The authentication-only mode of GCM — AES-GCM with no plaintext (empty message), producing only an authentication tag. Provides a MAC using the GHASH function with AES. Used in IPsec (RFC 4543) for integrity-only protection.

**GHASH**
The polynomial-hash function used inside GCM to compute the authentication tag. Operates over a Galois field — hence the name. Implementation must be constant-time to avoid timing attacks.

**GOST 28147-89 / GOST R 34.12**
Russian block cipher standards. Mandatory for Russian government systems; rarely used elsewhere.

**Grain-128AEAD**
A lightweight stream cipher with built-in authentication, standardised in ISO/IEC 29192-3. Designed for constrained environments (IoT, embedded, RFID) where AES-based constructions carry too much overhead. Uses a 128-bit key and 96-bit nonce. The authenticated variant (Grain-128AEAD) was a finalist in the NIST Lightweight Cryptography competition. In CycloneDX: `Grain-128-*`.

**Group (cryptographic)**
A mathematical structure — a set of elements with an operation (like multiplication) — used as the foundation for key exchange and signature algorithms. In cryptography, the security comes from a "hard problem" in the group (finding discrete logarithms, factoring, etc.).

---

## H

**Hash Function / Cryptographic Hash**
A one-way function that converts any input to a fixed-length fingerprint (digest). Properties: (1) the same input always produces the same output; (2) you cannot recover the input from the output; (3) it is computationally infeasible to find two different inputs with the same output (collision resistance). Used for data integrity checks, digital signatures, and password storage.

**Hash_DRBG**
A NIST SP 800-90A DRBG that uses a hash function (SHA-256, SHA-512, etc.) as its core operation. The internal state consists of a value V and a constant C, both updated at each step using iterative hashing.

**HashML-DSA**
A pre-hash variant of ML-DSA defined in FIPS 204 §6. Instead of signing the raw message M, the signer first hashes M with a contextually bound hash function (default SHA-512 for all parameter sets) to produce M′ = hash(context ∥ M), then signs M′. This allows signing arbitrarily large messages with a single hash pass before the lattice operations. OIDs: `id-hash-ml-dsa-44-with-sha512` (2.16.840.1.101.3.4.3.32), `…-65-…` (.33), `…-87-…` (.34). In CycloneDX: `HashML-DSA-(44|65|87)[-{hashAlgorithm}]`.

**HashSLH-DSA**
A pre-hash variant of SLH-DSA defined in FIPS 205 §10. Analogous to HashML-DSA: the message is first hashed, then the hash output is signed by the SLH-DSA core. Twelve parameter sets parallel the twelve pure SLH-DSA variants. OIDs assigned in the arc `2.16.840.1.101.3.4.3.35`–`.46`. In CycloneDX: `HashSLH-DSA-(SHA2|SHAKE)-(128s|128f|192s|192f|256s|256f)[-{hashAlgorithm}]`.

**HAWK**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on the Lattice Isomorphism Problem — a different hard problem from the lattices used in ML-DSA and ML-KEM.

**Hedged Signing**
A signing mode (the default in ML-DSA) that injects an additional 32 random bytes from a DRBG alongside the message before signing. This provides protection against fault-injection attacks (attempts to induce hardware errors to leak the private key) and against weak random number generators.

**HKDF — HMAC-Based Extract-and-Expand Key Derivation Function**
A two-step KDF (RFC 5869): the Extract step condenses potentially low-quality input keying material into a uniformly random "PRK", then the Expand step stretches it to the desired output length. Used in TLS 1.3, Signal Protocol, HPKE, and most modern protocols.

**HMAC — Keyed-Hash Message Authentication Code**
A MAC construction (RFC 2104) built around any hash function. Computed as HMAC(K, M) = H(K⊕opad ∥ H(K⊕ipad ∥ M)). Provides message authentication and integrity. HMAC-SHA-256 is the most widely used form.

**HMAC_DRBG**
A NIST SP 800-90A DRBG using HMAC as its core update function. Considered the best-proven of the three approved DRBGs — it has a machine-verified security proof. The standard choice for applications requiring FIPS 140-3 validation.

**HRNG — Hardware Random Number Generator**
A dedicated hardware chip or circuit that generates random numbers from a physical entropy source (thermal noise, shot noise, metastable circuits). Distinguished from CPU-integrated entropy instructions (RDRAND/RDSEED) by being a separate component, often with its own certification (Common Criteria, FIPS 140-3). Used to seed software DRBGs in high-security applications.

**HSM — Hardware Security Module**
A tamper-resistant physical device that safeguards cryptographic keys, performs cryptographic operations (signing, decryption, key wrapping), and enforces access policies. HSMs are required for stateful signature key management (LMS/XMSS per SP 800-208), certificate authority root keys, and payment card processing. Validated to FIPS 140-3 Level 3 or higher.

**HSS — Hierarchical Signature Scheme**
A multi-level extension of LMS (RFC 8554, NIST SP 800-208). An HSS key pair consists of L levels of LMS trees, where each tree's root public key is signed by the OTS key of the level above. The total signing capacity is the product of the capacities at each level: 2^(h₁ + h₂ + … + hₗ). HSS allows very large signing capacities while keeping tree heights manageable — for example, two levels of h=10 yield 2^20 signatures. The private key state must be managed by a FIPS 140-2/3 Level 3+ hardware module (SP 800-208 §5.3). Used for code and firmware signing where long-lived root keys are required.

**Harvest Now, Decrypt Later (HNDL) — Retrospective Decryption**
A threat model in which an attacker intercepts and stores encrypted ciphertext today, intending to decrypt it once a sufficiently powerful quantum computer becomes available. Because all RSA, ECDH, and DH-based key establishment can be broken by Shor's algorithm on a quantum computer, any confidential data encrypted with those schemes and captured now is at risk of future decryption. HNDL is most dangerous for long-lived secrets (national security data, health records, intellectual property) that must remain confidential for 10+ years. It is the primary driver of urgency in PQC migration, even before large quantum computers exist. Mitigation: migrate key establishment to ML-KEM (or a classical/PQC hybrid); NIST and CNSA 2.0 timelines reflect this urgency.

**Hybrid Post-Quantum Cryptography**
A deployment strategy combining a classical algorithm (e.g., ECDH P-256 or X25519) with a post-quantum algorithm (e.g., ML-KEM-768) in parallel, such that security is maintained as long as at least one of the two remains unbroken. For key encapsulation, the standard combiner is: run both KEM algorithms, then combine the two shared secrets (via concatenation into a KDF, or XOR) to derive the final session key. For digital signatures, the standard approach is to produce and verify two independent signatures. The TLS 1.3 hybrid `X25519MLKEM768` is the IETF-recommended hybrid for early deployment (draft-ietf-tls-hybrid-design). Hybrid deployment is the recommended transition strategy during the period before PQC implementations have accumulated sufficient operational confidence. See also ENISA Report "Post-Quantum Cryptography: Current state and quantum mitigation" (2021).

**DHKEM — Diffie-Hellman Key Encapsulation Mechanism**
The KEM construction defined in RFC 9180 §4.1 that builds a KEM from a Diffie-Hellman group. The sender generates an ephemeral DH key pair, performs DH with the recipient's public key, and derives the shared secret via HKDF (ExtractAndExpand). Defined instantiations: DHKEM(P-256, HKDF-SHA256) (KEM ID 0x0010), DHKEM(P-384, HKDF-SHA384) (0x0011), DHKEM(P-521, HKDF-SHA512) (0x0012), DHKEM(X25519, HKDF-SHA256) (0x0020), DHKEM(X448, HKDF-SHA512) (0x0021). All five support AuthEncap/AuthDecap (authenticated variants). The KDF used inside DHKEM's ExtractAndExpand is the KEM's associated KDF (not the ciphersuite KDF).

**HPKE — Hybrid Public Key Encryption**
A modern framework (RFC 9180, IRTF CFRG, February 2022) for public-key encryption combining: a **KEM** (key encapsulation — typically DHKEM), a **KDF** (key derivation — HKDF), and an **AEAD** (symmetric encryption — AES-GCM or ChaCha20-Poly1305). A ciphersuite is a triple (KEM, KDF, AEAD). The recipient holds a static key pair; the sender encapsulates an ephemeral shared secret with the recipient's public key and uses it to encrypt the payload. RFC 9180 defines four operational modes: **mode_base** (0x00, unauthenticated sender), **mode_psk** (0x01, PSK-authenticated sender), **mode_auth** (0x02, sender KEM-key authenticated via AuthEncap/AuthDecap), **mode_auth_psk** (0x03, both). Security: IND-CCA2 under classical assumptions (ROM). **Not post-quantum secure** — the KEM relies on ECDH; replace DHKEM with a PQC KEM (e.g. ML-KEM hybrid) for quantum resistance. Applications: TLS ECH (Encrypted Client Hello), MLS (Messaging Layer Security), email encryption (LAMPS WG), OHTTP (Oblivious HTTP).

**HQC — Hamming Quasi-Cyclic**
An IND-CCA2-secure post-quantum Key Encapsulation Mechanism (KEM) selected by NIST in March 2025 as the fifth PQC algorithm (code-based backup KEM). Security is based on the **Quasi-Cyclic Syndrome Decoding (QCSD)** problem — a variant of the NP-hard syndrome decoding problem for random linear codes over F₂, augmented by a quasi-cyclic structure that does not give adversaries a meaningful advantage beyond a small constant factor. HQC uses a double-circulant binary code with a concatenated **Reed-Muller / Reed-Solomon (RMRS)** error-correcting code for message encoding. IND-CCA2 security is obtained via the **Salted Fujisaki-Okamoto (SFO⊥) transform**. Hash functions: SHA3-512 (key/secret derivation), SHA3-256 (FO challenge), SHAKE256 (pseudorandom vector sampling). Three parameter sets target NIST levels 1/3/5 (HQC-128/192/256, also called HQC-1/3/5); encapsulation key sizes 2241/4514/7237 B; ciphertext sizes 4433/8978/14421 B; shared secret 32 B. A FIPS standard is expected ~2027 (NIST IR 8545 estimates draft + final ~2 years from the March 2025 announcement); SP 800-227 (draft, January 2025) will provide KEM usage guidance. OIDs are not yet assigned.

---

## I

**IDEA — International Data Encryption Algorithm**
A 64-bit block cipher, historically used in PGP. No longer recommended; superseded by AES.

**IEEE 754**
The international standard for floating-point arithmetic in computers. FN-DSA (Falcon) requires that the underlying processor strictly follows IEEE 754 rules during key generation and signing — non-compliant behaviour (e.g., extended precision in x87 mode, flush-to-zero) can produce incorrect or insecure output.

**IETF — Internet Engineering Task Force**
The organisation that develops and publishes Internet standards, published as RFCs. Working groups relevant to cryptography include CFRG (Crypto Forum Research Group) and LAMPS (Limited Additional Mechanisms for PKIX and SMIME).

**IKE — Internet Key Exchange**
The key agreement protocol used to set up IPsec security associations. IKEv2 is the current version.

**IND-CCA2 — Indistinguishability under Adaptive Chosen-Ciphertext Attack**
The standard security notion for public-key encryption schemes and KEMs. An encryption scheme is IND-CCA2-secure if an adversary who can request decryptions of any ciphertext (except the challenge ciphertext) cannot distinguish encryptions of two messages of their choice. This is the strongest standard security notion for encryption and KEMs. ML-KEM, Classic McEliece, and HQC achieve IND-CCA2 security via the **FO-transform**. The weaker notion **IND-CPA** (indistinguishability under chosen-plaintext attack — no decryption oracle access) is achieved by the underlying lattice schemes before applying the FO-transform.

**IND-CPA — Indistinguishability under Chosen-Plaintext Attack**
A weaker PKE security notion than IND-CCA2: an adversary who can request encryptions of chosen plaintexts cannot distinguish between encryptions of two chosen messages. All NIST PQC KEM algorithms achieve at least IND-CPA security in their basic form. IND-CPA alone is not sufficient for most real-world protocols — the FO-transform upgrades IND-CPA schemes to IND-CCA2.

**ISD — Information Set Decoding**
A family of generic algorithms for solving the syndrome decoding problem over F₂ — the computational hardness assumption underlying code-based cryptography (HQC, BIKE, Classic McEliece). ISD algorithms search for a low-weight solution to a random linear system without exploiting any algebraic structure. The best classical ISD algorithms (Stern, BJMM, May-Ozerov) have sub-exponential but super-polynomial complexity; the best quantum ISD algorithms (using Grover-type speedups) provide a quadratic reduction in the exponent, roughly halving the classical security level (e.g., 128-bit classical → ~64-bit quantum, requiring doubled parameter sizes). HQC parameter sets are sized conservatively against the best known quantum ISD.

**Integrity**
The guarantee that data has not been modified in transit or storage. Achieved by message authentication codes (MACs) or digital signatures.

**IPsec — Internet Protocol Security**
A suite of protocols for encrypting and authenticating IP packets, used in VPNs. Uses IKE for key exchange, AES for encryption, and HMAC for integrity.

**Isogeny**
A special kind of mapping between elliptic curves that preserves their algebraic structure. The difficulty of computing isogenies between supersingular elliptic curves is the basis for the SQIsign post-quantum signature scheme. The earlier SIKE/SIDH key exchange (based on isogenies) was broken in 2022.

**Iterations (KDF)**
The number of times a KDF's core function is repeated. More iterations = more time required to check each password guess = more expensive brute-force attacks. NIST SP 800-132 (2023) recommends at least 600 000 iterations for PBKDF2-HMAC-SHA256.

**IV — Initialisation Vector**
A random value used to initialise a block cipher mode (CBC, CFB, OFB) or AEAD construction. The IV ensures that encrypting the same message twice produces different ciphertext. The IV does not need to be secret but must be unpredictable (for CBC) or unique (for GCM/CTR).

---

## J

**J-PAKE — Password Authenticated Key Exchange by Juggling**
A password-based key exchange protocol where both parties prove knowledge of the same password without either party revealing it. Used in smart-home and IoT pairing protocols.

**Jasmin**
A low-level programming language designed for writing high-assurance cryptographic implementations. Jasmin programs can be formally verified using EasyCrypt. The mlkem-libjade implementation in the PQ Code Package is written in Jasmin.

**JCA / JCE — Java Cryptography Architecture / Java Cryptography Extension**
The Java platform's standard API for cryptographic operations. JCA defines the architecture (providers, algorithm names, key management); JCE extends it with encryption, key agreement, and MAC operations. OpenJDK 26 adds ML-KEM and ML-DSA as native JCA algorithm identifiers.

**JEP — JDK Enhancement Proposal**
The formal process for proposing and tracking significant changes to the Java Development Kit. JEP 496 (ML-KEM) and JEP 497 (ML-DSA) track the addition of post-quantum algorithms to OpenJDK.

**JOSE — JSON Object Signing and Encryption**
A family of IETF standards for signing and encrypting JSON data, including JWT (JSON Web Token), JWE (JSON Web Encryption), and JWS (JSON Web Signature). Widely used in web APIs and OAuth.

---

## K

**Kerberos**
A network authentication protocol (RFC 4120) using symmetric-key tickets issued by a trusted Key Distribution Center (KDC) to mutually authenticate clients and services. Uses AES encryption (RFC 3962); DES and RC4-HMAC are deprecated (RFC 6649). PKINIT extension (RFC 4556) adds public-key authentication.

**Keccak**
The cryptographic sponge function family designed by Guido Bertoni, Joan Daemen, Michaël Peeters, and Gilles Van Assche. Winner of the NIST hash function competition (2012). Keccak is the basis of the SHA-3 hash functions (FIPS 202), the SHAKE extendable-output functions, and the SP 800-185 derived functions (cSHAKE, KMAC, TupleHash, ParallelHash). Also used in the TUAK 3GPP authentication algorithm. The sponge construction absorbs input into a fixed-size internal state and squeezes output, enabling both fixed-length and arbitrary-length output modes.

**KAT — Known Answer Test**
A set of pre-computed input/output pairs used to verify that a cryptographic implementation produces the correct results. If an implementation passes all KATs, it is more likely to be correct.

**KDF — Key Derivation Function**
An algorithm that derives one or more strong cryptographic keys from a source of keying material (a shared secret, a password, or random bytes). KDFs ensure that derived keys are uniformly random and independent of each other. Examples: HKDF, PBKDF2, scrypt, Argon2.

**KEM — Key Encapsulation Mechanism**
A public-key mechanism for establishing a shared secret. The sender uses the recipient's public key to "encapsulate" a randomly generated key, producing a ciphertext. The recipient "decapsulates" using their private key to recover the key. ML-KEM (CRYSTALS-Kyber) is the NIST-standardised KEM (FIPS 203). HQC was selected by NIST as a second KEM standard in March 2025 (FIPS standard pending).

**Key**
A piece of secret data that controls the operation of a cryptographic algorithm. The security of the system depends entirely on keeping the key secret, not on keeping the algorithm secret.

**Key Agreement**
A protocol where two parties both contribute material, and the result is a shared secret that neither party could have predicted alone. Diffie-Hellman and ECDH are key agreement schemes.

**Key Encapsulation**
See **KEM**.

**Key Exchange**
General term covering both key agreement (where both parties contribute) and key encapsulation (where one party generates and encrypts a key).

**Key Length / Key Size**
The number of bits in a cryptographic key. Longer keys are harder to brute-force. For symmetric ciphers: 128 bits is the minimum for new systems, 256 bits for high-security. For RSA: 2048 bits minimum, 3072+ recommended.

**Key Management**
The processes and infrastructure for generating, distributing, storing, rotating, and revoking cryptographic keys.

**Key Wrap / Key Wrapping**
Encrypting a cryptographic key with another key for secure storage or transmission (AES-KW, AES-KWP).

**KMAC — Keccak Message Authentication Code**
A MAC construction (NIST SP 800-185) built on cSHAKE (the customisable variant of SHA-3). Two variants: KMAC128 (128-bit security) and KMAC256 (256-bit security). Unlike HMAC, KMAC has a built-in domain-separation mechanism via the cSHAKE customisation string, and can produce variable-length output (KMACXOF128, KMACXOF256). Recommended alongside HKDF for hybrid PQC key combination in BSI TR-02102-1.

**KSF — Key-Stretching Function**
A function that deliberately slows down key derivation from a password to make brute-force attacks expensive. KSFs are a subset of KDFs specifically designed for password-based inputs. Examples: PBKDF2, bcrypt, scrypt, Argon2. The term is used in OPAQUE to refer to the function applied to the password before key agreement.

**KeyCombine**
A function that merges two or more shared secrets (e.g., one classical and one post-quantum) into a single session key. Defined in NIST SP 800-56C §4.6.1 Eq.9 and §4.6.2 Eq.15. Used alongside CatKDF for hybrid PQC key agreement (BSI TR-02102-1 §2.2).

**KyberSlash**
A timing side-channel vulnerability (CVE-2023-49722) discovered in several CRYSTALS-Kyber / ML-KEM implementations where division operations on secret data leaked information through execution timing. Affected implementations including crystals-go, which was subsequently archived in favour of CIRCL.

**Kyber**
See **ML-KEM**. Kyber is the earlier name of the algorithm that became ML-KEM when standardised as FIPS 203.

---

## L

**LAMPS — Limited Additional Mechanisms for PKIX and SMIME**
An IETF working group responsible for updating the PKIX (Public Key Infrastructure) and S/MIME standards to support post-quantum algorithms. Key deliverables include CMS specifications for ML-DSA, SLH-DSA, and composite signatures.

**Lattice (cryptographic)**
A mathematical structure used as the basis for post-quantum algorithms (ML-KEM, ML-DSA, FN-DSA). The security relies on the computational difficulty of finding short vectors in a high-dimensional grid — a problem believed to be hard even for quantum computers.

**LCG — Linear Congruential Generator**
The simplest class of pseudorandom number generator, based on the formula Xₙ₊₁ = (a·Xₙ + c) mod m. Trivially predictable from a single output. Used in some C standard library `rand()` implementations. Never suitable for cryptography.

**LESS — Linear Equivalence Signature Scheme**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on the hardness of the Linear Code Equivalence problem.

**LIP — Lattice Isomorphism Problem**
A mathematical problem where the task is to determine whether two lattices are isomorphic (equivalent up to rotation). The hardness of LIP is the security basis for the HAWK post-quantum signature scheme. It is a different hard problem from the Module-LWE and SIS problems used in ML-KEM and ML-DSA.

**LMS — Leighton-Micali Signature**
A stateful hash-based signature scheme (RFC 8554, NIST SP 800-208). Uses a Merkle tree of LMOTS one-time signature keys. Very fast verification; the signer must track which keys have been used (if the same key is used twice, security breaks). SP 800-208 approves 20 parameter sets (4 hash functions × 5 tree heights h=5/10/15/20/25). Private key state must be managed in a FIPS 140-2/3 Level 3+ hardware cryptographic module. Suitable for firmware signing and code signing. See also **HSS** (multi-level extension).

**LMOTS — Leighton-Micali One-Time Signature**
The one-time signature primitive underlying LMS (RFC 8554, SP 800-208). Each LMOTS key can sign exactly one message. Parameterised by a Winternitz parameter w ∈ {1, 2, 4, 8} that trades signature size for computation time. CNSA 2.0 recommends w=4 (default) with SHA-256/192 (n=24) hash function parameters.

**LWE — Learning With Errors**
A computational problem where the task is to distinguish noisy linear equations over a finite field from uniformly random samples. The hardness of LWE (and its structured variants Ring-LWE and Module-LWE) is the security foundation of the NIST PQC lattice-based algorithms: ML-KEM and ML-DSA use Module-LWE; FrodoKEM uses plain LWE. LWE is believed to be hard even for quantum computers, and has a worst-case-to-average-case reduction from lattice problems (GapSVP).

**LUC**
A public-key cryptosystem based on Lucas sequences, proposed as an alternative to RSA. Uses properties of Lucas functions rather than modular exponentiation. Historically significant but not widely deployed.

---

## M

**MAC — Message Authentication Code**
A short value computed from a message and a secret key, used to verify both the integrity and authenticity of the message. The recipient recomputes the MAC and compares it; if they match, the message was not tampered with. A MAC provides authenticity; a hash function alone does not (hashes are not keyed).

**Montgomery Curve**
An elliptic curve of the form By² = x³ + Ax² + x. This form enables the Montgomery ladder algorithm — a method for computing scalar multiplication that is naturally constant-time (immune to timing side-channel attacks), because the same operations are performed regardless of the scalar bits. NIST SP 800-186 approves two Montgomery curves: Curve25519 (A=486662, B=1, cofactor h=8) for 128-bit security and Curve448 (A=156326, B=1, cofactor h=4) for 224-bit security. Used via the X25519 and X448 Diffie-Hellman functions (RFC 7748).

**MAYO**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on multivariate polynomial equations.

**MD5 — Message Digest 5**
A deprecated 128-bit hash function. Collision attacks were found in 2004 and fully exploited by 2008 (identical digital certificates). Disallowed for all cryptographic uses.

**MILENAGE**
The standard 3GPP authentication algorithm set (TS 35.206) based on AES-128, used in USIM cards for the AKA protocol in 3G/4G/5G networks. Computes authentication vectors from the subscriber key Ki and network challenges.

**MLS — Messaging Layer Security**
An IETF protocol (RFC 9420) for efficient end-to-end encrypted group messaging. Uses tree-based key agreement (TreeKEM) with HPKE for key encapsulation. Designed for scalability to very large groups.

**MSCash / MSCash2 — Microsoft Cached Domain Credentials**
Windows domain credential hashing algorithms. MSCash (DCC v1) uses MD4-based hashing. MSCash2 (DCC v2, Vista+) adds PBKDF2 with 10,240 iterations of HMAC-SHA-1. Both are targets for offline credential attacks.

**Memory Hardness**
A property of password-hashing algorithms (scrypt, Argon2) that requires a large amount of RAM during computation. This makes parallelisation expensive — an attacker using specialised hardware (GPUs, ASICs) must pay for large amounts of memory, not just compute cycles.

**Merkle Tree**
A tree structure where each leaf node holds a hash of data, and each parent node holds a hash of its children. The root hash is a compact commitment to all the leaf data. Used in LMS, XMSS, SLH-DSA, and blockchain systems.

**MGF — Mask Generation Function**
A function used inside RSA-OAEP and RSA-PSS padding schemes to expand a seed into a bit mask of the required length. The standard version is MGF1, which is MGF1-SHA256 when using SHA-256 as the underlying hash.

**Min-Entropy**
A conservative measure of how random a data source is. Defined as −log₂(probability of the most likely output). An entropy source with H_min ≥ 128 bits means even the most probable output has at most a 1-in-2¹²⁸ chance of occurring. Used in NIST SP 800-90B.

**Mirath**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) resulting from the merger of the MIRA and MiRitH proposals, based on MinRank-in-the-Head.

**MitH — MPC-in-the-Head**
A technique for constructing digital signature schemes by simulating a multi-party computation (MPC) protocol "in the head" of the signer. The signer runs a zero-knowledge proof protocol internally, committing to the views of virtual parties. Several NIST Round 2 additional signature candidates use this approach: FAEST, SDitH, MQOM, Mirath, PERK, and RYDE.

**ML-DSA — Module-Lattice-Based Digital Signature Algorithm**
The NIST standard digital signature algorithm (FIPS 204, August 2024), formerly known as CRYSTALS-Dilithium. Based on the hardness of lattice problems believed to be secure against quantum computers. Three parameter sets: ML-DSA-44 (128-bit security), ML-DSA-65 (192-bit), ML-DSA-87 (256-bit).

**ML-KEM — Module-Lattice-Based Key-Encapsulation Mechanism**
The NIST standard key encapsulation mechanism (FIPS 203, August 2024), formerly known as CRYSTALS-Kyber. Used to establish a shared secret (typically for use as an encryption key) using public-key cryptography resistant to quantum attacks. Three parameter sets: ML-KEM-512 (128-bit security), ML-KEM-768 (192-bit, recommended for TLS), ML-KEM-1024 (256-bit).

**Mode of Operation**
A technique for using a block cipher to encrypt messages longer than one block. Different modes have different security properties. Examples: ECB (insecure), CBC, CTR, GCM (AEAD).

**Module Lattice**
A lattice defined over polynomial rings, used in the CRYSTALS family (ML-KEM, ML-DSA). The "module" structure provides a balance between security and performance — module lattice problems are harder than ordinary lattice problems in the same dimension.

**Module-LWE — Module Learning With Errors**
The mathematical hard problem underlying ML-KEM and ML-DSA. Module-LWE asks an adversary to distinguish noisy linear equations over polynomial modules from uniformly random samples. Believed to be hard even for quantum computers. The "module" structure provides a balance between the efficiency of Ring-LWE and the conservative security assumptions of plain LWE.

**MQOM — MQ on my Mind**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on the hardness of the Multivariate Quadratic (MQ) problem.

**MPK / MSK**
Master Public Key / Master Secret Key — terminology used in some key derivation hierarchies.

---

## N

**Named Group**
A standardised elliptic curve or finite-field group identified by a short name (e.g. `x25519`, `secp256r1`, `ffdhe2048`) used in TLS and other protocols. Using named groups ensures interoperability and that well-vetted parameters are used.

**NIST CSRC — NIST Computer Security Resource Center**
The public-facing portal where NIST publishes cryptographic standards (FIPS), special publications (SP 800 series), and PQC submission packages. Algorithm submission materials and Known Answer Tests are distributed via CSRC.

**NIST IR — NIST Internal/Interagency Report**
A series of NIST publications providing technical analysis and status reports. NIST IR 8545 documents the status and evaluation criteria for the additional digital signature candidates in the NIST PQC process.

**NIAP — National Information Assurance Partnership**
The US government body overseeing Common Criteria evaluations for IT products under the CCEVS programme. Products providing cryptographic services for National Security Systems require NIAP or NSA validation in addition to FIPS 140.

**NIST — National Institute of Standards and Technology**
A US government agency that develops cryptographic standards, guidelines, and algorithm recommendations. Publishes FIPS standards and SP 800-series guidance. Managed the Post-Quantum Cryptography standardisation process (2016–present) that produced ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) in August 2024. FN-DSA (FIPS 206) is in the Initial Public Draft stage. HQC was selected as a fifth PQC standard in March 2025.

**Nonce**
A "number used once" — a random or counter value that must never be repeated for a given key. In AEAD ciphers (GCM, ChaCha20-Poly1305), reusing a nonce completely breaks security. In signatures, a random nonce is required for ECDSA (not for EdDSA, which is deterministic).

**Non-separability (Composite Signatures)**
A security property of composite signature schemes stating that a valid composite signature cannot be split into its component signatures and used independently (i.e. a valid ML-DSA-only signature cannot be extracted from a Composite ML-DSA signature and accepted by a verifier expecting a standalone ML-DSA signature). Non-separability is achieved through a domain-separation prefix bound into the signed message. Composite ML-DSA achieves weak non-separability by binding a scheme-specific label into the pre-hashed message digest; this prevents cross-protocol replay of component signatures.

**NSA — National Security Agency**
The US signals intelligence and cybersecurity agency. Defines the CNSA algorithm suites (1.0, 2.0) for National Security Systems and publishes cryptographic guidance through cybersecurity advisories.

**NSM — National Security Memorandum**
A White House directive setting national security policy. NSM-10 (2022) establishes PQC migration deadlines for US government systems, requiring transition to quantum-resistant algorithms by 2035.

**NSS — National Security Systems**
US government information systems that handle classified or intelligence data, as defined by FISMA and governed by CNSS policy. All NSS must use CNSA-approved algorithms and NIAP/NSA-validated cryptographic modules.

**NTRU**
A lattice-based public-key cryptosystem and the mathematical basis of FN-DSA. NTRU lattices are defined using polynomial rings, making them efficient to compute on.

**NTT — Number Theoretic Transform**
A mathematical operation (analogous to the Fast Fourier Transform over finite fields) used to efficiently multiply polynomials in lattice-based cryptography (ML-KEM, ML-DSA). NTT-based polynomial multiplication is the performance-critical inner loop of these algorithms; memory for the NTT of the public matrix A scales with the module dimensions.

---

## O

**OAEP — Optimal Asymmetric Encryption Padding**
A padding scheme for RSA encryption (RSAES-OAEP) that adds randomness and structure to the plaintext before encryption. Prevents chosen-ciphertext attacks. The recommended replacement for PKCS#1 v1.5 encryption padding.

**OCB — Offset Codebook Mode**
A patented AEAD mode with high performance. The patents have expired in most jurisdictions, but adoption has been limited due to historical licensing concerns.

**OFB — Output Feedback Mode**
A block cipher mode that generates a keystream independently of the plaintext, then XORs it with the message. Rarely preferred over CTR for new designs.

**One-Time Signature (OTS)**
A signature key that can securely sign exactly one message. Using it for a second message reveals the private key. Used as a building block in hash-based signature schemes (LMS, XMSS, SLH-DSA).

**OPAQUE / OPAQUE-3DH**
An asymmetric Password-Authenticated Key Exchange (aPAKE) protocol that allows a client to authenticate to a server using a password, without the server ever storing (or seeing) the plaintext password — even during registration. Uses OPRF and a KSF. The CycloneDX pattern `OPAQUE-3DH` refers to the 3DH (three-message Diffie-Hellman) instantiation described in the IETF CFRG draft (draft-irtf-cfrg-opaque).

**OPRF — Oblivious Pseudorandom Function**
A protocol where a client and server jointly compute a pseudorandom function on the client's input (e.g. a password), such that the server learns nothing about the input and the client learns nothing about the server's secret key. A core building block of OPAQUE.

**OID — Object Identifier**
A globally unique hierarchical identifier used in ASN.1 to unambiguously identify cryptographic algorithms, curves, and data structures. Each OID is a sequence of integers separated by dots (e.g., `2.16.840.1.101.3.4.1` for the AES arc). OIDs appear in X.509 certificates, CMS signatures, and algorithm negotiation protocols.

**OTAR — Over-The-Air Rekeying**
A protocol for remotely updating cryptographic keys on deployed radio or IoT devices without physical access. Uses key-wrapping (AES or 3DES) with CBC-MAC authentication. Referenced in SP 800-57 Part 3 §7.

**OQS — Open Quantum Safe**
An open-source project providing C libraries (liboqs) and integration wrappers (oqs-provider for OpenSSL) for post-quantum cryptographic algorithms. liboqs implements ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC, and experimental Round 2 candidates. When running against OpenSSL 3.5+, oqs-provider disables algorithms that OpenSSL now supports natively.

**OWASP — Open Web Application Security Project**
A non-profit community producing freely available security guidance and tools. The OWASP Password Storage Cheat Sheet is the primary practical reference for password-hashing parameter recommendations.

---

## P

**Padding**
Data added to a message so its length matches the block cipher's expected input size. PKCS#7 is the standard padding scheme for block ciphers. Padding oracles are attacks that exploit error messages about incorrect padding — PKCS#1 v1.5 RSA encryption is vulnerable; OAEP is not.

**PAKE — Password-Authenticated Key Exchange**
A key exchange protocol where both parties authenticate using a shared password, without either party transmitting the password. Provides mutual authentication. Examples: J-PAKE, SPAKE2, OPAQUE.

**ParallelHash**
A hash function (NIST SP 800-185) based on cSHAKE that splits its input into fixed-size blocks and hashes them independently before combining the results. Two variants: ParallelHash128 (128-bit security) and ParallelHash256 (256-bit security). Designed for efficient parallel processing on multi-core hardware. Both fixed-output and extendable-output (XOF) variants exist.

**Parallelism (Argon2)**
The number of independent computation threads Argon2 uses. Increasing parallelism allows attackers to use more CPU cores in parallel without extra memory cost, so it should reflect the attacker's thread count, not the defender's.

**PBKDF1 / PBKDF2 — Password-Based Key Derivation Function**
Standards (RFC 8018 / PKCS#5) for deriving a cryptographic key from a password. PBKDF2 applies an HMAC (or other PRF) thousands of times to slow brute-force attacks. NIST now requires ≥ 600 000 iterations with HMAC-SHA256 for new systems.

**PBES1 / PBES2 — Password-Based Encryption Scheme**
Standards for encrypting data with a password-derived key. PBES2 (using PBKDF2 + AES) is the recommended variant; PBES1 is deprecated.

**PCG — Permuted Congruential Generator**
A non-cryptographic PRNG using a linear congruential generator with a non-linear output permutation. Excellent statistical properties; very fast. Not cryptographically secure.

**Perfect Forward Secrecy**
See **Forward Secrecy**.

**PERK**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on the Permuted Kernel Problem.

**Personalization String**
An optional byte string supplied when instantiating a DRBG. It mixes application-specific data (e.g. hostname + process ID + timestamp) into the initial seed so that two DRBG instances started at the same time from the same entropy source will produce different output streams. Does not need to be secret.

**PFS**
See **Forward Secrecy**.

**PKCS — Public-Key Cryptography Standards**
A series of standards originally published by RSA Laboratories. Key documents: PKCS#1 (RSA cryptography), PKCS#5 (password-based cryptography), PKCS#7 (message syntax), PKCS#12 (personal information exchange / certificate stores).

**PKI — Public Key Infrastructure**
The ecosystem of standards, software, and organisations for issuing, verifying, and revoking digital certificates.

**PKIX — Public Key Infrastructure using X.509**
The IETF working group and standard framework (RFC 5280) for certificate-based PKI. Defines the X.509v3 certificate profile, CRL format, and certificate path validation rules used in TLS, S/MIME, and code signing.

**Plaintext**
A message or data in its original, readable form before encryption.

**Poly1305**
A one-time message authentication code designed by Daniel Bernstein. Used as the authentication component in ChaCha20-Poly1305.

**PMU — Performance Monitoring Unit**
A CPU subsystem that provides hardware counters for events such as cache misses, branch mispredictions, and instruction counts. PMU measurements can be used to detect timing side-channel vulnerabilities in cryptographic implementations (e.g., the KyberSlash analysis used PMU tooling to demonstrate cache-timing leaks).

**Post-Quantum Cryptography (PQC)**
Cryptographic algorithms designed to resist attacks from quantum computers. Classical algorithms (RSA, ECDSA, ECDH) are broken by Shor's algorithm on a sufficiently powerful quantum computer. NIST published three PQC standards in August 2024: ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205). FN-DSA (FIPS 206) is in the Initial Public Draft stage (expected late 2026/early 2027). HQC was selected as a fifth PQC standard in March 2025 (FIPS standard pending).

**PQCA — Post-Quantum Cryptography Alliance**
A Linux Foundation project bringing together industry and academic stakeholders to accelerate the development, testing, and deployment of production-quality post-quantum cryptographic implementations. Members include AWS, Cisco, Google, IBM, and others. The PQ Code Package (PQCP) initiative operates under PQCA.

**PQC Forum**
The official NIST mailing list (`pqc-forum@list.nist.gov`) where researchers, implementers, and standards bodies discuss post-quantum cryptography. Referenced throughout this repository for active implementation and standardisation discussions.

**PQ Code Package (PQCP)**
A community effort to produce formally verified, production-quality implementations of NIST PQC algorithms. Includes mlkem-native, mldsa-native, slhdsa-c, and mlkem-libjade.

**Prediction Resistance**
A DRBG property: if enabled, the generator reseeds from a live entropy source before every output, preventing an attacker who has compromised the internal state from predicting future output. Costs performance and requires a reliable entropy source to always be available.

**Pre-Shared Key Quantum Mitigation**
An interim mitigation strategy for protecting confidential communications against the **Harvest Now, Decrypt Later** threat, without requiring post-quantum algorithms. A pre-shared symmetric key (PSK) is mixed into the session key derivation alongside the public-key-derived shared secret. Any attacker who later breaks the public-key exchange with a quantum computer still cannot recover the session key without also knowing the PSK. Protocols: WireGuard's built-in PSK mode (`preshared-key`), ZRTP key continuity, and TLS 1.3's optional `psk_dhe_ke` extension. Limitation: PSKs require secure out-of-band provisioning and do not scale to open systems. Recommended for systems with a limited set of known peers (VPN endpoints, IoT devices, critical infrastructure). See ENISA "Post-Quantum Cryptography" §6.2.

**Pre-Hash Mode**
A signing mode where the message is hashed by the application before being passed to the signature algorithm. Useful for processing very large messages. All NIST PQC signature algorithms support both pure mode (algorithm hashes internally) and pre-hash mode.

**PRF — Pseudorandom Function**
A keyed function whose output is computationally indistinguishable from a truly random function. Building block of KDFs, MACs, and DRBGs. HMAC, AES-CMAC, and KMAC are all PRFs.

**PRNG — Pseudorandom Number Generator**
A deterministic algorithm for generating a sequence of numbers that appears random but is fully determined by its initial seed. Non-cryptographic PRNGs (Mersenne Twister, PCG) are fast but predictable. CSPRNGs are cryptographically secure.

**PSS — Probabilistic Signature Scheme**
A randomised padding scheme for RSA signatures (RSASSA-PSS). The recommended alternative to the older PKCS#1 v1.5 signature padding. Adds a random salt for security.

---

## Q

**Quantum Computer**
A computer exploiting quantum mechanical phenomena (superposition, entanglement) to solve certain mathematical problems exponentially faster than classical computers. Shor's algorithm on a quantum computer breaks RSA, ECDH, ECDSA, and DH. Grover's algorithm halves the effective key length of symmetric ciphers (AES-256 remains secure; AES-128 is weaker). No sufficiently powerful quantum computer exists yet (as of 2026), but cryptographic migration is already recommended.

**QKD — Quantum Key Distribution**
A quantum-physics-based method for distributing cryptographic keys between two parties, with security guaranteed by the laws of physics (eavesdropping disturbs the quantum state and is detectable). **QKD is not a form of post-quantum cryptography and does not replace PQC.** Key limitations: QKD requires a separate authenticated classical channel (which itself typically depends on public-key cryptography), specialised hardware, and point-to-point optical links — it is not directly applicable to large-scale Internet security. QKD provides key agreement only, not authentication or message confidentiality. ENISA and NIST recommend PQC as the primary migration path; QKD may complement PQC in specific high-security scenarios.

**QROM — Quantum Random Oracle Model**
A security proof model that models a cryptographic hash function as a random oracle accessible to quantum adversaries (i.e., an adversary that can query the hash function on quantum superpositions of inputs). The classical ROM (Random Oracle Model) is insufficient for post-quantum security proofs because quantum adversaries can query oracles in superposition. The QROM was proposed to address this. ML-KEM, ML-DSA, and SLH-DSA all have security proofs in the QROM. The Fiat-Shamir transform is secure in the QROM under slightly stronger conditions (requiring the underlying scheme to be "computationally unique" or using a concrete strengthening). Schemes whose security proofs rely only on the classical ROM should be treated with more caution in a post-quantum context.

**QR-UOV**
A post-quantum signature scheme based on Unbalanced Oil and Vinegar polynomials over a quotient ring structure.

---

## R

**Retrospective Decryption**
See **Harvest Now, Decrypt Later (HNDL)**.

**RBG — Random Bit Generator**
An umbrella term for any device or algorithm producing random bits, including both TRNGs (hardware entropy sources) and DRBGs (deterministic generators seeded from entropy sources).

**Rabin**
A public-key cryptosystem where encryption security is provably equivalent to integer factorisation. Encryption squares the message modulo n, yielding four possible decryptions. Historically significant but not used in modern protocols.

**RC2 / RC4 / RC5 / RC6**
A family of ciphers by Ron Rivest. RC4 (a stream cipher) is completely broken and disallowed. RC2 is deprecated. RC5 and RC6 are block ciphers not widely standardised for modern use.

**RC4-HMAC**
A Kerberos encryption type (etype 23) combining the RC4 stream cipher with HMAC-MD5 for key derivation. Deprecated (RFC 6649) due to RC4's cryptographic weaknesses. The EXP variant (etype 24) uses a 40-bit export-grade key and is disallowed.

**RDRAND**
An Intel/AMD CPU instruction that returns output from an on-chip AES-CTR DRBG. Very fast. Must not be used as the sole entropy source — its internal DRBG could have implementation flaws. Combine with OS entropy (`getrandom()`, `/dev/urandom`).

**RDSEED**
An Intel/AMD CPU instruction that returns raw (conditioned) hardware entropy directly, bypassing the on-chip DRBG. Slower than RDRAND. Suitable for seeding software DRBGs. May return a failure flag if entropy is not yet ready — callers must retry.

**Reference Implementation**
The official implementation of a cryptographic algorithm, typically written by the algorithm's designers, used to verify the standard and produce test vectors. Not necessarily optimised for production use.

**Reseed Interval**
The maximum number of generate calls before a DRBG must reseed from a fresh entropy source. NIST SP 800-90A allows up to 2⁴⁸ calls; implementations typically use shorter intervals for defence-in-depth.

**RFC — Request for Comments**
The document series published by the IETF that defines Internet standards and protocols. Relevant RFCs include: RFC 2104 (HMAC), RFC 5869 (HKDF), RFC 7914 (scrypt), RFC 8017 (RSA / PKCS#1), RFC 8018 (PBKDF2 / PBES), RFC 8032 (EdDSA), RFC 8554 (LMS), RFC 9106 (Argon2), RFC 9180 (HPKE).

**Ristretto255 / Decaf448**
Techniques for constructing prime-order groups from the Curve25519 and Curve448 elliptic curves, avoiding cofactor-related implementation pitfalls. Used in OPAQUE and SPAKE2+.

**RSA — Rivest-Shamir-Adleman**
The most widely used public-key algorithm for encryption and digital signatures, based on the difficulty of factoring large integers. Key sizes: 2048 bits minimum (provides ~112-bit security), 3072+ bits recommended (128-bit security). Broken by Shor's algorithm on a quantum computer — must be replaced by PQC algorithms.

**RSAES-OAEP**
RSA encryption using OAEP padding. The recommended RSA encryption mode.

**RSAES-PKCS1**
RSA encryption using PKCS#1 v1.5 padding. Vulnerable to Bleichenbacher's 1998 padding-oracle attack. Disallowed for new use.

**RSASSA-PKCSv1**
RSA signing using PKCS#1 v1.5 padding. Deprecated for new signing; RSA-PSS (RSASSA-PSS) is preferred.

**RSASSA-PSS**
RSA signing using PSS (Probabilistic Signature Scheme) padding. The recommended RSA signature mode.

**RYDE**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on the Rank Syndrome Decoding problem.

---

## S

**Safe-Prime Group**
A Diffie-Hellman prime group where p is a safe prime (p = 2q + 1, where q is also prime). The large prime-order subgroup of size q ensures that an attacker cannot exploit small subgroups to recover the private key. NIST SP 800-56A Rev.3 and RFC 7919 define named safe-prime groups (ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192) approved for TLS key agreement. Custom primes require full validation per SP 800-56A Appendix D.

**Salt**
A random value mixed into a password (or other input) before hashing to ensure that two identical passwords produce different hashes, preventing precomputed dictionary (rainbow table) attacks. The salt does not need to be secret — only the password does. Minimum 128 bits (16 bytes); 32 bytes recommended.

**S/MIME — Secure/Multipurpose Internet Mail Extensions**
A standard for sending encrypted and digitally signed email using CMS (Cryptographic Message Syntax). The IETF LAMPS working group is standardising ML-DSA and SLH-DSA for use in S/MIME certificates and signed messages.

**SBOM — Software Bill of Materials**
A machine-readable inventory of all software components, libraries, and their metadata (versions, licenses, known vulnerabilities). CycloneDX and SPDX are the two dominant SBOM standards.

**SCA — Software Composition Analysis**
A category of tools and processes that identify open-source and third-party components within a software project, track their versions and licenses, and flag known vulnerabilities. SCA tools consume SBOMs (CycloneDX, SPDX) and are the primary consumers of the cryptographic algorithm metadata documented in this repository.

**scrypt**
A memory-hard password-hashing / key-derivation function (RFC 7914). Parameters: N (CPU/memory cost, must be a power of 2), r (block mix factor), p (parallelism). Memory usage is 128·N·r bytes. Resistant to GPU/ASIC attacks.

**SDitH — Syndrome Decoding in the Head**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) using the MPC-in-the-Head paradigm applied to the Syndrome Decoding problem.

**Security Level / Security Strength**
A number (in bits) summarising how hard it is to break a cryptographic primitive. A 128-bit security level means approximately 2¹²⁸ operations are required for the best known attack. NIST defines security levels 1–5 for PQC algorithms (Level 1 ≈ AES-128, Level 3 ≈ AES-192, Level 5 ≈ AES-256).

**SEED**
A 128-bit block cipher standardised in South Korea (RFC 4269), used in Korean government and financial systems.

**Serpent**
A block cipher that was an AES finalist (1997–2001). Considered very conservative security margin but slower than AES.

**SIS — Short Integer Solution**
A mathematical problem where the task is to find a short non-zero vector in the kernel of a random matrix over a finite field. Together with LWE, SIS is one of the two fundamental hard problems underlying lattice-based cryptography. The security of ML-DSA signatures relies on the hardness of the Module-SIS problem.

**SHA-1 — Secure Hash Algorithm 1**
A 160-bit hash function. Collision attacks were found in 2005 and a practical collision demonstrated in 2017 (SHAttered). Disallowed for all digital signatures and certificate issuance; transitional use in non-signature contexts only until 2030.

**SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512)**
The current mainstream hash function family. SHA-256 is the most widely used (128-bit security); SHA-384/512 for higher-security applications. SHA-512/256 uses the SHA-512 computation but truncates output to 256 bits, providing stronger resistance to length-extension attacks.

**SHA-3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512)**
The third-generation hash standard (FIPS 202, 2015), based on the Keccak sponge construction — an entirely different design from SHA-1 and SHA-2. Provides structural diversity: an attack on SHA-2 would not automatically apply to SHA-3.

**SHAKE128 / SHAKE256**
Extendable-Output Functions (XOFs) from the SHA-3 family. Unlike SHA-3 which produces a fixed-length output, SHAKE can produce any desired output length. SHAKE128 provides 128-bit security for outputs ≥ 32 bytes; SHAKE256 provides 256-bit security for outputs ≥ 64 bytes.

**Shor's Algorithm**
A quantum algorithm that can efficiently solve the integer factorisation and discrete logarithm problems. This means it can break RSA, ECDH, ECDSA, DH, and DSA on a sufficiently powerful quantum computer.

**Side-Channel Attack**
An attack that exploits information leaked by the physical implementation of a cryptographic algorithm — such as execution time, power consumption, or electromagnetic radiation — rather than breaking the algorithm mathematically. Constant-time implementations are designed to resist timing side-channels.

**SipHash**
A fast, keyed hash function optimised for hash tables. Parameterised as SipHash-c-d where c and d are round counts; standard is SipHash-2-4. Designed to be fast but not suitable as a general-purpose MAC.

**SIV — Synthetic IV**
An AEAD mode where the IV is derived from the message, making it nonce-misuse-resistant. If a nonce is accidentally reused, confidentiality of the repeated message is lost but no forgery is possible.

**SLH-DSA — Stateless Hash-Based Digital Signature Standard**
The NIST standard digital signature algorithm (FIPS 205, August 2024), based on SPHINCS+. Stateless — unlike LMS and XMSS, the signer does not need to track state. Its security relies entirely on the security of the underlying hash function, making it the most conservative PQC signature choice. Signature sizes are larger than ML-DSA and FN-DSA.

**SM2, SM3, SM4**
Chinese national cryptographic standards: SM2 (elliptic curve public-key), SM3 (hash, 256-bit), SM4 (block cipher, 128-bit). Required for Chinese government and financial systems.

**SM9**
Chinese national pairing-based cryptographic standard (GM/T 0044-2016; ISO/IEC 14888-3). Provides four schemes based on identity-based cryptography over bilinear pairings: **SM9-SIG** (identity-based digital signature), **SM9-KEX** (identity-based key exchange), **SM9-KEM** (key encapsulation), and **SM9-ENC** (identity-based encryption/PKE). Identity-based means that a user's public key is derived from their identity string (e.g. email address) rather than from a certificate; a trusted Private Key Generator (PKG) issues private keys. All four variants are in the CycloneDX registry.

**SNOW 3G**
A word-oriented stream cipher used in 3GPP mobile networks (4G LTE) for confidentiality (128-EEA1) and integrity (128-EIA1). Standardised in 3GPP TS 35.216. Uses a 128-bit key and 128-bit IV. "SNOW" stands for "a new word-oriented stream cipher."

**SNOW-V**
A next-generation stream cipher designed as a candidate replacement for SNOW 3G in 5G networks. Proposed by Ekdahl, Johansson, and others (2019). Targets 256-bit security with higher throughput on modern processors. Not yet standardised by 3GPP.

**SNOVA**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on multivariate polynomial cryptography.

**SP 800 — NIST Special Publication 800 Series**
A series of NIST computer security publications providing guidance, recommendations, and technical details. Key documents: SP 800-57 (key management), SP 800-90A (DRBGs), SP 800-90B (entropy sources), SP 800-131A (algorithm transitions), SP 800-132 (PBKDF), SP 800-186 (elliptic curves), SP 800-208 (hash-based signatures).

**SPAKE2 / SPAKE2+**
A simple, efficient Password-Authenticated Key Exchange protocol. Provides mutual authentication; SPAKE2+ additionally provides augmented (server-not-equal-to-client) properties.

**SPDX — Software Package Data Exchange**
An open standard (ISO/IEC 5962) for describing software bill of materials, including license expressions and security metadata.

**SPHINCS+ / SPHINCS-Plus**
The predecessor to SLH-DSA, submitted to the NIST PQC process. Standardised as FIPS 205 (SLH-DSA) in August 2024.

**SQIsign**
A post-quantum digital signature scheme (NIST Round 2 additional signatures) based on the hardness of finding isogenies between supersingular elliptic curves. Produces the smallest signatures of all PQC candidates but is significantly slower to sign and verify.

**SRTP — Secure Real-time Transport Protocol**
A protocol (RFC 3711) providing confidentiality, authentication, and replay protection for RTP media streams (VoIP, video conferencing). Uses AES-CTR or AES-f8 for encryption and HMAC-SHA-1 for authentication. AES-GCM mode is also supported. Referenced in BSI TR-02102-1 §3.6.

**SRP — Secure Remote Password**
A password-based authentication protocol where the client proves knowledge of a password to the server without transmitting the password or storing a password verifier that would allow offline attacks. SRP-6a is the most widely deployed variant (RFC 5054 for TLS-SRP).

**SSH — Secure Shell**
A protocol for encrypted remote login and file transfer. Uses ECDH (typically X25519) for key exchange, AES-CTR or ChaCha20-Poly1305 for encryption, and HMAC or AEAD for integrity.

**SUF-CMA — Strong Unforgeability under Chosen-Message Attack**
A stronger security notion for digital signatures than EUF-CMA. EUF-CMA requires that an attacker cannot produce a valid signature on a message they have not previously queried; SUF-CMA additionally requires that the attacker cannot produce any *new* valid signature on a *previously signed* message (i.e. even if a valid (m, σ) pair is known, producing a different valid σ' on the same m must be infeasible). SUF-CMA is relevant in protocols where signature uniqueness matters (e.g. non-repudiation, transaction systems). Composite ML-DSA provides EUF-CMA but not SUF-CMA, because an attacker could potentially substitute one component signature for another valid one. Most modern schemes including ML-DSA itself are EUF-CMA; RSA-PSS and Ed25519 are SUF-CMA. See also **EUF-CMA**.

**Stateful Signature**
A signature scheme where the signer must maintain and update internal state between signing operations (e.g. LMS, XMSS). Signing the same message twice with the same state key compromises security — key management must ensure strict non-repetition.

**Stateless Signature**
A signature scheme requiring no state management (e.g. RSA, ECDSA, SLH-DSA, ML-DSA). Any message can be signed with any key at any time without tracking usage.

**Stream Cipher**
An encryption algorithm that produces a pseudorandom keystream and XORs it with the plaintext. Examples: RC4 (broken), ChaCha20, the output stage of CTR mode.

**Symmetric Encryption**
Encryption where the same key is used for both encryption and decryption. Fast and efficient; requires secure key distribution. Examples: AES, ChaCha20. Contrast with asymmetric encryption (different keys for encrypt and decrypt).

---

## T

**Tag (Authentication)**
See **Authentication Tag**.

**3DES — Triple DES**
A legacy cipher applying DES three times with either two or three independent keys. Provides approximately 112-bit effective security. Deprecated for encryption (NIST 2019), disallowed for new systems (NIST 2024). Replaced by AES.

**TSIG — Transaction Signature**
A mechanism (RFC 2845) for authenticating DNS messages (zone transfers, dynamic updates) using shared-secret HMAC signatures. HMAC-SHA-256 is the recommended algorithm; HMAC-MD5 is disallowed for federal use.

**TUAK**
An alternative 3GPP authentication algorithm set (TS 35.231) based on Keccak/SHA-3 for the AKA protocol. Standardised as an option alongside MILENAGE for 3G/4G/5G USIM authentication.

**TLS — Transport Layer Security**
The standard protocol for encrypted communications over the Internet (HTTPS, IMAPS, etc.). Current version: TLS 1.3 (RFC 8446). TLS 1.2 is conditionally approved for legacy interoperability. TLS 1.0 and 1.1 are disallowed.

**TLS 1.3**
The current recommended TLS version. Streamlined handshake (fewer round trips), mandatory forward secrecy (ECDHE), mandatory AEAD ciphers, removed weak legacy options.

**Twisted Edwards Curve**
An elliptic curve of the form ax² + y² = 1 + dx²y² (for a ≠ d, ad ≠ 0). Twisted Edwards curves enable the EdDSA signature algorithm and support very efficient, naturally complete addition formulas (no special cases for the point at infinity). NIST SP 800-186 approves two twisted Edwards curves: Edwards25519 (a=−1, d=−121665/121666; birationally equivalent to Curve25519) and Edwards448 (a=1, d=−39081; birationally equivalent to Curve448). These are used by Ed25519 and Ed448 respectively (RFC 8032, FIPS 186-5).

**TPM — Trusted Platform Module**
A tamper-resistant hardware security chip providing key storage, random number generation, and attestation. TPM 2.0 (TCG specification) exposes a random number generator via `TPM2_GetRandom`. Used in laptop/server security, BitLocker, Secure Boot.

**TPM RNG**
The hardware random number generator inside a TPM, accessed via the `TPM2_GetRandom` command. Operates within the TPM's security boundary, providing an entropy source independent of the main CPU.

**TRNG — True Random Number Generator**
A random number generator drawing from genuine physical entropy sources (thermal noise, quantum shot noise, metastable circuits, radioactive decay). Non-deterministic — the same device will never produce the same sequence twice. Used to seed DRBGs.

**TupleHash**
A hash function (NIST SP 800-185) based on cSHAKE that hashes a sequence of input strings such that the hash unambiguously encodes the boundaries between strings. Two variants: TupleHash128 (128-bit security) and TupleHash256 (256-bit security). Prevents an adversary from shifting bytes between adjacent inputs to produce a collision — a property that plain concatenation-then-hashing does not provide.

**Twofish**
A 128-bit block cipher (AES finalist, 1997–2001) designed by Bruce Schneier. Considered secure but not standardised by NIST for general use; superseded by AES in new designs.

---

## U

**UMAC — Universal Message Authentication Code**
A MAC with very high performance using universal hashing. Variants: UMAC-32, UMAC-64, UMAC-96, UMAC-128 (tag lengths). Defined in RFC 4418.

**UOV — Unbalanced Oil and Vinegar**
A post-quantum digital signature scheme based on multivariate polynomial equations. The "oil" and "vinegar" variables have asymmetric roles, making the trapdoor structure computationally hard to reverse.

---

## V

**VOLEitH — Vector Oblivious Linear Evaluation in the Head**
A variant of the MPC-in-the-Head paradigm used in the FAEST post-quantum signature scheme. Instead of simulating a general multi-party computation, VOLEitH simulates a two-party VOLE (Vector Oblivious Linear Evaluation) protocol, which is particularly efficient when the witness is an AES key. This allows FAEST to base its security solely on the security of AES.

---

## W

**Winternitz Parameter (w)**
A trade-off parameter in the WOTS+ one-time signature scheme: larger w means fewer but longer hash chains, trading signature time for signature size. In SLH-DSA (FIPS 205), this is fixed at w=16 for all parameter sets.

**WOTS+ — Winternitz One-Time Signature Plus**
An improved one-time signature scheme used inside SLH-DSA and XMSS. Each WOTS+ key can sign exactly one message; the Merkle tree structure in SLH-DSA/XMSS manages the one-time keys so the outer scheme can sign many messages.

---

## X

**X25519**
The Diffie-Hellman key exchange function using Curve25519. The default key exchange algorithm in TLS 1.3.

**X3DH — Extended Triple Diffie-Hellman**
The initial key agreement protocol used in the Signal messaging app. Combines multiple Diffie-Hellman exchanges to provide both authentication and forward secrecy.

**X448**
The Diffie-Hellman key exchange function using Curve448, providing approximately 224-bit security.

**XChaCha20-Poly1305**
A variant of ChaCha20-Poly1305 with a 192-bit nonce (compared to 96-bit), making it safe to use with randomly generated nonces (random 96-bit nonces have a non-trivial collision probability after ~2³² messages).

**XMSS — eXtended Merkle Signature Scheme**
A stateful hash-based signature scheme (RFC 8391, NIST SP 800-208). Uses a hierarchy of Merkle trees to support a large number of signatures. More complex state management than LMS. Suitable for long-lived signing keys such as firmware signing.

**XMSS^MT — Multi-Tree XMSS**
A multi-layer variant of XMSS (RFC 8391, NIST SP 800-208) supporting very high signing capacity through a hyper-tree structure of d XMSS tree layers, each of height h′. Total tree height H = h′×d, yielding a maximum of 2^H signatures. Each signature requires computing d WOTS+ signatures (one per layer), so signing time scales with d. Signing must be performed in a FIPS 140-2/3 Level 3+ hardware cryptographic module. Example: XMSSMT-SHA2_20/2_256 has H=20, d=2 layers, using SHA-256 with n=32-byte outputs.

**XOF — Extendable-Output Function**
A hash-like function that can produce output of any requested length, rather than a fixed-length digest. Examples: SHAKE128, SHAKE256, BLAKE3. Used where variable-length output is needed (key derivation, mask generation).

**Xorshift / Xoshiro**
A family of non-cryptographic PRNGs using XOR and bit-shift operations. Very fast and statistically good, but completely insecure for cryptographic use — internal state can be recovered from a small number of outputs.

**XTR — Efficient Compact Subgroup Trace Representation**
A method for performing public-key cryptography in GF(p^6) while representing elements compactly via their trace over GF(p^2). Reduces key and computation sizes compared to standard DH. Historically significant but superseded by ECC.

**XTS — XEX Tweakable-Code-Book Mode with Ciphertext Stealing**
A block cipher mode designed for disk and storage encryption (IEEE 1619). Uses two independent keys. Not suitable for network protocols; intended only for encrypting fixed-size sectors.

---

## Y

**Yarrow**
A CSPRNG architecture (Kelsey-Schneier-Ferguson, 1999) using two entropy pools, a block cipher generator, and per-source entropy estimators. Superseded by Fortuna, which eliminates the difficult-to-implement entropy estimator requirement.

**yescrypt**
A memory-hard KDF extending scrypt with additional parameters (t for extra time mixing, g for upgrade factor). Used as the default password-hashing scheme in modern Linux `/etc/shadow` files.

---

## Z

**ZUC**
A stream cipher specified for 3GPP mobile networks (3GPP TS 35.221), used for confidentiality (128-EEA3) and integrity (128-EIA3) in 4G LTE and 5G NR. Designed by the Data Assurance and Communication Security Research Center (DACAS) of the Chinese Academy of Sciences. Uses a 128-bit key and 128-bit IV. ZUC is one of three cipher families available in 3GPP alongside SNOW 3G and AES-based algorithms.

**Zero-Knowledge Proof**
A cryptographic protocol where one party proves knowledge of a secret without revealing the secret itself. Several post-quantum signature schemes (FAEST, SDitH, CROSS, Mirath) use MPC-in-the-Head, which is a form of zero-knowledge proof system based on simulating a multi-party computation.

---

## Abbreviation Quick Reference

| Abbreviation | Full name |
|:---|:---|
| 2TDEA | Two-Key Triple DES |
| 3GPP | 3rd Generation Partnership Project |
| AEAD | Authenticated Encryption with Associated Data |
| AES | Advanced Encryption Standard |
| AIS | Anforderungen an Implementierungen mit Sicherheitszertifikat (BSI technical guideline) |
| AKA | Authentication and Key Agreement (3GPP) |
| ANSSI | Agence Nationale de la Sécurité des Systèmes d'Information |
| ASN.1 | Abstract Syntax Notation One |
| BSI | Bundesamt für Sicherheit in der Informationstechnik |
| BSI TR | BSI Technical Regulation |
| CAVP | Cryptographic Algorithm Validation Program |
| CBMC | C Bounded Model Checker |
| CBOM | Cryptography Bill of Materials |
| CBC | Cipher Block Chaining |
| CMC | Certificate Management over CMS |
| CMP | Certificate Management Protocol |
| CC | Common Criteria |
| CFRG | Crypto Forum Research Group |
| CMAC | Cipher-Based Message Authentication Code |
| CMVP | Cryptographic Module Validation Program |
| CMS | Cryptographic Message Syntax |
| CNSA | Commercial National Security Algorithm Suite |
| COSE | Concise Object Signing and Encryption |
| CSRC | Computer Security Resource Center (NIST) |
| cSHAKE | Customisable SHAKE |
| CSPRNG | Cryptographically Secure Pseudorandom Number Generator |
| CTR | Counter mode |
| DFR | Decryption Failure Rate |
| DLIES | Discrete Logarithm Integrated Encryption Scheme |
| DNSSEC | Domain Name System Security Extensions |
| DH | Diffie-Hellman |
| DHKEM | Diffie-Hellman Key Encapsulation Mechanism |
| DRBG | Deterministic Random Bit Generator |
| DSA | Digital Signature Algorithm |
| ECB | Electronic Codebook |
| ECC CDH | Elliptic Curve Cofactor Diffie-Hellman |
| ECDH | Elliptic Curve Diffie-Hellman |
| EUF-CMA | Existential Unforgeability under Chosen-Message Attack |
| ECDSA | Elliptic Curve Digital Signature Algorithm |
| ECIES | Elliptic Curve Integrated Encryption Scheme |
| EdDSA | Edwards-Curve Digital Signature Algorithm |
| EFS | Encrypting File System |
| ENISA | European Union Agency for Cybersecurity |
| EST | Enrollment over Secure Transport |
| ETSI | European Telecommunications Standards Institute |
| FFDH | Finite Field Diffie-Hellman |
| FIPS | Federal Information Processing Standards |
| FISMA | Federal Information Security Modernization Act |
| FN-DSA | FFT over NTRU-Lattice Digital Signature Algorithm (Falcon) |
| FORS | Forest of Random Subsets |
| GCM | Galois/Counter Mode |
| GHASH | Galois Hash (authentication in GCM) |
| GMAC | Galois Message Authentication Code |
| HRNG | Hardware Random Number Generator |
| HSM | Hardware Security Module |
| HKDF | HMAC-Based Key Derivation Function |
| HMAC | Keyed-Hash Message Authentication Code |
| HNDL | Harvest Now, Decrypt Later |
| HPKE | Hybrid Public Key Encryption |
| HQC | Hamming Quasi-Cyclic |
| IEEE | Institute of Electrical and Electronics Engineers |
| IETF | Internet Engineering Task Force |
| IKE | Internet Key Exchange |
| IND-CCA2 | Indistinguishability under Adaptive Chosen-Ciphertext Attack |
| IND-CPA | Indistinguishability under Chosen-Plaintext Attack |
| IPsec | Internet Protocol Security |
| ISD | Information Set Decoding |
| IV | Initialisation Vector |
| JCA | Java Cryptography Architecture |
| JCE | Java Cryptography Extension |
| JEP | JDK Enhancement Proposal |
| JOSE | JSON Object Signing and Encryption |
| KAT | Known Answer Test |
| KDF | Key Derivation Function |
| KEM | Key Encapsulation Mechanism |
| KMAC | Keccak Message Authentication Code |
| KSF | Key-Stretching Function |
| LAMPS | Limited Additional Mechanisms for PKIX and SMIME |
| LCG | Linear Congruential Generator |
| LIP | Lattice Isomorphism Problem |
| HSS | Hierarchical Signature Scheme |
| LMS | Leighton-Micali Signature |
| LMOTS | Leighton-Micali One-Time Signature |
| LWE | Learning With Errors |
| MAC | Message Authentication Code |
| MGF | Mask Generation Function |
| MLS | Messaging Layer Security |
| MitH | MPC-in-the-Head |
| ML-DSA | Module-Lattice Digital Signature Algorithm |
| ML-KEM | Module-Lattice Key-Encapsulation Mechanism |
| NIAP | National Information Assurance Partnership |
| NIST | National Institute of Standards and Technology |
| NIST IR | NIST Internal/Interagency Report |
| NSA | National Security Agency |
| NSM | National Security Memorandum |
| NSS | National Security Systems |
| NTT | Number Theoretic Transform |
| NTRU | Number Theoretic Research Unit (lattice type) |
| OAEP | Optimal Asymmetric Encryption Padding |
| OID | Object Identifier |
| OQS | Open Quantum Safe |
| OPAQUE | Oblivious PRF + Asymmetric Password-Authenticated KE |
| OPRF | Oblivious Pseudorandom Function |
| OTS | One-Time Signature |
| OTAR | Over-The-Air Rekeying |
| OWASP | Open Web Application Security Project |
| PAKE | Password-Authenticated Key Exchange |
| PBKDF | Password-Based Key Derivation Function |
| PBES | Password-Based Encryption Scheme |
| PCG | Permuted Congruential Generator |
| PFS | Perfect Forward Secrecy |
| PKI | Public Key Infrastructure |
| PKIX | Public Key Infrastructure using X.509 |
| PSK | Pre-Shared Key |
| PMU | Performance Monitoring Unit |
| PKCS | Public-Key Cryptography Standards |
| PQC | Post-Quantum Cryptography |
| PQCA | Post-Quantum Cryptography Alliance |
| PQCP | PQ Code Package |
| PRF | Pseudorandom Function |
| PRNG | Pseudorandom Number Generator |
| PSS | Probabilistic Signature Scheme |
| RBG | Random Bit Generator |
| QKD | Quantum Key Distribution |
| QROM | Quantum Random Oracle Model |
| RFC | Request for Comments |
| RSA | Rivest-Shamir-Adleman |
| S/MIME | Secure/Multipurpose Internet Mail Extensions |
| SBOM | Software Bill of Materials |
| SCA | Software Composition Analysis |
| SHA | Secure Hash Algorithm |
| SHAKE | Secure Hash Algorithm Keccak (extendable output) |
| SNOW 3G | Stream cipher for 3GPP (4G LTE) |
| SNOW-V | Stream cipher candidate for 5G |
| SIS | Short Integer Solution |
| SIV | Synthetic Initialisation Vector |
| SLH-DSA | Stateless Hash-Based Digital Signature Standard |
| SM2/SM3/SM4 | ShāngMì (Chinese cryptographic standards) |
| SM9 | ShāngMì 9 (Chinese pairing-based cryptographic standard) |
| SPDX | Software Package Data Exchange |
| SRTP | Secure Real-time Transport Protocol |
| SRP | Secure Remote Password |
| SSH | Secure Shell |
| SUF-CMA | Strong Unforgeability under Chosen-Message Attack |
| TLS | Transport Layer Security |
| TSIG | Transaction Signature (DNS) |
| TPM | Trusted Platform Module |
| TRNG | True Random Number Generator |
| UMAC | Universal Message Authentication Code |
| UOV | Unbalanced Oil and Vinegar |
| ZUC | Stream cipher for 3GPP (128-EEA3/128-EIA3) |
| VOLEitH | Vector Oblivious Linear Evaluation in the Head |
| WOTS+ | Winternitz One-Time Signature Plus |
| X3DH | Extended Triple Diffie-Hellman |
| XTR | Efficient Compact Subgroup Trace Representation |
| XOF | Extendable-Output Function |
| XTS | XEX Tweakable-Code-Book Mode with Ciphertext Stealing |
