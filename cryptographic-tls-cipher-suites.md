# TLS Cipher Suite and Group Analysis

> **Source of truth:** [`ae-pattern-validator/.../registry/cr-tls.yaml`](ae-pattern-validator/src/main/resources/registry/cr-tls.yaml) — every cipher suite, supported group, and signature scheme entry carries an `iana:` block (with `recommended:` flag), an optional `nist:` block (SP 800-52 Rev 2 status + section reference), and an optional `bsi:` block (TR-02102-2 v2026-01 status + `useUpTo:` year + table reference). Regenerate with `python3 scripts/generate_protocol_composites.py`. The Python file holds the BSI/NIST overlay tables — update them when the upstream documents are revised.
>
> §1–§11 below are the human-readable view of the IANA portion (cipher suites, supported groups, signature schemes). §12 and §13 are the human-readable view of the BSI and NIST overlays. §14 is the side-by-side authority comparison.
>
> **Authorities covered:**
>
> | Authority | Document | Status |
> |:---|:---|:---|
> | **IANA** | TLS cipher suite registry | Recommended/Not-Recommended interop flag (encoded as `iana.recommended` in cr-tls.yaml) |
> | **IETF** | RFC 8446 (TLS 1.3), RFC 5246 (TLS 1.2), RFC 8996 (TLS 1.0/1.1 deprecation) | Protocol-level MUST/SHOULD/MAY (referenced in §1–§11 notes) |
> | **NIST** | SP 800-52 Rev 2 (Aug 2019) | US federal — minimum cipher-suite set with FIPS 140 validation requirement (encoded as `nist.status` / `nist.source` in cr-tls.yaml) |
> | **BSI** | TR-02102-2 v2026-01 (Jan 2026) | German federal — `use up to` deadlines, 120-bit security level, 7-year prediction horizon (encoded as `bsi.status` / `bsi.useUpTo` / `bsi.source` in cr-tls.yaml) |
>
> For algorithm-level status, see [cryptographic-algorithm-status.md](cryptographic-algorithm-status.md).
> For protocol-level guidance, see [cryptographic-protocol-status.md](cryptographic-protocol-status.md).

## 1. TLS 1.3 Cipher Suites

| IANA Value | Cipher Suite | Components | Notes |
|---|---|---|---|
| `0x13,0x01` | TLS_AES_128_GCM_SHA256 | `AES-128-GCM` + `HKDF-SHA-256` | IANA recommended |
| `0x13,0x02` | TLS_AES_256_GCM_SHA384 | `AES-256-GCM` + `HKDF-SHA-384` | IANA recommended |
| `0x13,0x03` | TLS_CHACHA20_POLY1305_SHA256 | `ChaCha20-Poly1305` + `HKDF-SHA-256` | IANA recommended |
| `0x13,0x04` | TLS_AES_128_CCM_SHA256 | `AES-128-CCM` + `HKDF-SHA-256` | IANA recommended |
| `0x13,0x05` | TLS_AES_128_CCM_8_SHA256 | `AES-128-CCM` + `HKDF-SHA-256` | |

## 2. TLS 1.2 Cipher Suites (ECDHE Key Exchange)

| IANA Value | Cipher Suite | Key Exchange | Authentication | Cipher | Hash/PRF |
|---|---|---|---|---|---|
| `0xC0,0x06` | TLS_ECDHE_ECDSA_WITH_NULL_SHA | `ECDH` | `ECDSA` | `NULL` | `SHA-1` |
| `0xC0,0x08` | TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA | `ECDH` | `ECDSA` | `3DES-CBC` | `SHA-1` |
| `0xC0,0x09` | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA | `ECDH` | `ECDSA` | `AES-128-CBC` | `SHA-1` |
| `0xC0,0x0A` | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA | `ECDH` | `ECDSA` | `AES-256-CBC` | `SHA-1` |
| `0xC0,0x10` | TLS_ECDHE_RSA_WITH_NULL_SHA | `ECDH` | `RSASSA-PSS` | `NULL` | `SHA-1` |
| `0xC0,0x12` | TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA | `ECDH` | `RSASSA-PSS` | `3DES-CBC` | `SHA-1` |
| `0xC0,0x13` | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA | `ECDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-1` |
| `0xC0,0x14` | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA | `ECDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-1` |
| `0xC0,0x23` | TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 | `ECDH` | `ECDSA` | `AES-128-CBC` | `SHA-256` |
| `0xC0,0x24` | TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 | `ECDH` | `ECDSA` | `AES-256-CBC` | `SHA-384` |
| `0xC0,0x27` | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 | `ECDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-256` |
| `0xC0,0x28` | TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 | `ECDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-384` |
| `0xC0,0x2B` | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | `ECDH` | `ECDSA` | `AES-128-GCM` | `SHA-256` |
| `0xC0,0x2C` | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | `ECDH` | `ECDSA` | `AES-256-GCM` | `SHA-384` |
| `0xC0,0x2F` | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | `ECDH` | `RSASSA-PSS` | `AES-128-GCM` | `SHA-256` |
| `0xC0,0x30` | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | `ECDH` | `RSASSA-PSS` | `AES-256-GCM` | `SHA-384` |
| `0xCC,0xA8` | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | `ECDH` | `RSASSA-PSS` | `ChaCha20-Poly1305` | `SHA-256` |
| `0xCC,0xA9` | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 | `ECDH` | `ECDSA` | `ChaCha20-Poly1305` | `SHA-256` |

### Static ECDH (non-ephemeral)

| IANA Value | Cipher Suite | Key Exchange | Authentication | Cipher | Hash/PRF |
|---|---|---|---|---|---|
| `0xC0,0x01` | TLS_ECDH_ECDSA_WITH_NULL_SHA | `ECDH` | `ECDSA` | `NULL` | `SHA-1` |
| `0xC0,0x03` | TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA | `ECDH` | `ECDSA` | `3DES-CBC` | `SHA-1` |
| `0xC0,0x04` | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA | `ECDH` | `ECDSA` | `AES-128-CBC` | `SHA-1` |
| `0xC0,0x05` | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA | `ECDH` | `ECDSA` | `AES-256-CBC` | `SHA-1` |
| `0xC0,0x0B` | TLS_ECDH_RSA_WITH_NULL_SHA | `ECDH` | `RSASSA-PSS` | `NULL` | `SHA-1` |
| `0xC0,0x0D` | TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA | `ECDH` | `RSASSA-PSS` | `3DES-CBC` | `SHA-1` |
| `0xC0,0x0E` | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA | `ECDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-1` |
| `0xC0,0x0F` | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA | `ECDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-1` |
| `0xC0,0x15` | TLS_ECDH_anon_WITH_NULL_SHA | `ECDH` | `NULL` | `NULL` | `SHA-1` |
| `0xC0,0x17` | TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA | `ECDH` | `NULL` | `3DES-CBC` | `SHA-1` |
| `0xC0,0x18` | TLS_ECDH_anon_WITH_AES_128_CBC_SHA | `ECDH` | `NULL` | `AES-128-CBC` | `SHA-1` |
| `0xC0,0x19` | TLS_ECDH_anon_WITH_AES_256_CBC_SHA | `ECDH` | `NULL` | `AES-256-CBC` | `SHA-1` |
| `0xC0,0x25` | TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 | `ECDH` | `ECDSA` | `AES-128-CBC` | `SHA-256` |
| `0xC0,0x26` | TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 | `ECDH` | `ECDSA` | `AES-256-CBC` | `SHA-384` |
| `0xC0,0x29` | TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 | `ECDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-256` |
| `0xC0,0x2A` | TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 | `ECDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-384` |
| `0xC0,0x2D` | TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 | `ECDH` | `ECDSA` | `AES-128-GCM` | `SHA-256` |
| `0xC0,0x2E` | TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 | `ECDH` | `ECDSA` | `AES-256-GCM` | `SHA-384` |
| `0xC0,0x31` | TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 | `ECDH` | `RSASSA-PSS` | `AES-128-GCM` | `SHA-256` |
| `0xC0,0x32` | TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 | `ECDH` | `RSASSA-PSS` | `AES-256-GCM` | `SHA-384` |

## 3. TLS 1.2 Cipher Suites (DHE Key Exchange)

| IANA Value | Cipher Suite | Key Exchange | Authentication | Cipher | Hash/PRF |
|---|---|---|---|---|---|
| `0x00,0x0D` | TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA | `FFDH` | `DSA` | `3DES-CBC` | `SHA-1` |
| `0x00,0x10` | TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA | `FFDH` | `RSASSA-PSS` | `3DES-CBC` | `SHA-1` |
| `0x00,0x13` | TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA | `FFDH` | `DSA` | `3DES-CBC` | `SHA-1` |
| `0x00,0x16` | TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA | `FFDH` | `RSASSA-PSS` | `3DES-CBC` | `SHA-1` |
| `0x00,0x1B` | TLS_DH_anon_WITH_3DES_EDE_CBC_SHA | `FFDH` | `NULL` | `3DES-CBC` | `SHA-1` |
| `0x00,0x30` | TLS_DH_DSS_WITH_AES_128_CBC_SHA | `FFDH` | `DSA` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x31` | TLS_DH_RSA_WITH_AES_128_CBC_SHA | `FFDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x32` | TLS_DHE_DSS_WITH_AES_128_CBC_SHA | `FFDH` | `DSA` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x33` | TLS_DHE_RSA_WITH_AES_128_CBC_SHA | `FFDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x34` | TLS_DH_anon_WITH_AES_128_CBC_SHA | `FFDH` | `NULL` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x36` | TLS_DH_DSS_WITH_AES_256_CBC_SHA | `FFDH` | `DSA` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x37` | TLS_DH_RSA_WITH_AES_256_CBC_SHA | `FFDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x38` | TLS_DHE_DSS_WITH_AES_256_CBC_SHA | `FFDH` | `DSA` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x39` | TLS_DHE_RSA_WITH_AES_256_CBC_SHA | `FFDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x3A` | TLS_DH_anon_WITH_AES_256_CBC_SHA | `FFDH` | `NULL` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x3E` | TLS_DH_DSS_WITH_AES_128_CBC_SHA256 | `FFDH` | `DSA` | `AES-128-CBC` | `SHA-256` |
| `0x00,0x3F` | TLS_DH_RSA_WITH_AES_128_CBC_SHA256 | `FFDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-256` |
| `0x00,0x40` | TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 | `FFDH` | `DSA` | `AES-128-CBC` | `SHA-256` |
| `0x00,0x67` | TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 | `FFDH` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-256` |
| `0x00,0x68` | TLS_DH_DSS_WITH_AES_256_CBC_SHA256 | `FFDH` | `DSA` | `AES-256-CBC` | `SHA-256` |
| `0x00,0x69` | TLS_DH_RSA_WITH_AES_256_CBC_SHA256 | `FFDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-256` |
| `0x00,0x6A` | TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 | `FFDH` | `DSA` | `AES-256-CBC` | `SHA-256` |
| `0x00,0x6B` | TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 | `FFDH` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-256` |
| `0x00,0x6C` | TLS_DH_anon_WITH_AES_128_CBC_SHA256 | `FFDH` | `NULL` | `AES-128-CBC` | `SHA-256` |
| `0x00,0x6D` | TLS_DH_anon_WITH_AES_256_CBC_SHA256 | `FFDH` | `NULL` | `AES-256-CBC` | `SHA-256` |
| `0x00,0x9E` | TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 | `FFDH` | `RSASSA-PSS` | `AES-128-GCM` | `SHA-256` |
| `0x00,0x9F` | TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 | `FFDH` | `RSASSA-PSS` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xA0` | TLS_DH_RSA_WITH_AES_128_GCM_SHA256 | `FFDH` | `RSASSA-PSS` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xA1` | TLS_DH_RSA_WITH_AES_256_GCM_SHA384 | `FFDH` | `RSASSA-PSS` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xA2` | TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 | `FFDH` | `DSA` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xA3` | TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 | `FFDH` | `DSA` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xA4` | TLS_DH_DSS_WITH_AES_128_GCM_SHA256 | `FFDH` | `DSA` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xA5` | TLS_DH_DSS_WITH_AES_256_GCM_SHA384 | `FFDH` | `DSA` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xA6` | TLS_DH_anon_WITH_AES_128_GCM_SHA256 | `FFDH` | `NULL` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xA7` | TLS_DH_anon_WITH_AES_256_GCM_SHA384 | `FFDH` | `NULL` | `AES-256-GCM` | `SHA-384` |
| `0xCC,0xAA` | TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 | `FFDH` | `RSASSA-PSS` | `ChaCha20-Poly1305` | `SHA-256` |

## 4. TLS 1.2 Cipher Suites (RSA Key Exchange)

| IANA Value | Cipher Suite | Key Exchange | Authentication | Cipher | Hash/PRF |
|---|---|---|---|---|---|
| `0x00,0x01` | TLS_RSA_WITH_NULL_MD5 | `RSAES-PKCS1` | `RSASSA-PSS` | `NULL` | `MD5` |
| `0x00,0x02` | TLS_RSA_WITH_NULL_SHA | `RSAES-PKCS1` | `RSASSA-PSS` | `NULL` | `SHA-1` |
| `0x00,0x0A` | TLS_RSA_WITH_3DES_EDE_CBC_SHA | `RSAES-PKCS1` | `RSASSA-PSS` | `3DES-CBC` | `SHA-1` |
| `0x00,0x2F` | TLS_RSA_WITH_AES_128_CBC_SHA | `RSAES-PKCS1` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x35` | TLS_RSA_WITH_AES_256_CBC_SHA | `RSAES-PKCS1` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x3B` | TLS_RSA_WITH_NULL_SHA256 | `RSAES-PKCS1` | `RSASSA-PSS` | `NULL` | `SHA-256` |
| `0x00,0x3C` | TLS_RSA_WITH_AES_128_CBC_SHA256 | `RSAES-PKCS1` | `RSASSA-PSS` | `AES-128-CBC` | `SHA-256` |
| `0x00,0x3D` | TLS_RSA_WITH_AES_256_CBC_SHA256 | `RSAES-PKCS1` | `RSASSA-PSS` | `AES-256-CBC` | `SHA-256` |
| `0x00,0x9C` | TLS_RSA_WITH_AES_128_GCM_SHA256 | `RSAES-PKCS1` | `RSASSA-PSS` | `AES-128-GCM` | `SHA-256` |
| `0x00,0x9D` | TLS_RSA_WITH_AES_256_GCM_SHA384 | `RSAES-PKCS1` | `RSASSA-PSS` | `AES-256-GCM` | `SHA-384` |

## 5. TLS 1.2 Cipher Suites (PSK)

| IANA Value | Cipher Suite | Key Exchange | Authentication | Cipher | Hash/PRF |
|---|---|---|---|---|---|
| `0x00,0x2C` | TLS_PSK_WITH_NULL_SHA | `PSK` | `PSK` | `NULL` | `SHA-1` |
| `0x00,0x2D` | TLS_DHE_PSK_WITH_NULL_SHA | `FFDH` | `PSK` | `NULL` | `SHA-1` |
| `0x00,0x2E` | TLS_RSA_PSK_WITH_NULL_SHA | `RSAES-PKCS1` | `PSK` | `NULL` | `SHA-1` |
| `0x00,0x8B` | TLS_PSK_WITH_3DES_EDE_CBC_SHA | `PSK` | `PSK` | `3DES-CBC` | `SHA-1` |
| `0x00,0x8C` | TLS_PSK_WITH_AES_128_CBC_SHA | `PSK` | `PSK` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x8D` | TLS_PSK_WITH_AES_256_CBC_SHA | `PSK` | `PSK` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x8F` | TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA | `FFDH` | `PSK` | `3DES-CBC` | `SHA-1` |
| `0x00,0x90` | TLS_DHE_PSK_WITH_AES_128_CBC_SHA | `FFDH` | `PSK` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x91` | TLS_DHE_PSK_WITH_AES_256_CBC_SHA | `FFDH` | `PSK` | `AES-256-CBC` | `SHA-1` |
| `0x00,0x93` | TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA | `RSAES-PKCS1` | `PSK` | `3DES-CBC` | `SHA-1` |
| `0x00,0x94` | TLS_RSA_PSK_WITH_AES_128_CBC_SHA | `RSAES-PKCS1` | `PSK` | `AES-128-CBC` | `SHA-1` |
| `0x00,0x95` | TLS_RSA_PSK_WITH_AES_256_CBC_SHA | `RSAES-PKCS1` | `PSK` | `AES-256-CBC` | `SHA-1` |
| `0x00,0xA8` | TLS_PSK_WITH_AES_128_GCM_SHA256 | `PSK` | `PSK` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xA9` | TLS_PSK_WITH_AES_256_GCM_SHA384 | `PSK` | `PSK` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xAA` | TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 | `FFDH` | `PSK` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xAB` | TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 | `FFDH` | `PSK` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xAC` | TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 | `RSAES-PKCS1` | `PSK` | `AES-128-GCM` | `SHA-256` |
| `0x00,0xAD` | TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 | `RSAES-PKCS1` | `PSK` | `AES-256-GCM` | `SHA-384` |
| `0x00,0xAE` | TLS_PSK_WITH_AES_128_CBC_SHA256 | `PSK` | `PSK` | `AES-128-CBC` | `SHA-256` |
| `0x00,0xAF` | TLS_PSK_WITH_AES_256_CBC_SHA384 | `PSK` | `PSK` | `AES-256-CBC` | `SHA-384` |
| `0x00,0xB0` | TLS_PSK_WITH_NULL_SHA256 | `PSK` | `PSK` | `NULL` | `SHA-256` |
| `0x00,0xB1` | TLS_PSK_WITH_NULL_SHA384 | `PSK` | `PSK` | `NULL` | `SHA-384` |
| `0x00,0xB2` | TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 | `FFDH` | `PSK` | `AES-128-CBC` | `SHA-256` |
| `0x00,0xB3` | TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 | `FFDH` | `PSK` | `AES-256-CBC` | `SHA-384` |
| `0x00,0xB4` | TLS_DHE_PSK_WITH_NULL_SHA256 | `FFDH` | `PSK` | `NULL` | `SHA-256` |
| `0x00,0xB5` | TLS_DHE_PSK_WITH_NULL_SHA384 | `FFDH` | `PSK` | `NULL` | `SHA-384` |
| `0x00,0xB6` | TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 | `RSAES-PKCS1` | `PSK` | `AES-128-CBC` | `SHA-256` |
| `0x00,0xB7` | TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 | `RSAES-PKCS1` | `PSK` | `AES-256-CBC` | `SHA-384` |
| `0x00,0xB8` | TLS_RSA_PSK_WITH_NULL_SHA256 | `RSAES-PKCS1` | `PSK` | `NULL` | `SHA-256` |
| `0x00,0xB9` | TLS_RSA_PSK_WITH_NULL_SHA384 | `RSAES-PKCS1` | `PSK` | `NULL` | `SHA-384` |
| `0xC0,0x34` | TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA | `ECDH` | `PSK` | `3DES-CBC` | `SHA-1` |
| `0xC0,0x35` | TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA | `ECDH` | `PSK` | `AES-128-CBC` | `SHA-1` |
| `0xC0,0x36` | TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA | `ECDH` | `PSK` | `AES-256-CBC` | `SHA-1` |
| `0xC0,0x37` | TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 | `ECDH` | `PSK` | `AES-128-CBC` | `SHA-256` |
| `0xC0,0x38` | TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 | `ECDH` | `PSK` | `AES-256-CBC` | `SHA-384` |
| `0xC0,0x39` | TLS_ECDHE_PSK_WITH_NULL_SHA | `ECDH` | `PSK` | `NULL` | `SHA-1` |
| `0xC0,0x3A` | TLS_ECDHE_PSK_WITH_NULL_SHA256 | `ECDH` | `PSK` | `NULL` | `SHA-256` |
| `0xC0,0x3B` | TLS_ECDHE_PSK_WITH_NULL_SHA384 | `ECDH` | `PSK` | `NULL` | `SHA-384` |
| `0xCC,0xAB` | TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 | `PSK` | `PSK` | `ChaCha20-Poly1305` | `SHA-256` |
| `0xCC,0xAC` | TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 | `ECDH` | `PSK` | `ChaCha20-Poly1305` | `SHA-256` |
| `0xCC,0xAD` | TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 | `FFDH` | `PSK` | `ChaCha20-Poly1305` | `SHA-256` |
| `0xCC,0xAE` | TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 | `RSAES-PKCS1` | `PSK` | `ChaCha20-Poly1305` | `SHA-256` |
| `0xD0,0x01` | TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 | `ECDH` | `PSK` | `AES-128-GCM` | `SHA-256` |
| `0xD0,0x02` | TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 | `ECDH` | `PSK` | `AES-256-GCM` | `SHA-384` |
| `0xD0,0x03` | TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 | `ECDH` | `PSK` | `AES-128-CCM` | `SHA-256` |
| `0xD0,0x05` | TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 | `ECDH` | `PSK` | `AES-128-CCM` | `SHA-256` |

## 6. Supported Groups

| IANA Value | Group | Components | Notes |
|---|---|---|---|
| `23` | tls-group:secp256r1 | `ECDH-P-256` | IANA recommended |
| `24` | tls-group:secp384r1 | `ECDH-P-384` | IANA recommended |
| `25` | tls-group:secp521r1 | `ECDH-P-521` | |
| `29` | tls-group:x25519 | `ECDH-Curve25519` | IANA recommended |
| `30` | tls-group:x448 | `ECDH-Curve448` | IANA recommended |
| `256` | tls-group:ffdhe2048 | `FFDH-ffdhe2048` | |
| `257` | tls-group:ffdhe3072 | `FFDH-ffdhe3072` | |
| `258` | tls-group:ffdhe4096 | `FFDH-ffdhe4096` | |
| `259` | tls-group:ffdhe6144 | `FFDH-ffdhe6144` | |
| `260` | tls-group:ffdhe8192 | `FFDH-ffdhe8192` | |
| `512` | tls-group:MLKEM512 | `ML-KEM-512` | |
| `513` | tls-group:MLKEM768 | `ML-KEM-768` | |
| `514` | tls-group:MLKEM1024 | `ML-KEM-1024` | |
| `4587` | tls-group:SecP256r1MLKEM768 | `ECDH-P-256` + `ML-KEM-768` | |
| `4588` | tls-group:X25519MLKEM768 | `ECDH-Curve25519` + `ML-KEM-768` | |
| `4589` | tls-group:SecP384r1MLKEM1024 | `ECDH-P-384` + `ML-KEM-1024` | |

## 7. Signature Schemes

| IANA Value | Scheme | Components | Notes |
|---|---|---|---|
| `0x0201` | tls-sig:rsa_pkcs1_sha1 | `RSASSA-PKCS1-v1_5-SHA-1` | |
| `0x0203` | tls-sig:ecdsa_sha1 | `ECDSA-SHA-1` | |
| `0x0401` | tls-sig:rsa_pkcs1_sha256 | `RSASSA-PKCS1-v1_5-SHA-256` | IANA recommended |
| `0x0403` | tls-sig:ecdsa_secp256r1_sha256 | `ECDSA-P-256-SHA-256` | IANA recommended |
| `0x0501` | tls-sig:rsa_pkcs1_sha384 | `RSASSA-PKCS1-v1_5-SHA-384` | IANA recommended |
| `0x0503` | tls-sig:ecdsa_secp384r1_sha384 | `ECDSA-P-384-SHA-384` | IANA recommended |
| `0x0601` | tls-sig:rsa_pkcs1_sha512 | `RSASSA-PKCS1-v1_5-SHA-512` | IANA recommended |
| `0x0603` | tls-sig:ecdsa_secp521r1_sha512 | `ECDSA-P-521-SHA-512` | IANA recommended |
| `0x0804` | tls-sig:rsa_pss_rsae_sha256 | `RSASSA-PSS-SHA-256` | IANA recommended |
| `0x0805` | tls-sig:rsa_pss_rsae_sha384 | `RSASSA-PSS-SHA-384` | IANA recommended |
| `0x0806` | tls-sig:rsa_pss_rsae_sha512 | `RSASSA-PSS-SHA-512` | IANA recommended |
| `0x0807` | tls-sig:ed25519 | `EdDSA-Ed25519` | IANA recommended |
| `0x0808` | tls-sig:ed448 | `EdDSA-Ed448` | IANA recommended |
| `0x0809` | tls-sig:rsa_pss_pss_sha256 | `RSASSA-PSS-SHA-256` | IANA recommended |
| `0x080A` | tls-sig:rsa_pss_pss_sha384 | `RSASSA-PSS-SHA-384` | IANA recommended |
| `0x080B` | tls-sig:rsa_pss_pss_sha512 | `RSASSA-PSS-SHA-512` | IANA recommended |
| `0x0904` | tls-sig:mldsa44 | `ML-DSA-44` | |
| `0x0905` | tls-sig:mldsa65 | `ML-DSA-65` | |
| `0x0906` | tls-sig:mldsa87 | `ML-DSA-87` | |

## 8. Summary

### Entries by Sub-Type

| Sub-type | Count |
|---|---|
| cipherSuite | 135 |
| supportedGroup | 16 |
| signatureScheme | 19 |
| **Total (TLS)** | **170** |

### Cipher Suites by Protocol Version

| Protocol Version | Count |
|---|---|
| TLS 1.3 | 5 |
| TLS 1.2 | 130 |

### TLS 1.2 Cipher Suites by Key Exchange Category

| Category | Count |
|---|---|
| ECDHE (ephemeral) | 18 |
| Static ECDH (non-ephemeral) | 20 |
| DHE / Static DH (FFDH) | 36 |
| RSA Key Transport | 10 |
| PSK (all variants) | 46 |

Note: PSK cipher suites using ECDHE or DHE key exchange are counted in the PSK
category since PSK authentication is their distinguishing characteristic.

### Cross-Protocol Entry Counts

| Protocol | Sub-type | Count |
|---|---|---|
| TLS | cipherSuite | 135 |
| TLS | supportedGroup | 16 |
| TLS | signatureScheme | 19 |
| SSH | sshKex | 7 |
| SSH | sshHostAuth | 6 |
| SSH | sshCipher | 8 |
| SSH | sshMac | 4 |
| IPsec | ipsecDhGroup | 10 |
| IPsec | espTransform | 7 |
| IPsec | ipsecIntegrity | 5 |
| X.509 | compositeSignature | 13 |
| **Total** | | **230** |

## 9. SSH Algorithms

### SSH Key Exchange (sshKex)

| Algorithm | Components |
|---|---|
| curve25519-sha256 | `ECDH-Curve25519` + `SHA-256` |
| ecdh-sha2-nistp256 | `ECDH-P-256` + `SHA-256` |
| ecdh-sha2-nistp384 | `ECDH-P-384` + `SHA-384` |
| ecdh-sha2-nistp521 | `ECDH-P-521` + `SHA-512` |
| diffie-hellman-group14-sha256 | `FFDH-ffdhe2048` + `SHA-256` |
| diffie-hellman-group16-sha512 | `FFDH-ffdhe4096` + `SHA-512` |
| diffie-hellman-group18-sha512 | `FFDH-ffdhe8192` + `SHA-512` |

### SSH Host Key Authentication (sshHostAuth)

| Algorithm | Components |
|---|---|
| ssh-ed25519 | `EdDSA-Ed25519` |
| ecdsa-sha2-nistp256 | `ECDSA-P-256-SHA-256` |
| ecdsa-sha2-nistp384 | `ECDSA-P-384-SHA-384` |
| ecdsa-sha2-nistp521 | `ECDSA-P-521-SHA-512` |
| rsa-sha2-256 | `RSASSA-PSS-SHA-256` |
| rsa-sha2-512 | `RSASSA-PSS-SHA-512` |

### SSH Ciphers (sshCipher)

| Algorithm | Components |
|---|---|
| chacha20-poly1305@openssh.com | `ChaCha20-Poly1305` |
| aes256-gcm@openssh.com | `AES-256-GCM` |
| aes128-gcm@openssh.com | `AES-128-GCM` |
| aes256-ctr | `AES-256-CTR` |
| aes192-ctr | `AES-192-CTR` |
| aes128-ctr | `AES-128-CTR` |
| aes256-cbc | `AES-256-CBC` |
| 3des-cbc | `3DES-CBC` |

### SSH MACs (sshMac)

| Algorithm | Components |
|---|---|
| hmac-sha2-256-etm@openssh.com | `HMAC-SHA-256` |
| hmac-sha2-512-etm@openssh.com | `HMAC-SHA-512` |
| hmac-sha2-256 | `HMAC-SHA-256` |
| hmac-sha2-512 | `HMAC-SHA-512` |

## 10. IPsec Algorithms

### IKEv2 Key Exchange / DH Groups (ipsecDhGroup)

| Algorithm | Components |
|---|---|
| ipsec-dh:group14 | `FFDH-ffdhe2048` |
| ipsec-dh:group15 | `FFDH-ffdhe3072` |
| ipsec-dh:group16 | `FFDH-ffdhe4096` |
| ipsec-dh:group17 | `FFDH-ffdhe6144` |
| ipsec-dh:group18 | `FFDH-ffdhe8192` |
| ipsec-dh:group19 | `ECDH-P-256` |
| ipsec-dh:group20 | `ECDH-P-384` |
| ipsec-dh:group21 | `ECDH-P-521` |
| ipsec-dh:group31 | `ECDH-Curve25519` |
| ipsec-dh:group32 | `ECDH-Curve448` |

### ESP Encryption Transforms (espTransform)

| Algorithm | Components |
|---|---|
| ipsec-esp:aes-128-gcm | `AES-128-GCM` |
| ipsec-esp:aes-256-gcm | `AES-256-GCM` |
| ipsec-esp:aes-128-ccm | `AES-128-CCM` |
| ipsec-esp:chacha20-poly1305 | `ChaCha20-Poly1305` |
| ipsec-esp:aes-128-cbc | `AES-128-CBC` |
| ipsec-esp:aes-256-cbc | `AES-256-CBC` |
| ipsec-esp:3des-cbc | `3DES-CBC` |

### IKEv2 Integrity / PRF (ipsecIntegrity)

| Algorithm | Components |
|---|---|
| ipsec-auth:hmac-sha2-256-128 | `HMAC-SHA-256` |
| ipsec-auth:hmac-sha2-384-192 | `HMAC-SHA-384` |
| ipsec-auth:hmac-sha2-512-256 | `HMAC-SHA-512` |
| ipsec-auth:aes-xcbc-96 | `AES-CMAC` |
| ipsec-auth:hmac-sha1-96 | `HMAC-SHA-1` |

## 11. X.509 composite Signatures

| OID | Name | Components |
|---|---|---|
| 2.16.840.1.114027.80.8.1.1 | MLDSA44-RSA2048-PSS-SHA256 | `ML-DSA-44` + `RSASSA-PSS-2048-SHA-256` |
| 2.16.840.1.114027.80.8.1.2 | MLDSA44-RSA2048-PKCS15-SHA256 | `ML-DSA-44` + `RSASSA-PKCS1-2048-SHA-256` |
| 2.16.840.1.114027.80.8.1.3 | MLDSA44-Ed25519 | `ML-DSA-44` + `EdDSA-Ed25519` |
| 2.16.840.1.114027.80.8.1.4 | MLDSA44-ECDSA-P256-SHA256 | `ML-DSA-44` + `ECDSA-P-256-SHA-256` |
| 2.16.840.1.114027.80.8.1.5 | MLDSA65-RSA3072-PSS-SHA512 | `ML-DSA-65` + `RSASSA-PSS-3072-SHA-512` |
| 2.16.840.1.114027.80.8.1.6 | MLDSA65-RSA3072-PKCS15-SHA512 | `ML-DSA-65` + `RSASSA-PKCS1-3072-SHA-512` |
| 2.16.840.1.114027.80.8.1.34 | MLDSA65-RSA4096-PSS-SHA512 | `ML-DSA-65` + `RSASSA-PSS-4096-SHA-512` |
| 2.16.840.1.114027.80.8.1.7 | MLDSA65-ECDSA-P384-SHA512 | `ML-DSA-65` + `ECDSA-P-384-SHA-512` |
| 2.16.840.1.114027.80.8.1.8 | MLDSA65-ECDSA-brainpoolP256r1-SHA512 | `ML-DSA-65` + `ECDSA-brainpoolP256r1-SHA-512` |
| 2.16.840.1.114027.80.8.1.9 | MLDSA65-Ed25519 | `ML-DSA-65` + `EdDSA-Ed25519` |
| 2.16.840.1.114027.80.8.1.10 | MLDSA87-ECDSA-P384-SHA512 | `ML-DSA-87` + `ECDSA-P-384-SHA-512` |
| 2.16.840.1.114027.80.8.1.11 | MLDSA87-ECDSA-brainpoolP384r1-SHA512 | `ML-DSA-87` + `ECDSA-brainpoolP384r1-SHA-512` |
| 2.16.840.1.114027.80.8.1.12 | MLDSA87-Ed448 | `ML-DSA-87` + `EdDSA-Ed448` |

---

## 12. BSI TR-02102-2 v2026-01 (TLS) Recommendations

> **Source:** Federal Office for Information Security (BSI), TR-02102-2
> v2026-01 "Use of Transport Layer Security (TLS)", January 27, 2026.
> Security level: 120 bits. Prediction period: 7 years (recommendations valid up to 2032+).
>
> **`Use up to` semantics:** the year denotes the end of the recommended period; a "+" suffix means the period may be extended beyond that year if a future revision so directs. **2026 is the final recommended year** for entries that already had limited applicability in v2025-01.

### 12.1 Recommended TLS Versions (TR-02102-2 §3.2 Table 2)

| TLS version | Specification | Use up to |
|:---|:---|:---|
| TLS 1.3 | RFC 8446 | 2032+ |
| TLS 1.2 | RFC 5246 | **2031** (no quantum-safe key agreement standardisable for TLS 1.2) |
| TLS 1.1, TLS 1.0, SSLv2, SSLv3 | — | **Not recommended** (RFC 8996, RFC 6176, RFC 7568) |

### 12.2 TLS 1.2 (EC)DHE Cipher Suites (TR-02102-2 §3.3.1.1 Table 3)

Cipher suites with Perfect Forward Secrecy. CBC suites are recommended **only in conjunction with the Encrypt-then-MAC extension** (RFC 7366).

<!-- AUTOGEN:BEGIN tls-bsi-12-2 -->
| Cipher suite | IANA | Spec | Use up to |
|:---|:---|:---|:---|
| `TLS_DHE_DSS_WITH_AES_128_CBC_SHA256` | `0x00,0x40` | RFC 5246 | 2029 |
| `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256` | `0x00,0x67` | RFC 5246 | 2029 |
| `TLS_DHE_DSS_WITH_AES_256_CBC_SHA256` | `0x00,0x6A` | RFC 5246 | 2029 |
| `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256` | `0x00,0x6B` | RFC 5246 | 2029 |
| `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` | `0x00,0x9E` | RFC 5288 | 2029 |
| `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` | `0x00,0x9F` | RFC 5288 | 2029 |
| `TLS_DHE_DSS_WITH_AES_128_GCM_SHA256` | `0x00,0xA2` | RFC 5288 | 2029 |
| `TLS_DHE_DSS_WITH_AES_256_GCM_SHA384` | `0x00,0xA3` | RFC 5288 | 2029 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x23` | RFC 5289 | 2031 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x24` | RFC 5289 | 2031 |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x27` | RFC 5289 | 2031 |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x28` | RFC 5289 | 2031 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x2B` | RFC 5289 | 2031 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x2C` | RFC 5289 | 2031 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x2F` | RFC 5289 | 2031 |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x30` | RFC 5289 | 2031 |
| `TLS_DHE_RSA_WITH_AES_128_CCM` | `0xC0,0x9E` | RFC 6655 | 2029 |
| `TLS_DHE_RSA_WITH_AES_256_CCM` | `0xC0,0x9F` | RFC 6655 | 2029 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_CCM` | `0xC0,0xAC` | RFC 7251 | 2031 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CCM` | `0xC0,0xAD` | RFC 7251 | 2031 |
<!-- AUTOGEN:END tls-bsi-12-2 -->

> **Note:** TLS_DHE_* cipher suites are scheduled for IETF deprecation
> (draft-ietf-tls-deprecate-obsolete-kex). BSI mirrors that schedule with the 2029 cut-off.

### 12.3 TLS 1.2 (EC)DH Cipher Suites without PFS (TR-02102-2 §3.3.1.2 Table 4)

Fallback when PFS suites are unavailable. **All entries: use up to 2026** — last year of recommendation.

<!-- AUTOGEN:BEGIN tls-bsi-12-3 -->
| Cipher suite | IANA | Spec | Use up to |
|:---|:---|:---|:---|
| `TLS_DH_DSS_WITH_AES_128_CBC_SHA256` | `0x00,0x3E` | RFC 5246 | **2026** |
| `TLS_DH_RSA_WITH_AES_128_CBC_SHA256` | `0x00,0x3F` | RFC 5246 | **2026** |
| `TLS_DH_DSS_WITH_AES_256_CBC_SHA256` | `0x00,0x68` | RFC 5246 | **2026** |
| `TLS_DH_RSA_WITH_AES_256_CBC_SHA256` | `0x00,0x69` | RFC 5246 | **2026** |
| `TLS_DH_RSA_WITH_AES_128_GCM_SHA256` | `0x00,0xA0` | RFC 5288 | **2026** |
| `TLS_DH_RSA_WITH_AES_256_GCM_SHA384` | `0x00,0xA1` | RFC 5288 | **2026** |
| `TLS_DH_DSS_WITH_AES_128_GCM_SHA256` | `0x00,0xA4` | RFC 5288 | **2026** |
| `TLS_DH_DSS_WITH_AES_256_GCM_SHA384` | `0x00,0xA5` | RFC 5288 | **2026** |
| `TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x25` | RFC 5289 | **2026** |
| `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x26` | RFC 5289 | **2026** |
| `TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x29` | RFC 5289 | **2026** |
| `TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x2A` | RFC 5289 | **2026** |
| `TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x2D` | RFC 5289 | **2026** |
| `TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x2E` | RFC 5289 | **2026** |
| `TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x31` | RFC 5289 | **2026** |
| `TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x32` | RFC 5289 | **2026** |
<!-- AUTOGEN:END tls-bsi-12-3 -->

### 12.4 TLS 1.2 PSK Cipher Suites (TR-02102-2 §3.3.1.3 Table 5)

<!-- AUTOGEN:BEGIN tls-bsi-12-4 -->
| Cipher suite | IANA | Spec | Use up to | PFS |
|:---|:---|:---|:---|:---:|
| `TLS_DHE_PSK_WITH_AES_128_GCM_SHA256` | `0x00,0xAA` | RFC 5487 | 2029 | ✓ |
| `TLS_DHE_PSK_WITH_AES_256_GCM_SHA384` | `0x00,0xAB` | RFC 5487 | 2029 | ✓ |
| `TLS_RSA_PSK_WITH_AES_128_GCM_SHA256` | `0x00,0xAC` | RFC 5487 | **2026** | ✗ |
| `TLS_RSA_PSK_WITH_AES_256_GCM_SHA384` | `0x00,0xAD` | RFC 5487 | **2026** | ✗ |
| `TLS_DHE_PSK_WITH_AES_128_CBC_SHA256` | `0x00,0xB2` | RFC 5487 | 2029 | ✓ |
| `TLS_DHE_PSK_WITH_AES_256_CBC_SHA384` | `0x00,0xB3` | RFC 5487 | 2029 | ✓ |
| `TLS_RSA_PSK_WITH_AES_128_CBC_SHA256` | `0x00,0xB6` | RFC 5487 | **2026** | ✗ |
| `TLS_RSA_PSK_WITH_AES_256_CBC_SHA384` | `0x00,0xB7` | RFC 5487 | **2026** | ✗ |
| `TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256` | `0xC0,0x37` | RFC 5489 | 2031 | ✓ |
| `TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384` | `0xC0,0x38` | RFC 5489 | 2031 | ✓ |
| `TLS_DHE_PSK_WITH_AES_128_CCM` | `0xC0,0xA6` | RFC 6655 | 2029 | ✓ |
| `TLS_DHE_PSK_WITH_AES_256_CCM` | `0xC0,0xA7` | RFC 6655 | 2029 | ✓ |
| `TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256` | `0xD0,0x01` | RFC 8442 | 2031 | ✓ |
| `TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384` | `0xD0,0x02` | RFC 8442 | 2031 | ✓ |
| `TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256` | `0xD0,0x05` | RFC 8442 | 2031 | ✓ |
<!-- AUTOGEN:END tls-bsi-12-4 -->

> **Note:** Cipher suites of the form `TLS_PSK_*` (no ephemeral key, no random number)
> are **not recommended** by BSI — security depends solely on the entropy and confidentiality of the PSK.

### 12.5 TLS 1.2 Diffie-Hellman Groups (TR-02102-2 §3.3.2 Table 6)

<!-- AUTOGEN:BEGIN tls-bsi-12-5 -->
| Group | Description | IANA | Spec | Use up to |
|:---|:---|:---|:---|:---|
| `secp256r1` | P-256 (secp256r1); 128-bit security | 23 | RFC 8422 | 2031 |
| `secp384r1` | P-384 (secp384r1); 192-bit security | 24 | RFC 8422 | 2031 |
| `secp521r1` | P-521 (secp521r1); 256-bit security | 25 | RFC 8422 | 2031 |
| `brainpoolP256r1` | Brainpool P-256r1 (TLS 1.2); 128-bit security | 26 | RFC 7027 | 2031 |
| `brainpoolP384r1` | Brainpool P-384r1 (TLS 1.2); 192-bit security | 27 | RFC 7027 | 2031 |
| `brainpoolP512r1` | Brainpool P-512r1 (TLS 1.2); 256-bit security | 28 | RFC 7027 | 2031 |
| `ffdhe3072` | 3072-bit FFDHE (named, RFC 7919); 128-bit security | 257 | RFC 7919 | 2031 |
| `ffdhe4096` | 4096-bit FFDHE (named, RFC 7919) | 258 | RFC 7919 | 2031 |
<!-- AUTOGEN:END tls-bsi-12-5 -->

### 12.6 TLS 1.2 Signature Algorithms (TR-02102-2 §3.3.3 Tables 7+8)

| Signature algorithm | IANA | Use up to |
|:---|:---|:---|
| `rsa` (PKCS #1 v1.5) | 1 | **2025** (PKCS #1 v1.5 padding discontinuation per TR-02102-1 §1.5) |
| `dsa` | 2 | 2029 |
| `ecdsa` | 3 | 2031 |
| `sha256` (hash for sig) | 4 | 2031 |
| `sha384` (hash for sig) | 5 | 2031 |
| `sha512` (hash for sig) | 6 | 2031 |

> **Note:** RSA-PSS in TLS 1.2 follows the recommendations of TR-02102-1 §1.3 and §4.2.3 (Tables 11/12).

### 12.7 TLS 1.3 PSK Modes (TR-02102-2 §3.4.1 Table 9)

| PSK mode | IANA | Spec | Use up to |
|:---|:---|:---|:---|
| `psk_ke` | 0 | RFC 8446 | **2026** (no Perfect Forward Secrecy) |
| `psk_dhe_ke` | 1 | RFC 8446 | 2032+ |

> **Note:** 0-RTT data is **not recommended** (replay risk).

### 12.8 TLS 1.3 Diffie-Hellman Groups (TR-02102-2 §3.4.2 Table 10)

<!-- AUTOGEN:BEGIN tls-bsi-12-8 -->
| Group | Description | IANA | Spec | Use up to |
|:---|:---|:---|:---|:---|
| `secp256r1` | P-256 (secp256r1); 128-bit security | 23 | RFC 8422 | 2031 |
| `secp384r1` | P-384 (secp384r1); 192-bit security | 24 | RFC 8422 | 2031 |
| `secp521r1` | P-521 (secp521r1); 256-bit security | 25 | RFC 8422 | 2031 |
| `brainpoolP256r1tls13` | Brainpool P-256r1 (TLS 1.3); 128-bit security | 31 | RFC 8734 | 2031 |
| `brainpoolP384r1tls13` | Brainpool P-384r1 (TLS 1.3); 192-bit security | 32 | RFC 8734 | 2031 |
| `brainpoolP512r1tls13` | Brainpool P-512r1 (TLS 1.3); 256-bit security | 33 | RFC 8734 | 2031 |
| `ffdhe3072` | 3072-bit FFDHE (named, RFC 7919); 128-bit security | 257 | RFC 7919 | 2031 |
| `ffdhe4096` | 4096-bit FFDHE (named, RFC 7919) | 258 | RFC 7919 | 2031 |
<!-- AUTOGEN:END tls-bsi-12-8 -->

> **Note (quantum migration):** From 2032 onwards, classical (EC)DHE applies **exclusively to hybrid use with quantum-safe mechanisms**. BSI intends to recommend `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` (draft-ietf-tls-ecdhe-mlkem) once the corresponding RFC has been adopted.

### 12.9 TLS 1.3 `signature_algorithms` Extension (TR-02102-2 §3.4.3 Table 11)

<!-- AUTOGEN:BEGIN tls-bsi-12-9 -->
| Signature algorithm | IANA | Spec | Use up to |
|:---|:---|:---|:---|
| `ecdsa_secp256r1_sha256` | `0x0403` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `ecdsa_secp384r1_sha384` | `0x0503` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `ecdsa_secp521r1_sha512` | `0x0603` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `rsa_pss_rsae_sha256` | `0x0804` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `rsa_pss_rsae_sha384` | `0x0805` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `rsa_pss_rsae_sha512` | `0x0806` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `rsa_pss_pss_sha256` | `0x0809` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `rsa_pss_pss_sha384` | `0x080A` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `rsa_pss_pss_sha512` | `0x080B` | RFC-ietf-tls-rfc8446bis-13 | 2032+ |
| `ecdsa_brainpoolP256r1tls13_sha256` | `0x081A` | RFC 8734 | 2032+ |
| `ecdsa_brainpoolP384r1tls13_sha384` | `0x081B` | RFC 8734 | 2032+ |
| `ecdsa_brainpoolP512r1tls13_sha512` | `0x081C` | RFC 8734 | 2032+ |
<!-- AUTOGEN:END tls-bsi-12-9 -->

### 12.10 TLS 1.3 `signature_algorithms_cert` Extension (TR-02102-2 §3.4.3 Table 12)

Adds three PKCS #1 v1.5 entries to Table 11; their `use up to` is 2025 (PKCS #1 v1.5 padding discontinuation):

<!-- AUTOGEN:BEGIN tls-bsi-12-10 -->
| Signature algorithm | IANA | Spec | Use up to |
|:---|:---|:---|:---|
| `rsa_pkcs1_sha256` | `0x0401` | RFC-ietf-tls-rfc8446bis-13 | **2025** |
| `rsa_pkcs1_sha384` | `0x0501` | RFC-ietf-tls-rfc8446bis-13 | **2025** |
| `rsa_pkcs1_sha512` | `0x0601` | RFC-ietf-tls-rfc8446bis-13 | **2025** |
<!-- AUTOGEN:END tls-bsi-12-10 -->

(All Table 11 entries also apply to `signature_algorithms_cert` with the same 2032+ deadlines.)

### 12.11 TLS 1.3 Cipher Suites (TR-02102-2 §3.4.4 Table 13)

> Auto-generated table merges TLS 1.3 cipher suites from cr-tls.yaml with both NIST and BSI columns. Suites without a BSI entry (e.g. `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_128_CCM_8_SHA256`) appear with `—` in the BSI column.

<!-- AUTOGEN:BEGIN tls-bsi-12-11 -->
| Cipher suite | IANA | NIST | BSI |
|:---|:---|:---|:---|
| `TLS_AES_128_GCM_SHA256` | `0x13,0x01` | ✓ Approved | ✅ Recommended (use up to 2032+) |
| `TLS_AES_256_GCM_SHA384` | `0x13,0x02` | ✓ Approved | ✅ Recommended (use up to 2032+) |
| `TLS_CHACHA20_POLY1305_SHA256` | `0x13,0x03` | — | — |
| `TLS_AES_128_CCM_SHA256` | `0x13,0x04` | ✓ Approved | ✅ Recommended (use up to 2032+) |
| `TLS_AES_128_CCM_8_SHA256` | `0x13,0x05` | ✓ Approved | — |
<!-- AUTOGEN:END tls-bsi-12-11 -->

### 12.12 TLS Extensions (TR-02102-2 §3.3.4, §3.4.5)

| Extension | RFC | BSI guidance |
|:---|:---|:---|
| Encrypt-then-MAC | RFC 7366 | **Recommended** (mandatory companion for any CBC suite in §12.2/§12.3/§12.4) |
| Extended Master Secret | RFC 7627 | **Recommended** (mitigates triple-handshake attack) |
| supported_groups (TLS 1.2 ECDHE) | RFC 8422 | Recommended |
| supported_groups (TLS 1.2 DHE) | RFC 7919 | Recommended |
| signature_algorithms (TLS 1.2) | RFC 5246 | Recommended |
| Renegotiation Indication | RFC 5746 | Required if renegotiation used; client-initiated renegotiation should be rejected by the server |
| truncated_hmac | RFC 6066 | **Not recommended** (truncates MAC to 80 bits) |
| Heartbeat | RFC 6520 | **Not recommended** (Heartbleed) |
| TLS compression | — | **Not recommended** (CRIME) |

### 12.13 Key Lengths (TR-02102-2 §3.6.1 Table 14)

| Algorithm | Minimum key length | Use from | Use up to |
|:---|:---|:---|:---|
| ECDSA (sig keys) | 250 bit | — | 2032+ |
| DSA (sig keys) | 3000 bit | 2023 | 2029 |
| RSA (sig keys) | 3000 bit | 2023 | 2032+ |
| ECDH (key agreement) | 250 bit | — | 2032+ |
| DH (key agreement) | 3000 bit | 2023 | **2031** (then hybrid only) |

### 12.14 Random Number Generators (TR-02102-2 §4.3)

For TLS key/signature generation, an RNG of class **DRG.3, DRG.4, DRT.1, PTG.3, or NTG.1** per [BSI AIS 20/31] is required.

---

## 13. NIST SP 800-52 Revision 2 (TLS) Recommendations

> **Source:** NIST SP 800-52 Rev 2 "Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations" (August 2019), Kerry McKay & David Cooper.
>
> **Audience:** US federal departments and agencies. Servers handling sensitive but unclassified federal data.
>
> **Headline requirements:** TLS 1.2 with FIPS-based cipher suites is the minimum supported protocol; TLS 1.3 support required since January 1, 2024. The cryptographic module **shall** be FIPS 140-validated. All cryptography **shall** provide at least **112 bits of security**. The server **shall** be configured to use only NIST-approved cipher suites.

### 13.1 Protocol Version Support (SP 800-52r2 §3.1, §4.1)

| Version | Server requirement | Client requirement |
|:---|:---|:---|
| TLS 1.3 | **shall** support (since 2024-01-01) | **shall** support (since 2024-01-01) |
| TLS 1.2 | **shall** support (configured with FIPS-based suites) | **shall** support |
| TLS 1.1 | **may** support only when interop with non-government systems requires | same |
| TLS 1.0 | **may** support only when interop with non-government systems requires | same |
| SSLv3 / SSLv2 | **shall not** be supported | **shall not** be supported |

### 13.2 TLS 1.2 Cipher Suites by Server Certificate Type (SP 800-52r2 §3.3.1.1)

> Suites listed below are the NIST-approved minimum set; servers **shall** be configured to use only suites from this list.

#### 13.2.1 ECDSA Server Certificate

<!-- AUTOGEN:BEGIN tls-nist-13-2-1 -->
| Cipher suite | IANA | Spec | Available in |
|:---|:---|:---|:---|
| `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` | `0xC0,0x09` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` | `0xC0,0x0A` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x23` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x24` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x2B` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x2C` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_CCM` | `0xC0,0xAC` | RFC 7251 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CCM` | `0xC0,0xAD` | RFC 7251 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8` | `0xC0,0xAE` | RFC 7251 | TLS 1.2 |
| `TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8` | `0xC0,0xAF` | RFC 7251 | TLS 1.2 |
<!-- AUTOGEN:END tls-nist-13-2-1 -->

#### 13.2.2 RSA Server Certificate

<!-- AUTOGEN:BEGIN tls-nist-13-2-2 -->
| Cipher suite | IANA | Spec | Available in |
|:---|:---|:---|:---|
| `TLS_DHE_RSA_WITH_AES_128_CBC_SHA` | `0x00,0x33` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DHE_RSA_WITH_AES_256_CBC_SHA` | `0x00,0x39` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DHE_RSA_WITH_AES_128_CBC_SHA256` | `0x00,0x67` | RFC 5246 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256` | `0x00,0x6B` | RFC 5246 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` | `0x00,0x9E` | RFC 5288 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_256_GCM_SHA384` | `0x00,0x9F` | RFC 5288 | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | `0xC0,0x13` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | `0xC0,0x14` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x27` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x28` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x2F` | RFC 5289 | TLS 1.2 |
| `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x30` | RFC 5289 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_128_CCM` | `0xC0,0x9E` | RFC 6655 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_256_CCM` | `0xC0,0x9F` | RFC 6655 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_128_CCM_8` | `0xC0,0xA2` | RFC 6655 | TLS 1.2 |
| `TLS_DHE_RSA_WITH_AES_256_CCM_8` | `0xC0,0xA3` | RFC 6655 | TLS 1.2 |
<!-- AUTOGEN:END tls-nist-13-2-2 -->

#### 13.2.3 DSA Server Certificate

<!-- AUTOGEN:BEGIN tls-nist-13-2-3 -->
| Cipher suite | IANA | Spec | Available in |
|:---|:---|:---|:---|
| `TLS_DHE_DSS_WITH_AES_128_CBC_SHA` | `0x00,0x32` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DHE_DSS_WITH_AES_256_CBC_SHA` | `0x00,0x38` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DHE_DSS_WITH_AES_128_CBC_SHA256` | `0x00,0x40` | RFC 5246 | TLS 1.2 |
| `TLS_DHE_DSS_WITH_AES_256_CBC_SHA256` | `0x00,0x6A` | RFC 5246 | TLS 1.2 |
| `TLS_DHE_DSS_WITH_AES_128_GCM_SHA256` | `0x00,0xA2` | RFC 5288 | TLS 1.2 |
| `TLS_DHE_DSS_WITH_AES_256_GCM_SHA384` | `0x00,0xA3` | RFC 5288 | TLS 1.2 |
<!-- AUTOGEN:END tls-nist-13-2-3 -->

#### 13.2.4 DH Server Certificate (DSA- or RSA-signed)

> SP 800-52r2 §3.3.1.1.4 covers both DH-DSS and DH-RSA cert types.

<!-- AUTOGEN:BEGIN tls-nist-13-2-4 -->
| Cipher suite | IANA | Spec | Available in |
|:---|:---|:---|:---|
| `TLS_DH_DSS_WITH_AES_128_CBC_SHA` | `0x00,0x30` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DH_RSA_WITH_AES_128_CBC_SHA` | `0x00,0x31` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DH_DSS_WITH_AES_256_CBC_SHA` | `0x00,0x36` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DH_RSA_WITH_AES_256_CBC_SHA` | `0x00,0x37` | RFC 5246 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_DH_DSS_WITH_AES_128_CBC_SHA256` | `0x00,0x3E` | RFC 5246 | TLS 1.2 |
| `TLS_DH_RSA_WITH_AES_128_CBC_SHA256` | `0x00,0x3F` | RFC 5246 | TLS 1.2 |
| `TLS_DH_DSS_WITH_AES_256_CBC_SHA256` | `0x00,0x68` | RFC 5246 | TLS 1.2 |
| `TLS_DH_RSA_WITH_AES_256_CBC_SHA256` | `0x00,0x69` | RFC 5246 | TLS 1.2 |
| `TLS_DH_RSA_WITH_AES_128_GCM_SHA256` | `0x00,0xA0` | RFC 5288 | TLS 1.2 |
| `TLS_DH_RSA_WITH_AES_256_GCM_SHA384` | `0x00,0xA1` | RFC 5288 | TLS 1.2 |
| `TLS_DH_DSS_WITH_AES_128_GCM_SHA256` | `0x00,0xA4` | RFC 5288 | TLS 1.2 |
| `TLS_DH_DSS_WITH_AES_256_GCM_SHA384` | `0x00,0xA5` | RFC 5288 | TLS 1.2 |
<!-- AUTOGEN:END tls-nist-13-2-4 -->

#### 13.2.5 ECDH Server Certificate (ECDSA- or RSA-signed)

> SP 800-52r2 §3.3.1.1.5 covers both ECDH-ECDSA and ECDH-RSA cert types.

<!-- AUTOGEN:BEGIN tls-nist-13-2-5 -->
| Cipher suite | IANA | Spec | Available in |
|:---|:---|:---|:---|
| `TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA` | `0xC0,0x04` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA` | `0xC0,0x05` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDH_RSA_WITH_AES_128_CBC_SHA` | `0xC0,0x0E` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDH_RSA_WITH_AES_256_CBC_SHA` | `0xC0,0x0F` | RFC 8422 | TLS 1.0 / 1.1 / 1.2 (interop only) |
| `TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x25` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x26` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256` | `0xC0,0x29` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384` | `0xC0,0x2A` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x2D` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x2E` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256` | `0xC0,0x31` | RFC 5289 | TLS 1.2 |
| `TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384` | `0xC0,0x32` | RFC 5289 | TLS 1.2 |
<!-- AUTOGEN:END tls-nist-13-2-5 -->

### 13.3 TLS 1.3 Cipher Suites (SP 800-52r2 §3.3.1.2)

<!-- AUTOGEN:BEGIN tls-nist-13-3 -->
| Cipher suite | IANA | Spec | Available in |
|:---|:---|:---|:---|
| `TLS_AES_128_GCM_SHA256` | `0x13,0x01` | RFC-ietf-tls-rfc8446bis-13 | TLS 1.3 |
| `TLS_AES_256_GCM_SHA384` | `0x13,0x02` | RFC-ietf-tls-rfc8446bis-13 | TLS 1.3 |
| `TLS_AES_128_CCM_SHA256` | `0x13,0x04` | RFC-ietf-tls-rfc8446bis-13 | TLS 1.3 |
| `TLS_AES_128_CCM_8_SHA256` | `0x13,0x05` | RFC-ietf-tls-rfc8446bis-13 | TLS 1.3 |
<!-- AUTOGEN:END tls-nist-13-3 -->

> **Compatibility:** TLS 1.3 cipher suites work with RSA and ECDSA server certificates; DSA and DH certificates are **not supported** by TLS 1.3. They may also be used with pre-shared keys per Appendix C.

### 13.4 Cipher Suite Preference Ordering (SP 800-52r2 §3.3.1.1)

When multiple acceptable suites are configured, NIST recommends ordering preference as:

1. Prefer ephemeral over static — DHE over DH, ECDHE over ECDH (provides Perfect Forward Secrecy)
2. Prefer GCM or CCM modes over CBC (AEAD prevents padding/timing attacks)
3. Prefer CCM over CCM_8 (longer authentication tag)

### 13.5 TLS Extensions (SP 800-52r2 §3.4)

**Mandatory (server `shall` support):**

| Extension | RFC | Applies to TLS |
|:---|:---|:---|
| Renegotiation Indication | RFC 5746 | 1.0, 1.1, 1.2 |
| Server Name Indication (SNI) | RFC 6066 | 1.0, 1.1, 1.2, 1.3 |
| Extended Master Secret | RFC 7627 | 1.0, 1.1, 1.2 |
| Signature Algorithms | RFC 5246 / RFC 8446 | 1.2, 1.3 |
| Certificate Status Request (OCSP stapling) | RFC 6066 | 1.0, 1.1, 1.2, 1.3 |

**Conditional (server `shall` support if applicable):**

| Extension | When applicable |
|:---|:---|
| Fallback Signaling Cipher Suite Value (SCSV) | Server supports versions prior to TLS 1.2 and not 1.3 |
| Supported Groups | Server supports ephemeral ECDH cipher suites or TLS 1.3 |
| Key Share | Server supports TLS 1.3 |
| EC Point Format | Server supports EC cipher suites |
| Multiple Certificate Status | OCSP available for server certificate (`should`) |
| Trusted CA Indication | Memory-constrained clients with multi-CA issuance |

**Discouraged:** Heartbeat (Heartbleed); compression (CRIME); truncated_hmac.

### 13.6 Validated Cryptography (SP 800-52r2 §3.3.3)

- The cryptographic module used by the server **shall** be FIPS 140-validated.
- All algorithms in configured cipher suites **and** the random number generator **shall** be within the validation scope.
- The RBG **shall** be validated per the SP 800-90 series (SP 800-90A/B/C).
- All ephemeral keys **shall** offer at least 112 bits of security; all symmetric keys protecting TLS data **shall** offer at least 112 bits of security.
- Server/client certificate signature **shall** offer at least 112 bits of security and use SHA-224 or stronger.

### 13.7 RSA Key Transport (Appendix D)

NIST is **deprecating** RSA key transport in TLS. RSA key transport cipher suites are listed in Appendix D for transition use only and **shall not** be used for new federal deployments.

---

## 14. Authority Recommendation Summary

This section condenses the per-suite recommendations from §12 (BSI) and §13 (NIST) into a single comparison.

### 14.1 TLS Versions

| Version | IETF | NIST SP 800-52r2 | BSI TR-02102-2 v2026-01 |
|:---|:---|:---|:---|
| TLS 1.3 | RFC 8446 (current) | **shall** support (since 2024-01-01) | ✓ Recommended (use up to 2032+) |
| TLS 1.2 | RFC 5246 (legacy) | **shall** support, FIPS-based suites | ✓ Recommended (**use up to 2031**) |
| TLS 1.1 | Deprecated (RFC 8996) | **may** support — interop only | Not recommended |
| TLS 1.0 | Deprecated (RFC 8996) | **may** support — interop only | Not recommended |
| SSLv3 / SSLv2 | Prohibited (RFC 7568, RFC 6176) | **shall not** | Not recommended |

### 14.2 TLS 1.3 Cipher Suites

| IANA | Cipher suite | NIST | BSI |
|:---|:---|:---|:---|
| `0x13,0x01` | TLS_AES_128_GCM_SHA256 | ✓ | ✓ (use up to 2032+) |
| `0x13,0x02` | TLS_AES_256_GCM_SHA384 | ✓ | ✓ (use up to 2032+) |
| `0x13,0x03` | TLS_CHACHA20_POLY1305_SHA256 | not listed | not recommended |
| `0x13,0x04` | TLS_AES_128_CCM_SHA256 | ✓ | ✓ (use up to 2032+) |
| `0x13,0x05` | TLS_AES_128_CCM_8_SHA256 | ✓ | not recommended (8-byte tag) |

### 14.3 Notable NIST/BSI Divergences

| Topic | NIST stance | BSI stance |
|:---|:---|:---|
| ChaCha20-Poly1305 | Not in SP 800-52r2 (no FIPS 140 validation path for ChaCha20 as of 2019) | Not recommended (BSI does not endorse stream ciphers in TR-02102-1) |
| 3DES cipher suites | **shall not** use (insufficient data limit per single key) | Not recommended (subsumed by TR-02102-1 disallowance) |
| RSA key transport | Deprecated (Appendix D, transition only) | Not present in TR-02102-2 (covered by TR-02102-1 PKCS #1 v1.5 disallowance from 2025) |
| RSA-PSS in TLS 1.2 | Approved when used | Recommended (TR-02102-1 §1.3, §4.2.3) |
| Brainpool curves | Not listed in primary suites | ✓ Recommended (TLS 1.2 codes 26/27/28; TLS 1.3 codes 31/32/33) |
| PSK without ephemeral | Acceptable per Appendix C | **Not recommended** (`TLS_PSK_*`) |
| Key length minimum | 112 bits security | 120 bits security (3000-bit RSA/DH, 250-bit EC) |
| TLS 1.3 PSK without DHE (`psk_ke`) | No specific stance | Recommended only **until 2026** (no PFS) |
| Quantum migration | Not addressed (2019 publication) | Hybrid only from 2032; intends to recommend `SecP256r1MLKEM768` / `SecP384r1MLKEM1024` |

### 14.4 Document Currency

| Document | Edition | Date | Status |
|:---|:---|:---|:---|
| NIST SP 800-52 Rev 2 | Rev 2 | August 2019 | Current — no Rev 3 announced. Pre-PQC; quantum-safe migration covered separately by NIST IR 8547. |
| BSI TR-02102-2 | v2026-01 | 2026-01-27 | Current — annual revision cycle. Next expected v2027-01 (~Jan 2027). |
