# TLS Cipher Suite and Group Analysis

> Auto-generated from the IANA TLS Parameters registries via
> `scripts/generate_iana_composites.py`. Re-generate with
> `python3 scripts/generate_iana_composites.py`.
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

### Entries by Sub-type

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

### Cross-protocol Entry Counts

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

## 11. X.509 Composite Signatures

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
