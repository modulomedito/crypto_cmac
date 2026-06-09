# crypto_cmac

An implementation of the Cipher-based Message Authentication Code (CMAC) algorithm,
conforming to NIST SP 800-38B.
This library supports AES-128, AES-192, and AES-256 for message authentication.
Comply with MISRA-C:2023 rules.

**Current version: 0.3.0**

## How To Use?

Copy all files in the `src` folder to your project, which are:

- crypto_aes.c
- crypto_aes.h
- crypto_cmac.c
- crypto_cmac.h
- rustlike_types.h

## Features

- Support for three key lengths via `crypto_cmac_KeyLen` (`_128`, `_192`, `_256`).
- Synchronous "one-shot" computation for simple use cases.
- Object-oriented streaming API for processing large or fragmented data.
- Returns a typed result via the `crypto_cmac_Ret` enum (not a bare `i32`).
- Buffer-overflow-safe: every output parameter takes a `mac_buf_size` argument.
- Dependency on `crypto_aes` library (v0.3.x).

## API Reference

### Return Type

All public functions return `crypto_cmac_Ret`:

| Value                            | Meaning                            |
| -------------------------------- | ---------------------------------- |
| `crypto_cmac_Ret_Ok`             | Success                            |
| `crypto_cmac_Ret_InvalidArg`     | Null pointer or invalid key length |
| `crypto_cmac_Ret_BufferTooSmall` | Output buffer too small            |

### One-shot Computation

```c
crypto_cmac_Ret crypto_cmac_compute(
    crypto_cmac_KeyLen key_len,
    const u8* data_ref,
    u32 data_len,
    const u8* key_ref,
    u8* mac_mut,
    u32 mac_buf_size
);
```

Computes the CMAC tag in a single call. `mac_buf_size` must be at least `CRYPTO_CMAC_MAC_SIZE` (16).

### Streaming API

```c
crypto_cmac_Ret crypto_cmac_Handle_init(
    crypto_cmac_Handle* self,
    crypto_cmac_KeyLen key_len,
    const u8* key_ref
);

crypto_cmac_Ret crypto_cmac_Handle_update(
    crypto_cmac_Handle* self,
    const u8* data_ref,
    u32 len
);

crypto_cmac_Ret crypto_cmac_Handle_finalize(
    crypto_cmac_Handle* self,
    u8* mac_mut,
    u32 mac_buf_size
);
```

- **`Handle_init`**: Initialize the CMAC object with the secret key and length.
- **`Handle_update`**: Process chunks of data incrementally.
- **`Handle_finalize`**: Complete the calculation and retrieve the MAC tag. `mac_buf_size` must be at least `CRYPTO_CMAC_MAC_SIZE` (16).

## Usage Example

```c
#include "crypto_cmac.h"

u8 key_buf[16] = { /* ... */ };
u8 data_buf[] = { /* ... */ };
u8 cmac_buf[CRYPTO_CMAC_MAC_SIZE];

// One-shot
crypto_cmac_compute(
    crypto_cmac_KeyLen_128,
    data_buf, sizeof(data_buf),
    key_buf,
    cmac_buf, sizeof(cmac_buf)
);

// Or Streaming
crypto_cmac_Handle handle;
crypto_cmac_Handle_init(&handle, crypto_cmac_KeyLen_128, key_buf);
crypto_cmac_Handle_update(&handle, data_buf, sizeof(data_buf));
crypto_cmac_Handle_finalize(&handle, cmac_buf, sizeof(cmac_buf));
```

## Testing

Test with xmake, you need to install [xmake](https://xmake.io/) first.

```bash
git clone https://github.com/modulomedito/crypto_cmac.git
cd crypto_cmac
xmake test -v
```

## License

Copyright (C) 2026. MIT License.
