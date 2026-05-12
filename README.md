# crypto_cmac

An implementation of the Cipher-based Message Authentication Code (CMAC) algorithm,
conforming to NIST SP 800-38B.
This library supports AES-128, AES-192, and AES-256 for message authentication.

## Features

- Support for multiple key lengths via `crypto_cmac__KeyLen`.
- Synchronous "one-shot" computation for simple use cases.
- Object-oriented streaming API for processing large or fragmented data.
- Dependency on `crypto_aes` library.

## API Reference

### One-shot Computation

```c
i32 crypto_cmac__compute(
    crypto_cmac__KeyLen key_len,
    const u8* data_ref,
    u32 data_len,
    const u8* key_ref,
    u8* mac_mut
);
```

### Streaming API

- `crypto_cmac__Obj_init`: Initialize the CMAC object with the secret key and length.
- `crypto_cmac__Obj_update`: Process chunks of data incrementally.
- `crypto_cmac__Obj_finalize`: Complete the calculation and retrieve the MAC tag.

## Usage Example

```c
#include "crypto_cmac.h"

u8 key_buf[16] = { /* ... */ };
u8 data_buf[] = { /* ... */ };
u8 cmac_buf[16];

// One-shot
crypto_cmac__compute(crypto_cmac__KeyLen_128, data_buf, sizeof(data_buf), key_buf, cmac_buf);

// Or Streaming
crypto_cmac__Obj obj;
crypto_cmac__Obj_init(&obj, crypto_cmac__KeyLen_128, key_buf);
crypto_cmac__Obj_update(&obj, data_buf, sizeof(data_buf));
crypto_cmac__Obj_finalize(&obj, cmac_buf);
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
