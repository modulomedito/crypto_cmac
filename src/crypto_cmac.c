//==================================================================================================
/// @file       crypto_cmac.c
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      CMAC algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// INCLUDE
//==================================================================================================
#include "crypto_cmac.h"
#include "crypto_aes.h"
#include <stdio.h>
#include <string.h>

//==================================================================================================
// IMPORTED SWITCH CHECK
//==================================================================================================
#if !defined(CRYPTO_AES__MAJOR_VERSION) || (CRYPTO_AES__MAJOR_VERSION != 0)
#error "CRYPTO_AES__MAJOR_VERSION is not match."
#endif
#if !defined(CRYPTO_AES__MINOR_VERSION) || (CRYPTO_AES__MINOR_VERSION != 1)
#error "CRYPTO_AES__MINOR_VERSION is not match."
#endif
#if !defined(CRYPTO_AES__PATCH_VERSION)
#error "CRYPTO_AES__PATCH_VERSION is not defined."
#endif

//==================================================================================================
// PRIVATE DEFINE
//==================================================================================================

//==================================================================================================
// PRIVATE TYPEDEF
//==================================================================================================

//==================================================================================================
// PRIVATE ENUM
//==================================================================================================

//==================================================================================================
// PRIVATE STRUCT
//==================================================================================================

//==================================================================================================
// PRIVATE UNION
//==================================================================================================

//==================================================================================================
// PRIVATE FUNCTION DECLARATION
//==================================================================================================
static i32 crypto_cmac__Obj_generate_subkeys(crypto_cmac__Obj* self);
static void crypto_cmac__leftshift(const u8* in_ref, u8* out_mut);

//==================================================================================================
// PRIVATE VARIABLE DEFINITION
//==================================================================================================
// clang-format off
static const u8 crypto_cmac__rb_buf[CRYPTO_CMAC__AES_BLOCK_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
};
// clang-format on
static const u8 crypto_cmac__zero_buf[CRYPTO_CMAC__AES_BLOCK_SIZE] = {0};

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
/// For synchronously compute the CMAC of a piece of data
i32 crypto_cmac__compute(
    crypto_cmac__KeyLen key_len,
    const u8* data_ref,
    u32 data_len,
    const u8* key_ref,
    u8* mac_mut
) {
    crypto_cmac__Obj obj;

    if (crypto_cmac__Obj_init(&obj, key_len, key_ref) < 0) {
        return -1;
    }
    if (crypto_cmac__Obj_update(&obj, data_ref, data_len) < 0) {
        return -1;
    }
    if (crypto_cmac__Obj_finalize(&obj, mac_mut) < 0) {
        return -1;
    }

    return 0;
}

i32 crypto_cmac__Obj_init(crypto_cmac__Obj* self, crypto_cmac__KeyLen key_len, const u8* key_ref) {
    if (key_ref == NULL) {
        return -1;
    }

    memset(&(self->ctx), 0, sizeof(crypto_cmac__Ctx));

    switch (key_len) {
    case crypto_cmac__KeyLen_128:
        self->key_len = key_len;
        memcpy(self->ctx.key_buf, key_ref, 128 / 8);
        break;
    case crypto_cmac__KeyLen_192:
        self->key_len = key_len;
        memcpy(self->ctx.key_buf, key_ref, 192 / 8);
        break;
    case crypto_cmac__KeyLen_256:
        self->key_len = key_len;
        memcpy(self->ctx.key_buf, key_ref, 256 / 8);
        break;
    default:
        return -1;
    }

    crypto_cmac__Obj_generate_subkeys(self);

    return 0;
}

i32 crypto_cmac__Obj_update(crypto_cmac__Obj* self, const u8* data_ref, u32 len) {
    if (data_ref == NULL) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    crypto_aes__KeyLen aes_key_len;

    switch (self->key_len) {
    case crypto_cmac__KeyLen_128:
        aes_key_len = crypto_aes__KeyLen_128;
        break;
    case crypto_cmac__KeyLen_192:
        aes_key_len = crypto_aes__KeyLen_192;
        break;
    case crypto_cmac__KeyLen_256:
        aes_key_len = crypto_aes__KeyLen_256;
        break;
    default:
        return -1;
    }

    u32 i;
    u8 temp_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];

    self->ctx.total_len += len;

    while (len > 0) {
        u32 space = CRYPTO_CMAC__AES_BLOCK_SIZE - self->ctx.data_buf_len;
        u32 copy_len = (len < space) ? len : space;

        memcpy(self->ctx.data_buf + self->ctx.data_buf_len, data_ref, copy_len);
        self->ctx.data_buf_len += copy_len;
        data_ref += copy_len;
        len -= copy_len;

        if (self->ctx.data_buf_len == CRYPTO_CMAC__AES_BLOCK_SIZE) {
            if (len > 0) {
                for (i = 0; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
                    temp_buf[i] = self->ctx.data_buf[i] ^ self->ctx.state_buf[i];
                }

                // Execute the AES encryption
                crypto_aes__encrypt(
                    aes_key_len,
                    crypto_aes__Mode_Ecb,
                    temp_buf,
                    CRYPTO_CMAC__AES_BLOCK_SIZE,
                    self->ctx.key_buf,
                    NULL,
                    self->ctx.state_buf
                );

                self->ctx.data_buf_len = 0;
            }
        }
    }

    return 0;
}

i32 crypto_cmac__Obj_finalize(crypto_cmac__Obj* self, u8* mac_mut) {
    if (mac_mut == NULL) {
        return -1;
    }

    crypto_aes__KeyLen aes_key_len;

    switch (self->key_len) {
    case crypto_cmac__KeyLen_128:
        aes_key_len = crypto_aes__KeyLen_128;
        break;
    case crypto_cmac__KeyLen_192:
        aes_key_len = crypto_aes__KeyLen_192;
        break;
    case crypto_cmac__KeyLen_256:
        aes_key_len = crypto_aes__KeyLen_256;
        break;
    default:
        return -1;
    }

    u8 last_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u8 temp_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u32 i;

    if (self->ctx.data_buf_len == CRYPTO_CMAC__AES_BLOCK_SIZE) {
        for (i = 0; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
            last_buf[i] = self->ctx.data_buf[i] ^ self->ctx.k1_buf[i];
        }
    } else {
        self->ctx.data_buf[self->ctx.data_buf_len] = 0x80;
        for (i = self->ctx.data_buf_len + 1; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
            self->ctx.data_buf[i] = 0;
        }
        for (i = 0; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
            last_buf[i] = self->ctx.data_buf[i] ^ self->ctx.k2_buf[i];
        }
    }

    for (i = 0; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
        temp_buf[i] = last_buf[i] ^ self->ctx.state_buf[i];
    }

    // Execute the AES encryption
    crypto_aes__encrypt(
        aes_key_len,
        crypto_aes__Mode_Ecb,
        temp_buf,
        CRYPTO_CMAC__AES_BLOCK_SIZE,
        self->ctx.key_buf,
        NULL,
        mac_mut
    );

    return 0;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static i32 crypto_cmac__Obj_generate_subkeys(crypto_cmac__Obj* self) {
    u8 temp_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u32 i;

    crypto_aes__KeyLen aes_key_len;

    switch (self->key_len) {
    case crypto_cmac__KeyLen_128:
        aes_key_len = crypto_aes__KeyLen_128;
        break;
    case crypto_cmac__KeyLen_192:
        aes_key_len = crypto_aes__KeyLen_192;
        break;
    case crypto_cmac__KeyLen_256:
        aes_key_len = crypto_aes__KeyLen_256;
        break;
    default:
        return -1;
    }

    // Execute the AES encryption
    crypto_aes__encrypt(
        aes_key_len,
        crypto_aes__Mode_Ecb,
        crypto_cmac__zero_buf,
        CRYPTO_CMAC__AES_BLOCK_SIZE,
        self->ctx.key_buf,
        NULL,
        temp_buf
    );

    crypto_cmac__leftshift(temp_buf, self->ctx.k1_buf);
    if (temp_buf[0] & 0x80) {
        for (i = 0; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
            self->ctx.k1_buf[i] ^= crypto_cmac__rb_buf[i];
        }
    }

    crypto_cmac__leftshift(self->ctx.k1_buf, self->ctx.k2_buf);
    if (self->ctx.k1_buf[0] & 0x80) {
        for (i = 0; i < CRYPTO_CMAC__AES_BLOCK_SIZE; i++) {
            self->ctx.k2_buf[i] ^= crypto_cmac__rb_buf[i];
        }
    }

    return 0;
}

static void crypto_cmac__leftshift(const u8* in_ref, u8* out_mut) {
    u8 overflow = 0;
    i32 i;

    for (i = CRYPTO_CMAC__AES_BLOCK_SIZE - 1; i >= 0; i--) {
        out_mut[i] = (u8)((in_ref[i] << 1) | overflow);
        overflow = (in_ref[i] & 0x80) ? 1 : 0;
    }
}

//==================================================================================================
// TEST
//==================================================================================================
static i32 crypto_cmac__test_tc1(void) {
    // clang-format off
    const u8 key_buf[16] = {
        0x0b, 0x0c, 0x0d, 0x0a, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0d, 0x0a, 0x0b, 0x0c,
    };
    const u8 data_buf[16] = {
        0x02, 0x03, 0x04, 0x01, 0x01, 0x02, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x04, 0x01, 0x02, 0x03,
    };
    const u8 expected_cmac_buf[CRYPTO_CMAC__AES_BLOCK_SIZE] = {
        0x1c, 0xfa, 0x6b, 0x03, 0xfd, 0x9b, 0x87, 0xa5,
        0x7a, 0x3f, 0x5f, 0xad, 0x91, 0x82, 0x0b, 0x5f,
    };
    // clang-format on
    u8 actual_cmac_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];

    i32 ret;

    ret = crypto_cmac__compute(crypto_cmac__KeyLen_128, data_buf, 16, key_buf, actual_cmac_buf);
    if (ret != 0) {
        return __LINE__;
    }

    ret = memcmp(expected_cmac_buf, actual_cmac_buf, CRYPTO_CMAC__AES_BLOCK_SIZE * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_cmac__test_tc2(void) {
    // clang-format off
    const u8 key_buf[24] = {
        0x1c, 0xfa, 0x6b, 0x03, 0xfd, 0x9b, 0x87, 0xa5,
        0x1c, 0xfa, 0x6b, 0x03, 0xfd, 0x9b, 0x87, 0xa5,
        0x1c, 0xfa, 0x6b, 0x03, 0xfd, 0x9b, 0x87, 0xa5,
    };
    const u8 data_buf[24] = {
        0x02, 0x03, 0x04, 0x01, 0x01, 0x02, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x04, 0x01, 0x02, 0x03,
        0x02, 0x03, 0x04, 0x01, 0x01, 0x02, 0x03, 0x04,
    };
    const u8 expected_cmac_buf[CRYPTO_CMAC__AES_BLOCK_SIZE] = {
        0x47, 0xab, 0xbb, 0x49, 0x12, 0x0d, 0x41, 0x22,
        0xb0, 0xe3, 0x84, 0x91, 0xa5, 0x24, 0xee, 0x46,
    };
    // clang-format on
    u8 actual_cmac_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];

    i32 ret;

    ret = crypto_cmac__compute(crypto_cmac__KeyLen_192, data_buf, 24, key_buf, actual_cmac_buf);
    if (ret != 0) {
        return __LINE__;
    }

    ret = memcmp(expected_cmac_buf, actual_cmac_buf, CRYPTO_CMAC__AES_BLOCK_SIZE * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_cmac__test_tc3(void) {
    // clang-format off
    const u8 key_buf[32] = {
        0x47, 0xab, 0xbb, 0x49, 0x12, 0x0d, 0x41, 0x22,
        0xb0, 0xe3, 0x84, 0x91, 0xa5, 0x24, 0xee, 0x46,
        0x47, 0xab, 0xbb, 0x49, 0x12, 0x0d, 0x41, 0x22,
        0xb0, 0xe3, 0x84, 0x91, 0xa5, 0x24, 0xee, 0x46,
    };
    const u8 data_buf[40] = {
        0x02, 0x03, 0x04, 0x01, 0x01, 0x02, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x04, 0x01, 0x02, 0x03,
        0x02, 0x03, 0x04, 0x01, 0x01, 0x02, 0x03, 0x04,
        0x47, 0xab, 0xbb, 0x49, 0x12, 0x0d, 0x41, 0x22,
        0xb0, 0xe3, 0x84, 0x91, 0xa5, 0x24, 0xee, 0x46,
    };
    const u8 expected_cmac_buf[CRYPTO_CMAC__AES_BLOCK_SIZE] = {
        0x41, 0xa6, 0xeb, 0xfa, 0x15, 0xde, 0x3b, 0x67,
        0x5e, 0x1e, 0x6f, 0xcb, 0x7d, 0xdd, 0x87, 0x2d,
    };
    // clang-format on
    u8 actual_cmac_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];

    i32 ret;

    ret = crypto_cmac__compute(crypto_cmac__KeyLen_256, data_buf, 40, key_buf, actual_cmac_buf);
    if (ret != 0) {
        return __LINE__;
    }

    ret = memcmp(expected_cmac_buf, actual_cmac_buf, CRYPTO_CMAC__AES_BLOCK_SIZE * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

i32 crypto_cmac__test(void) {
    i32 result;

    // Test synchronous AES128-CMAC compute
    result = crypto_cmac__test_tc1();
    if (result != 0) {
        return result;
    }

    // Test synchronous AES192-CMAC compute
    result = crypto_cmac__test_tc2();
    if (result != 0) {
        return result;
    }

    // Test synchronous AES256-CMAC compute
    result = crypto_cmac__test_tc3();
    if (result != 0) {
        return result;
    }

    return 0;
}
