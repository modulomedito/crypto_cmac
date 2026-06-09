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
#include <string.h>

//==================================================================================================
// IMPORTED SWITCH CHECK
//==================================================================================================
#if !defined(CRYPTO_AES_MAJOR_VERSION) || (CRYPTO_AES_MAJOR_VERSION != 0)
#error "CRYPTO_AES_MAJOR_VERSION is NOT defined or NOT match!!!"
#endif
#if !defined(CRYPTO_AES_MINOR_VERSION) || (CRYPTO_AES_MINOR_VERSION != 3)
#error "CRYPTO_AES_MINOR_VERSION is NOT defined or NOT match!!!"
#endif
#if !defined(CRYPTO_AES_PATCH_VERSION)
#error "CRYPTO_AES_PATCH_VERSION is NOT defined!!!"
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
static crypto_cmac_Ret crypto_cmac_Handle_generate_subkeys(crypto_cmac_Handle* self);
static void crypto_cmac_leftshift(const u8* in_ref, u8* out_mut);

//==================================================================================================
// PRIVATE VARIABLE DEFINITION
//==================================================================================================
// clang-format off
static const u8 crypto_cmac_rb_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87,
};
// clang-format on
static const u8 crypto_cmac_zero_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {0};

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
/// For synchronously compute the CMAC of a piece of data
crypto_cmac_Ret crypto_cmac_compute(
    crypto_cmac_KeyLen key_len,
    const u8* data_ref,
    u32 data_len,
    const u8* key_ref,
    u8* mac_mut,
    u32 mac_buf_size
) {
    crypto_cmac_Handle handle;
    crypto_cmac_Ret ret;

    ret = crypto_cmac_Handle_init(&handle, key_len, key_ref);
    if (ret != crypto_cmac_Ret_Ok) {
        return ret;
    }

    ret = crypto_cmac_Handle_update(&handle, data_ref, data_len);
    if (ret != crypto_cmac_Ret_Ok) {
        return ret;
    }

    ret = crypto_cmac_Handle_finalize(&handle, mac_mut, mac_buf_size);
    if (ret != crypto_cmac_Ret_Ok) {
        return ret;
    }

    return crypto_cmac_Ret_Ok;
}

crypto_cmac_Ret crypto_cmac_Handle_init(
    crypto_cmac_Handle* self,
    crypto_cmac_KeyLen key_len,
    const u8* key_ref
) {
    if (key_ref == NULL) {
        return -1;
    }

    memset(self, 0, sizeof(crypto_cmac_Handle));

    switch (key_len) {
    case crypto_cmac_KeyLen_128:
        self->key_len = key_len;
        memcpy(self->key_buf, key_ref, 128 / 8);
        break;
    case crypto_cmac_KeyLen_192:
        self->key_len = key_len;
        memcpy(self->key_buf, key_ref, 192 / 8);
        break;
    case crypto_cmac_KeyLen_256:
        self->key_len = key_len;
        memcpy(self->key_buf, key_ref, 256 / 8);
        break;
    default:
        return -1;
    }

    crypto_cmac_Handle_generate_subkeys(self);

    return 0;
}

crypto_cmac_Ret crypto_cmac_Handle_update(crypto_cmac_Handle* self, const u8* data_ref, u32 len) {
    if (data_ref == NULL) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    crypto_aes_KeyLen aes_key_len;

    switch (self->key_len) {
    case crypto_cmac_KeyLen_128:
        aes_key_len = crypto_aes_KeyLen_128;
        break;
    case crypto_cmac_KeyLen_192:
        aes_key_len = crypto_aes_KeyLen_192;
        break;
    case crypto_cmac_KeyLen_256:
        aes_key_len = crypto_aes_KeyLen_256;
        break;
    default:
        return -1;
    }

    u32 i;
    u8 temp_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];

    self->total_len += len;

    while (len > 0) {
        u32 space = CRYPTO_CMAC_AES_BLOCK_SIZE - self->data_buf_len;
        u32 copy_len = (len < space) ? len : space;

        memcpy(self->data_buf + self->data_buf_len, data_ref, copy_len);
        self->data_buf_len += copy_len;
        data_ref += copy_len;
        len -= copy_len;

        if (self->data_buf_len == CRYPTO_CMAC_AES_BLOCK_SIZE) {
            if (len > 0) {
                for (i = 0; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
                    temp_buf[i] = self->data_buf[i] ^ self->state_buf[i];
                }

                // Execute the AES encryption
                crypto_aes_encrypt(
                    aes_key_len,
                    crypto_aes_Mode_Ecb,
                    temp_buf,
                    CRYPTO_CMAC_AES_BLOCK_SIZE,
                    self->key_buf,
                    NULL,
                    self->state_buf,
                    CRYPTO_CMAC_AES_BLOCK_SIZE * sizeof(u8)
                );

                self->data_buf_len = 0;
            }
        }
    }

    return 0;
}

crypto_cmac_Ret crypto_cmac_Handle_finalize(
    crypto_cmac_Handle* self,
    u8* mac_mut,
    u32 mac_buf_size
) {
    if ((self == NULL) || (mac_mut == NULL) || (mac_buf_size == 0)) {
        return crypto_cmac_Ret_InvalidArg;
    }

    crypto_aes_KeyLen aes_key_len;

    switch (self->key_len) {
    case crypto_cmac_KeyLen_128:
        aes_key_len = crypto_aes_KeyLen_128;
        break;
    case crypto_cmac_KeyLen_192:
        aes_key_len = crypto_aes_KeyLen_192;
        break;
    case crypto_cmac_KeyLen_256:
        aes_key_len = crypto_aes_KeyLen_256;
        break;
    default:
        return crypto_cmac_Ret_InvalidArg;
    }

    u8 last_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u8 temp_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u32 i;

    if (self->data_buf_len == CRYPTO_CMAC_AES_BLOCK_SIZE) {
        for (i = 0; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
            last_buf[i] = self->data_buf[i] ^ self->k1_buf[i];
        }
    } else {
        self->data_buf[self->data_buf_len] = 0x80;
        for (i = self->data_buf_len + 1; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
            self->data_buf[i] = 0;
        }
        for (i = 0; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
            last_buf[i] = self->data_buf[i] ^ self->k2_buf[i];
        }
    }

    for (i = 0; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
        temp_buf[i] = last_buf[i] ^ self->state_buf[i];
    }

    // Execute the AES encryption
    crypto_aes_Ret ret = crypto_aes_encrypt(
        aes_key_len,
        crypto_aes_Mode_Ecb,
        temp_buf,
        CRYPTO_CMAC_AES_BLOCK_SIZE,
        self->key_buf,
        NULL,
        mac_mut,
        mac_buf_size
    );

    return crypto_cmac_Ret_Ok;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static crypto_cmac_Ret crypto_cmac_Handle_generate_subkeys(crypto_cmac_Handle* self) {
    u8 temp_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u32 i;

    crypto_aes_KeyLen aes_key_len;

    switch (self->key_len) {
    case crypto_cmac_KeyLen_128:
        aes_key_len = crypto_aes_KeyLen_128;
        break;
    case crypto_cmac_KeyLen_192:
        aes_key_len = crypto_aes_KeyLen_192;
        break;
    case crypto_cmac_KeyLen_256:
        aes_key_len = crypto_aes_KeyLen_256;
        break;
    default:
        return crypto_cmac_Ret_InvalidArg;
    }

    // Execute the AES encryption
    crypto_aes_encrypt(
        aes_key_len,
        crypto_aes_Mode_Ecb,
        crypto_cmac_zero_buf,
        CRYPTO_CMAC_AES_BLOCK_SIZE,
        self->key_buf,
        NULL,
        temp_buf,
        sizeof(temp_buf)
    );

    crypto_cmac_leftshift(temp_buf, self->k1_buf);
    if (temp_buf[0] & 0x80) {
        for (i = 0; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
            self->k1_buf[i] ^= crypto_cmac_rb_buf[i];
        }
    }

    crypto_cmac_leftshift(self->k1_buf, self->k2_buf);
    if (self->k1_buf[0] & 0x80) {
        for (i = 0; i < CRYPTO_CMAC_AES_BLOCK_SIZE; i++) {
            self->k2_buf[i] ^= crypto_cmac_rb_buf[i];
        }
    }

    return crypto_cmac_Ret_Ok;
}

static void crypto_cmac_leftshift(const u8* in_ref, u8* out_mut) {
    u8 overflow = 0;
    i32 i;

    for (i = CRYPTO_CMAC_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        out_mut[i] = (u8)((in_ref[i] << 1) | overflow);
        overflow = (in_ref[i] & 0x80) ? 1 : 0;
    }
}

//==================================================================================================
// TEST
//==================================================================================================
// Binary-safe memcmp for test assertions (not string, not flagged by MISRA string checkers)
static inline i32 crypto_cmac_memcmp(const u8* a_ref, const u8* b_ref, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (a_ref[i] != b_ref[i]) {
            return (i32)(a_ref[i] - b_ref[i]);
        }
    }
    return 0;
}

static i32 crypto_cmac_test_tc1(void) {
    // clang-format off
    const u8 key_buf[16] = {
        0x0b, 0x0c, 0x0d, 0x0a, 0x0a, 0x0b, 0x0c, 0x0d,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0d, 0x0a, 0x0b, 0x0c,
    };
    const u8 data_buf[16] = {
        0x02, 0x03, 0x04, 0x01, 0x01, 0x02, 0x03, 0x04,
        0x01, 0x02, 0x03, 0x04, 0x04, 0x01, 0x02, 0x03,
    };
    const u8 expected_cmac_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {
        0x1c, 0xfa, 0x6b, 0x03, 0xfd, 0x9b, 0x87, 0xa5,
        0x7a, 0x3f, 0x5f, 0xad, 0x91, 0x82, 0x0b, 0x5f,
    };
    // clang-format on
    u8 actual_cmac_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {0};

    crypto_cmac_Ret ret = crypto_cmac_compute(
        crypto_cmac_KeyLen_128,
        data_buf,
        16,
        key_buf,
        actual_cmac_buf,
        sizeof(actual_cmac_buf)
    );
    if (ret != crypto_cmac_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_cmac_memcmp(
        expected_cmac_buf,
        actual_cmac_buf,
        CRYPTO_CMAC_AES_BLOCK_SIZE * sizeof(u8)
    );
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_cmac_test_tc2(void) {
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
    const u8 expected_cmac_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {
        0x47, 0xab, 0xbb, 0x49, 0x12, 0x0d, 0x41, 0x22,
        0xb0, 0xe3, 0x84, 0x91, 0xa5, 0x24, 0xee, 0x46,
    };
    // clang-format on
    u8 actual_cmac_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {0};

    crypto_cmac_Ret ret = crypto_cmac_compute(
        crypto_cmac_KeyLen_192,
        data_buf,
        24,
        key_buf,
        actual_cmac_buf,
        sizeof(actual_cmac_buf)
    );
    if (ret != crypto_cmac_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_cmac_memcmp(
        expected_cmac_buf,
        actual_cmac_buf,
        CRYPTO_CMAC_AES_BLOCK_SIZE * sizeof(u8)
    );
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_cmac_test_tc3(void) {
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
    const u8 expected_cmac_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {
        0x41, 0xa6, 0xeb, 0xfa, 0x15, 0xde, 0x3b, 0x67,
        0x5e, 0x1e, 0x6f, 0xcb, 0x7d, 0xdd, 0x87, 0x2d,
    };
    // clang-format on
    u8 actual_cmac_buf[CRYPTO_CMAC_AES_BLOCK_SIZE] = {0};

    crypto_cmac_Ret ret = crypto_cmac_compute(
        crypto_cmac_KeyLen_256,
        data_buf,
        40,
        key_buf,
        actual_cmac_buf,
        sizeof(actual_cmac_buf)
    );
    if (ret != crypto_cmac_Ret_Ok) {
        return __LINE__;
    }

    i32 cmp = crypto_cmac_memcmp(
        expected_cmac_buf,
        actual_cmac_buf,
        CRYPTO_CMAC_AES_BLOCK_SIZE * sizeof(u8)
    );
    if (cmp != 0) {
        return __LINE__;
    }

    return 0;
}

i32 crypto_cmac_test(void) {
    i32 result;

    // Test synchronous AES128-CMAC compute
    result = crypto_cmac_test_tc1();
    if (result != 0) {
        return result;
    }

    // Test synchronous AES192-CMAC compute
    result = crypto_cmac_test_tc2();
    if (result != 0) {
        return result;
    }

    // Test synchronous AES256-CMAC compute
    result = crypto_cmac_test_tc3();
    if (result != 0) {
        return result;
    }

    return 0;
}
