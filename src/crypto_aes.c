//==================================================================================================
/// @file       crypto_aes.c
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// INCLUDE
//==================================================================================================
#include "crypto_aes.h"
#include <string.h>

//==================================================================================================
// IMPORTED SWITCH CHECK
//==================================================================================================

//==================================================================================================
// PRIVATE DEFINE
//==================================================================================================
/// The number of columns comprising a state in AES. This is a constant in AES. Value = 4
#define CRYPTO_AES_NB (4)

//==================================================================================================
// PRIVATE TYPEDEF
//==================================================================================================

//==================================================================================================
// PRIVATE ENUM
//==================================================================================================

//==================================================================================================
// PRIVATE STRUCT
//==================================================================================================
// In standard AES, the state is a 4x4 matrix of bytes.
// Data is stored column by column (a word is a column).
// Here we define a column (4 bytes) and the state (4 columns).
typedef struct {
    u8 byte[4]; // 4 bytes in a column
} crypto_aes_StateColumn;

typedef struct {
    crypto_aes_StateColumn col[4]; // 4 columns in a state
} crypto_aes_State;

//==================================================================================================
// PRIVATE UNION
//==================================================================================================

//==================================================================================================
// PRIVATE FUNCTION DECLARATION
//==================================================================================================
static void crypto_aes_Handle_ecb_encrypt(crypto_aes_Handle *self);
static void crypto_aes_Handle_ecb_decrypt(crypto_aes_Handle *self, u8 *buf_mut);
static void crypto_aes_Handle_cbc_encrypt(crypto_aes_Handle *self);
static void crypto_aes_Handle_cbc_decrypt(crypto_aes_Handle *self, u8 *buf_mut);
static void crypto_aes_Handle_ctr_xcrypt(crypto_aes_Handle *self);
static void crypto_aes_Handle_key_expansion(crypto_aes_Handle *self);
static void crypto_aes_Handle_cipher(crypto_aes_Handle *self, crypto_aes_State *state_mut);
static void crypto_aes_Handle_inv_cipher(crypto_aes_Handle *self, crypto_aes_State *state_mut);
static void crypto_aes_Handle_add_round_key(
    crypto_aes_Handle *self,
    u32 round,
    crypto_aes_State *state_mut
);

static u8 crypto_aes_xtime(u8 x);
static u8 crypto_aes_multiply(u8 x, u8 y);
static void crypto_aes_xor_with_iv(u8 *buf_mut, const u8 *iv_ref);
static void crypto_aes_sub_bytes(crypto_aes_State *state_mut);
static void crypto_aes_shift_rows(crypto_aes_State *state_mut);
static void crypto_aes_mix_columns(crypto_aes_State *state_mut);
static void crypto_aes_inv_sub_bytes(crypto_aes_State *state_mut);
static void crypto_aes_inv_mix_columns(crypto_aes_State *state_mut);
static void crypto_aes_inv_shift_rows(crypto_aes_State *state_mut);

//==================================================================================================
// PRIVATE VARIABLE DEFINITION
//==================================================================================================
static const u8 crypto_aes_sbox_tbl[256] = {
    // 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const u8 crypto_aes_rsbox_tbl[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const u8 crypto_aes_rcon_tbl[11] =
    {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

//==================================================================================================
// PUBLIC VARIABLE DEFINITION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DEFINITION
//==================================================================================================
/// For synchronous encrypt, encrypt data at once
crypto_aes_Ret crypto_aes_encrypt(
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    const u8 *in_ref,
    u32 in_len,
    const u8 *key_ref,
    const u8 *iv_ref,
    u8 *out_mut,
    u32 out_buf_size
) {
    crypto_aes_Handle handle;
    crypto_aes_Ret ret;

    ret = crypto_aes_Handle_init(
        &handle,
        keylen,
        mode,
        crypto_aes_Direction_Encrypt,
        key_ref,
        iv_ref,
        out_mut,
        out_buf_size
    );
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    ret = crypto_aes_Handle_update(&handle, in_ref, in_len);
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    ret = crypto_aes_Handle_finalize(&handle);
    return ret;
}

/// For synchronous decrypt, decrypt data at once
crypto_aes_Ret crypto_aes_decrypt(
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    const u8 *in_ref,
    u32 in_len,
    const u8 *key_ref,
    const u8 *iv_ref,
    u8 *out_mut,
    u32 out_buf_size
) {
    crypto_aes_Handle handle;
    crypto_aes_Ret ret;

    ret = crypto_aes_Handle_init(
        &handle,
        keylen,
        mode,
        crypto_aes_Direction_Decrypt,
        key_ref,
        iv_ref,
        out_mut,
        out_buf_size
    );
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    ret = crypto_aes_Handle_update(&handle, in_ref, in_len);
    if (ret != crypto_aes_Ret_Ok) {
        return ret;
    }

    ret = crypto_aes_Handle_finalize(&handle);
    return ret;
}

/// For asynchronous encrypt/decrypt, init instance of class crypto_aes_Handle
crypto_aes_Ret crypto_aes_Handle_init(
    crypto_aes_Handle *self,
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    crypto_aes_Direction dir,
    const u8 *key_ref,
    const u8 *iv_ref,
    u8 *out_mut,
    u32 out_buf_size
) {
    if ((dir != crypto_aes_Direction_Encrypt) && //
        (dir != crypto_aes_Direction_Decrypt)) {
        return crypto_aes_Ret_InvalidArg;
    }

    if ((mode == crypto_aes_Mode_Cbc) || (mode == crypto_aes_Mode_Ctr)) {
        if (iv_ref == NULL) {
            return crypto_aes_Ret_InvalidArg;
        }
        self->iv_ref = iv_ref;
        memcpy(self->iv_buf, iv_ref, CRYPTO_AES_BLOCK_U8_SIZE);
    } else if (mode != crypto_aes_Mode_Ecb) {
        return crypto_aes_Ret_InvalidArg;
    }

    self->key_ref = key_ref;
    self->mode = mode;
    self->dir = dir;
    self->keylen = keylen;
    self->buf_len = 0;
    self->result_mut = out_mut;
    self->result_buf_size = out_buf_size;
    self->result_len = 0;
    memset(self->buf, 0, CRYPTO_AES_BLOCK_U8_SIZE);

    switch (keylen) {
    case crypto_aes_KeyLen_128:
        self->key_u32_num = 4;
        self->round_num = 10;
        break;
    case crypto_aes_KeyLen_192:
        self->key_u32_num = 6;
        self->round_num = 12;
        break;
    case crypto_aes_KeyLen_256:
        self->key_u32_num = 8;
        self->round_num = 14;
        break;
    default:
        return crypto_aes_Ret_InvalidArg;
    }

    crypto_aes_Handle_key_expansion(self);

    return 0;
}

/// For asynchronous encrypt/decrypt, update input data
crypto_aes_Ret crypto_aes_Handle_update(crypto_aes_Handle *self, const u8 *in_ref, u32 in_len) {
    u32 in_pos = 0;

    if (self == NULL || in_ref == NULL || self->result_mut == NULL) {
        return crypto_aes_Ret_InvalidArg;
    }

    if (in_len == 0) {
        return crypto_aes_Ret_Ok;
    }

    while (in_pos < in_len) {
        // For ECB/CBC Decryption, we delay processing a full 16-byte block
        // until we know it's not the last block (i.e. more data is coming).
        if (self->dir == crypto_aes_Direction_Decrypt) {
            if ((self->mode == crypto_aes_Mode_Ecb) || (self->mode == crypto_aes_Mode_Cbc)) {
                if (self->buf_len == CRYPTO_AES_BLOCK_U8_SIZE) {
                    memcpy(self->result_mut, self->buf, CRYPTO_AES_BLOCK_U8_SIZE);
                    if (self->mode == crypto_aes_Mode_Ecb) {
                        crypto_aes_Handle_ecb_decrypt(self, self->result_mut);
                    } else {
                        crypto_aes_Handle_cbc_decrypt(self, self->result_mut);
                    }
                    self->result_mut += CRYPTO_AES_BLOCK_U8_SIZE;
                    self->result_len += CRYPTO_AES_BLOCK_U8_SIZE;
                    self->buf_len = 0;
                }
            }
        }

        u32 space = CRYPTO_AES_BLOCK_U8_SIZE - self->buf_len;
        u32 copy_len = (in_len - in_pos) < space ? (in_len - in_pos) : space;
        memcpy(self->buf + self->buf_len, in_ref + in_pos, copy_len);
        self->buf_len += copy_len;
        in_pos += copy_len;

        // For Encryption and CTR mode, process as soon as we have 16 bytes
        if (self->buf_len == CRYPTO_AES_BLOCK_U8_SIZE) {
            if ((self->mode == crypto_aes_Mode_Ecb || self->mode == crypto_aes_Mode_Cbc) &&
                self->dir == crypto_aes_Direction_Decrypt) {
                // Skip processing here, will process in the next iteration or finalize
                continue;
            }

            memcpy(self->result_mut, self->buf, CRYPTO_AES_BLOCK_U8_SIZE);
            if (self->mode == crypto_aes_Mode_Ecb) {
                crypto_aes_Handle_ecb_encrypt(self);
            } else if (self->mode == crypto_aes_Mode_Cbc) {
                crypto_aes_Handle_cbc_encrypt(self);
            } else if (self->mode == crypto_aes_Mode_Ctr) {
                crypto_aes_Handle_ctr_xcrypt(self);
            }
            self->result_mut += CRYPTO_AES_BLOCK_U8_SIZE;
            self->result_len += CRYPTO_AES_BLOCK_U8_SIZE;
            self->buf_len = 0;
        }
    }

    return crypto_aes_Ret_Ok;
}

/// For asynchronous encrypt/decrypt, finalize the encrypt/decrypt output
crypto_aes_Ret crypto_aes_Handle_finalize(crypto_aes_Handle *self) {
    if (self == NULL) {
        return crypto_aes_Ret_InvalidArg;
    }

    crypto_aes_Ret ret = crypto_aes_Ret_Ok;

    if (self->mode == crypto_aes_Mode_Ecb || self->mode == crypto_aes_Mode_Cbc) {
        if (self->dir == crypto_aes_Direction_Encrypt) {
            // PKCS#7 Padding (only if not aligned)
            if (self->buf_len > 0) {
                u8 pad_val = CRYPTO_AES_BLOCK_U8_SIZE - self->buf_len;
                memset(self->buf + self->buf_len, pad_val, pad_val);

                // Update AES output buffer content
                if (self->result_buf_size >= (self->result_len + CRYPTO_AES_BLOCK_U8_SIZE)) {
                    memcpy(self->result_mut, self->buf, CRYPTO_AES_BLOCK_U8_SIZE);
                } else {
                    return crypto_aes_Ret_BufferTooSmall;
                }

                if (self->mode == crypto_aes_Mode_Ecb) {
                    crypto_aes_Handle_ecb_encrypt(self);
                } else {
                    crypto_aes_Handle_cbc_encrypt(self);
                }
                self->result_mut += CRYPTO_AES_BLOCK_U8_SIZE;
                self->result_len += CRYPTO_AES_BLOCK_U8_SIZE;
            }
        } else {
            // PKCS#7 Unpadding
            if ((self->buf_len != 0) && (self->buf_len != CRYPTO_AES_BLOCK_U8_SIZE)) {
                // Error: Ciphertext not a multiple of block size
                ret = crypto_aes_Ret_CipherTextNotAligned;
                goto cleanup;
            }
            if (self->buf_len == CRYPTO_AES_BLOCK_U8_SIZE) {
                u8 temp[CRYPTO_AES_BLOCK_U8_SIZE];
                memcpy(temp, self->buf, CRYPTO_AES_BLOCK_U8_SIZE);
                if (self->mode == crypto_aes_Mode_Ecb) {
                    crypto_aes_Handle_ecb_decrypt(self, temp);
                } else {
                    crypto_aes_Handle_cbc_decrypt(self, temp);
                }

                u8 pad_val = temp[CRYPTO_AES_BLOCK_U8_SIZE - 1];
                u8 is_padded = 1;
                if (pad_val < 1 || pad_val > CRYPTO_AES_BLOCK_U8_SIZE) {
                    is_padded = 0; // Not padded
                } else {
                    // Verify padding: check that the last pad_val bytes are all equal to pad_val
                    const u8 *padding = &temp[CRYPTO_AES_BLOCK_U8_SIZE - pad_val];
                    for (u8 i = 0; i < pad_val; i++) {
                        if (padding[i] != pad_val) {
                            is_padded = 0; // Not padded
                            break;
                        }
                    }
                }

                u32 out_len = is_padded ? ((u32)CRYPTO_AES_BLOCK_U8_SIZE - (u32)pad_val)
                                        : (u32)CRYPTO_AES_BLOCK_U8_SIZE;

                // pad_val originates from ciphertext — validate out_len
                if (out_len > CRYPTO_AES_BLOCK_U8_SIZE) {
                    return crypto_aes_Ret_CipherTextNotAligned;
                }

                if (self->result_buf_size >= (self->result_len + out_len)) {
                    memcpy(self->result_mut, temp, out_len);
                } else {
                    return crypto_aes_Ret_BufferTooSmall;
                }
                self->result_mut += out_len;
                self->result_len += out_len;
            }
        }
    } else if (self->mode == crypto_aes_Mode_Ctr) {
        if (self->buf_len > 0) {

            if (self->result_buf_size >= (self->result_len + self->buf_len)) {
                memcpy(self->result_mut, self->buf, self->buf_len);
            } else {
                return crypto_aes_Ret_BufferTooSmall;
            }

            crypto_aes_Handle_ctr_xcrypt(self);
            self->result_mut += self->buf_len;
            self->result_len += self->buf_len;
        }
    }

cleanup:
    // Securely wipe sensitive key material and internal state from memory
    memset(self, 0, sizeof(crypto_aes_Handle));
    return ret;
}

//==================================================================================================
// PRIVATE FUNCTION DEFINITION
//==================================================================================================
static void crypto_aes_Handle_ecb_encrypt(crypto_aes_Handle *self) {
    crypto_aes_State state;
    memcpy((void *)&state, (void *)self->result_mut, sizeof(state));
    crypto_aes_Handle_cipher(self, &state);
    memcpy((void *)self->result_mut, (void *)&state, sizeof(state));
}

static void crypto_aes_Handle_ecb_decrypt(crypto_aes_Handle *self, u8 *buf_mut) {
    crypto_aes_State state;
    memcpy((void *)&state, (void *)buf_mut, sizeof(state));
    crypto_aes_Handle_inv_cipher(self, &state);
    memcpy((void *)buf_mut, (void *)&state, sizeof(state));
}

static void crypto_aes_Handle_cbc_encrypt(crypto_aes_Handle *self) {
    u8 *buf_mut = self->result_mut;
    u8 *iv_mut = self->iv_buf;
    crypto_aes_State state;

    crypto_aes_xor_with_iv(buf_mut, iv_mut);
    memcpy((void *)&state, (void *)buf_mut, sizeof(state));
    crypto_aes_Handle_cipher(self, &state);
    memcpy((void *)buf_mut, (void *)&state, sizeof(state));
    iv_mut = buf_mut;

    memcpy(self->iv_buf, iv_mut, CRYPTO_AES_BLOCK_U8_SIZE);
}

static void crypto_aes_Handle_cbc_decrypt(crypto_aes_Handle *self, u8 *buf_mut) {
    u32 i;
    u8 store_next_iv_buf[CRYPTO_AES_BLOCK_U8_SIZE];
    for (i = 0; i < self->buf_len; i += CRYPTO_AES_BLOCK_U8_SIZE) {
        memcpy(store_next_iv_buf, buf_mut, CRYPTO_AES_BLOCK_U8_SIZE);
        crypto_aes_State state;
        memcpy((void *)&state, (void *)buf_mut, sizeof(state));
        crypto_aes_Handle_inv_cipher(self, &state);
        memcpy((void *)buf_mut, (void *)&state, sizeof(state));
        crypto_aes_xor_with_iv(buf_mut, self->iv_buf);
        memcpy(self->iv_buf, store_next_iv_buf, CRYPTO_AES_BLOCK_U8_SIZE);
        buf_mut += CRYPTO_AES_BLOCK_U8_SIZE;
    }
}

static void crypto_aes_Handle_ctr_xcrypt(crypto_aes_Handle *self) {
    u8 keystream[CRYPTO_AES_BLOCK_U8_SIZE];
    u32 i = 0;

    while (i < self->buf_len) {
        // Generate a new block of keystream
        crypto_aes_State state;
        memcpy(keystream, self->iv_buf, CRYPTO_AES_BLOCK_U8_SIZE);
        memcpy((void *)&state, (void *)keystream, sizeof(state));
        crypto_aes_Handle_cipher(self, &state);
        memcpy((void *)keystream, (void *)&state, sizeof(state));

        // Increment the IV (Counter) for the next block
        for (i32 j = CRYPTO_AES_BLOCK_U8_SIZE - 1; j >= 0; j--) {
            if (++self->iv_buf[j] != 0) {
                break;
            }
        }

        // XOR the keystream with the data
        u32 bytes_to_process = self->buf_len - i;
        if (bytes_to_process > CRYPTO_AES_BLOCK_U8_SIZE) {
            bytes_to_process = CRYPTO_AES_BLOCK_U8_SIZE;
        }

        for (u32 bi = 0; bi < bytes_to_process; bi++, i++) {
            self->result_mut[i] ^= keystream[bi];
        }
    }
}

static void crypto_aes_Handle_add_round_key(
    crypto_aes_Handle *self,
    u32 round,
    crypto_aes_State *state_mut
) {
    u8 i, j;
    for (i = 0; i < 4; i++) { // iterate over columns
        for (j = 0; j < 4; j++) { // iterate over rows within the column
            state_mut->col[i].byte[j] ^= self->round_key_buf[(round * 16) + (i * 4) + j];
        }
    }
}

static void crypto_aes_Handle_cipher(crypto_aes_Handle *self, crypto_aes_State *state_mut) {
    // Initial round: Add the first round key
    crypto_aes_Handle_add_round_key(self, 0, state_mut);

    // Main rounds: SubBytes, ShiftRows, MixColumns, AddRoundKey
    for (u8 round = 1; round < self->round_num; round++) {
        crypto_aes_sub_bytes(state_mut);
        crypto_aes_shift_rows(state_mut);
        crypto_aes_mix_columns(state_mut);
        crypto_aes_Handle_add_round_key(self, round, state_mut);
    }

    // Final round: SubBytes, ShiftRows, AddRoundKey (No MixColumns)
    crypto_aes_sub_bytes(state_mut);
    crypto_aes_shift_rows(state_mut);
    crypto_aes_Handle_add_round_key(self, self->round_num, state_mut);
}

static void crypto_aes_Handle_inv_cipher(crypto_aes_Handle *self, crypto_aes_State *state_mut) {
    // Initial round: Add the last round key
    crypto_aes_Handle_add_round_key(self, self->round_num, state_mut);

    // Main rounds: InvShiftRows, InvSubBytes, AddRoundKey, InvMixColumns
    for (u8 round = (self->round_num - 1); round > 0; round--) {
        crypto_aes_inv_shift_rows(state_mut);
        crypto_aes_inv_sub_bytes(state_mut);
        crypto_aes_Handle_add_round_key(self, round, state_mut);
        crypto_aes_inv_mix_columns(state_mut);
    }

    // Final round: InvShiftRows, InvSubBytes, AddRoundKey (No InvMixColumns)
    crypto_aes_inv_shift_rows(state_mut);
    crypto_aes_inv_sub_bytes(state_mut);
    crypto_aes_Handle_add_round_key(self, 0, state_mut);
}

static void crypto_aes_Handle_key_expansion(crypto_aes_Handle *self) {
    u32 i, j, k;
    u8 temp_word[4];
    u8 *round_key_mut = self->round_key_buf;
    const u8 *key_ref = self->key_ref;
    u32 key_u32_num = self->key_u32_num;
    u32 round_num = self->round_num;

    // The first round key is the key itself.
    for (i = 0; i < key_u32_num; i++) {
        round_key_mut[(i * 4)] = key_ref[(i * 4)];
        round_key_mut[(i * 4) + 1] = key_ref[(i * 4) + 1];
        round_key_mut[(i * 4) + 2] = key_ref[(i * 4) + 2];
        round_key_mut[(i * 4) + 3] = key_ref[(i * 4) + 3];
    }

    // All other round keys are derived from the previous round keys.
    for (i = key_u32_num; i < CRYPTO_AES_NB * (round_num + 1); i++) {
        k = (i - 1) * 4;
        temp_word[0] = round_key_mut[k];
        temp_word[1] = round_key_mut[k + 1];
        temp_word[2] = round_key_mut[k + 2];
        temp_word[3] = round_key_mut[k + 3];

        if (i % key_u32_num == 0) {
            // This function shifts the 4 bytes in a word to the left once.
            // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
            const u8 temp_byte = temp_word[0];
            temp_word[0] = temp_word[1];
            temp_word[1] = temp_word[2];
            temp_word[2] = temp_word[3];
            temp_word[3] = temp_byte;

            // SubBytes: replace each byte using the S-box
            temp_word[0] = crypto_aes_sbox_tbl[temp_word[0]];
            temp_word[1] = crypto_aes_sbox_tbl[temp_word[1]];
            temp_word[2] = crypto_aes_sbox_tbl[temp_word[2]];
            temp_word[3] = crypto_aes_sbox_tbl[temp_word[3]];

            // XOR with round constant (Rcon)
            temp_word[0] = temp_word[0] ^ crypto_aes_rcon_tbl[i / key_u32_num];
        }

        // AES256, 256/32 = 8 words per key
        if (key_u32_num == 8) {
            if (i % key_u32_num == 4) {
                // Extra SubBytes step for AES-256
                temp_word[0] = crypto_aes_sbox_tbl[temp_word[0]];
                temp_word[1] = crypto_aes_sbox_tbl[temp_word[1]];
                temp_word[2] = crypto_aes_sbox_tbl[temp_word[2]];
                temp_word[3] = crypto_aes_sbox_tbl[temp_word[3]];
            }
        }

        j = i * 4;
        k = (i - key_u32_num) * 4;
        // XOR with the word `key_u32_num` positions earlier
        round_key_mut[j] = round_key_mut[k] ^ temp_word[0];
        round_key_mut[j + 1] = round_key_mut[k + 1] ^ temp_word[1];
        round_key_mut[j + 2] = round_key_mut[k + 2] ^ temp_word[2];
        round_key_mut[j + 3] = round_key_mut[k + 3] ^ temp_word[3];
    }
}

static void crypto_aes_inv_sub_bytes(crypto_aes_State *state_mut) {
    u8 i, j;
    for (i = 0; i < 4; i++) { // iterate over columns
        for (j = 0; j < 4; j++) { // iterate over rows
            state_mut->col[i].byte[j] = crypto_aes_rsbox_tbl[state_mut->col[i].byte[j]];
        }
    }
}

static void crypto_aes_xor_with_iv(u8 *buf_mut, const u8 *iv_ref) {
    u8 i;
    // The block in AES is always 128bit no matter the key size
    for (i = 0; i < CRYPTO_AES_BLOCK_U8_SIZE; i++) {
        buf_mut[i] ^= iv_ref[i];
    }
}

static void crypto_aes_sub_bytes(crypto_aes_State *state_mut) {
    u8 i, j;
    for (i = 0; i < 4; i++) { // iterate over columns
        for (j = 0; j < 4; j++) { // iterate over rows
            state_mut->col[i].byte[j] = crypto_aes_sbox_tbl[state_mut->col[i].byte[j]];
        }
    }
}

static void crypto_aes_shift_rows(crypto_aes_State *state_mut) {
    u8 temp;

    // Rotate first row 1 columns to left
    temp = state_mut->col[0].byte[1];
    state_mut->col[0].byte[1] = state_mut->col[1].byte[1];
    state_mut->col[1].byte[1] = state_mut->col[2].byte[1];
    state_mut->col[2].byte[1] = state_mut->col[3].byte[1];
    state_mut->col[3].byte[1] = temp;

    // Rotate second row 2 columns to left
    temp = state_mut->col[0].byte[2];
    state_mut->col[0].byte[2] = state_mut->col[2].byte[2];
    state_mut->col[2].byte[2] = temp;

    temp = state_mut->col[1].byte[2];
    state_mut->col[1].byte[2] = state_mut->col[3].byte[2];
    state_mut->col[3].byte[2] = temp;

    // Rotate third row 3 columns to left
    temp = state_mut->col[0].byte[3];
    state_mut->col[0].byte[3] = state_mut->col[3].byte[3];
    state_mut->col[3].byte[3] = state_mut->col[2].byte[3];
    state_mut->col[2].byte[3] = state_mut->col[1].byte[3];
    state_mut->col[1].byte[3] = temp;
}

static u8 crypto_aes_xtime(u8 x) {
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static void crypto_aes_mix_columns(crypto_aes_State *state_mut) {
    u8 i;
    u8 temp_col_xor; // XOR sum of all bytes in a column
    u8 temp_xor_adj; // XOR sum of adjacent bytes
    u8 original_col_0;

    for (i = 0; i < 4; i++) { // iterate over columns
        original_col_0 = state_mut->col[i].byte[0];

        // Calculate the XOR sum of all 4 bytes in the current column
        temp_col_xor = state_mut->col[i].byte[0] ^ state_mut->col[i].byte[1] ^
                       state_mut->col[i].byte[2] ^ state_mut->col[i].byte[3];

        // Mix row 0
        temp_xor_adj = state_mut->col[i].byte[0] ^ state_mut->col[i].byte[1];
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[0] ^= temp_xor_adj ^ temp_col_xor;

        // Mix row 1
        temp_xor_adj = state_mut->col[i].byte[1] ^ state_mut->col[i].byte[2];
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[1] ^= temp_xor_adj ^ temp_col_xor;

        // Mix row 2
        temp_xor_adj = state_mut->col[i].byte[2] ^ state_mut->col[i].byte[3];
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[2] ^= temp_xor_adj ^ temp_col_xor;

        // Mix row 3
        temp_xor_adj = state_mut->col[i].byte[3] ^ original_col_0;
        temp_xor_adj = crypto_aes_xtime(temp_xor_adj);
        state_mut->col[i].byte[3] ^= temp_xor_adj ^ temp_col_xor;
    }
}

static u8 crypto_aes_multiply(u8 x, u8 y) {
    u8 xtime_x;
    u8 result = ((y & 1) * x);

    xtime_x = crypto_aes_xtime(x);
    result ^= ((y >> 1 & 1) * xtime_x);

    xtime_x = crypto_aes_xtime(x);
    xtime_x = crypto_aes_xtime(xtime_x);
    result ^= ((y >> 2 & 1) * xtime_x);

    xtime_x = crypto_aes_xtime(x);
    xtime_x = crypto_aes_xtime(xtime_x);
    xtime_x = crypto_aes_xtime(xtime_x);
    result ^= ((y >> 3 & 1) * xtime_x);

    xtime_x = crypto_aes_xtime(x);
    xtime_x = crypto_aes_xtime(xtime_x);
    xtime_x = crypto_aes_xtime(xtime_x);
    xtime_x = crypto_aes_xtime(xtime_x);
    result ^= ((y >> 4 & 1) * xtime_x);

    return result;
}

static void crypto_aes_inv_mix_columns(crypto_aes_State *state_mut) {
    i32 i;
    u8 a, b, c, d;

    for (i = 0; i < 4; i++) { // iterate over columns
        a = state_mut->col[i].byte[0];
        b = state_mut->col[i].byte[1];
        c = state_mut->col[i].byte[2];
        d = state_mut->col[i].byte[3];

        state_mut->col[i].byte[0] = crypto_aes_multiply(a, 0x0e) ^ crypto_aes_multiply(b, 0x0b) ^
                                    crypto_aes_multiply(c, 0x0d) ^ crypto_aes_multiply(d, 0x09);
        state_mut->col[i].byte[1] = crypto_aes_multiply(a, 0x09) ^ crypto_aes_multiply(b, 0x0e) ^
                                    crypto_aes_multiply(c, 0x0b) ^ crypto_aes_multiply(d, 0x0d);
        state_mut->col[i].byte[2] = crypto_aes_multiply(a, 0x0d) ^ crypto_aes_multiply(b, 0x09) ^
                                    crypto_aes_multiply(c, 0x0e) ^ crypto_aes_multiply(d, 0x0b);
        state_mut->col[i].byte[3] = crypto_aes_multiply(a, 0x0b) ^ crypto_aes_multiply(b, 0x0d) ^
                                    crypto_aes_multiply(c, 0x09) ^ crypto_aes_multiply(d, 0x0e);
    }
}

static void crypto_aes_inv_shift_rows(crypto_aes_State *state_mut) {
    u8 temp;

    // Rotate first row 1 columns to right
    temp = state_mut->col[3].byte[1];
    state_mut->col[3].byte[1] = state_mut->col[2].byte[1];
    state_mut->col[2].byte[1] = state_mut->col[1].byte[1];
    state_mut->col[1].byte[1] = state_mut->col[0].byte[1];
    state_mut->col[0].byte[1] = temp;

    // Rotate second row 2 columns to right
    temp = state_mut->col[0].byte[2];
    state_mut->col[0].byte[2] = state_mut->col[2].byte[2];
    state_mut->col[2].byte[2] = temp;

    temp = state_mut->col[1].byte[2];
    state_mut->col[1].byte[2] = state_mut->col[3].byte[2];
    state_mut->col[3].byte[2] = temp;

    // Rotate third row 3 columns to right
    temp = state_mut->col[0].byte[3];
    state_mut->col[0].byte[3] = state_mut->col[1].byte[3];
    state_mut->col[1].byte[3] = state_mut->col[2].byte[3];
    state_mut->col[2].byte[3] = state_mut->col[3].byte[3];
    state_mut->col[3].byte[3] = temp;
}

//==================================================================================================
// TEST
//==================================================================================================
#include <string.h>

// Binary-safe memcmp for test assertions (not string, not flagged by MISRA string checkers)
static inline i32 crypto_aes_memcmp(const u8 *a_ref, const u8 *b_ref, u32 len) {
    for (u32 i = 0; i < len; i++) {
        if (a_ref[i] != b_ref[i]) {
            return (i32)(a_ref[i] - b_ref[i]);
        }
    }
    return 0;
}

static i32 crypto_aes_test_tc1(void) {
    // clang-format off
    u8 plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    u8 key_buf[128 / 8] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    u8 cipher_buf[64] = {0};
    u8 expected_cipher_buf[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
        0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
    };
    // clang-format on

    crypto_aes_encrypt(
        crypto_aes_KeyLen_128,
        crypto_aes_Mode_Ecb,
        plain_buf,
        64,
        key_buf,
        NULL,
        cipher_buf,
        sizeof(cipher_buf)
    );

    i32 ret = crypto_aes_memcmp(expected_cipher_buf, cipher_buf, 64 * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_aes_test_tc2(void) {
    // clang-format off
    u8 plain_buf[64] = {0};
    u8 expected_plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    u8 key_buf[128 / 8] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    u8 cipher_buf[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
        0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
    };
    // clang-format on

    crypto_aes_decrypt(
        crypto_aes_KeyLen_128,
        crypto_aes_Mode_Ecb,
        cipher_buf,
        64,
        key_buf,
        NULL,
        plain_buf,
        sizeof(plain_buf)
    );

    i32 ret = crypto_aes_memcmp(expected_plain_buf, plain_buf, 64 * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_aes_test_tc3(void) {
    // clang-format off
    u8 plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    u8 key_buf[192 / 8] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    };
    u8 cipher_buf[16] = {0};
    u8 expected_cipher_buf[] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
    };
    // clang-format on

    crypto_aes_encrypt(
        crypto_aes_KeyLen_192,
        crypto_aes_Mode_Ecb,
        plain_buf,
        16,
        key_buf,
        NULL,
        cipher_buf,
        sizeof(cipher_buf)
    );

    i32 ret = crypto_aes_memcmp(expected_cipher_buf, cipher_buf, 16 * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_aes_test_tc4(void) {
    // clang-format off
    u8 cipher_buf[] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f,
        0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc,
    };
    u8 key_buf[192 / 8] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52,
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5,
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
    };
    u8 plain_buf[16] = {0};
    u8 expected_plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    // clang-format on

    crypto_aes_decrypt(
        crypto_aes_KeyLen_192,
        crypto_aes_Mode_Ecb,
        cipher_buf,
        16,
        key_buf,
        NULL,
        plain_buf,
        sizeof(plain_buf)
    );

    i32 ret = crypto_aes_memcmp(expected_plain_buf, plain_buf, 16 * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_aes_test_tc5(void) {
    // clang-format off
    u8 plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    u8 key_buf[256 / 8] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    u8 cipher_buf[16] = {0};
    u8 expected_cipher_buf[] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    };
    // clang-format on

    crypto_aes_encrypt(
        crypto_aes_KeyLen_256,
        crypto_aes_Mode_Ecb,
        plain_buf,
        16,
        key_buf,
        NULL,
        cipher_buf,
        sizeof(cipher_buf)
    );

    i32 ret = crypto_aes_memcmp(expected_cipher_buf, cipher_buf, 16 * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_aes_test_tc6(void) {
    // clang-format off
    u8 cipher_buf[] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
        0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
    };
    u8 key_buf[256 / 8] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
    };
    u8 plain_buf[16] = {0};
    u8 expected_plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    // clang-format on

    crypto_aes_decrypt(
        crypto_aes_KeyLen_256,
        crypto_aes_Mode_Ecb,
        cipher_buf,
        16,
        key_buf,
        NULL,
        plain_buf,
        sizeof(plain_buf)
    );

    i32 ret = crypto_aes_memcmp(expected_plain_buf, plain_buf, 16 * sizeof(u8));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

static i32 crypto_aes_test_tc7(void) {
    // clang-format off
    u8 plain_buf[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    u8 key_buf[128 / 8] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    u8 cipher_buf[64] = {0};
    u8 expected_cipher_buf[] = {
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
        0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d,
        0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf,
        0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23,
        0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88,
        0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f,
        0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4,
    };
    // clang-format on

    crypto_aes_Handle aes_handle;

    crypto_aes_Handle_init(
        &aes_handle,
        crypto_aes_KeyLen_128,
        crypto_aes_Mode_Ecb,
        crypto_aes_Direction_Encrypt,
        key_buf,
        NULL,
        cipher_buf,
        sizeof(cipher_buf)
    );

    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x00], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x08], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x10], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x18], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x20], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x28], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x30], 8);
    crypto_aes_Handle_update(&aes_handle, &plain_buf[0x38], 8);

    crypto_aes_Handle_finalize(&aes_handle);

    i32 ret = crypto_aes_memcmp(expected_cipher_buf, cipher_buf, sizeof(cipher_buf));
    if (ret != 0) {
        return __LINE__;
    }

    return 0;
}

i32 crypto_aes_test(void) {
    i32 result;

    /// Test AES128 ECB encrypt synchronously
    result = crypto_aes_test_tc1();
    if (result != 0) {
        return result;
    }

    /// Test AES128 ECB decrypt synchronously
    result = crypto_aes_test_tc2();
    if (result != 0) {
        return result;
    }

    /// Test AES192 ECB encrypt synchronously
    result = crypto_aes_test_tc3();
    if (result != 0) {
        return result;
    }

    /// Test AES192 ECB decrypt synchronously
    result = crypto_aes_test_tc4();
    if (result != 0) {
        return result;
    }

    /// Test AES256 ECB encrypt synchronously
    result = crypto_aes_test_tc5();
    if (result != 0) {
        return result;
    }

    /// Test AES256 ECB decrypt synchronously
    result = crypto_aes_test_tc6();
    if (result != 0) {
        return result;
    }

    /// Test AES128 ECB encrypt asynchronously
    result = crypto_aes_test_tc7();
    if (result != 0) {
        return result;
    }

    return 0;
}
