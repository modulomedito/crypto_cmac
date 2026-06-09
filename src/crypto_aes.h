//==================================================================================================
/// @file       crypto_aes.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      AES algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// GUARD START
//==================================================================================================
#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H
#ifdef __cplusplus
extern "C" {
#endif

//==================================================================================================
// INCLUDE
//==================================================================================================
#include "rustlike_types.h"

//==================================================================================================
// PUBLIC TYPEDEF
//==================================================================================================

//==================================================================================================
// PUBLIC DEFINE
//==================================================================================================
#define CRYPTO_AES_MAJOR_VERSION (0)
#define CRYPTO_AES_MINOR_VERSION (3)
#define CRYPTO_AES_PATCH_VERSION (0)

/// Block length in bytes - AES is 128b block only
#define CRYPTO_AES_BLOCK_U8_SIZE (16)

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================
typedef enum {
    crypto_aes_Ret_Ok = 0,
    crypto_aes_Ret_InvalidArg,
    crypto_aes_Ret_BufferTooSmall,
    crypto_aes_Ret_CipherTextNotAligned,
} crypto_aes_Ret;

typedef enum {
    crypto_aes_KeyLen_128,
    crypto_aes_KeyLen_192,
    crypto_aes_KeyLen_256,
} crypto_aes_KeyLen;

typedef enum {
    crypto_aes_Mode_Ecb,
    crypto_aes_Mode_Cbc,
    crypto_aes_Mode_Ctr,
} crypto_aes_Mode;

typedef enum {
    crypto_aes_Direction_Encrypt,
    crypto_aes_Direction_Decrypt,
} crypto_aes_Direction;

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
typedef struct {
    /// Use the maxium key exp size for compatibility
    /// - AES128, key len = 16, key exp size = 176
    /// - AES192, key len = 24, key exp size = 208
    /// - AES256, key len = 32, key exp size = 240
    u8 round_key_buf[240];
    u8 iv_buf[CRYPTO_AES_BLOCK_U8_SIZE];
    crypto_aes_KeyLen keylen;
    crypto_aes_Mode mode;
    crypto_aes_Direction dir;
    const u8 *key_ref;
    const u8 *iv_ref;
    u32 key_u32_num;
    u32 round_num;
    u8 *result_mut;
    u32 result_buf_size;
    u32 result_len;
    u8 buf[CRYPTO_AES_BLOCK_U8_SIZE];
    u32 buf_len;
} crypto_aes_Handle;

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================
extern crypto_aes_Ret crypto_aes_encrypt(
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    const u8 *in_ref,
    u32 in_len,
    const u8 *key_ref,
    const u8 *iv_ref,
    u8 *out_mut,
    u32 out_buf_size
);
extern crypto_aes_Ret crypto_aes_decrypt(
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    const u8 *in_ref,
    u32 in_len,
    const u8 *key_ref,
    const u8 *iv_ref,
    u8 *out_mut,
    u32 out_buf_size
);

extern crypto_aes_Ret crypto_aes_Handle_init(
    crypto_aes_Handle *self,
    crypto_aes_KeyLen keylen,
    crypto_aes_Mode mode,
    crypto_aes_Direction dir,
    const u8 *key_ref,
    const u8 *iv_ref,
    u8 *out_mut,
    u32 out_buf_size
);
extern crypto_aes_Ret crypto_aes_Handle_update(
    crypto_aes_Handle *self,
    const u8 *in_ref,
    u32 in_len
);
extern crypto_aes_Ret crypto_aes_Handle_finalize(crypto_aes_Handle *self);

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_AES_H
