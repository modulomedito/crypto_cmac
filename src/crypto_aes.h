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
#define CRYPTO_AES__MAJOR_VERSION (0)
#define CRYPTO_AES__MINOR_VERSION (1)
#define CRYPTO_AES__PATCH_VERSION (1)

/// Block length in bytes - AES is 128b block only
#define CRYPTO_AES__BLOCK_U8_SIZE (16)

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================
typedef enum {
    crypto_aes__KeyLen_128,
    crypto_aes__KeyLen_192,
    crypto_aes__KeyLen_256,
} crypto_aes__KeyLen;

typedef enum {
    crypto_aes__Mode_Ecb,
    crypto_aes__Mode_Cbc,
    crypto_aes__Mode_Ctr,
} crypto_aes__Mode;

typedef enum {
    crypto_aes__Direction_Encrypt,
    crypto_aes__Direction_Decrypt,
} crypto_aes__Direction;

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
typedef struct {
    /// Use the maxium key exp size for compatibility
    /// - AES128, key len = 16, key exp size = 176
    /// - AES192, key len = 24, key exp size = 208
    /// - AES256, key len = 32, key exp size = 240
    u8 round_key_buf[240];
    u8 iv_buf[CRYPTO_AES__BLOCK_U8_SIZE];
} crypto_aes__Ctx;

typedef struct {
    crypto_aes__Ctx ctx;
    crypto_aes__KeyLen keylen;
    crypto_aes__Mode mode;
    crypto_aes__Direction dir;
    const u8* key_ref;
    const u8* iv_ref;
    u8* out_mut;
    u32 key_u32_num;
    u32 round_num;
    u32 buf_len;
    u8* result_buf;
    u32 result_len;
    u8 buf[CRYPTO_AES__BLOCK_U8_SIZE];
} crypto_aes__Obj;

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================
extern i32 crypto_aes__encrypt(
    crypto_aes__KeyLen keylen,
    crypto_aes__Mode mode,
    const u8* in_ref,
    u32 in_len,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
);
extern i32 crypto_aes__decrypt(
    crypto_aes__KeyLen keylen,
    crypto_aes__Mode mode,
    const u8* in_ref,
    u32 in_len,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
);

extern i32 crypto_aes__Obj_init(
    crypto_aes__Obj* self,
    crypto_aes__KeyLen keylen,
    crypto_aes__Mode mode,
    crypto_aes__Direction dir,
    const u8* key_ref,
    const u8* iv_ref,
    u8* out_mut
);
extern i32 crypto_aes__Obj_update(crypto_aes__Obj* self, const u8* in_ref, u32 in_len);
extern i32 crypto_aes__Obj_finalize(
    crypto_aes__Obj* self,
    u8** result_buf_mut,
    u32* result_len_mut
);

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_AES_H
