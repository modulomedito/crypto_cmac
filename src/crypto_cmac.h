//==================================================================================================
/// @file       crypto_cmac.h
/// @author     modulomedito (chcchc1995@outook.com)
/// @brief      CMAC algorithm
/// @copyright  Copyright (C) 2026. MIT License.
/// @details
//==================================================================================================
//==================================================================================================
// GUARD START
//==================================================================================================
#ifndef CRYPTO_CMAC_H
#define CRYPTO_CMAC_H
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
#define CRYPTO_CMAC__MAJOR_VERSION (0)
#define CRYPTO_CMAC__MINOR_VERSION (1)
#define CRYPTO_CMAC__PATCH_VERSION (0)

// Fixed constant
#define CRYPTO_CMAC__AES_BLOCK_SIZE (16)
#define CRYPTO_CMAC__MAC_SIZE (16)

// Use the maximum key size to support from AES128 to AES256
#define CRYPTO_CMAC__MAX_KEY_SIZE (32)

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================
typedef enum {
    crypto_cmac__KeyLen_128,
    crypto_cmac__KeyLen_192,
    crypto_cmac__KeyLen_256,
} crypto_cmac__KeyLen;

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
typedef struct {
    u8 key_buf[CRYPTO_CMAC__MAX_KEY_SIZE];
    u8 state_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u8 k1_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u8 k2_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u8 data_buf[CRYPTO_CMAC__AES_BLOCK_SIZE];
    u32 data_buf_len;
    u32 total_len;
} crypto_cmac__Ctx;

typedef struct {
    crypto_cmac__KeyLen key_len;
    crypto_cmac__Ctx ctx;
} crypto_cmac__Obj;

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================
extern i32 crypto_cmac__compute(
    crypto_cmac__KeyLen key_len,
    const u8* data_ref,
    u32 data_len,
    const u8* key_ref,
    u8* mac_mut
);

extern i32 crypto_cmac__Obj_init(
    crypto_cmac__Obj* self,
    crypto_cmac__KeyLen key_len,
    const u8* key_ref
);
extern i32 crypto_cmac__Obj_update(crypto_cmac__Obj* self, const u8* data_ref, u32 len);
extern i32 crypto_cmac__Obj_finalize(crypto_cmac__Obj* self, u8* mac_mut);

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_CMAC_H
