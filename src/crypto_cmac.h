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
#define CRYPTO_CMAC_MAJOR_VERSION (0)
#define CRYPTO_CMAC_MINOR_VERSION (3)
#define CRYPTO_CMAC_PATCH_VERSION (0)

// Fixed constant
#define CRYPTO_CMAC_AES_BLOCK_SIZE (16)
#define CRYPTO_CMAC_MAC_SIZE (16)

// Use the maximum key size to support from AES128 to AES256
#define CRYPTO_CMAC_MAX_KEY_SIZE (32)

//==================================================================================================
// PUBLIC ENUM
//==================================================================================================
typedef enum {
    crypto_cmac_Ret_Ok = 0,
    crypto_cmac_Ret_InvalidArg,
    crypto_cmac_Ret_BufferTooSmall,
} crypto_cmac_Ret;

typedef enum {
    crypto_cmac_KeyLen_128,
    crypto_cmac_KeyLen_192,
    crypto_cmac_KeyLen_256,
} crypto_cmac_KeyLen;

//==================================================================================================
// PUBLIC STRUCT
//==================================================================================================
typedef struct {
    crypto_cmac_KeyLen key_len;
    u8 key_buf[CRYPTO_CMAC_MAX_KEY_SIZE];
    u8 state_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u8 k1_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u8 k2_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u8 data_buf[CRYPTO_CMAC_AES_BLOCK_SIZE];
    u32 data_buf_len;
    u32 total_len;
} crypto_cmac_Handle;

//==================================================================================================
// PUBLIC UNION
//==================================================================================================

//==================================================================================================
// PUBLIC VARIABLE DECLARATION
//==================================================================================================

//==================================================================================================
// PUBLIC FUNCTION DECLARATION
//==================================================================================================
extern crypto_cmac_Ret crypto_cmac_compute(
    crypto_cmac_KeyLen key_len,
    const u8* data_ref,
    u32 data_len,
    const u8* key_ref,
    u8* mac_mut,
    u32 mac_buf_size
);

extern crypto_cmac_Ret crypto_cmac_Handle_init(
    crypto_cmac_Handle* self,
    crypto_cmac_KeyLen key_len,
    const u8* key_ref
);
extern crypto_cmac_Ret crypto_cmac_Handle_update(
    crypto_cmac_Handle* self,
    const u8* data_ref,
    u32 len
);
extern crypto_cmac_Ret crypto_cmac_Handle_finalize(
    crypto_cmac_Handle* self,
    u8* mac_mut,
    u32 mac_buf_size
);

//==================================================================================================
// GUARD END
//==================================================================================================
#ifdef __cplusplus
}
#endif
#endif // #ifndef CRYPTO_CMAC_H
