////////////////////////////////////////////////////////////////////////////////
//
// @file prng.h
// @brief Pseudorandom number generator.
// @author MStar Semiconductor Inc.
//
// PRNG header file.
//
// Features:
// - Define definition of PRNG APIs.
//
// Notes:
//
////////////////////////////////////////////////////////////////////////////////
#ifndef POLARSSL_PRNG_H
#define POLARSSL_PRNG_H

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------
// Include Files
//-----------------------------------------------------------------------------
#include "config.h"

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------
#undef INTERFACE
#ifdef _POLARSSL_PRNG_C_
#define INTERFACE
#else
#define INTERFACE extern
#endif

//-----------------------------------------------------------------------------
// Enums
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Exported global variables
//-----------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Extern Functions
//------------------------------------------------------------------------------
INTERFACE void cc_prng( U8 *u8pOutput, U32 u32BitsLen );
INTERFACE void cc_prng_didin( U8 *pu8Input, U32 InLen, U8 *u8pOutput, U32 u32BitsLen );
INTERFACE void cc_prng_set_seed( U8 *u8pSeed );
INTERFACE void cc_prng_get_seed( U8 *u8pSeed );
#undef INTERFACE

#ifdef __cplusplus
}
#endif

#endif // POLARSSL_PRNG_H