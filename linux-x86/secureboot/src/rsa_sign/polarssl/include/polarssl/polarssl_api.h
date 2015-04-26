///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2009 MStar Semiconductor, Inc.
// All rights reserved.
//
// Unless otherwise stipulated in writing, any and all information contained
// herein regardless in any format shall remain the sole proprietary of
// MStar Semiconductor Inc. and be kept in strict confidence
// (¡§MStar Confidential Information¡¨) by the recipient.
// Any unauthorized act including without limitation unauthorized disclosure,
// copying, use, reproduction, sale, distribution, modification, disassembling,
// reverse engineering and compiling of the contents of MStar Confidential
// Information is unlawful and strictly prohibited. MStar hereby reserves the
// rights to any and all damages, losses, costs and expenses resulting therefrom.
//
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
///
/// file    polarssl_api.h
/// @brief  PolarSSL LIB API Interface
/// @author MStar Semiconductor Inc.
///
///////////////////////////////////////////////////////////////////////////////
#ifndef _POLARSSL_API_H_
#define _POLARSSL_API_H_

#ifdef __cplusplus
extern "C" {
#endif

//-----------------------------------------------------------------------------
// Include Files
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------
#define CC_SYSTEM_VERSION                       0x01
#define CC_AUTH_MAX_ROOT_CERT_SIZE              (2048)
#define CC_AUTH_MAX_BRAND_CERT_SIZE             CC_AUTH_MAX_ROOT_CERT_SIZE
#define CC_AUTH_MAX_DEVICE_CERT_SIZE            CC_AUTH_MAX_ROOT_CERT_SIZE
#define CC_AUTH_MAX_DEVICE_KEY_CERT_SIZE        CC_AUTH_MAX_ROOT_CERT_SIZE
#define CC_AUTH_PRNG_SEED_SIZE                  (128 >> 3)
#define CC_AUTH_NONCE_SIZE                      (256 >> 3)
#define CC_AUTH_DH_EXPONENT_SIZE                (2048 >> 3)
#define CC_AUTH_DHPH_SIZE                       CC_AUTH_DH_EXPONENT_SIZE
#define CC_AUTH_DHPM_SIZE                       CC_AUTH_DH_EXPONENT_SIZE
#define CC_AUTH_DHSK_SIZE                       CC_AUTH_DH_EXPONENT_SIZE
#define CC_AUTH_DHSK_TAIL_SIZE                  (128 >> 3)
#define CC_AUTH_DH_P_SIZE                       CC_AUTH_DH_EXPONENT_SIZE
#define CC_AUTH_DH_G_SIZE                       CC_AUTH_DH_EXPONENT_SIZE
#define CC_AUTH_DH_Q_SIZE                       (256 >> 3)
#define CC_AUTH_PRNG_SEED_SIZE                  (128 >> 3)
#define CC_AUTH_SIGNATURE_SIZE                  (2048 >> 3)
#define CC_AUTH_SHA256_HASH_SIZE                (256 >> 3)
#define CC_AUTH_NS_SIZE                         (64 >> 3)
#define CC_AUTH_ID_SIZE                         (64 >> 3)
#define CC_AUTH_KEY_REGISTER_SIZE               (8 >> 3)
#define CC_AUTH_AKH_SIZE                        (256 >> 3)
#define CC_AUTH_AKM_SIZE                        (256 >> 3)
#define CC_AUTH_VERSION_SIZE                    (8 >> 3)
#define CC_AUTH_MSG_LABEL_SIZE                  (8 >> 3)
#define CC_AUTH_KP_SIZE                         (256 >> 3)
#define CC_AUTH_STATUS_SIZE                     (8 >> 3)
#define CC_AUTH_KS_SIZE                         (256 >> 3)
#define CC_AUTH_SEK_SIZE                        (128 >> 3)
#define CC_AUTH_SAK_SIZE                        (128 >> 3)
#define CC_AUTH_SIV_SIZE                        (128 >> 3)
#define CC_AUTH_SLK_SIZE                        (128 >> 3)
#define CC_AUTH_CLK_SIZE                        (128 >> 3)
#define CC_AUTH_DES_CCK_SIZE                    (64 >> 3)
#define CC_AUTH_AES_CCK_SIZE                    (128 >> 3)
#define CC_AUTH_AES_CIV_SIZE                    (128 >> 3)
#define CC_AUTH_URI_CONFIRM_SIZE                (256 >> 3)
#define CC_AUTH_URI_VERSION_SIZE                (256 >> 3)
#define CC_AUTH_URI_SIZE                        (64 >> 3)
#define CC_AUTH_SAC_AUTH_SIZE                   (16)
#define CC_AUTH_RSA_M_N_SIZE                    (256)
#define CC_AUTH_RSA_M_E_SIZE                    (3)
#define CC_AUTH_RSA_N_SIZE                      (256)
#define CC_AUTH_RSA_E_SIZE                      (3)
#define CC_AUTH_RSA_D_SIZE                      (256)
#define CC_AUTH_RSA_P_SIZE                      (128)
#define CC_AUTH_RSA_Q_SIZE                      (128)
#define CC_AUTH_RSA_DP_SIZE                     (128)
#define CC_AUTH_RSA_DQ_SIZE                     (128)
#define CC_AUTH_RSA_QP_SIZE                     (128)

#define CC_AUTH_HOST_DEV_CERTIFICATE_REQ        0x0001
#define CC_AUTH_HOST_BRAND_CERTIFICATE_REQ      0x0002
#define CC_AUTH_SIGNATURE_A_REQ                 0x0004
#define CC_AUTH_DHPH_REQ                        0x0008
#define CC_AUTH_URI_CNF                         0x0010
#define CC_AUTH_STATUS_REQ                      0x0020
#define CC_AUTH_AKH_REQ                         0x0040
#define CC_AUTH_HOST_ID_REQ                     0x0080
#define CC_AUTH_NS_HOST_REQ                     0x0100
#define CC_AUTH_URI_VERSION_REQ                 0x0200

#define CC_AUTH_CICMA_BRAND_CERTIFICATE_VALID   0x01
#define CC_AUTH_CICMA_DEV_CERTIFICATE_VALID     0x02
#define CC_AUTH_SIGNATURE_B_VALID               0x04
#define CC_AUTH_DHPM_VALID                      0x08

#define CC_AUTH_SIGNATURE_VERSION               0x01
#define CC_AUTH_SIGNATURE_MSG_LABEL             0x02

#define SAC_DATA_DECRYPT                        0
#define SAC_DATA_ENCRYPT                        1

#undef INTERFACE
#ifdef _POLARSSL_API_C_
#define INTERFACE
#else
#define INTERFACE extern
#endif

//-----------------------------------------------------------------------------
// Enums
//-----------------------------------------------------------------------------
typedef enum
{
    E_CIPLUS_SSL_CMD_LOAD_CREDENTIALS           = 0x00,
    E_CIPLUS_SSL_CMD_GET_HOST_DEVICE_CERT,
    E_CIPLUS_SSL_CMD_GET_HOST_BRAND_CERT,
    E_CIPLUS_SSL_CMD_VERIFY_CICAM_BRAND_CERT,
    E_CIPLUS_SSL_CMD_VERIFY_CICAM_DEVICE_CERT,
    E_CIPLUS_SSL_CMD_GET_SLK,
    E_CIPLUS_SSL_CMD_GET_CLK,
    E_CIPLUS_SSL_CMD_SET_AUTH_NONCE,
    E_CIPLUS_SSL_CMD_GET_AUTH_NONCE,
    E_CIPLUS_SSL_CMD_MAKE_DHX,
    E_CIPLUS_SSL_CMD_GET_DHX,
    E_CIPLUS_SSL_CMD_COMPUTE_DHPH,
    E_CIPLUS_SSL_CMD_VERIFY_DHPH,
    E_CIPLUS_SSL_CMD_GET_DHPH,
    E_CIPLUS_SSL_CMD_VERIFY_DHPM,
    E_CIPLUS_SSL_CMD_GET_DHPM,
    E_CIPLUS_SSL_CMD_COMPUTE_DHSK,
    E_CIPLUS_SSL_CMD_GET_DHSK,
    E_CIPLUS_SSL_CMD_RSA_SIGN,
    E_CIPLUS_SSL_CMD_RSA_VERIFY,
    E_CIPLUS_SSL_CMD_VERIFY_SIGNATURE_A,
    E_CIPLUS_SSL_CMD_GET_SIGNATURE_A,
    E_CIPLUS_SSL_CMD_SHA_256_HASH,
    E_CIPLUS_SSL_CMD_SET_AKH,
    E_CIPLUS_SSL_CMD_GET_AKH,
    E_CIPLUS_SSL_CMD_AES_128_ECB_ENCRYPT,
    E_CIPLUS_SSL_CMD_AES_128_ECB_DECRYPT,
    E_CIPLUS_SSL_CMD_AES_128_CBC_ENCRYPT,
    E_CIPLUS_SSL_CMD_AES_128_CBC_DECRYPT,
    E_CIPLUS_SSL_CMD_AES_128_XCBC_MAC,
    E_CIPLUS_SSL_CMD_GET_HOST_ID,
    E_CIPLUS_SSL_CMD_GET_CICAM_ID,
    E_CIPLUS_SSL_CMD_MAKE_NS_HOST,
    E_CIPLUS_SSL_CMD_GET_NS_HOST,
    E_CIPLUS_SSL_CMD_SET_NS_MODULE,
    E_CIPLUS_SSL_CMD_GET_NS_MODULE,
    E_CIPLUS_SSL_CMD_SET_SCRAMBLER_MODE,
    E_CIPLUS_SSL_CMD_GET_SCRAMBLER_MODE,
    E_CIPLUS_SSL_CMD_GET_CICAM_BRAND_ID,
    E_CIPLUS_SSL_CMD_IDSA_ENCRYPT,
    E_CIPLUS_SSL_CMD_IDSA_DECRYPT,
    E_CIPLUS_SSL_CMD_AES_SET_SBOX,
    E_CIPLUS_SSL_CMD_UPDATE_SYSTIME,
    E_CIPLUS_SSL_CMD_DONE                       = 0xFF
} E_CIPLUS_SSL_CMD_T;

typedef enum
{
    E_CIPLUS_CC_SIGNATURE_TAG_VERSION,
    E_CIPLUS_CC_SIGNATURE_TAG_MSG_LABEL,
    E_CIPLUS_CC_SIGNATURE_TAG_AUTH_NONCE,
    E_CIPLUS_CC_SIGNATURE_TAG_DHPM,
    E_CIPLUS_CC_SIGNATURE_TAG_DHPH
} E_CIPLUS_CC_SIGNATURE_TAG;

typedef enum
{
    E_CIPLUS_CC_INVALID_SCRAMBLER_MODE          = 0x00,
    E_CIPLUS_CC_DES_56_ECB,
    E_CIPLUS_CC_AES_128_CBC
} E_CIPLUS_CC_SCRAMBLER_MODE;

typedef enum {
    EN_CREDENTIAL_ROOT_CERTIFICATE              = 0x01,
    EN_CREDENTIAL_HOST_DEVICE_CERTIFICATE,
    EN_CREDENTIAL_HOST_BRAND_CERTIFICATE,
    EN_CREDENTIAL_HDQ,
    EN_CREDENTIAL_DH_P,
    EN_CREDENTIAL_DH_G,
    EN_CREDENTIAL_DH_Q,
    EN_CREDENTIAL_SIV,
    EN_CREDENTIAL_PRNG_SEED,
    EN_CREDENTIAL_SLK,
    EN_CREDENTIAL_CLK,
    EN_CREDENTIAL_NONE                          = 0xFF
} EN_CREDENTIAL_TYPE;

//-----------------------------------------------------------------------------
// Structures
//-----------------------------------------------------------------------------
#define U8  unsigned char
#define U16 unsigned short
#define U32 unsigned long

typedef struct
{
    U16 u16Year;
    U8  u8Month;
    U8  u8Day;
    U8  u8Hour;
    U8  u8Min;
    U8  u8Sec;
} SYSTIME;

//-----------------------------------------------------------------------------
// Exported global variables
//-----------------------------------------------------------------------------
INTERFACE SYSTIME gSysTime;

//------------------------------------------------------------------------------
// Extern Functions
//------------------------------------------------------------------------------
INTERFACE int PolarSSL_Get_HostID( const U8 *u8pInput, U8* u8Output);

INTERFACE U8 ASCII2HEX( char* Ascii );

#undef INTERFACE

#ifdef __cplusplus
}
#endif

#endif // _POLARSSL_API_H_
