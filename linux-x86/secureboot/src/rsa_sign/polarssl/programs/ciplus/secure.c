#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "polarssl/config.h"
#include "polarssl/polarssl_api.h"
#include "polarssl/aes.h"
#include "polarssl/des.h"

#define USAGE   \
    "\n  Readme: \n" \
    "\n  For CI+ Credentials: secure <mode> <device cert filename> <keys cert filename> <serial no> <ci+.bin filename> \n" \
    "\n  <mode>: 0 = Create ci+.bin, 1 = Verify ci+.bin\n" \
    "\n  example: ./secure 0 device.der keys.der 3 ci+.bin\n" \
    "\n  example: ./secure 1 ci+.bin\n" \
    "\n  For CANAL READY Auth Certificate: secure <mode> <canal ready auth cert filename> <canal_ready_auth.bin filename> \n" \
    "\n  <mode>: 2 = Create canal_ready_auth.bin, 3 = Verify canal_ready_auth.bin\n" \
    "\n  example: ./secure 2 TNT_XXX_BETA7.bin canal_ready_auth.bin\n" \
    "\n  example: ./secure 3 canal_ready_auth.bin\n" \
    "\n"

#define LOG 1

#define U8  unsigned char
#define U16 unsigned short
#define U32 unsigned long

#define BIN_SERIAL_NO_LENGTH                        4
#define BIN_CIPLUS_HOST_ID_LENGTH                   8
#define BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH         2
#define BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH   2
#define BIN_CANAL_READY_AUTH_CERT_SIZE_LENGTH       2
#define BIN_CIPLUS_CRC_LENGTH                       4

/* CI+ Credentials */
static U8 _u8agDH_p[CC_AUTH_DH_P_SIZE] =
{
    0xa4, 0x79, 0x27, 0x2e, 0x24, 0x3d, 0x44, 0x36, 0xc8, 0x5c, 0x82, 0xb0, 0xff, 0x7d, 0x93, 0xe1,
    0x63, 0x8d, 0x82, 0x9d, 0x2a, 0xc7, 0x9d, 0x4d, 0x40, 0x99, 0xc8, 0xd3, 0x25, 0xa5, 0x4f, 0x01,
    0x15, 0xec, 0x29, 0x01, 0x18, 0x3b, 0x93, 0xb8, 0x36, 0xb8, 0xe0, 0xaa, 0x4f, 0x3a, 0x20, 0x77,
    0x6e, 0xb4, 0x96, 0x37, 0x36, 0x55, 0x1c, 0x36, 0x60, 0x00, 0xf7, 0x95, 0x71, 0x74, 0x48, 0xc4,
    0x77, 0x6c, 0xb2, 0x79, 0xca, 0xaa, 0x33, 0x62, 0x87, 0xf5, 0x42, 0x12, 0x1c, 0x43, 0xe0, 0x1c,
    0x12, 0x53, 0xb2, 0xef, 0x31, 0x56, 0x91, 0x5e, 0xe0, 0xf3, 0x92, 0x71, 0x80, 0x44, 0x0d, 0xa2,
    0xf2, 0x14, 0x2f, 0xb4, 0x29, 0xda, 0xf6, 0xe6, 0x31, 0x65, 0x4f, 0x12, 0xea, 0x88, 0x12, 0xc3,
    0x64, 0xe5, 0xf6, 0xe8, 0x29, 0xc4, 0x2d, 0xb3, 0x84, 0xe7, 0x6a, 0x15, 0x91, 0x0b, 0xd2, 0x38,
    0x48, 0x35, 0x59, 0x78, 0xd7, 0xad, 0xef, 0x52, 0x1e, 0x5c, 0x29, 0x4e, 0xea, 0xd0, 0x30, 0xd9,
    0xc2, 0x96, 0x66, 0xc6, 0x92, 0x20, 0xc2, 0xfa, 0xd5, 0xd5, 0x58, 0xd7, 0x26, 0xef, 0x46, 0x58,
    0x36, 0xc6, 0x22, 0x08, 0x7e, 0x48, 0x2f, 0xa6, 0xd5, 0x9e, 0x1c, 0x1c, 0x8a, 0x0f, 0x5a, 0x09,
    0xe1, 0x7d, 0xb7, 0xe6, 0x9a, 0xb2, 0x6f, 0xe7, 0x34, 0x96, 0x96, 0x63, 0xbd, 0x71, 0xaa, 0xfd,
    0x81, 0x81, 0x99, 0xef, 0xaa, 0xdc, 0x54, 0xed, 0x6a, 0x4b, 0xef, 0xcd, 0x39, 0x67, 0x71, 0x69,
    0x76, 0x0c, 0xd5, 0x54, 0xd4, 0xf3, 0xcf, 0x90, 0x52, 0xce, 0xad, 0xc6, 0x05, 0xe6, 0x05, 0xb4,
    0xe2, 0xff, 0x00, 0x25, 0xa2, 0x3a, 0xfc, 0xc1, 0x54, 0x6e, 0x52, 0x6e, 0x83, 0x0b, 0xde, 0x3c,
    0x62, 0xd7, 0x3c, 0x7a, 0x8e, 0xee, 0x14, 0x34, 0x9a, 0x2e, 0xcb, 0x69, 0xdf, 0x1c, 0xc0, 0x03
};

static U8 _u8agDH_g[CC_AUTH_DH_G_SIZE] =
{
    0x96, 0xb1, 0x9b, 0xd8, 0xe1, 0x0c, 0x5f, 0x9d, 0xe4, 0x12, 0x66, 0x49, 0xcb, 0x51, 0x11, 0x65,
    0x73, 0x9f, 0xeb, 0x2c, 0xaf, 0x27, 0x20, 0x24, 0x77, 0xf8, 0x42, 0x92, 0xc3, 0x30, 0x36, 0x06,
    0x64, 0xa4, 0x89, 0x5d, 0xce, 0x0a, 0x51, 0x34, 0x56, 0x0f, 0xba, 0x24, 0x25, 0xcc, 0x40, 0x29,
    0x72, 0x5d, 0x40, 0x3b, 0x6e, 0x6f, 0x1f, 0x22, 0x3f, 0x4e, 0x3d, 0xb7, 0x36, 0xee, 0x10, 0xbb,
    0xd8, 0x45, 0x3c, 0xe4, 0x69, 0x3c, 0x33, 0x34, 0x51, 0xf2, 0x10, 0x13, 0xad, 0xd3, 0x1e, 0xe8,
    0x0b, 0xab, 0xa2, 0x4f, 0xdf, 0xa4, 0xec, 0xb6, 0x05, 0xf0, 0x3c, 0x9f, 0x09, 0x35, 0xa8, 0x7f,
    0xd4, 0x4d, 0x3b, 0x9c, 0x23, 0x4d, 0xb9, 0xde, 0xd7, 0xa7, 0x20, 0xce, 0x25, 0x9d, 0x1c, 0x65,
    0x49, 0x32, 0xed, 0x9e, 0xfe, 0x02, 0x76, 0x11, 0x0d, 0x23, 0x5b, 0xaa, 0xaf, 0x61, 0xa5, 0x1e,
    0x04, 0xe9, 0x37, 0x2a, 0x23, 0x97, 0x55, 0x64, 0x43, 0x53, 0x4f, 0x3b, 0xb7, 0xfb, 0x73, 0x23,
    0x61, 0x03, 0x4a, 0x16, 0x65, 0x78, 0x6d, 0xcc, 0x94, 0x41, 0xf5, 0x60, 0x40, 0x8e, 0x15, 0xf2,
    0x87, 0x8e, 0x35, 0x3a, 0xa6, 0xb0, 0x78, 0xed, 0xcd, 0x71, 0x8f, 0x5c, 0xff, 0xee, 0x9e, 0x69,
    0x1a, 0xe0, 0xa8, 0xd0, 0xd5, 0xf9, 0x24, 0x2a, 0xdd, 0xbd, 0xf2, 0x3d, 0x21, 0xb2, 0x13, 0x2f,
    0xe7, 0xd2, 0xe3, 0xc9, 0x1a, 0x64, 0x65, 0x14, 0x14, 0x37, 0x47, 0x23, 0x7c, 0xbb, 0xd3, 0x0f,
    0x4d, 0xc9, 0x65, 0x9d, 0xf5, 0xb7, 0xf5, 0x86, 0xcb, 0xd7, 0x29, 0x5b, 0x08, 0x31, 0x77, 0x15,
    0xc5, 0x81, 0xf2, 0x04, 0x60, 0x2f, 0x39, 0xb8, 0xfd, 0x6c, 0xa6, 0xc4, 0xc9, 0x43, 0x35, 0xc1,
    0x40, 0x0e, 0x30, 0x0b, 0x22, 0x9a, 0xcd, 0x50, 0x87, 0x34, 0x61, 0x6d, 0x23, 0x5b, 0x15, 0x60
};

static U8 _u8agDH_q[CC_AUTH_DH_Q_SIZE] =
{
    0xd8, 0x5e, 0xab, 0xe8, 0xbe, 0x5b, 0xe3, 0xd2, 0xcf, 0x50, 0xe7, 0x90, 0xa8, 0x6a, 0x3f, 0xad,
    0xda, 0xb6, 0xe8, 0xa5, 0x0f, 0x32, 0x87, 0x71, 0xfd, 0x0b, 0xf0, 0x52, 0xae, 0x3c, 0xa9, 0x37
};

static U8 _u8agSIV[CC_AUTH_SIV_SIZE] =
{
    0xd1, 0xe8, 0xde, 0x32, 0x2e, 0x44, 0xd8, 0x7c, 0x56, 0x90, 0x81, 0x89, 0x5f, 0x50, 0x50, 0x35
};

static U8 _u8agPRNGSeed[CC_AUTH_PRNG_SEED_SIZE] =
{
    0xe5, 0x82, 0x97, 0x31, 0x7f, 0x8c, 0x60, 0x47, 0xdd, 0xd4, 0xa5, 0xd3, 0xd3, 0x2d, 0xc1, 0x5c
};

static U8 _gu8aSLK[CC_AUTH_SLK_SIZE] =
{
    0x9c, 0x69, 0xd1, 0x46, 0x70, 0x0d, 0x81, 0x6c, 0xfd, 0x49, 0x69, 0x71, 0x26, 0x93, 0xa3, 0x8a
};

static U8 _gu8aCLK[CC_AUTH_CLK_SIZE] =
{
    0xae, 0xdc, 0x1b, 0x80, 0x4c, 0x50, 0xd9, 0x5d, 0xad, 0x6d, 0x3d, 0x46, 0xac, 0xd6, 0x01, 0xa8
};

/* Auth & Encryt Keys. */
static U8 _gu8aAesXcbcKey[16] =
{
    0x09, 0x28, 0x48, 0x92, 0x49, 0x09, 0x82, 0x39, 0x66, 0x83, 0x09, 0x82, 0x39, 0x68, 0x36, 0x21
};
static U8 _gu8aAesCbcKey[16] =
{
    0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78, 0x87, 0x96, 0xA5, 0xB4, 0xC3, 0xD2, 0xE1, 0xF0
};
static U8 _gu8aAesCbcIV[16] =
{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

#if LOG
void _Log( U8 *u8pInfo, U16 u16InfoSize )
{
    U16 k = 0;

    if ( NULL == u8pInfo )
    {
        return ;
    }

    printf( "\t" );

    for ( k = 0; k < u16InfoSize; k++ )
    {
        printf( "0x%02X", u8pInfo[k] );
        if ( 0 == ( ( k + 1 ) & 0x000F ) )
            printf( "\r\n\t" );
        else
            printf( " " );
    }
    printf( "\r\n" );
}
#else
void _Log( U8 *u8pInfo, U16 u16InfoSize )
{
    return;
}
#endif

void aes_cbc_handling( U8 u8Mode, U8* u8pInput, U16 u16InputLen, U8* u8pOutput, U8* u8pKey, U8* u8pIV )
{
    aes_context aes_ctx;

    if ( AES_ENCRYPT == u8Mode )
    {
        memset( &aes_ctx, 0, sizeof( aes_context ) );
        aes_setkey_enc( &aes_ctx, u8pKey, 128 );
        aes_crypt_cbc( &aes_ctx, AES_ENCRYPT, u16InputLen, u8pIV, u8pInput, u8pOutput );
    }
    else if ( AES_DECRYPT == u8Mode )
    {
        memset( &aes_ctx, 0, sizeof( aes_context ) );
        aes_setkey_dec( &aes_ctx, u8pKey, 128 );

        aes_crypt_cbc( &aes_ctx, AES_DECRYPT, u16InputLen, u8pIV, u8pInput, u8pOutput );
    }
    else
        printf( "[Error] AES Mode is wrong!\r\n" );
}

void aes_xcbc_handling( U8* u8pInput, U16 u16InputLen, U8* u8pOutput, U8* u8pKey )
{
    aes_context aes_ctx;

    memset( &aes_ctx, 0, sizeof( aes_context ) );

    aes_setkey_enc( &aes_ctx, u8pKey, CC_AUTH_SAK_SIZE << 3 );
    aes_crypt_xcbc( &aes_ctx, AES_XCBC_MAC, u16InputLen, u8pInput, u8pOutput );
}

unsigned long crc32_encode(const unsigned char *octets, int len)
{
  unsigned long crc = 0xFFFFFFFF;
  unsigned long temp;
  int j;

  while (len--)
  {
    temp = (unsigned long)((crc & 0xFF) ^ *octets++);
    for (j = 0; j < 8; j++)
    {
      if (temp & 0x1)
        temp = (temp >> 1) ^ 0xEDB88320;
      else
        temp >>= 1;
    }
    crc = (crc >> 8) ^ temp;
  }
  return crc ^ 0xFFFFFFFF;
}

int main( int argc, char *argv[] )
{
    FILE *fin_root_cert = NULL;
    off_t filesize_root_cert = 0;
    FILE *fin_brand_cert = NULL;
    off_t filesize_brand_cert = 0;
    FILE *fin_device_cert = NULL;
    off_t filesize_device_cert = 0;
    FILE *fin_keys_cert = NULL;
    off_t filesize_keys_cert = 0;
    FILE *fout_ciplus = NULL;
    
    FILE *fin_canal_ready_auth_cert = NULL;
    off_t filesize_canal_ready_auth_cert = 0;
    FILE *fout_canal_ready_auth_cert = NULL;
    
    EN_CREDENTIAL_TYPE eCredentialType = EN_CREDENTIAL_NONE;
    off_t filesize = 0;
    U16 u16CrendentialsBinSize = 0;
    U16 u16CertificateLen = 0;
    U8 u8aTempBuf[6000] = { 0 };
    U8 u8aXCBC_Auth[CC_AUTH_SAK_SIZE] = { 0 };
    U8 u8agHostID[CC_AUTH_ID_SIZE] = { 0 };
    U16 u16BufIndex = 0, u16Offset = 0;
    U16 u16PaddingLen = 0;
    U32 u32SerialNumber = 0;
    U32 u32CRC = 0;
    U8 u8aCRC[BIN_CIPLUS_CRC_LENGTH] = { 0 };
    U8 i = 0;

    printf( "============================\r\n" );
    printf( "=== CI+ Credentials Tool ===\r\n" );
    printf( "============================\r\n" );

    if ( ('0' == *argv[1]) && (8 == argc) )
    {
        if ( NULL == argv[2] )
        {
            printf( USAGE );
            goto exit;
        }
        else
            printf( "Root Certificate: %s\r\n", argv[2] );

        if ( NULL == argv[3] )
        {
            printf( USAGE );
            goto exit;
        }
        else
            printf( "Brand Certificate: %s\r\n", argv[3] );

        if ( NULL == argv[4] )
        {
            printf( USAGE );
            goto exit;
        }
        else
            printf( "Device Certificate: %s\r\n", argv[4] );

        if ( NULL == argv[5] )
        {
            printf( USAGE );
            goto exit;
        }
        else
            printf( "Keys Certificate: %s\r\n", argv[5] );

        if ( NULL == argv[6] )
        {
            printf( USAGE );
            goto exit;
        }
        else
        {
            if(atof(argv[6]) > 0xFFFFFFFF)
            {
                printf( "S/N Range is between 0 to 4294967295 \r\n" );
                goto exit;
            }
            else
                printf( "S/N: %s\r\n", argv[6] );
        }

        if ( NULL == argv[7] )
        {
            printf( USAGE );
            goto exit;
        }
        else
            printf( "CI+ Credentials Bin: %s\r\n", argv[7] );

        /***************************************************************************/
        if ( ( fin_root_cert = fopen( argv[2], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed\n", argv[2] );
            goto exit;
        }
        fseek( fin_root_cert, 0, SEEK_END );
        filesize_root_cert = ftell( fin_root_cert );
        fseek( fin_root_cert, 0, SEEK_SET );

        if ( ( fin_brand_cert = fopen( argv[3], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed\n", argv[3] );
            goto exit;
        }
        fseek( fin_brand_cert, 0, SEEK_END );
        filesize_brand_cert = ftell( fin_brand_cert );
        fseek( fin_brand_cert, 0, SEEK_SET );

        if ( ( fin_device_cert = fopen( argv[4], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed\n", argv[4] );
            goto exit;
        }
        fseek( fin_device_cert, 0, SEEK_END );
        filesize_device_cert = ftell( fin_device_cert );
        fseek( fin_device_cert, 0, SEEK_SET );
        
        if ( ( fin_keys_cert = fopen( argv[5], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed\n", argv[5] );
            goto exit;
        }
        fseek( fin_keys_cert, 0, SEEK_END );
        filesize_keys_cert = ftell( fin_keys_cert );
        fseek( fin_keys_cert, 0, SEEK_SET );

        /***************************************************************************/
        if ( ( fout_ciplus = fopen( argv[7], "wb+" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,wb+) failed!\r\n", argv[5] );
            goto exit;
        }

        u16Offset = ( BIN_SERIAL_NO_LENGTH + BIN_CIPLUS_HOST_ID_LENGTH ); // Serial No. + Host ID
        u16BufIndex += ( u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH );

        /* Root Cert */
        printf( "Handling Root Cert ...\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_ROOT_CERTIFICATE;
        u16CertificateLen = (unsigned short)filesize_root_cert;
        printf( "Root Cert: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        if ( fread( &u8aTempBuf[u16BufIndex], 1, u16CertificateLen, fin_root_cert ) != u16CertificateLen )
        {
            fprintf( stderr, "fread %s failed!\r\n", argv[2] );
            goto exit;
        }
        u16BufIndex += u16CertificateLen;

        /* Host Device Cert */
        printf( "Handling Host Device Cert ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_HOST_DEVICE_CERTIFICATE;
        u16CertificateLen = (unsigned short)filesize_device_cert;
        printf( "Host Device Cert: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        if ( fread( &u8aTempBuf[u16BufIndex], 1, u16CertificateLen, fin_device_cert ) != u16CertificateLen )
        {
            fprintf( stderr, "fread %s failed!\r\n", argv[4] );
            goto exit;
        }
        u16BufIndex += u16CertificateLen;

        /* Host Brand Cert */
        printf( "Handling Host Brand Cert ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_HOST_BRAND_CERTIFICATE;
        u16CertificateLen = (unsigned short)filesize_brand_cert;
        printf( "Host Brand Cert: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        if ( fread( &u8aTempBuf[u16BufIndex], 1, u16CertificateLen, fin_brand_cert ) != u16CertificateLen )
        {
            fprintf( stderr, "fread %s failed!\r\n", argv[3] );
            goto exit;
        }
        u16BufIndex += u16CertificateLen;

        /* HDQ */
        printf( "Handling HDQ ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_HDQ;
        u16CertificateLen = (unsigned short)filesize_keys_cert;
        printf( "HDQ: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        if ( fread( &u8aTempBuf[u16BufIndex], 1, u16CertificateLen, fin_keys_cert ) != u16CertificateLen )
        {
            fprintf( stderr, "fread %s failed!\r\n", argv[5] );
            goto exit;
        }
        u16BufIndex += u16CertificateLen;

        /* DH_P */
        printf( "Handling DH_P ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_DH_P;
        u16CertificateLen = sizeof( _u8agDH_p );
        printf( "DH_P: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _u8agDH_p, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* DH_G */
        printf( "Handling DH_G ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_DH_G;
        u16CertificateLen = sizeof( _u8agDH_g );
        printf( "DH_G: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _u8agDH_g, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* DH_Q */
        printf( "Handling DH_Q ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_DH_Q;
        u16CertificateLen = sizeof( _u8agDH_q );
        printf( "DH_Q: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _u8agDH_q, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* SIV */
        printf( "Handling SIV ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_SIV;
        u16CertificateLen = sizeof( _u8agSIV );
        printf( "SIV: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _u8agSIV, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* PRNG Seed */
        printf( "Handling PRNG Seed ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_PRNG_SEED;
        u16CertificateLen = sizeof( _u8agPRNGSeed );
        printf( "PRNG Seed: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _u8agPRNGSeed, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* SLK */
        printf( "Handling SLK ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_SLK;
        u16CertificateLen = sizeof( _gu8aSLK );
        printf( "SLK: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _gu8aSLK, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* CLK */
        printf( "Handling CLK ...\r\n" );
        u8aTempBuf[u16BufIndex] = EN_CREDENTIAL_CLK;
        u16CertificateLen = sizeof( _gu8aCLK );
        printf( "CLK: %u bytes\n", u16CertificateLen );
        u8aTempBuf[u16BufIndex + 1] = (U8)( u16CertificateLen >> 8 );
        u8aTempBuf[u16BufIndex + 2] = (U8)u16CertificateLen;
        u16BufIndex += 3;
        memcpy( &u8aTempBuf[u16BufIndex], _gu8aCLK, u16CertificateLen );
        u16BufIndex += u16CertificateLen;

        /* Padding... */
        u16PaddingLen = 16 - ( ( u16BufIndex - u16Offset - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH ) % 16 );
        if ( u16PaddingLen )
        {
            u8aTempBuf[u16BufIndex] = 0x80;
            u16BufIndex++;
            u16PaddingLen--;

            for ( ; u16PaddingLen > 0; u16PaddingLen-- )
            {
                u8aTempBuf[u16BufIndex] = 0x00;
                u16BufIndex++;
            }
        }

        /* AES-128-XCBC MAC */
        printf( "=== AES-128-XCBC MAC ...\r\n" );
        aes_xcbc_handling( &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], (unsigned short)(u16BufIndex - u16Offset - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH), &u8aTempBuf[u16BufIndex], _gu8aAesXcbcKey );
        u16BufIndex += CC_AUTH_SAC_AUTH_SIZE;

        //Credentials Size
        u16CrendentialsBinSize = u16BufIndex - u16Offset;
        u8aTempBuf[u16Offset    ] = (U8)( u16CrendentialsBinSize >> 8 );
        u8aTempBuf[u16Offset + 1] = (U8)( u16CrendentialsBinSize      );
        printf( "Credentials Size is %d bytes.\r\n", u16CrendentialsBinSize );

        u32SerialNumber = atol(argv[6]);
        //Serial number
        u8aTempBuf[0] = (U8)( u32SerialNumber >> 24 );
        u8aTempBuf[1] = (U8)( u32SerialNumber >> 16 );
        u8aTempBuf[2] = (U8)( u32SerialNumber >>  8 );
        u8aTempBuf[3] = (U8)( u32SerialNumber       );

        //Host ID
        PolarSSL_Get_HostID( &u8aTempBuf[u16Offset], u8agHostID );
        printf( "~HostID: %02X %02X %02X %02X %02X %02X %02X %02X\r\n", u8agHostID[0], u8agHostID[1], u8agHostID[2], u8agHostID[3], u8agHostID[4], u8agHostID[5], u8agHostID[6], u8agHostID[7] );
        memcpy( &u8aTempBuf[BIN_SERIAL_NO_LENGTH], u8agHostID, CC_AUTH_ID_SIZE );

        /* AES-128-CBC Encrypt */
        printf( "=== AES-128-CBC Encrypt ...\r\n" );
        aes_cbc_handling( AES_ENCRYPT, &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], (unsigned short)(u16CrendentialsBinSize - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH), &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], _gu8aAesCbcKey, _gu8aAesCbcIV );

        /* Make up file */
        printf( "=== Make up %s ...\r\n", argv[7] );
        if ( 0 == fwrite( u8aTempBuf, u16Offset + u16CrendentialsBinSize, 1, fout_ciplus ) )
        {
            fprintf( stderr, "fwrite(%s,wb) failed!\r\n", argv[7] );
            goto exit;
        }

        //CRC32
        u32CRC = ~crc32_encode( u8aTempBuf, u16Offset + u16CrendentialsBinSize );
        u8aCRC[0] = (U8)( u32CRC >> 24 );
        u8aCRC[1] = (U8)( u32CRC >> 16 );
        u8aCRC[2] = (U8)( u32CRC >>  8 );
        u8aCRC[3] = (U8)( u32CRC       );
        printf("~CRC32: 0x%lx\r\n", u32CRC);

        /* Make up file of CRC32 */
        if ( 0 == fwrite( u8aCRC, BIN_CIPLUS_CRC_LENGTH, 1, fout_ciplus ) )
        {
            fprintf( stderr, "fwrite(%s,wb) failed!\r\n", argv[7] );
            goto exit;
        }

        printf( "Total Credentials Bin Length is %d bytes.\r\n", u16CrendentialsBinSize );
        printf( "The real Credential content:\r\n" );
        _Log( u8aTempBuf + 12, u16CrendentialsBinSize);

        filesize = ftell( fout_ciplus );
        printf( "%s has %d bytes.\r\n", argv[7], (int)filesize );
    }
    else if ('1' == *argv[1])
    {
        if ( ( fout_ciplus = fopen( argv[2], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed!\r\n", argv[2] );
            goto exit;
        }

        if ( fread( u8aTempBuf, 1, BIN_SERIAL_NO_LENGTH, fout_ciplus ) != BIN_SERIAL_NO_LENGTH )
        {
            fprintf( stderr, "fread failed!\r\n" );
            goto exit;
        }
        u32SerialNumber = (U32)u8aTempBuf[0] << 24 | (U32)u8aTempBuf[1] << 16 | (U32)u8aTempBuf[2] << 8 | (U32)u8aTempBuf[3];
        printf( "S/N: %ld \r\n", u32SerialNumber);

        if ( fread( &u8aTempBuf[BIN_SERIAL_NO_LENGTH], 1, BIN_CIPLUS_HOST_ID_LENGTH, fout_ciplus ) != BIN_CIPLUS_HOST_ID_LENGTH )
        {
            fprintf( stderr, "fread failed!\r\n" );
            goto exit;
        }
        memcpy( u8agHostID, &u8aTempBuf[BIN_SERIAL_NO_LENGTH], BIN_CIPLUS_HOST_ID_LENGTH );
        printf( "~HostID: 0x%02X%02X%02X%02X%02X%02X%02X%02X \r\n", u8agHostID[0], u8agHostID[1], u8agHostID[2], u8agHostID[3], u8agHostID[4], u8agHostID[5], u8agHostID[6], u8agHostID[7] );

        u16Offset = ( BIN_SERIAL_NO_LENGTH + BIN_CIPLUS_HOST_ID_LENGTH );

        if ( fread( &u8aTempBuf[u16Offset], 1, BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH, fout_ciplus ) != BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH )
        {
            fprintf( stderr, "fread failed!\r\n" );
            goto exit;
        }
        u16CrendentialsBinSize = (U16)u8aTempBuf[u16Offset] << 8 |
                                    (U16)u8aTempBuf[u16Offset + 1];
        printf( "Credentials Bin Size is %d bytes.\r\n", u16CrendentialsBinSize );

        if ( (U16)fread( &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], 1, u16CrendentialsBinSize - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH + BIN_CIPLUS_CRC_LENGTH, fout_ciplus ) != ( u16CrendentialsBinSize - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH + BIN_CIPLUS_CRC_LENGTH ) )
        {
            fprintf( stderr, "fread failed!\r\n" );
            goto exit;
        }

        /* CRC32 Checking */
        u32CRC = ~crc32_encode( u8aTempBuf, u16Offset + u16CrendentialsBinSize );

        if ( ((U32)u8aTempBuf[u16Offset + u16CrendentialsBinSize + 3] | (U32)u8aTempBuf[u16Offset + u16CrendentialsBinSize + 2] << 8 | (U32)u8aTempBuf[u16Offset + u16CrendentialsBinSize + 1] << 16 | (U32)u8aTempBuf[u16Offset + u16CrendentialsBinSize] << 24) == u32CRC )
            printf("~u32CRC = 0x%lX, OK! \r\n", u32CRC);
        else
            printf("~u32CRC = 0x%lX, NG! \r\n", u32CRC);

        /* AES-128-CBC Decrypt */
        printf( "=== AES-128-CBC Decrypt ...\r\n" );
        aes_cbc_handling( AES_DECRYPT, &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], (unsigned short)u16CrendentialsBinSize - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH, &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], _gu8aAesCbcKey, _gu8aAesCbcIV );

        /* AES-128-XCBC MAC */
        printf( "=== AES-128-XCBC MAC ...\r\n" );
        aes_xcbc_handling( &u8aTempBuf[u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH], (unsigned short)( u16CrendentialsBinSize - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH - CC_AUTH_SAC_AUTH_SIZE ), u8aXCBC_Auth, _gu8aAesXcbcKey );

        if ( memcmp( u8aXCBC_Auth, &u8aTempBuf[u16Offset + u16CrendentialsBinSize - CC_AUTH_SAC_AUTH_SIZE], CC_AUTH_SAC_AUTH_SIZE ) )
            printf( "Auth NG!\n" );
        else
            printf( "Auth OK!\n" );
        u16BufIndex = u16Offset + BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH;

        /* Root Cert */
        if ( EN_CREDENTIAL_ROOT_CERTIFICATE == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling Root Cert ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* Host Device Cert */
        if ( EN_CREDENTIAL_HOST_DEVICE_CERTIFICATE == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling Host Device Cert ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* Host Brand Cert */
        if ( EN_CREDENTIAL_HOST_BRAND_CERTIFICATE == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling Host Brand Cert ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* HDQ */
        if ( EN_CREDENTIAL_HDQ == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling HDQ ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* DH_P */
        if ( EN_CREDENTIAL_DH_P == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling DH_P ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* DH_G */
        if ( EN_CREDENTIAL_DH_G == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling DH_G ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* DH_Q */
        if ( EN_CREDENTIAL_DH_Q == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling DH_Q ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* SIV */
        if ( EN_CREDENTIAL_SIV == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling SIV ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* PRNG Seed */
        if ( EN_CREDENTIAL_PRNG_SEED == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling PRNG Seed ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* SLK */
        if ( EN_CREDENTIAL_SLK == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling SLK ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }

        /* CLK */
        if ( EN_CREDENTIAL_CLK == u8aTempBuf[u16BufIndex] )
        {
            printf( "Handling CLK ...\r\n" );

            u16BufIndex++;
            u16CertificateLen  = (U16)u8aTempBuf[u16BufIndex] << 8 | (U16)u8aTempBuf[u16BufIndex + 1];
            u16BufIndex += 2;
            _Log( &u8aTempBuf[u16BufIndex], u16CertificateLen );
            u16BufIndex += u16CertificateLen;
        }
    }
    else if ( '2' == *argv[1] )
    {
        if ( NULL == argv[2] )
        {
            printf( USAGE );
            goto exit;
        }
        else
            printf( "CANAL READY Auth Certificate: %s\r\n", argv[2] );

        /***************************************************************************/
        if ( ( fin_canal_ready_auth_cert = fopen( argv[2], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed\n", argv[2] );
            goto exit;
        }
        fseek( fin_canal_ready_auth_cert, 0, SEEK_END );
        filesize_canal_ready_auth_cert = ftell( fin_canal_ready_auth_cert );
        fseek( fin_canal_ready_auth_cert, 0, SEEK_SET );

        /***************************************************************************/
        if ( ( fout_canal_ready_auth_cert = fopen( argv[3], "wb+" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,wb+) failed!\r\n", argv[3] );
            goto exit;
        }

        u16BufIndex = BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + BIN_CANAL_READY_AUTH_CERT_SIZE_LENGTH;

        u16CertificateLen = (unsigned short)filesize_canal_ready_auth_cert;
        printf( "CANAL READY Auth Cert: %u bytes\n", u16CertificateLen );
        if ( fread( &u8aTempBuf[u16BufIndex], 1, u16CertificateLen, fin_canal_ready_auth_cert ) != u16CertificateLen )
        {
            fprintf( stderr, "fread %s failed!\r\n", argv[2] );
            goto exit;
        }
        u16BufIndex += u16CertificateLen;
        u16CertificateLen += BIN_CANAL_READY_AUTH_CERT_SIZE_LENGTH;

        /* Padding... */
        u16PaddingLen = 16 - ( u16CertificateLen % 16 );
        if ( u16PaddingLen )
        {
            u8aTempBuf[u16BufIndex] = 0x80;
            u16BufIndex++;
            u16PaddingLen--;
        
            for ( ; u16PaddingLen > 0; u16PaddingLen-- )
            {
                u8aTempBuf[u16BufIndex] = 0x00;
                u16BufIndex++;
            }
        }

        u8aTempBuf[2] = (U8)( filesize_canal_ready_auth_cert >> 8 );
        u8aTempBuf[3] = (U8)( filesize_canal_ready_auth_cert      );

        /* AES-128-XCBC MAC */
        printf( "=== AES-128-XCBC MAC ...\r\n" );
        aes_xcbc_handling( &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], (unsigned short)(u16BufIndex - BIN_CIPLUS_CREDENTIALSS_SIZE_LENGTH), &u8aTempBuf[u16BufIndex], _gu8aAesXcbcKey );

        u16BufIndex += CC_AUTH_SAC_AUTH_SIZE;

        //Credentials Size
        u16CrendentialsBinSize = u16BufIndex - BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH;
        u8aTempBuf[0] = (U8)( u16CrendentialsBinSize >> 8 );
        u8aTempBuf[1] = (U8)( u16CrendentialsBinSize      );

        printf( "CANAL READY Auth Certificate Bin Size is %d bytes.\r\n", u16CrendentialsBinSize );

        /* AES-128-CBC Encrypt */
        printf( "=== AES-128-CBC Encrypt ...\r\n" );
        aes_cbc_handling( AES_ENCRYPT, &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], u16CrendentialsBinSize, &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], _gu8aAesCbcKey, _gu8aAesCbcIV );
        
        /* Make up file */
        printf( "=== Make up %s ...\r\n", argv[3] );
        if ( 0 == fwrite( u8aTempBuf, u16BufIndex, 1, fout_canal_ready_auth_cert ) )
        {
            fprintf( stderr, "fwrite(%s,wb) failed!\r\n", argv[3] );
            goto exit;
        }

        //CRC32
        u32CRC = ~crc32_encode( u8aTempBuf, u16BufIndex );
        u8aCRC[0] = (U8)( u32CRC >> 24 );
        u8aCRC[1] = (U8)( u32CRC >> 16 );
        u8aCRC[2] = (U8)( u32CRC >>  8 );
        u8aCRC[3] = (U8)( u32CRC       );
        printf("~CRC32: 0x%lX\r\n", u32CRC);

        /* Make up file of CRC32 */
        if ( 0 == fwrite( u8aCRC, BIN_CIPLUS_CRC_LENGTH, 1, fout_canal_ready_auth_cert ) )
        {
            fprintf( stderr, "fwrite(%s,wb) failed!\r\n", argv[3] );
            goto exit;
        }

        printf( "Total CANAL READY Auth Certificate Bin Length is %d bytes.\r\n", u16BufIndex + BIN_CIPLUS_CRC_LENGTH );
        //_Log( u8aTempBuf, u16CertificateLen );

        filesize = ftell( fout_canal_ready_auth_cert );
        printf( "%s has %d bytes.\r\n", argv[3], (int)filesize );
    }
    else if ('3' == *argv[1])
    {
        if ( ( fout_canal_ready_auth_cert = fopen( argv[2], "rb" ) ) == NULL )
        {
            fprintf( stderr, "fopen(%s,rb) failed!\r\n", argv[2] );
            goto exit;
        }

        if ( fread( &u8aTempBuf[0], 1, BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH, fout_canal_ready_auth_cert ) != BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH )
        {
            fprintf( stderr, "fread failed!\r\n" );
            goto exit;
        }
        u16CrendentialsBinSize = (U16)u8aTempBuf[0] << 8 | (U16)u8aTempBuf[1];
        printf( "Credentials Bin Size is %d bytes.\r\n", u16CrendentialsBinSize );

        if ( (U16)fread( &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], 1, u16CrendentialsBinSize + BIN_CIPLUS_CRC_LENGTH, fout_canal_ready_auth_cert ) != ( u16CrendentialsBinSize + BIN_CIPLUS_CRC_LENGTH ) )
        {
            fprintf( stderr, "fread failed!\r\n" );
            goto exit;
        }

        /* CRC32 Checking */
        u32CRC = ~crc32_encode( u8aTempBuf, BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + u16CrendentialsBinSize );

        if ( ((U32)u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + u16CrendentialsBinSize + 3] | (U32)u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + u16CrendentialsBinSize + 2] << 8 | (U32)u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + u16CrendentialsBinSize + 1] << 16 | (U32)u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + u16CrendentialsBinSize] << 24) == u32CRC )
            printf("~u32CRC = 0x%lX, OK! \r\n", u32CRC);
        else
            printf("~u32CRC = 0x%lX, NG! \r\n", u32CRC);

        /* AES-128-CBC Decrypt */
        printf( "=== AES-128-CBC Decrypt ...\r\n" );
        aes_cbc_handling( AES_DECRYPT, &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], (unsigned short)u16CrendentialsBinSize, &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], _gu8aAesCbcKey, _gu8aAesCbcIV );

        /* AES-128-XCBC MAC */
        printf( "=== AES-128-XCBC MAC ...\r\n" );
        aes_xcbc_handling( &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH], (unsigned short)( u16CrendentialsBinSize - CC_AUTH_SAC_AUTH_SIZE ), u8aXCBC_Auth, _gu8aAesXcbcKey );

        if ( memcmp( u8aXCBC_Auth, &u8aTempBuf[BIN_CANAL_READY_AUTH_CERT_BIN_SIZE_LENGTH + u16CrendentialsBinSize - CC_AUTH_SAC_AUTH_SIZE], CC_AUTH_SAC_AUTH_SIZE ) )
            printf( "Auth NG!\n" );
        else
            printf( "Auth OK!\n" );
    }
    else
    {
        printf( "[Warning] Error Para ...\r\n" );
        return 0;
    }

exit:
    fflush( fout_ciplus );

    if ( NULL != fout_ciplus )
        fclose( fout_ciplus );

    if ( NULL != fin_device_cert )
        fclose( fin_device_cert );

    if ( NULL != fin_keys_cert )
        fclose( fin_keys_cert );

    fflush( fout_canal_ready_auth_cert );
    if ( NULL != fout_canal_ready_auth_cert )
        fclose( fout_canal_ready_auth_cert );

    return 0;
}
