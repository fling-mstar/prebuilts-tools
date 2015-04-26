#include "polarssl/config.h"

#if defined(POLARSSL_RSA_C)

#define _POLARSSL_PRNG_C_

/*****************************************************************************/
/*                      Include files                                        */
/*****************************************************************************/
#include <time.h>
#include <stdio.h>
#include <string.h>
#include "polarssl/aes.h"
#include "polarssl/prng.h"
#include "polarssl/polarssl_api.h"

/*****************************************************************************/
/*                      Define                                               */
/*****************************************************************************/
#define PRNG_SEED_SIZE          16
#define AES_BLOCK_SIZE          16
#define MAX_RANDOM_NUMBER_LEN   2097152

/*****************************************************************************/
/*                      Global Variables                                     */
/*****************************************************************************/
static U8 _u8agPrngSeed[PRNG_SEED_SIZE] = { 0 };

/*****************************************************************************/
/*                      Functions                                            */
/*****************************************************************************/
void cc_prng( U8 *u8pOutput, U32 u32BitsLen )
{
    U8  key[AES_BLOCK_SIZE]             = { 0 };
    U8  i[AES_BLOCK_SIZE]               = { 0 };
    U8  s[AES_BLOCK_SIZE]               = { 0 };
    U8  *r                              = NULL;
    U32 j                               = 0;
    U32 k                               = 0;
    aes_context aes_ctx;
    U8  DTi[AES_BLOCK_SIZE]             = { 0 };
    U32 u32SysTime                      = time(NULL);
    U8  buffer[MAX_RANDOM_NUMBER_LEN]   = { 0 };
    U32  u32Round                         = 0;

    memcpy( s, _u8agPrngSeed, PRNG_SEED_SIZE );

    unsigned int m=0;

    if ( u32BitsLen > ( MAX_RANDOM_NUMBER_LEN << 3 ) )
    {
        printf( "[Warning]u16BitsLen is larger than %d bits.\n", MAX_RANDOM_NUMBER_LEN << 3);
        return;
    }


    if ( u32BitsLen > ( AES_BLOCK_SIZE << 3 ) )
    {
        u32Round = u32BitsLen >> 7;
        if ( 0 != ( u32BitsLen % ( AES_BLOCK_SIZE << 3 ) ) )
            u32Round++;
    }
    else
        u32Round = 1;
    /* Get Date and Time for DTi, a Plain Text. */
    memcpy( &DTi[0], (U8 *)&u32SysTime, 4 );
    memcpy( &DTi[4], (U8 *)&u32SysTime, 4 );
    memcpy( &DTi[8], (U8 *)&u32SysTime, 4 );
    memcpy( &DTi[12], (U8 *)&u32SysTime, 4 );
    
    aes_setkey_enc( &aes_ctx, key, AES_BLOCK_SIZE << 3 );
    for ( j = 0; j < u32Round; j++ )
    {
        printf("DTi\n");

        for(k=0;k<16;k++)
        {
            printf("%x ",*(DTi+k));
        }
        printf("\n");

        for(k=0;k<16;k++)
        {
            printf("%x ",*(s+k));
        }
        printf("\n");
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, DTi, i );
        for( k = 0; k < AES_BLOCK_SIZE; k++ )
            s[k] = (U8)( i[k] ^ s[k] );
        r = buffer + ( AES_BLOCK_SIZE * j );
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, s, r );
        for( k = 0; k < AES_BLOCK_SIZE; k++ )
            s[k] = (U8)( i[k] ^ r[k] );
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, s, s );
    }

    memcpy( u8pOutput, buffer, u32BitsLen >> 3 );

    return;
}

void cc_prng_didin(U8 *pu8Input, U32 InLen, U8 *u8pOutput, U32 u32BitsLen )
{

    U8  key[AES_BLOCK_SIZE]             = { 0 };
    U8  i[AES_BLOCK_SIZE]               = { 0 };
    U8  s[AES_BLOCK_SIZE]               = { 0 };
    U8  *r                              = NULL;
    U32 j                               = 0;
    U32 k                               = 0;
    aes_context aes_ctx;
    U8  DTi[AES_BLOCK_SIZE]             = { 0 };
    U32 u32SysTime                      = time(NULL);
    U8  buffer[MAX_RANDOM_NUMBER_LEN]   = { 0 };
    U32  u32Round                         = 0;
    memcpy( s, _u8agPrngSeed, PRNG_SEED_SIZE );
    //printf("InLen=%d\n",InLen);


    unsigned int m=0;
    if ( u32BitsLen > ( MAX_RANDOM_NUMBER_LEN << 3 ) )
    {
        printf( "[Warning]u16BitsLen is larger than %d bits.\n", MAX_RANDOM_NUMBER_LEN << 3);
        return;
    }

    if ( u32BitsLen > ( AES_BLOCK_SIZE << 3 ) )
    {
        u32Round = u32BitsLen >> 7;
        if ( 0 != ( u32BitsLen % ( AES_BLOCK_SIZE << 3 ) ) )
            u32Round++;
    }
    else
        u32Round = 1;
    /* Get Date and Time for DTi, a Plain Text. */
    //memcpy( &DTi[0], (U8 *)&u32SysTime, 4 );
    //memcpy( &DTi[4], (U8 *)&u32SysTime, 4 );
    //memcpy( &DTi[8], (U8 *)&u32SysTime, 4 );
    //memcpy( &DTi[12], (U8 *)&u32SysTime, 4 );
    memcpy(&DTi[0],pu8Input,InLen);


    aes_setkey_enc( &aes_ctx, key, AES_BLOCK_SIZE << 3 );
    for ( j = 0; j < u32Round; j++ )
    {

        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, DTi, i );
        for( k = 0; k < AES_BLOCK_SIZE; k++ )
            s[k] = (U8)( i[k] ^ s[k] );
        r = buffer + ( AES_BLOCK_SIZE * j );
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, s, r );
        for( k = 0; k < AES_BLOCK_SIZE; k++ )
            s[k] = (U8)( i[k] ^ r[k] );
        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, s, s );
    }

    memcpy( u8pOutput, buffer, u32BitsLen >> 3 );

    return;
}

void cc_prng_set_seed( U8 *u8pSeed )
{

    memcpy( _u8agPrngSeed, u8pSeed, PRNG_SEED_SIZE );
}

void cc_prng_get_seed( U8 *u8pSeed )
{
    memcpy( u8pSeed, _u8agPrngSeed, PRNG_SEED_SIZE );
}

#undef _POLARSSL_PRNG_C_

#endif