/*
 *  The RSA public-key cryptosystem
 *
 *  Based on XySSL: Copyright (C) 2006-2008  Christophe Devine
 *
 *  Copyright (C) 2009  Paul Bakker <polarssl_maintainer at polarssl dot org>
 *
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the names of PolarSSL or XySSL nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 *  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 *  RSA was designed by Ron Rivest, Adi Shamir and Len Adleman.
 *
 *  http://theory.lcs.mit.edu/~rivest/rsapaper.pdf
 *  http://www.cacr.math.uwaterloo.ca/hac/about/chap8.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_RSA_C)

#include "polarssl/prng.h"
#include "polarssl/sha1.h"
#include "polarssl/rsa.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define RSA_DEBUG    FALSE

#if RSA_DEBUG
void rsa_log( unsigned char *data, int datalen )
{
    U16 k = 0;

    if ( NULL == data )
    {
        return ;
    }
    
    printf( "\t" );
    
    for ( k = 0; k < datalen; k++ )
    {
        printf( "0x%02X", data[k] );
        if ( 0 == ( ( k + 1 ) & 0x000F ) )
            printf( ",\r\n\t" );
        else
            printf( ", " );
    }
    printf( "\r\n" );
}
#endif

static void I2OSP( unsigned int x, unsigned int xLen, unsigned char *X ) 
{
    unsigned char temp[4];
    
    /* 1.  If x ? 256^xLen, output ¡§integer too large¡¨ and stop */
    
    /* 2.  Write the integer x in its unique xLen-digit representation in base 256: */

    
    /* 3.  Let the octet Xi have the integer value  xxLen¡Vi for 1 ?  i ?  xLen.
            Output the octet string
            X = X1 X2 ¡K XxLen.
    */
    if ( 4 == xLen )
    {
        temp[0] = (unsigned char)( x >> 24 );
        temp[1] = (unsigned char)( x >> 16 );
        temp[2] = (unsigned char)( x >> 8 );
        temp[3] = (unsigned char)( x >> 0 );

        memcpy( X, temp, 4 );
    }
}

static void MGF1( unsigned char* p_mgfSeed, int maskLen, int hLen, unsigned char *mask )
{
    unsigned char T[1024];
    unsigned char HashInput[1024];
    unsigned char HashOutput[20];
    unsigned char mgfSeed[20];
    int counter;
    int counter_end;
    unsigned char C[4];
    
    counter_end = maskLen / hLen;
    memcpy( mgfSeed, p_mgfSeed, hLen );
    
    /* 1. If maskLen > 2^32 hLen, output "mask too long" and stop. */
    //FIXME_ALEC


    /* 2. Let T be the empty octet string. */
    memset( T, 0, sizeof( T ) );

    /* 3. For counter from 0 to [ maskLen / hLen ] - 1, do the following: */
    /* Exmaple:[ maskLen / hLen ] = ceil (maskLen / hLen) , ex. ceil(235/20)=12 */  
    /* ceil --- Returns the next highest integer value by rounding up value if necessary. */
    for ( counter = 0; counter <= counter_end; counter++ )
    {
        /* a.  Convert counter to an octet string C of length 4 octets (see Section 4.1):
                C = I2OSP (counter, 4) .
        */
        I2OSP( counter, 4, C );
        
        /* b.  Concatenate the hash of the seed mgfSeed and C to the octet string T:
                T = T || Hash (mgfSeed || C) .
        */
        if ( ( hLen * ( counter + 1 ) ) > maskLen )
        {
            memcpy( HashInput, mgfSeed, hLen );
            memcpy( HashInput + hLen, C, 4 );
            sha1( HashInput, hLen + 4, HashOutput );
            memcpy( T + ( hLen * counter ), HashOutput, maskLen - ( hLen * counter ) );
        }
        else
        {
            memcpy( HashInput, mgfSeed, hLen );
            memcpy( HashInput + hLen, C, 4 );
            sha1( HashInput, hLen + 4, HashOutput );
            memcpy( T + ( hLen * counter ), HashOutput, hLen );
        }
    }

    /* 4. Output the leading maskLen octets of T as the octet string mask. */
    memcpy( mask, T, maskLen );
}

int EMSA_PSS_Encode( rsa_context *ctx,
                     int hash_id,
                     unsigned char *M,
                     int MLen,
                     unsigned char *EM )
{
    int emLen, psLen, dbLen;
    unsigned char mHash[20]     = { 0 };
    unsigned char M_[256]       = { 0 };
    unsigned char salt[20]      = { 0 };
    unsigned char DB[256]       = { 0 };
    unsigned char maskedDB[256] = { 0 };
    
    /* 1.  If the length of M is greater than the input limitation for the hash function
     *     (2^61¡V 1 octets for SHA-1), output ¡§message too long¡¨ and stop.
     */
    //FIXME_ALEC
    
    switch( hash_id )
    {
        case RSA_SHA1:
        {
            int hLen = 20;
            int sLen = 20;
            int i;
            unsigned char H[20] = { 0 };

#if RSA_DEBUG
            printf( "\r\nM:\r\n" );
            rsa_log( M, MLen );
#endif
            
            /* 2.  Let mHash = Hash (M), an octet string of length hLen.
             */
            sha1( M, MLen, mHash );
#if RSA_DEBUG
            printf( "\r\nmHash:\r\n" );
            rsa_log( mHash, hLen );
#endif

            /* 3.  If emLen < hLen + sLen + 2, output ¡§encoding error¡¨ and stop
             */
            emLen = ctx->len;

            if ( emLen < ( hLen + sLen + 2 ) )
            {
                return( POLARSSL_ERR_RSA_ENCODING_ERROR );
            }
            
            /* 4.  Generate a random octet string salt of length sLen; if sLen = 0,
             *     then salt is the empty string.
             */
            cc_prng( salt, 160 );
#if RSA_DEBUG
            printf( "\r\nsalt:\r\n" );
            rsa_log( salt, 20 );
#endif

            /* 5.  Let
             *          M¡¦ = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
             *     M¡¦ is an octet string of length 8 + hLen + sLen with eight initial zero octets.
             */
            memset( M_, 0, sizeof( M_ ) );
            memcpy( M_ + 8, mHash, hLen );
            memcpy( M_ + 8 + hLen, salt, sLen );
#if RSA_DEBUG
            printf( "M':\r\n" );
            rsa_log( M_, 8 + hLen + sLen );
#endif
            
            /* 6.  Let H = Hash (M¡¦), an octet string of length hLen.
             */
            sha1( M_, 8 + hLen + sLen, H );
#if RSA_DEBUG
            printf( "H:\r\n" );
            rsa_log( H, hLen );
#endif

            /* 7.  Generate an octet string PS consisting of  emLen ¡V  sLen ¡V hLen ¡V 2 zero octets.
             *     The length of PS may be 0.
             */
            psLen = emLen - sLen - hLen - 2;
            
            /* 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length emLen ¡V hLen ¡V 1.
             */
            memset( DB, 0x00, psLen );
            DB[psLen] = 0x01;
            memcpy( &DB[psLen + 1], salt, sLen );
            dbLen = emLen - hLen - 1;
#if RSA_DEBUG
            printf( "DB:\r\n" );
            rsa_log( DB, dbLen );
#endif

            /* 9.  Let dbMask = MGF (H, emLen ¡V hLen ¡V 1).
             */
            MGF1( H, dbLen, hLen, maskedDB );
#if RSA_DEBUG
            printf( "MGF Output:\r\n" );
            rsa_log( maskedDB, dbLen );
#endif

            /* 10. Let maskedDB = DB ¡ò dbMask.
             */
            for ( i = 0; i < dbLen; i++ )
            {
                maskedDB[i] = maskedDB[i] ^ DB[i];
            }
#if RSA_DEBUG
            printf( "maskedDB:\r\n" );
            rsa_log( maskedDB, dbLen );
#endif

            /* 11. Set the leftmost 8emLen ¡V emBits bits of the leftmost octet in maskedDB to zero.
             */
            {
                maskedDB[0] &= 0xFF >> ( ( emLen << 3 ) - ( ( emLen << 3 ) - 1 ) );
#if RSA_DEBUG
                printf( "maskedDB:\r\n" );
                rsa_log( maskedDB, dbLen );
#endif
            }
            
            /* 12. Let EM = maskedDB || H || 0xbc.
             */
            memcpy( EM, maskedDB, dbLen );
            memcpy( EM + dbLen, H, hLen );
            EM[dbLen + hLen] = 0xbc;
#if RSA_DEBUG
            printf( "EM:\r\n" );
            rsa_log( EM, dbLen + hLen + 1 );
#endif
        }   
        break;
            
        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }
    
    return 0;
}

int EMSA_PSS_Verify( rsa_context *ctx,
                     int hash_id,
                     unsigned char *M,
                     int MLen,
                     unsigned char *EM_ )
{
    int emLen, dbLen;
    unsigned char mHash[20]     = { 0 };
    unsigned char M_[256]       = { 0 };
    unsigned char salt[256]     = { 0 };
    unsigned char DB[256]       = { 0 };
    unsigned char maskedDB[256] = { 0 };
    unsigned char dbMask[256]   = { 0 };
    int M_Len;
    
    /* 1.  If the length of M is greater than the input limitation for the hash function
     *     (2^61¡V 1 octets for SHA-1), output ¡§message too long¡¨ and stop.
     */
    
    
    switch( hash_id )
    {
        case RSA_SHA1:
        {
            int hLen = 20;
            int sLen = 20;
            int i;
            unsigned char H[20];
            unsigned char H_[20];

#if RSA_DEBUG
            printf( "EM':\r\n" );
            rsa_log( EM_, ctx->len );
#endif

            /* 2.  Let mHash = Hash (M), an octet string of length hLen.
             */
            sha1( M, MLen, mHash );
#if RSA_DEBUG
            printf( "mHash:\r\n" );
            rsa_log( mHash, hLen );
#endif

            /* 3.  If emLen < hLen + sLen + 2, output ¡§encoding error¡¨ and stop.
             */
            emLen = ctx->len;
            
            if ( emLen < ( hLen + sLen + 2 ) )
            {
                return( POLARSSL_ERR_RSA_ENCODING_ERROR );
            }
            
            /* 4.  If the rightmost octet of  EM does not have hexadecimal value 0xbc, output
             *     ¡§inconsistent¡¨ and stop.
             */
            if ( 0xbc != EM_[emLen - 1] )
            {
                return( POLARSSL_ERR_RSA_INCONSISTENT );
            }
            
            /* 5.  Let maskedDB be the leftmost emLen ¡V hLen ¡V 1 octets of EM, and let H be the
             *     next hLen octets.
             */
            dbLen = emLen - hLen - 1;
            memcpy( maskedDB, EM_, dbLen );
#if RSA_DEBUG
            printf( "maskedDB:\r\n" );
            rsa_log( maskedDB, dbLen );
#endif

            memcpy( H, &EM_[dbLen], hLen );
#if RSA_DEBUG
            printf( "H:\r\n" );
            rsa_log( H, hLen );
#endif
            
            /* 6.  If the leftmost 8emLen ¡V emBits bits of the leftmost octet in maskedDB are not all
             *     equal to zero, output ¡§inconsistent¡¨ and stop.
             */
            {
                if ( ( maskedDB[0] & ~( 0xFF >> ( ( emLen << 3 ) - ( ( emLen << 3 ) - 1 ) ) ) ) != 0 )
                {
                    return( POLARSSL_ERR_RSA_INCONSISTENT );
                }
            }
            
            /* 7.  Let dbMask = MGF (H, emLen ¡V hLen ¡V 1).
             */
            MGF1( H, dbLen, hLen, dbMask );
#if RSA_DEBUG
            printf( "dbMask:\r\n" );
            rsa_log( dbMask, dbLen );
#endif

            /* 8.  Let DB = maskedDB ¡ò dbMask.
             */
            for ( i = 0; i < dbLen; i++ )
            {
                DB[i] = maskedDB[i] ^ dbMask[i];
            }
#if RSA_DEBUG
            printf( "DB:\r\n" );
            rsa_log( DB, dbLen );
#endif

            /* 9.  Set the leftmost 8emLen ¡V emBits bits of the leftmost octet in DB to zero.
             */
            DB[0] &= 0xFF >> ( ( emLen << 3 ) - ( ( emLen << 3 ) - 1 ) );
            
            /* 10. If the emLen ¡V hLen ¡V sLen ¡V 2 leftmost octets of DB are not zero or if the octet at
             *     position emLen ¡V hLen ¡V sLen ¡V 1 (the leftmost position is ¡§position 1¡¨) does not
             *     have hexadecimal value 0x01, output ¡§inconsistent¡¨ and stop.
             */
            for ( i = 0; i < ( emLen - hLen - sLen - 2 ); i++)
            {
                if ( 0x00 != DB[i] )
                {
                    return( POLARSSL_ERR_RSA_INCONSISTENT );
                }
            }
            
            if ( 0x01 != DB[i++] )
            {
                return( POLARSSL_ERR_RSA_INCONSISTENT );
            }
            
            /*  11. Let salt be the last sLen octets of DB.
             */
            memcpy( salt, &DB[dbLen - sLen], sLen );
#if RSA_DEBUG
            printf( "salt:\r\n" );
            rsa_log( salt, sLen );
#endif

            /* 12. Let
             *          M¡¦ = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
             *     M¡¦ is an octet string of length 8 + hLen + sLen with eight initial zero octets.
             */
            memset( M_, 0, sizeof( M_ ) );
            memcpy( M_ + 8, mHash, hLen );
            memcpy( M_ + 8 + hLen, salt, sLen );
            M_Len = 8 + hLen + sLen;
#if RSA_DEBUG
            printf( "M':\r\n" );
            rsa_log( M_, M_Len );
#endif

            /*  13. Let H¡¦ = Hash (M¡¦), an octet string of length hLen.
             */
            sha1( M_, M_Len, H_ );
#if RSA_DEBUG
            printf( "H':\r\n" );
            rsa_log( H_, hLen );
#endif
            
            /* 14. If H = H¡¦, output ¡§consistent.¡¨ Otherwise, output ¡§inconsistent.¡¨
             */
            if ( memcmp( H, H_, hLen ) != 0 )
            {
                return( POLARSSL_ERR_RSA_INCONSISTENT );
            }
        }
        break;
            
        default:
            return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }
    
    return 0;
}

/*
 * Initialize an RSA context
 */
void rsa_init( rsa_context *ctx,
               int padding,
               int hash_id,
               int (*f_rng)(void *),
               void *p_rng )
{
    memset( ctx, 0, sizeof( rsa_context ) );

    ctx->padding = padding;
    ctx->hash_id = hash_id;

    ctx->f_rng = f_rng;
    ctx->p_rng = p_rng;
}

#if defined(POLARSSL_GENPRIME)

/*
 * Generate an RSA keypair
 */
int rsa_gen_key( rsa_context *ctx, int nbits, int exponent )
{
    int ret;
    mpi P1, Q1, H, G;

    if( ctx->f_rng == NULL || nbits < 128 || exponent < 3 )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    mpi_init( &P1, &Q1, &H, &G, NULL );

    /*
     * find primes P and Q with Q < P so that:
     * GCD( E, (P-1)*(Q-1) ) == 1
     */
    MPI_CHK( mpi_lset( &ctx->E, exponent ) );

    do
    {
        MPI_CHK( mpi_gen_prime( &ctx->P, ( nbits + 1 ) >> 1, 0, 
                                ctx->f_rng, ctx->p_rng ) );

        MPI_CHK( mpi_gen_prime( &ctx->Q, ( nbits + 1 ) >> 1, 0,
                                ctx->f_rng, ctx->p_rng ) );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) < 0 )
            mpi_swap( &ctx->P, &ctx->Q );

        if( mpi_cmp_mpi( &ctx->P, &ctx->Q ) == 0 )
            continue;

        MPI_CHK( mpi_mul_mpi( &ctx->N, &ctx->P, &ctx->Q ) );
        if( mpi_msb( &ctx->N ) != nbits )
            continue;

        MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
        MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
        MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
        MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );
    }
    while( mpi_cmp_int( &G, 1 ) != 0 );

    /*
     * D  = E^-1 mod ((P-1)*(Q-1))
     * DP = D mod (P - 1)
     * DQ = D mod (Q - 1)
     * QP = Q^-1 mod P
     */
    MPI_CHK( mpi_inv_mod( &ctx->D , &ctx->E, &H  ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DP, &ctx->D, &P1 ) );
    MPI_CHK( mpi_mod_mpi( &ctx->DQ, &ctx->D, &Q1 ) );
    MPI_CHK( mpi_inv_mod( &ctx->QP, &ctx->Q, &ctx->P ) );

    ctx->len = ( mpi_msb( &ctx->N ) + 7 ) >> 3;

cleanup:

    mpi_free( &G, &H, &Q1, &P1, NULL );

    if( ret != 0 )
    {
        rsa_free( ctx );
        return( POLARSSL_ERR_RSA_KEY_GEN_FAILED | ret );
    }

    return( 0 );   
}

#endif

/*
 * Check a public RSA key
 */
int rsa_check_pubkey( rsa_context *ctx )
{
    if( ( ctx->N.p[0] & 1 ) == 0 || 
        ( ctx->E.p[0] & 1 ) == 0 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->N ) < 128 ||
        mpi_msb( &ctx->N ) > 4096 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    if( mpi_msb( &ctx->E ) < 2 ||
        mpi_msb( &ctx->E ) > 64 )
        return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED );

    return( 0 );
}

/*
 * Check a private RSA key
 */
int rsa_check_privkey( rsa_context *ctx )
{
    int ret;
    mpi PQ, DE, P1, Q1, H, I, G;

    if( ( ret = rsa_check_pubkey( ctx ) ) != 0 )
        return( ret );

    mpi_init( &PQ, &DE, &P1, &Q1, &H, &I, &G, NULL );

    MPI_CHK( mpi_mul_mpi( &PQ, &ctx->P, &ctx->Q ) );
    MPI_CHK( mpi_mul_mpi( &DE, &ctx->D, &ctx->E ) );
    MPI_CHK( mpi_sub_int( &P1, &ctx->P, 1 ) );
    MPI_CHK( mpi_sub_int( &Q1, &ctx->Q, 1 ) );
    MPI_CHK( mpi_mul_mpi( &H, &P1, &Q1 ) );
    MPI_CHK( mpi_mod_mpi( &I, &DE, &H  ) );
    MPI_CHK( mpi_gcd( &G, &ctx->E, &H  ) );

    if( mpi_cmp_mpi( &PQ, &ctx->N ) == 0 &&
        mpi_cmp_int( &I, 1 ) == 0 &&
        mpi_cmp_int( &G, 1 ) == 0 )
    {
        mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, NULL );
        return( 0 );
    }

cleanup:

    mpi_free( &G, &I, &H, &Q1, &P1, &DE, &PQ, NULL );
    return( POLARSSL_ERR_RSA_KEY_CHECK_FAILED | ret );
}

/*
 * Do an RSA public key operation
 */
int rsa_public( rsa_context *ctx,
                unsigned char *input,
                unsigned char *output )
{
    int ret, olen;
    mpi T;

    mpi_init( &T, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

    olen = ctx->len;
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->E, &ctx->N, &ctx->RN ) );
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

cleanup:

    mpi_free( &T, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PUBLIC_FAILED | ret );

    return( 0 );
}

/*
 * Do an RSA private key operation
 */
int rsa_private( rsa_context *ctx,
                 unsigned char *input,
                 unsigned char *output )
{
    int ret, olen;
    mpi T, T1, T2;
    mpi_init( &T, &T1, &T2, NULL );

    MPI_CHK( mpi_read_binary( &T, input, ctx->len ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
    }

#if 0
    MPI_CHK( mpi_exp_mod( &T, &T, &ctx->D, &ctx->N, &ctx->RN ) );
#else
    /*
     * faster decryption using the CRT
     *
     * T1 = input ^ dP mod P
     * T2 = input ^ dQ mod Q
     */
    MPI_CHK( mpi_exp_mod( &T1, &T, &ctx->DP, &ctx->P, &ctx->RP ) );
    MPI_CHK( mpi_exp_mod( &T2, &T, &ctx->DQ, &ctx->Q, &ctx->RQ ) );

    /*
     * T = (T1 - T2) * (Q^-1 mod P) mod P
     */
    MPI_CHK( mpi_sub_mpi( &T, &T1, &T2 ) );
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->QP ) );
    MPI_CHK( mpi_mod_mpi( &T, &T1, &ctx->P ) );

    /*
     * output = T2 + T * Q
     */
    MPI_CHK( mpi_mul_mpi( &T1, &T, &ctx->Q ) );
    MPI_CHK( mpi_add_mpi( &T, &T2, &T1 ) );
#endif

    olen = ctx->len;
    MPI_CHK( mpi_write_binary( &T, output, olen ) );

    if( mpi_cmp_mpi( &T, &ctx->N ) >= 0 )
    {
        mpi_free( &T, NULL );
        return( POLARSSL_ERR_RSA_OUTPUT_TO_LARGE );
    }
    
cleanup:

    mpi_free( &T, &T1, &T2, NULL );

    if( ret != 0 )
        return( POLARSSL_ERR_RSA_PRIVATE_FAILED | ret );

    return( 0 );
}

/*
 * Add the message padding, then do an RSA operation
 */
int rsa_pkcs1_encrypt( rsa_context *ctx,
                       int mode, int  ilen,
                       unsigned char *input,
                       unsigned char *output )
{
    int nb_pad, olen;
    unsigned char *p = output;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( ilen < 0 || olen < ilen + 11 )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            nb_pad = olen - 3 - ilen;

            *p++ = 0;
            *p++ = RSA_CRYPT;

            while( nb_pad-- > 0 )
            {
                do {
                    *p = (unsigned char) rand();
                } while( *p == 0 );
                p++;
            }
            *p++ = 0;
            memcpy( p, input, ilen );
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, output, output )
            : rsa_private( ctx, output, output ) );
}

/*
 * Do an RSA operation, then remove the message padding
 */
int rsa_pkcs1_decrypt( rsa_context *ctx,
                       int mode, int *olen,
                       unsigned char *input,
                       unsigned char *output,
                       int output_max_len)
{
    int ret, ilen;
    unsigned char *p;
    unsigned char buf[512];

    ilen = ctx->len;

    if( ilen < 16 || ilen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, input, buf )
          : rsa_private( ctx, input, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_CRYPT )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + ilen - 1 )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    if (ilen - (int)(p - buf) > output_max_len)
        return( POLARSSL_ERR_RSA_OUTPUT_TO_LARGE );

    *olen = ilen - (int)(p - buf);
    memcpy( output, p, *olen );

    return( 0 );
}

/*
 * Do an RSA operation to sign the message digest
 */
int rsa_pkcs1_sign( rsa_context *ctx,
                    int mode,
                    int hash_id,
                    int hashlen,
                    unsigned char *hash,
                    unsigned char *sig )
{
    int nb_pad, olen;
    unsigned char *p = sig;

    olen = ctx->len;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            switch( hash_id )
            {
                case RSA_RAW:
                    nb_pad = olen - 3 - hashlen;
                    break;

                case RSA_MD2:
                case RSA_MD4:
                case RSA_MD5:
                    nb_pad = olen - 3 - 34;
                    break;

                case RSA_SHA1:
                    nb_pad = olen - 3 - 35;
                    break;
                case RSA_SHA256:
                    nb_pad = olen - 3 - 51;
                    break;

                default:
                    return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );
            }

            if( nb_pad < 8 )
                return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

            *p++ = 0;
            *p++ = RSA_SIGN;
            memset( p, 0xFF, nb_pad );
            p += nb_pad;
            *p++ = 0;

            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    switch( hash_id )
    {
        case RSA_RAW:
            memcpy( p, hash, hashlen );
            break;

        case RSA_MD2:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 2; break;

        case RSA_MD4:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 4; break;

        case RSA_MD5:
            memcpy( p, ASN1_HASH_MDX, 18 );
            memcpy( p + 18, hash, 16 );
            p[13] = 5; break;

        case RSA_SHA1:
            memcpy( p, ASN1_HASH_SHA1, 15 );
            memcpy( p + 15, hash, 20 );
            break;
        case RSA_SHA256:
            memcpy( p, ASN1_HASH_SHA2X, 19 );
            memcpy( p + 19, hash, 32 );
            p[1] += 32; p[14] = 1; p[18] += 32; break;

    }

    return( ( mode == RSA_PUBLIC )
            ? rsa_public(  ctx, sig, sig )
            : rsa_private( ctx, sig, sig ) );
}

/*
 * Do an RSA operation and check the message digest
 */
int rsa_pkcs1_verify( rsa_context *ctx,
                      int mode,
                      int hash_id,
                      int hashlen,
                      unsigned char *hash,
                      unsigned char *sig )
{
    int ret, len, siglen;
    unsigned char *p, c;
    unsigned char buf[512];

    siglen = ctx->len;

    if( siglen < 16 || siglen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = ( mode == RSA_PUBLIC )
          ? rsa_public(  ctx, sig, buf )
          : rsa_private( ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;

    switch( ctx->padding )
    {
        case RSA_PKCS_V15:

            if( *p++ != 0 || *p++ != RSA_SIGN )
                return( POLARSSL_ERR_RSA_INVALID_PADDING );

            while( *p != 0 )
            {
                if( p >= buf + siglen - 1 || *p != 0xFF )
                    return( POLARSSL_ERR_RSA_INVALID_PADDING );
                p++;
            }
            p++;
            break;

        default:

            return( POLARSSL_ERR_RSA_INVALID_PADDING );
    }

    len = siglen - (int)( p - buf );

    if( len == 34 )
    {
        c = p[13];
        p[13] = 0;

        if( memcmp( p, ASN1_HASH_MDX, 18 ) != 0 )
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );

        if( ( c == 2 && hash_id == RSA_MD2 ) ||
            ( c == 4 && hash_id == RSA_MD4 ) ||
            ( c == 5 && hash_id == RSA_MD5 ) )
        {
            if( memcmp( p + 18, hash, 16 ) == 0 ) 
                return( 0 );
            else
                return( POLARSSL_ERR_RSA_VERIFY_FAILED );
        }
    }

    if( len == 35 && hash_id == RSA_SHA1 )
    {
        if( memcmp( p, ASN1_HASH_SHA1, 15 ) == 0 &&
            memcmp( p + 15, hash, 20 ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    if( len == 19 + 32 && p[14] == 1 && hash_id == RSA_SHA256 )
    {
        printf("verify\n");
        c = p[1] - 17;
        p[1] = 17;
        p[14] = 0;

        if( p[18] == c &&
                memcmp( p, ASN1_HASH_SHA2X, 18 ) == 0 &&
                memcmp( p + 19, hash, c ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }


    if( len == hashlen && hash_id == RSA_RAW )
    {
        if( memcmp( p, hash, hashlen ) == 0 )
            return( 0 );
        else
            return( POLARSSL_ERR_RSA_VERIFY_FAILED );
    }

    return( POLARSSL_ERR_RSA_INVALID_PADDING );
}

/*
 * Do an RSAv2 operation to sign the message digest
 */
int rsa_pkcs2_sign( rsa_context *ctx,
                     int hash_id,
                     unsigned char *M,
                     int MLen,
                     unsigned char *sig )
{
    int ret1 = 0, ret2 = 1;
    unsigned char *EM = sig;

    do
    {
        if ( ( ret1 = EMSA_PSS_Encode( ctx, hash_id, M, MLen, EM ) ) != 0 )
        {
            printf( "[Error] EMSA_PSS_Encode returned %d\n", ret1 );
            return ret1;
        }

        if ( ( ret2 = rsa_private( ctx, sig, sig ) ) != 0 )
        {
            printf( "Maybe need to Sign Again...\n" );
        }
    } while ( POLARSSL_ERR_RSA_BAD_INPUT_DATA == ret2 || POLARSSL_ERR_RSA_OUTPUT_TO_LARGE == ret2 );
    
    return ret2;
}

/*
 * Do an RSAv2 operation and check the message digest
 */
int rsa_pkcs2_verify( rsa_context *ctx,
                      int hash_id,
                      unsigned char *M,
                      int MLen,
                      unsigned char *sig )
{
    int ret, siglen;
    unsigned char *p;
    unsigned char buf[512];

    siglen = ctx->len;

    if( siglen < 16 || siglen > (int) sizeof( buf ) )
        return( POLARSSL_ERR_RSA_BAD_INPUT_DATA );

    ret = rsa_public( ctx, sig, buf );

    if( ret != 0 )
        return( ret );

    p = buf;
    
    ret = EMSA_PSS_Verify( ctx, hash_id, M, MLen, buf );
    
    return ret;
}

/*
 * Free the components of an RSA key
 */
void rsa_free( rsa_context *ctx )
{
    mpi_free( &ctx->RQ, &ctx->RP, &ctx->RN,
              &ctx->QP, &ctx->DQ, &ctx->DP,
              &ctx->Q,  &ctx->P,  &ctx->D,
              &ctx->E,  &ctx->N,  NULL );
}

#if defined(POLARSSL_SELF_TEST)

#include "polarssl/sha1.h"

/*
 * Example RSA-1024 keypair, for test purposes
 */
#define KEY_LEN 128

#define RSA_N   "9292758453063D803DD603D5E777D788" \
                "8ED1D5BF35786190FA2F23EBC0848AEA" \
                "DDA92CA6C3D80B32C4D109BE0F36D6AE" \
                "7130B9CED7ACDF54CFC7555AC14EEBAB" \
                "93A89813FBF3C4F8066D2D800F7C38A8" \
                "1AE31942917403FF4946B0A83D3D3E05" \
                "EE57C6F5F5606FB5D4BC6CD34EE0801A" \
                "5E94BB77B07507233A0BC7BAC8F90F79"

#define RSA_E   "10001"

#define RSA_D   "24BF6185468786FDD303083D25E64EFC" \
                "66CA472BC44D253102F8B4A9D3BFA750" \
                "91386C0077937FE33FA3252D28855837" \
                "AE1B484A8A9A45F7EE8C0C634F99E8CD" \
                "DF79C5CE07EE72C7F123142198164234" \
                "CABB724CF78B8173B9F880FC86322407" \
                "AF1FEDFDDE2BEB674CA15F3E81A1521E" \
                "071513A1E85B5DFA031F21ECAE91A34D"

#define RSA_P   "C36D0EB7FCD285223CFB5AABA5BDA3D8" \
                "2C01CAD19EA484A87EA4377637E75500" \
                "FCB2005C5C7DD6EC4AC023CDA285D796" \
                "C3D9E75E1EFC42488BB4F1D13AC30A57"

#define RSA_Q   "C000DF51A7C77AE8D7C7370C1FF55B69" \
                "E211C2B9E5DB1ED0BF61D0D9899620F4" \
                "910E4168387E3C30AA1E00C339A79508" \
                "8452DD96A9A5EA5D9DCA68DA636032AF"

#define RSA_DP  "C1ACF567564274FB07A0BBAD5D26E298" \
                "3C94D22288ACD763FD8E5600ED4A702D" \
                "F84198A5F06C2E72236AE490C93F07F8" \
                "3CC559CD27BC2D1CA488811730BB5725"

#define RSA_DQ  "4959CBF6F8FEF750AEE6977C155579C7" \
                "D8AAEA56749EA28623272E4F7D0592AF" \
                "7C1F1313CAC9471B5C523BFE592F517B" \
                "407A1BD76C164B93DA2D32A383E58357"

#define RSA_QP  "9AE7FBC99546432DF71896FC239EADAE" \
                "F38D18D2B2F0E2DD275AA977E2BF4411" \
                "F5A3B2A5D33605AEBBCCBA7FEB9F2D2F" \
                "A74206CEC169D74BF5A8C50D6F48EA08"

#define PT_LEN  24
#define RSA_PT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD"

/*
 * Checkup routine
 */
int rsa_self_test( int verbose )
{
    int len;
    rsa_context rsa;
    unsigned char sha1sum[20];
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN];

    memset( &rsa, 0, sizeof( rsa_context ) );

    rsa.len = KEY_LEN;
    mpi_read_string( &rsa.N , 16, RSA_N  );
    mpi_read_string( &rsa.E , 16, RSA_E  );
    mpi_read_string( &rsa.D , 16, RSA_D  );
    mpi_read_string( &rsa.P , 16, RSA_P  );
    mpi_read_string( &rsa.Q , 16, RSA_Q  );
    mpi_read_string( &rsa.DP, 16, RSA_DP );
    mpi_read_string( &rsa.DQ, 16, RSA_DQ );
    mpi_read_string( &rsa.QP, 16, RSA_QP );

    if( verbose != 0 )
        printf( "  RSA key validation: " );

    if( rsa_check_pubkey(  &rsa ) != 0 ||
        rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PT, PT_LEN );

    if( rsa_pkcs1_encrypt( &rsa, RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 decryption : " );

    if( rsa_pkcs1_decrypt( &rsa, RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
                           sizeof(rsa_decrypted) ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 data sign  : " );

    sha1( rsa_plaintext, PT_LEN, sha1sum );

    if( rsa_pkcs1_sign( &rsa, RSA_PRIVATE, RSA_SHA1, 20,
                        sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 sig. verify: " );

    if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, RSA_SHA1, 20,
                          sha1sum, rsa_ciphertext ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n\n" );

    rsa_free( &rsa );

    return( 0 );
}

#endif

#endif
