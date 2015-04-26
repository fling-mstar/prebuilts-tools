/*
 *  RSA/SHA-1 signature creation program
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

#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <string.h>
#include <stdio.h>

#include "polarssl/rsa.h"
#include "polarssl/sha1.h"

int main( int argc, char *argv[] )
{
    FILE *f;
    int ret, i;
    rsa_context rsa;
    unsigned char strBuf[2048]={0};
    unsigned char hash[32];
    unsigned char buf[1000]={0};
    FILE *fHash  = NULL;
    FILE *fSignature  = NULL;

    ret = 1;

    if( argc != 3 )
    {
        printf( "usage: rsa_sign <filename> <rsa private key> \n" );

#ifdef WIN32
        printf( "\n" );
#endif

        goto exit;
    }

    //printf( "\n  . Reading private key from rsa_priv.txt\n" );
    fflush( stdout );

    //if( ( f = fopen( "rsa_priv.txt", "rb" ) ) == NULL )
    if( ( f = fopen( argv[2], "rb" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
        goto exit;
    }
    
    if( ( fHash = fopen( "hash.bin", "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        ret = 1;
        goto exit;
    }

    strcpy(strBuf,argv[1]);    
    strcat(strBuf,".sig");        
    strcat(strBuf,".bin");        

    if( ( fSignature = fopen(strBuf, "wb+" ) ) == NULL )
    {
        printf( " failed\n  ! could not open rsa_pub.txt for writing\n\n" );
        ret = 1;
        goto exit;
    }

    rsa_init( &rsa, RSA_PKCS_V15, 0, NULL, NULL );
    
    if( ( ret = mpi_read_file( &rsa.N , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.D , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.P , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.Q , 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DP, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DQ, 16, f ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.QP, 16, f ) ) != 0 )
    {
        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
        goto exit;
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;

    fclose( f );

    /*
     * Compute the SHA-1 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    //printf( "\n  . Generating the RSA/SHA-1 signature\n" );
    fflush( stdout );

    if( ( ret = sha2_file( argv[1], hash ,0) ) != 0 )
    {
        printf( " failed\n  ! Could not open or read %s\n\n", argv[1] );
        goto exit;
    }
    #if 0
    printf("\nhash\n\n");
    for (i=0;i<sizeof(hash);i++)
    {
        printf("%x ",hash[i]);
    }
    printf("\n");

    printf("\nbuf\n\n");

    for (i=0;i<sizeof(hash);i++)
    {
        printf("%x ",hash[i]);
    }
    printf("\n");
    #endif
    fwrite(hash,sizeof(unsigned char),sizeof(hash),fHash);
    if( ( ret = rsa_pkcs1_sign( &rsa, RSA_PRIVATE, RSA_SHA256,
                                20, hash, buf ) ) != 0 )
    {
        printf( " failed\n  ! rsa_pkcs1_sign returned %d\n\n", ret );
        goto exit;
    }
    #if 0
    printf("\nsignature\n\n");
    for (i=0;i<256;i++)
    {
        printf("%x ",buf[i]);
    }
    printf("\n");
    #endif
    fwrite(buf,sizeof(unsigned char),256,fSignature);
    /*
     * Write the signature into <filename>-sig.txt
     */
    //memcpy( argv[1] + strlen( argv[1] ), ".sig", 5 );
    memset(strBuf,0,sizeof(strBuf));
    strcpy(strBuf,argv[1]);    
    strcat(strBuf,".sig");        
    if( ( f = fopen( strBuf, "wb+" ) ) == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not create %s\n\n", argv[1] );
        goto exit;
    }

    for( i = 0; i < rsa.len; i++ )
        fprintf( f, "%02X%s", buf[i],
                 ( i + 1 ) % 16 == 0 ? "\r\n" : " " );

    fclose( f );

    printf( ". Done (created signature \"%s\")\n", argv[1] );
exit:

#ifdef WIN32
    printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
