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



#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "polarssl/havege.h"
#include "polarssl/bignum.h"
#include "polarssl/x509.h"
#include "polarssl/rsa.h"

#define PPT_LEN  256
#define RSA_PPT  "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A\x0B\x0C\xCC\xDD\xDD\xDD\xDD\xDD" \
                "\xAA\xBB\xCC\x03\x02\x01\x00\xFF\xFF\xFF\xFF\xFF" \
                "\x11\x22\x33\x0A"
                
int main(int argc, char *argv[])
{
#if 1
    FILE *f_ciphertext=NULL;
    FILE *f_plaintext=NULL;
        FILE *f_pri=NULL;

    int len;
    int i=0,j=0,k=0;
    rsa_context rsa;
    unsigned char buf[2048];
    unsigned int filesize = 0;
    unsigned int ret = 0;
    unsigned char sha1sum[20];
    unsigned char rsa_plaintext[256]={0};
    unsigned char rsa_decrypted[256]={0};
    unsigned char rsa_ciphertext[256] ={0};

    f_pri = fopen( "rsa_priv.txt", "rb" ) ;
   if(  f_pri == NULL )
    {
        ret = 1;
        printf( " failed\n  ! Could not open rsa_priv.txt\n" \
                "  ! Please run rsa_genkey first\n\n" );
    }
    

    rsa_init( &rsa, RSA_PKCS_V15, 0, NULL, NULL );
    
    if( ( ret = mpi_read_file( &rsa.N , 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.E , 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.D , 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.P , 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.Q , 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DP, 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.DQ, 16, f_pri ) ) != 0 ||
        ( ret = mpi_read_file( &rsa.QP, 16, f_pri ) ) != 0 )
    {
        printf( " failed\n  ! mpi_read_file returned %d\n\n", ret );
    }

    rsa.len = ( mpi_msb( &rsa.N ) + 7 ) >> 3;
    printf("rsa.len = %d \n",rsa.len);
    fclose( f_pri );

    /*
     * Compute the SHA-1 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    printf( "\n  . Generating \n" );    

    if( ( f_ciphertext = fopen( "ciphertext.txt", "w+" ) ) == NULL )
        return( 1 );
    
    if( ( f_plaintext = fopen( "planttext.txt", "w+" ) ) == NULL )
        return( 1 );

    printf( "passed\n  PKCS#1 encryption : " );

    memcpy( rsa_plaintext, RSA_PPT, PPT_LEN );
    memset(rsa_ciphertext,0,256);

    if( rsa_pkcs1_encrypt( &rsa, RSA_PRIVATE, 240,
                           rsa_plaintext, rsa_ciphertext ) != 0 )
    {
        printf( "failed\n" );        
        return( 1 );
    }
    printf( "passed\n" );   
    dataDump(rsa_ciphertext, 256, "rsa_ciphertext");
#if 1
    // tranfer byte to string ex: 0xab => "AB"
    unsigned char strdeviceid [(512)+1]={0};
    char strpattern[17] = "0123456789ABCDEF";
    int multiple=0;
    int residue = 0;
printf("%d\n",__LINE__);
    for(j=0;j<256;j++)
    {
        multiple = rsa_ciphertext[j]/(0x10);
        residue = rsa_ciphertext[j]%(0x10);
        strdeviceid[2*j]=strpattern[multiple];
        strdeviceid[(2*j)+1]=strpattern[residue];
    }
printf("%d\n",__LINE__);
#if 0
    FILE* PWD_file;
    PWD_file=fopen("pwd_file","w+");
    if(PWD_file==NULL)
    {
        return;
    }
    #endif
    printf("%d\n",__LINE__);
    fprintf(f_ciphertext,"%s",strdeviceid);
        printf("%d\n",__LINE__);

    fclose(f_ciphertext);
        printf("%d\n",__LINE__);

#endif

  //  fwrite(rsa_ciphertext,sizeof(unsigned char),(256),f_ciphertext);
    if( rsa_pkcs1_decrypt( &rsa, RSA_PUBLIC, &len,
                           rsa_ciphertext, rsa_decrypted,
                           sizeof(rsa_decrypted) ) != 0 )
    {
            printf( "failed\n" );

        return( 1 );
    }
    printf("len =%d \n",len);
    dataDump(rsa_decrypted, 256, "rsa_decrypted");


#if 1
    // tranfer byte to string ex: 0xab => "AB"
    //unsigned char strdeviceid [(512)+1]={0};
    memset(strdeviceid,0,513);
  //  char strpattern[17] = "0123456789ABCDEF";
    multiple=0;
    residue = 0;
printf("%d\n",__LINE__);
    for(j=0;j<256;j++)
    {
        multiple = rsa_decrypted[j]/(0x10);
        residue = rsa_decrypted[j]%(0x10);
        strdeviceid[2*j]=strpattern[multiple];
        strdeviceid[(2*j)+1]=strpattern[residue];
    }
printf("%d\n",__LINE__);
#if 0
    FILE* PWD_file;
    PWD_file=fopen("pwd_file","w+");
    if(PWD_file==NULL)
    {
        return;
    }
    #endif
    printf("%d\n",__LINE__);
    fprintf(f_plaintext,"%s",strdeviceid);
        printf("%d\n",__LINE__);

    fclose(f_plaintext);
        printf("%d\n",__LINE__);

#endif

    //fwrite(rsa_plaintext,sizeof(unsigned char),(len),f_plaintext);

   // if( rsa_pkcs1_encrypt( &rsa, RSA_PUBLIC, filesize,
       //                    rsa_plaintext, rsa_ciphertext ) != 0 )
#if 0
    printf( "passed\n  PKCS#1 decryption : " );

    if( rsa_pkcs1_decrypt( &rsa, RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
                           sizeof(rsa_decrypted) ) != 0 )
    {
            printf( "failed\n" );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
            printf( "failed\n" );

        return( 1 );
    }

    printf( "passed\n  PKCS#1 data sign  : " );

#endif

    rsa_free( &rsa );

    return( 0 );
    #endif
}

