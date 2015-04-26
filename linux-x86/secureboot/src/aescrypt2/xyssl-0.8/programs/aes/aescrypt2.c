/**
 * MStar Semiconductor
 * Data : 2009/03/12
 * Creator : Timothy Tsai
 * Description:  Encrypt Image with AES Protocol ( AES-128 EBC mode )
 */

#include <sys/types.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "xyssl/aes.h"
#include "xyssl/sha2.h"

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  aescrypt2 <mode> <input filename> <output filename> <key>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: aescrypt2 0 file file.aes hex:E76B2413958B00E193\n" \
    "\n"

int main( int argc, char *argv[] )
{
    int ret = 1, n, retLen;
    int keylen, mode;
    FILE *fkey, *fin, *fout;

    char *p;
    unsigned char key[16];
    unsigned char bufferin[16];
    unsigned char bufferout[16];

    off_t filesize, offset;

    aes_context aes_ctx;

    /*
     * Parse the command-line arguments.
     */
    if( argc != 5 )
    {
        printf( USAGE );

        goto exit;
    }

    mode = atoi( argv[1] );

    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        fprintf( stderr, "invalide operation mode\n" );
        goto exit;
    }

    if( strcmp( argv[2], argv[3] ) == 0 )
    {
        fprintf( stderr, "input and output filenames must differ\n" );
        goto exit;
    }

    if( ( fin = fopen( argv[2], "rb" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,rb) failed\n", argv[2] );
        goto exit;
    }

    if( ( fout = fopen( argv[3], "wb+" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,wb+) failed\n", argv[3] );
        goto exit;
    }

    /*
     * Read the secret key.
     */
    if( ( fkey = fopen( argv[4], "rb" ) ) != NULL )
    {
        keylen = fread( key, 1, sizeof( key ), fkey );
        if(fkey)
        {
            if(fclose(fkey))
            {
                fprintf( stderr, "fclose(%s,rb) failed\n", argv[4] );
            }
        }
    }
    else
    {
        if( memcmp( argv[4], "hex:", 4 ) == 0 )
        {
            p = &argv[4][4];
            keylen = 0;

            while( sscanf( p, "%02X", &n ) > 0 && keylen < (int) sizeof( key ) )
            {
                key[keylen++] = (unsigned char) n;
                p += 2;
            }
        }
        else
        {
            printf("error key format . It must be hex:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \n");
            goto exit;
        }
    }

    if ( keylen != 16 )
    {
        printf("error key length =%d. It must be 128 bits for AES\n",keylen);
        goto exit;
    }
     /*
    if( mode == MODE_ENCRYPT )
    {
        if( fwrite( key, 1, 16, fout ) != 16 )
        {
            fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
            goto exit;
        }
    }
    */
    if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 )
    {
        perror( "lseek" );
        goto exit;
    }

    if( fseek( fin, 0, SEEK_SET ) < 0 )
    {
        fprintf( stderr, "fseek(0,SEEK_SET) failed\n" );
        goto exit;
    }

    memset( bufferin, 0, sizeof( bufferin ) );
    memset( bufferout, 0, sizeof( bufferout ) );
    memset( &aes_ctx, 0, sizeof(  aes_context ) );

    if( mode == MODE_ENCRYPT )
    {
        aes_setkey_enc( &aes_ctx, key, 128 );
       
        /*
         * Encrypt and write the ciphertext.
         */
        for( offset = 0; offset < filesize; offset += 16 )
        {
            n = ( filesize - offset > 16 ) ? 16 : (int)( filesize - offset );

            if( fread( bufferin, 1, n, fin ) != (size_t) n )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", n );
                goto exit;
            }

            aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, bufferin, bufferout );

            if( fwrite( bufferout, 1, 16, fout ) != 16 )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
                goto exit;
            }
        }
    }
    else
    {
        if( fread( bufferin, 1, 16, fin ) != (size_t) 16 )
        {
            fprintf( stderr, "fread(%d bytes) failed\n", n );
            goto exit;
        }

        aes_setkey_dec( &aes_ctx, key, 128 );

        /*
         * Decrypt and write the plaintext.
         */
		fseek(fin,0,SEEK_SET);
        for( offset = 0; offset < filesize; offset += 16 )
        {
            n = ( filesize - offset > 16 ) ? 16 : (int)( filesize - offset );
			retLen=fread( bufferin, 1, n, fin );
			if( retLen != (size_t) n )
            //if( fread( bufferin, 1, n, fin ) != (size_t) n )
            {
				fprintf( stderr, "offset=%d\n", offset );
				fprintf( stderr, "filesize=%d\n", filesize );
				fprintf( stderr, "retLen=%d\n", retLen );
                fprintf( stderr, "fread(%d bytes) failed\n", n );
                goto exit;
            }

            aes_crypt_ecb( &aes_ctx, AES_DECRYPT, bufferin, bufferout );

            if( fwrite( bufferout, 1, 16, fout ) != 16 )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
                goto exit;
            }
        }
    }

    ret = 0;

    fclose(fin);
    fclose(fout);

exit:

    return( ret );
}

