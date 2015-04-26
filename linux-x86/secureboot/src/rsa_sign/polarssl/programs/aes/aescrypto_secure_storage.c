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

#include "polarssl/aes.h"
#include "polarssl/sha2.h"

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1
//#define Hmac	1
#define SHA256			2
#define HMAC256			1
#define NONE		0
#define USAGE_1   \
    "\n  ./aescrypto_secure_storage <mode> <input filename> <output filename> <key> <verifymode> <hmackey>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n   <verifymode>: 0 = no verified mode, 1 = hmac on, 2 = sha on\n" \
    "\n   if hmac is on, input hmac key, else hmac key can be empty \n" \
    "\n  example: ./aescrypto_secure_storage 0 file file.aes aeskeyfile(16 bytes) 1 hmackeyfile(32 bytes) \n" \
    "\n  example: ./aescrypto_secure_storage 0 file file.aes aeskeyfile(16 bytes) 0 \n" \
    "\n  example: ./aescrypto_secure_storage 0 file file.aes aeskeyfile(16 bytes) 2 \n" \
    "\n"


#define SEGMENT_SIZE 16
#define PADDING_SIZE 2
#define ENCRYPTED_ID_SIZE 1
#define VERIFIED_ID_SIZE 1
#define KEY_INDEX_SIZE 1
#define DUMMY_SIZE 26
#define VERSION_SIZE 1
#define INFO_SIZE 64
#define SW_VERSION 1
#define CRYPTO_SIZE    16
#define KshLen                  0x20
#define MAGIC_ID_SIZE   32


/// key Index
enum
{
    /// no verification mode
    E_NO_KEY = 0,
    /// aes rootkey
    E_UNIFORM_KEY,
    /// kss key 
    E_UNIQUE_KEY
};

/// Crypto Mode
enum
{
    /// decryption mode 
    E_CLEAR_DATA = 0,
    /// aesdma ecb
    E_AESDMA_ECB_MODE = 0x1,
    /// aesdma cbc
    E_AESDMA_CBC_MODE = 0x2,
};

enum
{
    /// decryption mode 
    E_NO_VERIFY_MODE = 0,
    /// aesdma ecb
    E_HMAC256_MODE = 0x1,
    /// aesdma cbc
    E_SHA256_MODE = 0x2,
};
//#define HmacLen                 0x20
//system("./aescrypt2.exe 1 input output");

unsigned char Magic_ID[MAGIC_ID_SIZE]="MSTAR_SECURE_STORE_FILE_MAGIC_ID";

void dataDump(unsigned char *data, unsigned long len, const char *str)
{
     unsigned int i=0;
     if(str!=NULL)
     printf("\033[0;31mdump %s\033[0m\n",str);
     for(i=0;i<len;i++){
         if(((i%16)==0)&&(i!=0))
             printf("\n");

             printf("0x%x ",data[i]);

     }
     printf("\n");
}

int main( int argc, char *argv[] )
{
    FILE *fkey, *fin, *fout,*ftmp, *fhmackey;
    sha2_context sha2_ctx;
    off_t filesize, offset;
    aes_context aes_ctx;
    int ret = 1, n;
    int keylen, mode, verifymode, hmackeylen;

    char *p;
    unsigned char key[16]={0};
    unsigned char bufferin[16]={0};
    unsigned char bufferout[16]={0};
    unsigned char sha2sum[32]={0};
    unsigned char u8KshBuffer[32]={0};

    unsigned int VirtualFileSize = 0;
    unsigned short PaddingSize= 0;
    unsigned char Encrypted_ID = 0 ;
    unsigned char Hmac_ID = 0 ;
    //unsigned int HmacLen =0;
    unsigned int VerifyLen =0;

    unsigned char* pBuffer=NULL;
    int retlen=0;
    unsigned int i=0;

    /*
     * Parse the command-line arguments.
     */
    if(argc<6)
    {
        printf( USAGE_1 );
        goto exit;
    }

    mode = atoi( argv[1] );

    verifymode = atoi( argv[5] );
    if( verifymode != HMAC256 && verifymode != NONE && verifymode != SHA256 )
    {
        fprintf( stderr, "invalide operation mode\n" );
        goto exit;
    }

    if (verifymode == HMAC256)
    {
        if( argc != 7 )
        {
            printf( USAGE_1 );
            goto exit;
        }
    }    	
    else
    { 		
        if( argc != 6 )
        {
            printf( USAGE_1 );
            goto exit;
        }
    }
    
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

    if( ( fin = fopen( argv[2], "rb+" ) ) == NULL )
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

    if(verifymode == HMAC256)
    {
        if( ( fhmackey = fopen( argv[6], "rb" ) ) != NULL )
        {
            hmackeylen = fread( u8KshBuffer, 1, sizeof( u8KshBuffer ), fhmackey );
            if(fhmackey)
            {
            if(fclose(fhmackey))
                {
                    fprintf( stderr, "fclose(%s,rb) failed\n", argv[6] );
                }
            }
        }

        if ( hmackeylen != 32 )
        {
            printf("error hmackeylen length =%d. It must be 256 bits for AES\n",hmackeylen);
            goto exit;
        }
    }
		
    if ( keylen != 16 )
    {
      printf("error keylen length =%d. It must be 128 bits for AES\n",keylen);
      goto exit;
    }

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
    
/************************padding**************************/
    pBuffer = malloc(filesize*10);
    if(pBuffer == NULL)
    {
        return 0;
    }
    //printf("filesize=%d\n",filesize);
    memset(pBuffer,0,filesize*10);
    

    if(mode == MODE_ENCRYPT )
    {
        if( (verifymode == HMAC256) ||(verifymode == SHA256))
        {
            VerifyLen = 0x20;
        }

        printf(">>>>>>>>ENCRYPTION<<<<<<<<<<\n");

        /*copy padding size*/
        memcpy(pBuffer,&PaddingSize,PADDING_SIZE);
        
        /*copy Encryption ID*/
        pBuffer[PADDING_SIZE]=E_AESDMA_ECB_MODE;
        
        /*copy Hmac ID*/
        if(verifymode == HMAC256)
        {   
            pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE]=E_HMAC256_MODE;

        }
        else if(verifymode == SHA256)
        {   
            pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE]=E_SHA256_MODE;
        }

        //printf("%s \n",argv[4]);
        if((strstr(argv[4],"efuse")!= NULL)||(strstr(argv[4],"Efuse")!= NULL))
        {
            ///write key index  for TSB should be unique key
            printf("efuse key \n");
            pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+VERIFIED_ID_SIZE] = E_UNIQUE_KEY;
        }
        else if((strstr(argv[4],"AESBoot")!= NULL)||(strstr(argv[4],"Kcust")!= NULL))
        {
            ///write key index for trunk should be uniform key
            printf("AES Boot key \n");
            pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+VERIFIED_ID_SIZE] = E_UNIFORM_KEY;
        }
        //printf("Key Index= %d \n",pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+VERIFIED_ID_SIZE]);

        /*dummy bytes 0xff*/
        for(i=0; i<DUMMY_SIZE;i++)
        {
            pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+VERIFIED_ID_SIZE+KEY_INDEX_SIZE+i] = 0xff;
        }

        /*sw version*/
        pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+VERIFIED_ID_SIZE+KEY_INDEX_SIZE+DUMMY_SIZE] = SW_VERSION;
       
        /// write Magic ID
        for(i=0;i<(MAGIC_ID_SIZE);i++)
        {
            pBuffer[INFO_SIZE-MAGIC_ID_SIZE+i] = Magic_ID[i];
        }

        fseek(fin, 0, SEEK_SET);
        retlen = fread(pBuffer+INFO_SIZE, sizeof(char), filesize,fin);
        if( retlen != filesize )
        {
            printf("filesize is wrong in reading in encryption\n");
            return 0;
        }

        if(verifymode == HMAC256)
        {
        	printf(">>>>>>>>HMAC<<<<<<<<<<\n");
                //dataDump(&u8KshBuffer[0], KshLen, "KshLen");
                //dataDump(&pBuffer[INFO_SIZE], filesize, "raw data");
        	sha2_hmac_starts( &sha2_ctx, &u8KshBuffer[0], KshLen, 0 );
        	sha2_hmac_update( &sha2_ctx, &pBuffer[INFO_SIZE], filesize );
        	sha2_hmac_finish( &sha2_ctx, sha2sum );
              //dataDump(sha2sum, VerifyLen, "hmac");

        }

        if(verifymode == SHA256)
        {
            printf(">>>>>>>>SHA<<<<<<<<<<\n");
            sha2(&pBuffer[INFO_SIZE], filesize, sha2sum, 0);
            //dataDump(sha2sum, VerifyLen, "sha");
        }

        memcpy(pBuffer+INFO_SIZE+filesize, &sha2sum[0], VerifyLen);

        if(filesize%SEGMENT_SIZE)
        {
            //pad to segment size
            PaddingSize = SEGMENT_SIZE - (filesize%SEGMENT_SIZE);
            printf("****PADDING SIZE : 0x%x ****\n",PaddingSize);
            memcpy(pBuffer, &PaddingSize, PADDING_SIZE);
        }

    	VirtualFileSize = filesize + PaddingSize + INFO_SIZE + VerifyLen;

    }
    else
    {        
        fseek(fin, 0, SEEK_SET);
        retlen = fread(pBuffer, sizeof(char), filesize, fin);
        if( retlen != filesize )
        {
            printf("filesize is wrong in decryption\n");
            return 0;
        }

        VirtualFileSize = filesize;
    }

  /**********************padding end******************************/
    memset( bufferin, 0, sizeof( bufferin ) );
    memset( bufferout, 0, sizeof( bufferout ) );
    memset( &aes_ctx, 0, sizeof(  aes_context ) );
#if 1
    if( mode == MODE_ENCRYPT )
    {
        aes_setkey_enc( &aes_ctx, key, 128 );
        /*
         * Encrypt and write the ciphertext.
         */
        retlen =fwrite( pBuffer, 1, INFO_SIZE, fout );
        if(retlen != INFO_SIZE)
        {
            printf("write info failed \n");
        }
        
        for( offset = INFO_SIZE; offset < VirtualFileSize; offset += CRYPTO_SIZE )
        {
            memcpy(bufferin, pBuffer+offset, CRYPTO_SIZE);
            //dataDump(bufferin, CRYPTO_SIZE, "for encrypting data");

            aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, bufferin, bufferout );
            //dataDump(bufferout, CRYPTO_SIZE, "encrypted data");
            if( fwrite( bufferout, 1, CRYPTO_SIZE, fout ) != CRYPTO_SIZE )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", CRYPTO_SIZE);
                goto exit;
            }
        }
    }
    else
    {		
    //dataDump(&key[0], 16, "key");
        aes_setkey_dec( &aes_ctx, key, 128 );

        /*
         * Decrypt and write the plaintext.
         */
        for( offset = INFO_SIZE; offset < VirtualFileSize; offset += CRYPTO_SIZE )
        {
            memcpy(bufferin, pBuffer+offset, CRYPTO_SIZE);
            //dataDump(bufferin, CRYPTO_SIZE, "ready for encrypted");
            aes_crypt_ecb( &aes_ctx, AES_DECRYPT, bufferin, bufferout );
            memcpy(pBuffer+offset, bufferout, CRYPTO_SIZE);
            //dataDump(pBuffer+offset, CRYPTO_SIZE, "encrypted data");
            #if 0
            if( fwrite( pBuffer+offset, 1, CRYPTO_SIZE, ftmp ) != CRYPTO_SIZE )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", CRYPTO_SIZE );
                goto exit;
            }
            #endif
        }
    }
#endif
    if( mode == MODE_DECRYPT )
    {
        printf(">>>>>>>>DECRYPTION<<<<<<<<<<\n");
        memcpy(&PaddingSize,pBuffer,PADDING_SIZE);
        //printf("PaddingSize = %d \n",PaddingSize);
        memcpy(&Encrypted_ID,pBuffer+PADDING_SIZE,ENCRYPTED_ID_SIZE);
        //printf("Encrypted_ID = %d \n",Encrypted_ID);

        memcpy(&Hmac_ID,pBuffer+PADDING_SIZE+ENCRYPTED_ID_SIZE,VERIFIED_ID_SIZE);
        //printf("Hmac_ID = %d \n",Hmac_ID);

        if(Encrypted_ID == 0x1)
        {            
            if(Hmac_ID != 0x0)
            {
                VerifyLen = 0x20;
            }
            
            filesize = VirtualFileSize - PaddingSize - INFO_SIZE - VerifyLen;
            if(Hmac_ID ==0x1)
            {

                printf(">>>>>>>>HMAC<<<<<<<<<<\n");
                //dataDump(&pBuffer[INFO_SIZE], filesize, "filesize");
                //dataDump(&u8KshBuffer[0], KshLen, "KshLen");

                sha2_hmac_starts( &sha2_ctx, &u8KshBuffer[0], KshLen, 0 );
                sha2_hmac_update( &sha2_ctx, &pBuffer[INFO_SIZE], filesize );
                sha2_hmac_finish( &sha2_ctx, sha2sum );

                for(i=0;i<VerifyLen;i++)
                {
                    if(pBuffer[ INFO_SIZE+filesize+i ] != sha2sum[i])
                    {
                        printf(">>>>>HMAC OUTPUT COMPARE FAIL<<<<<\n");
                        //free(pBuf);
                        dataDump(&pBuffer[INFO_SIZE+filesize], VerifyLen, "hmacOut");
                        dataDump(sha2sum, VerifyLen, "hmac");
                        fclose(fin);
                        fclose(fout);
                        return 0;
                    }
                }

                printf(">>>>>HMAC OUTPUT COMPARE SUCCESS<<<<<\n");
            }
            else if( Hmac_ID ==0x2)
            {
                printf(">>>>>>>>SHA<<<<<<<<<<\n");

                //dataDump(&pBuffer[INFO_SIZE], filesize, "pBuffer");

                sha2( &pBuffer[INFO_SIZE], filesize, sha2sum, 0 );
                //dataDump(sha2sum, 32, "shaOut");
                for(i=0;i<VerifyLen;i++)
                {
                    if(pBuffer[i+INFO_SIZE+filesize] != sha2sum[i])
                    {
                        printf(">>>>>SHA OUTPUT COMPARE FAIL<<<<<\n");
                        dataDump(&pBuffer[filesize], VerifyLen, "ShaOut");
                        dataDump(sha2sum, VerifyLen, "sha");
                        fclose(fin);
                        fclose(fout);
                        return 0;
                    }
                }
                printf(">>>>>SHA OUTPUT COMPARE SUCCESS<<<<<\n");
            }
        //printf("filesize = %ld \n",filesize);

        fwrite(pBuffer+INFO_SIZE,sizeof(char),filesize,fout);
        }
    }

    ret = 0;
    fclose(fin);
    fclose(fout);
exit:

    return( ret );
}
