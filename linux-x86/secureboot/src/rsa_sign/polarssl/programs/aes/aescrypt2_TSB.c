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

//#define Hmac	1
#define SEGMENT_SIZE 16
#define PADDING_SIZE 2
#define ENCRYPTED_ID_SIZE 1
#define HMAC_ID_SIZE 1
#define KEY_INDEX_SIZE 1
#define DUMMY_SIZE 26
#define VERSION_SIZE 1
#define INFO_SIZE 64
#define SW_VERSION 1

#define CRYPTO_SIZE    16
#define MAGIC_ID_SIZE   32

unsigned char efuse_Aes_Key[16]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char Magic_ID[32]="MSTAR_SECURE_STORE_FILE_MAGIC_ID";

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

int encryption(unsigned char *bufin, unsigned char *bufout, int len, int mode)
{
    sha2_context sha2_ctx;
    off_t offset;
    aes_context aes_ctx;
    int ret = 1, n,retval=0;

    char *p;
    unsigned char bufferin[16]={0};
    unsigned char bufferout[16]={0};
    unsigned char sha2sum[32]={0};
    unsigned char u8KshBuffer[32]={0};
    unsigned int FileSize = 0;
    unsigned int VirtualFileSize = 0;
    unsigned short PaddingSize= 0;
    unsigned char Encrypted_ID = 0 ;
    unsigned char Hmac_ID = 0 ;
    //unsigned int HmacLen =0;
    unsigned int VerifyLen =0;

    unsigned char* pBuffer=NULL;
    unsigned char PadData[SEGMENT_SIZE]={0};
    int buffersize=0;
    int retlen=0;
    int paddsize=0;
    unsigned int i=0;


    // malloc
    pBuffer = (unsigned char*) malloc(len*10);
    if(pBuffer == NULL)
    {
        return 0;
    }
    //printf("filesize=%d\n",filesize);
    memset(pBuffer,0,len*10);


    printf(">>>>>>>>ENCRYPTION<<<<<<<<<<\n");

    /*copy padding size*/
    if(len%SEGMENT_SIZE)
    {   
        PaddingSize = SEGMENT_SIZE-(len%SEGMENT_SIZE);
    }
    
    printf("****PADDING SIZE : 0x%x ****\n",PaddingSize);
    memcpy(pBuffer,&PaddingSize,PADDING_SIZE);

    /*copy Encryption ID*/
    pBuffer[PADDING_SIZE]=0x1;
    /*copy verification ID 0 : no verified mode, 2 : sha256*/
    pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE]=0x0;
    /*copy Key index  2:efuse_aes_Key*/
    pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+HMAC_ID_SIZE] = 0x2;

    /*dummy bytes 0xff*/
    for(i=0; i<DUMMY_SIZE;i++)
    {
        pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+HMAC_ID_SIZE+KEY_INDEX_SIZE+i] = 0xff;
    }

    /*sw version*/
    pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE+HMAC_ID_SIZE+KEY_INDEX_SIZE+DUMMY_SIZE] = SW_VERSION;
    
    /// write Magic ID
    for(i=0;i<(MAGIC_ID_SIZE);i++)
    {
        pBuffer[INFO_SIZE-MAGIC_ID_SIZE+i] = Magic_ID[i];
    }

    memcpy(pBuffer+INFO_SIZE, bufin, len);

    if(mode == 1 )
    {
        printf(">>>>>>>>SHA<<<<<<<<<<\n");
        pBuffer[PADDING_SIZE+ENCRYPTED_ID_SIZE]=0x2;
        VerifyLen = 0x20;
        sha2(&pBuffer[INFO_SIZE], len, sha2sum, 0);
        //dataDump(sha2sum, sizeof(sha2sum), "shasum");
        memcpy(pBuffer+INFO_SIZE+len, &sha2sum[0], VerifyLen);
    }

    VirtualFileSize = len + PaddingSize + INFO_SIZE + VerifyLen;

    /*
     * Encrypt and write the ciphertext.
     */
    memset( bufferin, 0, sizeof( bufferin ) );
    memset( bufferout, 0, sizeof( bufferout ) );
    memset( &aes_ctx, 0, sizeof(  aes_context ) );

    aes_setkey_enc( &aes_ctx, efuse_Aes_Key, 128 );

    memcpy(bufout, pBuffer, INFO_SIZE);

    for( offset = INFO_SIZE; offset < VirtualFileSize; offset += CRYPTO_SIZE )
    {
        memcpy(bufferin, pBuffer+offset, CRYPTO_SIZE);
        //dataDump(bufferin, CRYPTO_SIZE, "for encrypting data");

        aes_crypt_ecb( &aes_ctx, AES_ENCRYPT, bufferin, bufferout );

        memcpy(bufout+offset,bufferout,CRYPTO_SIZE);
    }
    return VirtualFileSize;
}

int decryption(unsigned char *bufin, unsigned char *bufout, int len)
{
    sha2_context sha2_ctx;
    off_t offset;
    aes_context aes_ctx;
    int ret = 1, n,retval=0;

    char *p;
    unsigned char bufferin[16]={0};
    unsigned char bufferout[16]={0};
    unsigned char sha2sum[32]={0};
    unsigned int VirtualFileSize = 0;
    unsigned short PaddingSize= 0;
    unsigned char Encrypted_ID = 0 ;
    unsigned char Hmac_ID = 0 ;
    unsigned int VerifyLen =0;

    unsigned char* pBuffer=NULL;
    unsigned char PadData[SEGMENT_SIZE]={0};
    int buffersize=0;
    int retlen=0;
    int filesize = 0;
    int paddsize=0;
    unsigned int i=0;

    pBuffer = (unsigned char*) malloc(len*10);
    if(pBuffer == NULL)
    {
        return 0;
    }
    //printf("filesize=%d\n",filesize);
    memset(pBuffer,0,len*10);


    memcpy(pBuffer, bufin, len);
    VirtualFileSize = len;
      aes_setkey_dec( &aes_ctx, efuse_Aes_Key, 128 );

    /*
     * Decrypt and write the plaintext.
     */
    for( offset = INFO_SIZE; offset < VirtualFileSize; offset += CRYPTO_SIZE )
    {
        memcpy(bufferin, pBuffer+offset, CRYPTO_SIZE);
        //dataDump(bufferin, CRYPTO_SIZE, "ready for encrypted");
        aes_crypt_ecb( &aes_ctx, AES_DECRYPT, bufferin, bufferout );
        memcpy(pBuffer+offset, bufferout, CRYPTO_SIZE);
        //dataDump(pBuffer+offset, CRYPTO_SIZE, "clear data");
     }

    printf(">>>>>>>>DECRYPTION<<<<<<<<<<\n");
    memcpy(&PaddingSize,pBuffer,PADDING_SIZE);
    memcpy(&Encrypted_ID,pBuffer+PADDING_SIZE,ENCRYPTED_ID_SIZE);
    memcpy(&Hmac_ID,pBuffer+PADDING_SIZE+ENCRYPTED_ID_SIZE,HMAC_ID_SIZE);

    if(Hmac_ID !=0)
    {
        VerifyLen = 0x20;
    }
    //printf("PaddingSize=%x\n",PaddingSize);
    //printf("Encrypted_ID=%x\n",Encrypted_ID);
    //printf("Hmac_ID=%x\n",Hmac_ID);
    if(Encrypted_ID == 0x1)
    {
         filesize = VirtualFileSize - PaddingSize - INFO_SIZE - VerifyLen;

        if(Hmac_ID !=0)
        {
            printf(">>>>>>>>SHA<<<<<<<<<<\n");
            //printf("filesize=%x\n",filesize);
            //dataDump(&pBuffer[INFO_SIZE], filesize, "pBuffer");
            sha2( &pBuffer[INFO_SIZE], filesize, sha2sum, 0 );
            //dataDump(sha2sum, 32, "shaOut");
            for(i=0;i<VerifyLen;i++)
            {
                if(pBuffer[i+INFO_SIZE+filesize] != sha2sum[i])
                {
                    printf(">>>>>SHA OUTPUT COMPARE FAIL<<<<<\n");
                    //free(pBuf);
                    dataDump(&pBuffer[filesize], VerifyLen, "ShaOut");
                    dataDump(sha2sum, VerifyLen, "sha");
                    return 0;
                }
            }
            printf(">>>>>SHA OUTPUT COMPARE SUCCESS<<<<<\n");
        }
     //printf("filesize=%x\n",filesize);
    //rite(pBuffer+INFO_SIZE,sizeof(char),filesize,fout);
    memcpy(bufout, &pBuffer[INFO_SIZE], filesize);
    }

    return filesize;
}

int main( int argc, char *argv[] )
//int main(void)
{
	//char argv[5][20];
	//int argc = 5;
    FILE *fkey, *fin, *fout,*ftmp1, *ftmp2;
    sha2_context sha2_ctx;
    off_t filesize, offset;
    aes_context aes_ctx;
    int ret = 0, n,retval=0;

    char *p;
    unsigned char key[16]={0};
    unsigned char bufferin[16]={0};
    unsigned char bufferout[16]={0};
    unsigned char sha2sum[32]={0};
#if 0
	unsigned char u8KshBuffer[32]={0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
																 0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33,0x33};
#endif

    unsigned char u8KshBuffer[32]={0};
    unsigned int FileSize = 0;
    unsigned int VirtualFileSize = 0;
    unsigned short PaddingSize= 0;
    unsigned char Encrypted_ID = 0 ;
    unsigned char Hmac_ID = 0 ;
    //unsigned int HmacLen =0;
    unsigned int VerifyLen =0;

    unsigned char* pBufferin=NULL;
    unsigned char* pBufferout=NULL;

    unsigned char PadData[SEGMENT_SIZE]={0};
    int buffersize=0;
    int retlen=0;
    int paddsize=0;
    int cpysize=0;
    unsigned int i=0;

    char* tmpfile1 ="tmp1";
    char* tmpfile2 ="tmp2";
    /*
     * Parse the command-line arguments.
     */

    if( ( fin = fopen( argv[1], "rb+" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,rb) failed\n", argv[2] );
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
    pBufferin = malloc(filesize*10);
    if(pBufferin == NULL)
    {
        return 0;
    }
    
    pBufferout = malloc(filesize*10);
    if(pBufferout == NULL)
    {
        return 0;
    }
    //printf("filesize=%d\n",filesize);
    memset(pBufferin,0,filesize*10);


    ret = fread(pBufferin,sizeof(char), filesize, fin);
    if(ret != filesize)
    {
        goto exit;
    }

    if( ( ftmp1= fopen( tmpfile1, "wb" ) ) == NULL )
    {
        goto exit;
    }

    VirtualFileSize = encryption(pBufferin, pBufferout, filesize, 0 );
        fwrite(pBufferout, sizeof(unsigned char), VirtualFileSize, ftmp1);

    printf("VirtualFileSize = %d\n",VirtualFileSize);
//    dataDump(pBufferout, VirtualFileSize, "encrypted data");
    memset(pBufferin,0,filesize);    
    ret = decryption(pBufferout, pBufferin,  VirtualFileSize);
//    dataDump(pBufferin, ret, "clear data");

    fwrite(pBufferin, sizeof(unsigned char), ret, ftmp1);

    printf("\n\n*********SHA256**********\n\n");

    if( ( ftmp2= fopen( tmpfile2, "wb" ) ) == NULL )
    {
        goto exit;
    }

    VirtualFileSize = encryption(pBufferin, pBufferout, filesize, 1 );
    printf("VirtualFileSize = %d\n",VirtualFileSize);
    fwrite(pBufferout, sizeof(unsigned char), VirtualFileSize, ftmp2);

//    dataDump(pBufferout, VirtualFileSize, "encrypted data");
    memset(pBufferin,0,filesize);    
    ret = decryption(pBufferout, pBufferin,  VirtualFileSize);

//    dataDump(pBufferin, ret, "clear data");
    fwrite(pBufferin, sizeof(unsigned char), ret, ftmp2);

    
exit:
    ret = 0;
    return( ret );
}
