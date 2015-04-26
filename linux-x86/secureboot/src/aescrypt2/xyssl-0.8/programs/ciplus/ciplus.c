/**
 * MStar Semiconductor
 * Data : 2008/02/21
 * Creator : Max Huang
 * Description: Encode 188 Transport Stream with CI plus protocol ( AES-128 CBC mode or DES-56 ECB mode)
 */
 
 
#include <sys/types.h>
#include <unistd.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "xyssl/aes.h"
#include "xyssl/des.h"

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1
#define AES_PROTOCOL    0
#define DES_PROTOCOL    1
#define TS_PACKET_LENGTH 188
#define EVEN_KEY_FLAG  2    // bit 10
#define ODD_KEY_FLAG 3    // bit 11

#define USAGE   \
    "\n  ciplus PID <protocol> <mode> <input filename> <output filename> <even|odd> <key> <IV> \n" \
    "\n  PID : 0x0111   for hex presentation\n" \
    "\n  protocol: aes or des\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  0 for even key , 1 for odd key\n" \
    "\n  key: 64 bits for DES , 128 bits for AES\n" \
    "\n  IV : 128 bits only for AES protocol\n" \
    "\n  example: ciplus 0x01ff des 0 file file.des 0 hex:E75533F311223344 \n" \
    "\n  example: ciplus 0x0100 aes 0 file file.aes 1 hex:E75533F3112233E75533F3112233AABB hex:E75533F3112233E75533F3112233AABB\n" \
    "\n"



void aes_ts_packet(int mode,unsigned char* bufferin,unsigned char* bufferout,unsigned char* key,unsigned char* IV);
void des_ts_packet(int mode,unsigned char* bufferin,unsigned char* bufferout,unsigned char* key);

unsigned char odd_even_key;
    
int main( int argc, char *argv[] )
{
    int ret = 1, i, n;
    int keylen, mode, lastn,protocol;
    FILE *fkey, *fin, *fout;
    int pid;
    
    char *p;
    unsigned char IV[16];
    unsigned char packetIV[16];
    unsigned char key[16];
    unsigned char buffer[TS_PACKET_LENGTH];
    unsigned char outbuffer[TS_PACKET_LENGTH];
    

    off_t filesize, offset;
    
    
    if( argc != 8 && argc != 9 )
    {
        printf( USAGE );
        goto exit;
    }
    
    sscanf(argv[1],"0x%04X" , &pid);
    
    
    if ( strcmp( argv[2] , "des") == 0 )
    {
        protocol = DES_PROTOCOL;
            
    } else if (  strcmp( argv[2] , "aes") ==0 )
    {
        protocol = AES_PROTOCOL; 
        
    }
    else
    {
        printf("CI plus only supports AES/DES encryption/descrption.\n");
        goto exit;        
        
    }
    
    mode = atoi( argv[3] );

    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        fprintf( stderr, "invalide operation mode\n" );
        goto exit;
    }
    
    if( strcmp( argv[4], argv[5] ) == 0 )
    {
        fprintf( stderr, "input and output filenames must differ\n" );
        goto exit;
    }
    
    if( ( fin = fopen( argv[4], "rb" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,rb) failed\n", argv[3] );
        goto exit;
    }

    if( ( fout = fopen( argv[5], "wb+" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,wb+) failed\n", argv[4] );
        goto exit;
    }
    
    if ( memcmp( argv[6],"0",1) == 0)
    {
    	odd_even_key = EVEN_KEY_FLAG;
    	
    	
    } else
    {
    	odd_even_key = ODD_KEY_FLAG ; 
	}
    if( memcmp( argv[7], "hex:", 4 ) == 0 )
    {
        p = &argv[7][4];
        keylen = 0;

        while( sscanf( p, "%02X", &n ) > 0 &&
             keylen < (int) sizeof( key ) )
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
    
    
    
    if ( protocol == DES_PROTOCOL )
    {
        if ( keylen != 8 )
        {
            printf("error key length . It must be 64 bits for DES\n");
            goto exit;
        }
    
    }
    else  // AES protocol
    {
        int ivlen;
        if ( keylen != 16 )
        {
            printf("error key length =%d. It must be 128 bits for AES\n",keylen);
            goto exit;
        }
        if( memcmp( argv[8], "hex:", 4 ) == 0 )
        {
            p = &argv[8][4];
            ivlen = 0;

            while( sscanf( p, "%02X", &n ) > 0 &&
                ivlen < (int) sizeof( IV ) )
            {
                IV[ivlen++] = (unsigned char) n;
                p += 2;
            }
        }
        else 
        {
            printf("error IV format . It must be hex:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \n");        
            goto exit;
        }   
        if ( ivlen != 16)
        {
            printf("error IV length . It must be 128 bits for AES\n");
            goto exit;         
        }
    }
    
    //printf("key length is %d  PID=0x%04X\n",keylen,pid);
    
    while ( fread( buffer, 1, TS_PACKET_LENGTH, fin ) == TS_PACKET_LENGTH )
    {
        if ( buffer[0] != 0x47 )
        {
            printf("The first byte of TS packet is not 0x47 \n");
            break;
        
        }
        if (  (((buffer[1] & 0x1F) << 8) | buffer[2] )  == pid )
        {
            if ( protocol == AES_PROTOCOL )
            {
                memcpy(packetIV,IV,16);
                aes_ts_packet( mode , buffer , outbuffer , key , packetIV);
                
            }
            else  //DES protocol
            {
                des_ts_packet( mode , buffer , outbuffer, key);
                
            }
            
            fwrite(outbuffer , 1 , TS_PACKET_LENGTH,fout);
            
        }
        else
            fwrite(buffer , 1, TS_PACKET_LENGTH , fout);
        
       
    }
    
    fclose(fin);
    fclose(fout);
    
    
/*    if ( protocol == AES_PROTOCOL)
    {
        if ( mode == MODE_ENCRYPT )
        {
            aes_setkey_enc(&aes_ctx,key,128);
            
            if( fread( buffer, 1, 32, fin ) != 32 )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", 32 );
                goto exit;
            }
            
            aes_crypt_cbc(&aes_ctx,AES_ENCRYPT ,16,IV,buffer,outbuffer);
            aes_crypt_cbc(&aes_ctx,AES_ENCRYPT ,16,IV,buffer+16,outbuffer+16);
            n=32;
            if( fwrite( outbuffer, 1, n, fout ) != (size_t) n )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", n );
                goto exit;
            }
        }
        else
        {
            aes_setkey_dec(&aes_ctx,key,128);     
            if( fread( buffer, 1, 32, fin ) != 32 )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", 32 );
                goto exit;
            }
            
            aes_crypt_cbc(&aes_ctx,AES_DECRYPT ,16,IV,buffer,outbuffer);
            aes_crypt_cbc(&aes_ctx,AES_DECRYPT ,16,IV,buffer+16,outbuffer+16);
            n=32;
            if( fwrite( outbuffer, 1, n, fout ) != (size_t) n )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", n );
                goto exit;
            }            
            
        }
    }   
    else   //DES protocol
    {
        if ( mode == MODE_ENCRYPT )
        {
            des_setkey_enc(&des_ctx,key);
            
            if( fread( buffer, 1, 32, fin ) != 32 )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", 32 );
                goto exit;
            }
            
            des_crypt_ecb(&des_ctx,buffer,outbuffer);
            des_crypt_ecb(&des_ctx,buffer+8,outbuffer+8);
            des_crypt_ecb(&des_ctx,buffer+16,outbuffer+16);
            des_crypt_ecb(&des_ctx,buffer+24,outbuffer+24);
            n=32;
            if( fwrite( outbuffer, 1, n, fout ) != (size_t) n )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", n );
                goto exit;
            }
        }
        else
        {
            des_setkey_dec(&des_ctx,key);     
            if( fread( buffer, 1, 32, fin ) != 32 )
            {
                fprintf( stderr, "fread(%d bytes) failed\n", 32 );
                goto exit;
            }
            
            des_crypt_ecb(&des_ctx,buffer,outbuffer);
            des_crypt_ecb(&des_ctx,buffer+8,outbuffer+8);
            des_crypt_ecb(&des_ctx,buffer+16,outbuffer+16);
            des_crypt_ecb(&des_ctx,buffer+24,outbuffer+24);
            n=32;
            if( fwrite( outbuffer, 1, n, fout ) != (size_t) n )
            {
                fprintf( stderr, "fwrite(%d bytes) failed\n", n );
                goto exit;
            }            
            
        }
    }  
*/               
exit:    
    return 0;   
}


void aes_ts_packet(int mode,unsigned char* bufferin,unsigned char* bufferout,unsigned char* key,unsigned char* IV)
{
    aes_context aes_ctx;
    int header_len=0;
    int ts_left=TS_PACKET_LENGTH-4;
    int adaptation_field_flag=0;
    int adaptation_field_length=0;
    
    adaptation_field_flag = ((  (bufferin[3]& 0x30) >> 4  ) >=2 ) ? 1 : 0 ;
    if ( adaptation_field_flag != 0 )
        ts_left -= ( 1 + bufferin[4]);
    
    if ( mode == MODE_ENCRYPT )  //encrypt
    {
        bufferin[3] = (( bufferin[3] & 0x3F ) | (odd_even_key << 6));
        header_len = TS_PACKET_LENGTH - ts_left;
        memcpy( bufferout , bufferin,  header_len);
        bufferin+= header_len;
        bufferout+= header_len;
        
        aes_setkey_enc(&aes_ctx,key,128);
        //printf("ts left = %d\n",ts_left);
        while ( ts_left > 15 )
        {
            
            
            aes_crypt_cbc(&aes_ctx,AES_ENCRYPT ,16,IV,bufferin,bufferout);
            //memcpy(bufferout,bufferin,16);
            ts_left -= 16;
            bufferin += 16;
            bufferout+= 16;  
        }
        //printf("ts left = %d\n",ts_left);
        memcpy( bufferout,bufferin,ts_left);
        
    }
    else  //decrypt
    {
        bufferin[3] = bufferin[3] & 0x3F ;
        header_len = TS_PACKET_LENGTH - ts_left;
        memcpy( bufferout , bufferin,  header_len);
        bufferin+= header_len;
        bufferout+= header_len;
        aes_setkey_dec(&aes_ctx,key,128);
        while ( ts_left > 15 )
        {
            
            aes_crypt_cbc(&aes_ctx,AES_DECRYPT ,16,IV, bufferin , bufferout );
            
            //memcpy(bufferout,bufferin,16);
            ts_left -= 16;
            bufferin += 16;
            bufferout+= 16;  
        }
        memcpy( bufferout,bufferin,ts_left);        
    }
}

void des_ts_packet(int mode,unsigned char* bufferin,unsigned char* bufferout,unsigned char* key)
{
    des_context des_ctx;
    int header_len=0;
    int ts_left=TS_PACKET_LENGTH-4;
    int adaptation_field_flag=0;
    int adaptation_field_length=0;
    
    adaptation_field_flag = ((  (bufferin[3]& 0x30) >> 4  ) >=2 ) ? 1 : 0 ;
    if ( adaptation_field_flag != 0 )
        ts_left -= ( 1 + bufferin[4]);
    
    if ( mode == MODE_ENCRYPT )  //encrypt
    {
        bufferin[3] = (( bufferin[3] & 0x3F ) | (odd_even_key << 6));
        header_len = TS_PACKET_LENGTH - ts_left;
        memcpy( bufferout , bufferin,  header_len);
        bufferin+= header_len;
        bufferout+= header_len;
        
        des_setkey_enc(&des_ctx,key);
        while ( ts_left > 7 )
        {
            
            des_crypt_ecb(&des_ctx,bufferin,bufferout);
            
            //memcpy(bufferout,bufferin,8);
            ts_left -= 8;
            bufferin += 8;
            bufferout+= 8;  
        }
        memcpy( bufferout,bufferin,ts_left);
        
    }
    else  //decrypt
    {
        bufferin[3] = bufferin[3] & 0x3F ;
        header_len = TS_PACKET_LENGTH - ts_left;
        memcpy( bufferout , bufferin,  header_len);
        bufferin+= header_len;
        bufferout+= header_len;
        des_setkey_dec(&des_ctx,key); 
        while ( ts_left > 7 )
        {
            
            
            des_crypt_ecb(&des_ctx,bufferin,bufferout);
            //memcpy(bufferout,bufferin,8);
            ts_left -= 8;
            bufferin += 8;
            bufferout+= 8;  
        }
        memcpy( bufferout,bufferin,ts_left);        
    }    
    
}
