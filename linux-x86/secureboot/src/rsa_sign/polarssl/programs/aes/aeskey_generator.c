/*
 *  AES-256 file encryption program
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

#if defined(WIN32)
#include <windows.h>
#include <io.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "polarssl/aes.h"
#include "polarssl/sha2.h"
#include "polarssl/prng.h"
#include "polarssl/CommonUtility.h"

#define AESKEY_LEN 0x10

int main( int argc, char *argv[] )
{
    int ret = 0;
    int i,j,k;
    int seed=0;
    unsigned char u8Seed[AESKEY_LEN]={0};
    unsigned char Time[16]={0};
    unsigned char aeskey[AESKEY_LEN]={0};
    FILE* fAesKey = NULL;
    FILE* fAesKeytext = NULL;

    
    printf("Please input seed  : ");
    ret =scanf("%d",&seed);
    if (ret != 1)
    {
        return 0;
    }
    printf("ret = %d \n",ret);
    printf("seed = %d \n",seed);
    
    fAesKey = fopen ("AES_KEY.bin","w+");
    if(fAesKey == NULL)
    {
        return 0;
    }

    fAesKeytext = fopen ("AES_KEY.txt","w+");
    if(fAesKeytext == NULL)
    {
        fclose(fAesKey);
        return 0;
    }    
    
    memcpy(u8Seed, &seed, sizeof(seed));
    for (i=0; i < sizeof(u8Seed); i++)    
        printf(" %x ",u8Seed[i]);
    printf("\n");
    //memset(pu8Seed, 0, sizeof(pu8Seed));

    //dataDump(Time, sizeof(Time), "before get time");
    Get_Time(Time);
    //dataDump(Time, sizeof(Time), "after get time");

    cc_prng_set_seed( u8Seed );

    cc_prng_didin(Time, sizeof(Time), aeskey, sizeof(aeskey)*8 );
    for (i=0; i<sizeof(aeskey); i++)    
        printf(" %x ",aeskey[i]);
    printf("\n");
    fwrite(aeskey, sizeof(unsigned char), AESKEY_LEN, fAesKey);

    unsigned char *aeskey_textbuf = NULL;
    aeskey_textbuf = malloc(2*AESKEY_LEN+1);
    if(aeskey_textbuf == NULL)
    {
        return;
    }

    HextoAcsii(aeskey, AESKEY_LEN,  aeskey_textbuf);
    printf("%s \n",aeskey_textbuf);
    fwrite(aeskey_textbuf, sizeof(unsigned char), AESKEY_LEN*2, fAesKeytext);
    return( ret );
}
