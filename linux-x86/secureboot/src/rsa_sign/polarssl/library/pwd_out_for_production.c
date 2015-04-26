#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

//#include "prng.h"
//#include "timing.h"
#include "CommonUtility.h"


#define DID_LEN 16 //bytes
#define LOOKUP_RAND_INFO 8
#define RESERVED 8
#define DATA_IN (DID_LEN+LOOKUP_RAND_INFO+RESERVED)

#define LOOKUP_ROOT_INFO 8
#define LOOKUP_INFO  (LOOKUP_ROOT_INFO+LOOKUP_RAND_INFO)


// new design efuse_kss_key to gen did
#define RANDOM_NUM_LEN 8
#define TIME_LEN 8 //from year to micro second
#define EFUSE_KSS_KEY (TIME_LEN+RANDOM_NUM_LEN)
#define DEVICE_ID_LEN (RANDOM_NUM_LEN+RANDOM_NUM_LEN)
#define PWD_LEN 5

#define PRODUCTION_USAGE   \
    "\n  ./PWD_OUT.exe 001122  <-16byes\n" \
    "\n  example: ./PWD_OUT.exe 00112233445566778899aabbccddeeff\n" \
    "\n"


int unittestflag=0;



#define KSS_PWD_DEBUG 0
#if KSS_PWD_DEBUG
#define KSS_PWD_DBG(x) x
#else
#define KSS_PWD_DBG(x)
#endif
void PWD_OUT(unsigned char *DeviceID, unsigned long DID_Len)
{
    int j=0;
    FILE* fPWD=NULL;
    unsigned char pu8Seed[16]={0};
    //unsigned char Password[PWD_LEN] = {0};
    //unsigned char pwd_textbuf[2*PWD_LEN+1]={0};
    unsigned char *Password = NULL;
    unsigned int pwd_num = 0;

    printf("How Many bytes in Password : ");
    scanf("%d",&pwd_num);

    Password = malloc(pwd_num);
    if(Password == NULL)
    {
        return;
    }

    fPWD = fopen("pwd_file","w+");
    if(fPWD==NULL)
    {
        return;
    }

    cc_prng_set_seed( pu8Seed );
    memset(Password, 0, sizeof(Password));
    cc_prng_didin(DeviceID,DEVICE_ID_LEN,Password,(pwd_num-1)*8 );
    KSS_PWD_DBG(dataDump(Password, PWD_LEN, "Password before add crc8"));

    // calculate the crc8 of pwd
    crc8_clear();
    for(j=0; j<(pwd_num-1); j++)
    {
        crc8_addbyte(Password[j]);
    }
    Password[pwd_num-1]=crc8_getcrc();
    KSS_PWD_DBG(dataDump(Password, pwd_num, "Password after add crc8"));
    
    unsigned char *pwd_textbuf = NULL;
    pwd_textbuf = malloc(2*pwd_num+1);
    if(pwd_textbuf == NULL)
    {
        return;
    }
    //transfer hex into acsii write kss key into file
    HextoAcsii(Password, pwd_num,  pwd_textbuf);
    printf("%s \n",pwd_textbuf);
    fwrite(pwd_textbuf,sizeof(unsigned char),pwd_num*2,fPWD);
#if 0
    int i,j,k;
    unsigned char lookup_table[LOOKUP_INFO]={0};
    unsigned char MagicDeviceID[DATA_OUT]={0};
    unsigned int tmp_buf=0;
    unsigned int residue=0;
    unsigned char minute=0;
    unsigned char second=0;
    unsigned char pu8Seed[16]={0};
    struct hr_time t;

    get_timer(&t,1);
    printf("%d\n",get_timer(&t,0));
    minute = ((DeviceID[3]&0x1f)<<1)|((DeviceID[4]>>7)&0x1);
    second = ((DeviceID[4]>>1)&0x3f);
    //printf("miunte=%x\n",minute);
    //printf("second=%x\n",second);
    residue=(minute*60+second) %3600;
    lookup_table[0]= (unsigned char)(residue & 0x000000ff);
    lookup_table[1] = (unsigned char)((residue & 0x0000ff00)>>8);
    printf("residue=%d\n",residue);
    printf("residue=%x\n",residue);
    printf("lookup_table[0]=%x\n",lookup_table[0]);
    printf("lookup_table[1]=%x\n",lookup_table[1]);
    cc_prng_set_seed( pu8Seed );
    cc_prng_didin(lookup_table,LOOKUP_ROOT_INFO,&lookup_table[LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO*8 );

    get_timer(&t,1);
    memcpy(&DeviceID[DID_LEN],&lookup_table[LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO);
    cc_prng_set_seed( pu8Seed );
    printf("%d\n",get_timer(&t,0));
#if 1
        printf("DeviceID\n");
        for(j=0;j<32;j++)
        {
            printf("%x ",DeviceID[j]);
        }
        printf("\n");
#endif
get_timer(&t,1);
    unsigned char PWD[DB_PWD_LEN]={0};
    cc_prng_didin(DeviceID,DID_Len,MagicDeviceID,sizeof(MagicDeviceID)*8 );
    memcpy(PWD,&MagicDeviceID[KSS_LEN+KSH_LEN],sizeof(PWD));
printf("%d\n",get_timer(&t,0));
#if 0
        printf("MagicDeviceID\n");
        for(j=0;j<32;j++)
        {
            printf("%x ",MagicDeviceID[j]);
        }
        printf("\n");
#endif
    printf("\n");
    printf("debug password\n");
    for(j=0;j<DB_PWD_LEN;j++)
    {
        printf("%x ",PWD[j]);
    }
    printf("\n\n");

get_timer(&t,1);

#if 1
    // tranfer byte to string ex: 0xab => "AB"
    unsigned char strdeviceid [(STR_DB_PWD_LEN)+1]={0};
    char strpattern[17] = "0123456789ABCDEF";
    int multiple=0;
    residue = 0;

    for(j=0;j<DB_PWD_LEN;j++)
    {
        multiple = PWD[j]/(0x10);
        residue = PWD[j]%(0x10);
        strdeviceid[2*j]=strpattern[multiple];
        strdeviceid[(2*j)+1]=strpattern[residue];
    }

#endif

    FILE* PWD_file;
    PWD_file=fopen("pwd_file","w+");
    if(PWD_file==NULL)
    {
        return;
    }
    fprintf(PWD_file,"%s",strdeviceid);
    putc('\n',PWD_file);
    fclose(PWD_file);
    printf("%d\n",get_timer(&t,0));
#endif
    //fwrite(PWD_file,sizeof(unsigned char),STR_DB_PWD_LEN,PWD_file);
}

int main(int argc, char *argv[])
{
    //printf("%s\n",argv[1]);
    int i,j,k;

    if(argc == 1)
    {
        printf(PRODUCTION_USAGE);
        return 0;
    }
    
    if(argc >= 2)
    {  
        if(strlen(argv[1]) == 32)
        {
            //printf("Gen PWD\n");
            unsigned char DeviceID[16]={0};
            convertStrtoHex(argv[1],DeviceID);
            #if 0
            for(i=0;i<16;i++)
            {
                printf("%02X ", DeviceID[i]); 
            }
            printf("\n");
            #endif
            PWD_OUT(DeviceID,sizeof(DeviceID));
        }
        else
        {
            printf(PRODUCTION_USAGE);
        }
    }
    else
    {
        printf(PRODUCTION_USAGE);
    }
    
    return 0;
}

