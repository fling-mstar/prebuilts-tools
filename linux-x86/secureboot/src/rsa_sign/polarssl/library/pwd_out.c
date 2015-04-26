#if 0
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#include "prng.h"
#include "timing.h"


#define DID_LEN 16 //bytes
#define LOOKUP_RAND_INFO 8
#define RESERVED 8
#define DATA_IN (DID_LEN+LOOKUP_RAND_INFO+RESERVED)

#define LOOKUP_ROOT_INFO 8
#define LOOKUP_INFO  (LOOKUP_ROOT_INFO+LOOKUP_RAND_INFO)

#define KSS_LEN 16 //bytes
#define KSH_LEN 32 //bytes
#define DB_PWD_LEN 5 //bytes
#define ALIGNED_LEN 11
#define OTHERS_LEN 75 //byts
#define OTP_INFO_LEN (KSS_LEN+KSH_LEN+DB_PWD_LEN)
#define DATA_OUT (KSS_LEN+KSH_LEN+DB_PWD_LEN+OTHERS_LEN)

#define RELEASE_DATA (DID_LEN+KSS_LEN+KSH_LEN+DB_PWD_LEN)
#define ONE_YEAR 3600


#define STR_DID_LEN 32 //bytes
#define STR_KSS_LEN 32
#define STR_KSH_LEN 64
#define STR_DB_PWD_LEN 10
#define STR_RELEASE_DATA (STR_DID_LEN+STR_KSS_LEN+STR_KSH_LEN+STR_DB_PWD_LEN)

#define PRODUCTION_USAGE   \
    
    "\n  ./PWD_OUT.exe <mode>\n" \
    "\n   <mode>: 1. test 2. 001122  <-16byes\n" \
    "\n  example: ./GenerateDataBase test\n" \
    "\n  example: ./GenerateDataBasse 00112233445566778899aabbccddeeff\n" \
    "\n"


int unittestflag=0;

void GenLookupTable(unsigned char lookup_table[],int d1,int d2 )
{
    unsigned int tmp_buf=0;
    int i,j,k;
    unsigned char pu8Seed[16]={0};

    for(j=0;j<d1;j++)
    {
        cc_prng_set_seed( pu8Seed );

        tmp_buf =j ;
        memcpy(&lookup_table[j*d2],&tmp_buf,sizeof(tmp_buf));
        cc_prng_didin(&lookup_table[j*d2],LOOKUP_ROOT_INFO,&lookup_table[j*d2+LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO*8 );
    }
}

void PWD_OUT(unsigned char *DeviceID, unsigned long DID_Len)
{
    int i,j,k;
    unsigned char lookup_table[LOOKUP_INFO]={0};
    unsigned char MagicDeviceID[DATA_OUT]={0};
    unsigned int tmp_buf=0;
    unsigned int residue=0;
    unsigned char minute=0;
    unsigned char second=0;
    unsigned char pu8Seed[16]={0};
#if 0
    for(j=0;j<ONE_YEAR;j++)
    {
        cc_prng_set_seed( pu8Seed );

        tmp_buf =j ;
        memcpy(&lookup_table[j][0],&tmp_buf,sizeof(tmp_buf));
        cc_prng_didin(&lookup_table[j][0],8,&lookup_table[j][8],64 );
    }
#endif
//    GenLookupTable(lookup_table[0],ONE_YEAR,LOOKUP_INFO);

    minute = ((DeviceID[3]&0x1f)<<1)|((DeviceID[4]>>7)&0x1);
    second = ((DeviceID[4]>>1)&0x3f);
    //printf("miunte=%x\n",minute);
    //printf("second=%x\n",second);
    residue=(minute*60+second) %3600;
    lookup_table[0]= (unsigned char)(residue & 0x000000ff);
    lookup_table[1] = (unsigned char)((residue & 0x0000ff00)>>8);

    cc_prng_set_seed( pu8Seed );
    cc_prng_didin(lookup_table,LOOKUP_ROOT_INFO,&lookup_table[LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO*8 );

    memcpy(&DeviceID[DID_LEN],&lookup_table[LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO);
    cc_prng_set_seed( pu8Seed );

#if 0
        printf("DeviceID\n");
        for(j=0;j<32;j++)
        {
            printf("%x ",DeviceID[j]);
        }
        printf("\n");
#endif

    unsigned char PWD[DB_PWD_LEN]={0};
    cc_prng_didin(DeviceID,DID_Len,MagicDeviceID,sizeof(MagicDeviceID)*8 );
    memcpy(PWD,&MagicDeviceID[KSS_LEN+KSH_LEN],sizeof(PWD));
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
    fclose(PWD_file);
    //fwrite(PWD_file,sizeof(unsigned char),STR_DB_PWD_LEN,PWD_file);
}


unsigned int  _atoi(char *str, int hexflag)
{	
    unsigned int  value=0;

       if(*str=='\0') return  value;

    if(hexflag==1){   
    // 16Hex
    //printf("hex\n");
    	//str+=2;
    	while(1){

    	   if(*str>=0x61)
    	   	*str-=0x27;
    	   else if(*str>=0x41)
    	   	*str-=0x07;
    	   
    	   value|=(*str-'0');
    	   str++;
    	   //i++;
              if(*str=='\0') break;
    	   value=value<<4;	  
          }
    }
    else{
    // 10 Dec
    //	printf("dec\n");
           unsigned int  len,tmp=1;;	
    	len=strlen(str);
    	while(len){
    		if(*str>'9') return 0;
    		
    		value+=((str[len-1]-'0')*tmp);

    		len--;
    		tmp=tmp*10;
           }
    }
    return value;
	
}

int convertStrtoHex(char* str, unsigned char* DeviceID)
{
    unsigned char strDeviceID[128]={0};
    //unsigned char DeviceID[16]={0};
    int hexflag=0;
    int i,j,k;
    //printf("%s\n",str);
    //printf("%d\n",strlen(str));

    strncpy(strDeviceID,str,strlen(str));

    if(*strDeviceID=='\0') 
        return 0;

    //if((strDeviceID[0]=='0')&&((strDeviceID[1]=='x')||(strDeviceID[1]=='X')))
        hexflag = 1;
    //else
        //hexflag =0;

    memset(strDeviceID,0,sizeof(strDeviceID));
    for(i=0;i<DID_LEN;i++)
    {
        strncpy(strDeviceID,str+(i)*2,2);        
        DeviceID[i]=_atoi(strDeviceID,hexflag);
    }

#if 0
    for(i=0;i<DID_LEN;i++)
    {
        printf("%02x ",DeviceID[i]);
    }
    printf("\n");
#endif
}
#if 0
void unittest(void)
{
#if 1
    FILE* test_magicfile;
    FILE* test_file;
    unsigned char PWDbuf[DB_PWD_LEN]={0};
    unsigned char DIDbuf[DATA_IN]={0};
    int i,j,k;
    unsigned long filesize=0;    
    //Generate_ReleaseData();

    test_file=fopen("test_file","r");
    if (test_file==NULL)
    {
        return;
    }

    test_magicfile=fopen("test_magicfile","r");
    if (test_magicfile==NULL)
    {
        return;
    }

    fseek(test_file,0,SEEK_END);
    filesize=ftell(test_file);
    fseek(test_file,0,SEEK_SET);
    //printf("filesize=%x\n",filesize);
    //printf("filesize/0x20=%x\n",(filesize/0x20));
    for(i=0;i<(filesize/0x20);i++)
    {
        fread(DIDbuf, sizeof(unsigned char), DID_LEN,test_file);
        fseek(test_file,LOOKUP_RAND_INFO+RESERVED,SEEK_CUR);
#if 0
        printf("DID \n");
        for(j=0;j<0x10;j++)
        {
            printf("%x ",DIDbuf[j]);
        }
        printf("\n");
#endif
        PWD_OUT(DIDbuf,sizeof(DIDbuf));


        fseek(test_magicfile,KSS_LEN+KSH_LEN,SEEK_CUR);
        fread(PWDbuf, sizeof(unsigned char), DB_PWD_LEN,test_magicfile);
        
        printf("debug password in read back\n");
        for(j=0;j<DB_PWD_LEN;j++)
        {
            printf("%x ",PWDbuf[j]);
        }
        printf("\n");
    }
    
    fclose(test_file);
    #endif
}
#endif
void test(void)
{
    int i,j,k;
    char strbuf[128]={0};
    unsigned char DIDbuf[STR_DID_LEN+1]={0};
    unsigned int filesize = 0;
    FILE *strreleasefile;
    strreleasefile=fopen("strreleasefile","r");
    if (strreleasefile==NULL)
    {
        return;
    }
    
    fseek(strreleasefile,0,SEEK_END);
    filesize=ftell(strreleasefile);
    printf("filesize=%d\n",filesize);
    printf("STR_RELEASE_DATA+1=%d\n",STR_RELEASE_DATA+1);
    fseek(strreleasefile,0,SEEK_SET);
    
    for(i=0;i<(filesize/(STR_RELEASE_DATA+1));i++)
    {
        memset(DIDbuf,0,sizeof(DIDbuf));
        fread(DIDbuf,sizeof(unsigned char),STR_DID_LEN,strreleasefile);
        fseek(strreleasefile,STR_KSS_LEN+STR_KSH_LEN+STR_DB_PWD_LEN+1,SEEK_CUR);
        printf("%s \n",DIDbuf);
        sprintf(strbuf,"%s %s","./PWD_OUT.exe",DIDbuf);
        printf("%s \n",strbuf);
        system(strbuf);
    }
    fclose(strreleasefile);
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
        if (strncmp(argv[1],"test",4)==0)
        {
            printf("\n");
            printf("unit_test\n");
            unittestflag = 1;
            //unittest();
            test();
        }
        else if(strlen(argv[1]) == 32)
        {
            //printf("Gen PWD\n");
            unsigned char DeviceID[32]={0};
            convertStrtoHex(argv[1],DeviceID);
            #if 0
            for(i=0;i<32;i++)
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
#endif
