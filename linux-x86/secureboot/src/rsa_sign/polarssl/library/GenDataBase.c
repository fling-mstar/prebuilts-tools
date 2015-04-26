#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#include "prng.h"
#include "timing.h"
#include "CommonUtility.h"

#define ESN_LEN 0x10
#define ESN_BASE32_LEN 0x10
#define ESN_MODELID_LEN 10
#define ESN_DEVICEID_LEN 6

#define KPE_LEN 0x10
#define KPE_BASE64_LEN 0x18

#define KPH_LEN 0x20
#define KPH_BASE64_LEN 0x2C

#define DID_LEN 16 //bytes
#define LOOKUP_RAND_INFO 8
#define RESERVED 8
#define DATA_IN (DID_LEN+LOOKUP_RAND_INFO+RESERVED)

#define LOOKUP_ROOT_INFO 8
#define LOOKUP_INFO  (LOOKUP_ROOT_INFO+LOOKUP_RAND_INFO)

#define KSS_LEN 16 //bytes
#define KSH_LEN 32 //bytes
#define DB_PWD_LEN 5 //bytes
#define OTHERS_LEN 75 //byts
#define OTP_INFO_LEN (KSS_LEN+KSH_LEN+DB_PWD_LEN)
#define DATA_OUT (KSS_LEN+KSH_LEN+DB_PWD_LEN+OTHERS_LEN)
 
#define CRC32_LEN  4
#define ALIGNED_LEN (16-DB_PWD_LEN-DB_PWD_LEN-CRC32_LEN)
#define RELEASE_DATA (DID_LEN+KSS_LEN+KSH_LEN+DB_PWD_LEN+DB_PWD_LEN+CRC32_LEN)
#define ONE_YEAR 3600

// new design efuse_kss_key to gen did
#define RANDOM_NUM_LEN 8
#define TIME_LEN 8 //from year to micro second
#define EFUSE_KSS_KEY (TIME_LEN+RANDOM_NUM_LEN)
#define DEVICE_ID_LEN (RANDOM_NUM_LEN+RANDOM_NUM_LEN)
#define PWD_LEN 5

#define PRODUCTION_USAGE   \
    "\n  ./GenerateDataBase <mode>\n" \
    "\n   <mode>: 1. KEY_PWD  2. PreSharedKey 3. crc_check 4. GenKssKshPwd \n " \
    "\n  example: ./GenDataBase KEY_PWD\n" \
    "\n  example: ./GenDataBase PreSharedKey\n" \
    "\n  example: ./GenDataBase crc_check\n" \
    "\n  example: ./GenDataBase GenKssKshPwd\n" \
    "\n"
    
int unittestflag=1;

#define KSS_PWD_DEBUG 0
#if KSS_PWD_DEBUG
#define KSS_PWD_DBG(x) x
#else
#define KSS_PWD_DBG(x)
#endif
void GenKss_Pwd(void)
{
    FILE* releasefile=NULL;
    FILE* deviceid_file=NULL;

    int i,j,k;
    
    unsigned char Time[TIME_LEN+RANDOM_NUM_LEN] = {0};
    //unsigned char TimeWRandInfo[TIME_LEN+RANDOM_NUM_LEN] = {0};

    unsigned char Efuse_Kss_Key[EFUSE_KSS_KEY] = {0};
    unsigned char DeviceID[DEVICE_ID_LEN] = {0};
    //unsigned char Password[PWD_LEN] = {0};
    unsigned char pu8Seed[16]={0};
    unsigned int number = 0;
    unsigned int pwd_num = 0;
    unsigned int RandInfoLen = 0;
    unsigned char *Password = NULL;
    printf("How Many sets in MP : ");
    scanf("%d",&number);
    
    printf("How Many bytes in Password : ");
    scanf("%d",&pwd_num);

    Password = malloc(pwd_num);
    if(Password == NULL)
    {
        return;
    }
    releasefile = fopen("kss_pwd_release_file","w+");
    if(releasefile==NULL)
    {
        return;
    }

    deviceid_file = fopen("device_id_file","w+");
    if(releasefile==NULL)
    {
        return;
    }


    for(i=0;i<number;i++)
    {
        cc_prng_set_seed( pu8Seed );

        // start get time
        memset(Time,0,sizeof(Time));
        // one number in one element
        Get_Time(Time);
        //memset(Time,0,sizeof(Time));

        // convert time and add micro second, add randon number
        //Convert_Add_Micro_into_Time(fuse_id,Time);

        KSS_PWD_DBG(dataDump(Time, sizeof(Time), "Time"));
        RandInfoLen = 8;
        Add_Random_Info(Time,Time,RandInfoLen);
        KSS_PWD_DBG(dataDump(Time, sizeof(Time), "after add random info intoTime"));
        
        memset(pu8Seed, 0, sizeof(pu8Seed));
        /*Gen Kss by time and write into file in ASCII*/
        // send Time into prng and gen pwd
        cc_prng_set_seed( pu8Seed );
        memset(Efuse_Kss_Key, 0, sizeof(Efuse_Kss_Key));
        cc_prng_didin(Time,sizeof(Time),Efuse_Kss_Key,(EFUSE_KSS_KEY-1)*8 );
        
        KSS_PWD_DBG(dataDump(Efuse_Kss_Key, EFUSE_KSS_KEY, "Kss_Key : before add crc"));
        
        // calculate the crc8 of efuse_kss_key
        crc8_clear();
        for(j=0; j<EFUSE_KSS_KEY-1; j++)
        {
            crc8_addbyte(Efuse_Kss_Key[j]);
        }
        Efuse_Kss_Key[EFUSE_KSS_KEY-1]=crc8_getcrc();
        KSS_PWD_DBG(dataDump(Efuse_Kss_Key, EFUSE_KSS_KEY, "Kss_Key : after add crc"));

        //transfer hex into acsii write kss key into file
        unsigned char kss_textbuf[2*EFUSE_KSS_KEY+1]={0};
        HextoAcsii(Efuse_Kss_Key, EFUSE_KSS_KEY,  kss_textbuf);
        KSS_PWD_DBG(printf("%s \n",kss_textbuf));
        fwrite(kss_textbuf,sizeof(unsigned char),2*EFUSE_KSS_KEY,releasefile);
        /*Gen Kss by time and write into file in ASCII*/


        //copy 8bytes to device id from kss key and reverse
        memcpy(&DeviceID[0],&Efuse_Kss_Key[0],DEVICE_ID_LEN/2); // <- what bits in kss key need to be assign to device id
        for(j=0; j<DEVICE_ID_LEN/2; j++)
        {
            DeviceID[j+(DEVICE_ID_LEN/2)] = ~DeviceID[j];
        }
        KSS_PWD_DBG(dataDump(DeviceID, DEVICE_ID_LEN, "DeviceID"));

        unsigned char deviceid_textbuf[2*DEVICE_ID_LEN+1]={0};
        HextoAcsii(DeviceID, EFUSE_KSS_KEY,  deviceid_textbuf);
        KSS_PWD_DBG(printf("%s \n",deviceid_textbuf));
        fwrite(deviceid_textbuf,sizeof(unsigned char),2*EFUSE_KSS_KEY,deviceid_file);
        putc('\n',deviceid_file);



        /*Gen PWD by DID and write into file in ASCII*/
        // send device id into prng and gen pwd
        memset(pu8Seed, 0, sizeof(pu8Seed));
        cc_prng_set_seed( pu8Seed );
        memset(Password, 0, pwd_num);
        cc_prng_didin(DeviceID,DEVICE_ID_LEN,Password,(pwd_num-1)*8 );
        KSS_PWD_DBG(dataDump(Password, pwd_num, "Password before add crc8"));

        // calculate the crc8 of pwd
        crc8_clear();
        for(j=0; j<(pwd_num-1); j++)
        {
            crc8_addbyte(Password[j]);
        }
        Password[pwd_num-1]=crc8_getcrc();
        KSS_PWD_DBG(dataDump(Password, pwd_num, "Password after add crc8"));

        //transfer hex into acsii write kss key into file
        //unsigned char pwd_textbuf[2*pwd_num+1]={0};
        unsigned char *pwd_textbuf = NULL;
        pwd_textbuf = malloc(2*pwd_num+1);
        if(pwd_textbuf == NULL)
        {
            return;
        }

        HextoAcsii(Password, pwd_num,  pwd_textbuf);
        KSS_PWD_DBG(printf("%s \n",pwd_textbuf));
        fwrite(pwd_textbuf,sizeof(unsigned char),pwd_num*2,releasefile);
        //or fprintf(PWD_file,"%s",hexbuf);
        /*Gen PWD by DID and write into file in ASCII*/
        
        putc('\n',releasefile);
    }
            fclose(releasefile);

    return;
}


int Generate_ReleaseData(void)
{
 //  int fuse_id[64];
    int i,j,k;
    unsigned char DeviceID[DATA_IN]={0};
    unsigned char MagicDeviceID[DATA_OUT]={0};
    unsigned char ReleaseData[RELEASE_DATA+ALIGNED_LEN] ={0};
    //unsigned char DBPassword[DB_PWD_LEN]={0};
    unsigned char pu8Seed[16]={0};
    unsigned char lookup_table[LOOKUP_INFO]={0};
    unsigned char aligned_data[ALIGNED_LEN]={0};//for beautiful
    FILE* test_file;
    FILE* test_magicfile;
    FILE* releasefile;
    
    unsigned int number = 0;
    unsigned char minute=0;
    unsigned char second=0;
    unsigned int RandInfoLen = 0;

    int residue=0;


    printf("How Many sets in MP ( < 2^30 ): ");
    scanf("%d",&number);
    if(number > (1073741824))
    {
        printf("set number is larger 2^30");
        return 0;
    }

    test_file = fopen("test_file","w+");
    if(test_file==NULL)
    {
        return 0;
    }

    test_magicfile = fopen("test_magicfile","w+");
    if(test_magicfile==NULL)
    {
        return 0;
    }
    
    releasefile = fopen("releasefile","w+");
    if(releasefile==NULL)
    {
        return 0;
    }

    FILE* strreleasefile;
    strreleasefile = fopen("strreleasefile","w+");
    if(strreleasefile==NULL)
    {
        return 0;
    }

    //GenLookupTable(lookup_table[0],ONE_YEAR,LOOKUP_INFO);
    //printf("number=%d\n",number);
    for(i=0;i<number;i++)
    {
        cc_prng_set_seed( pu8Seed );

        //printf("i=%d\n",i);
        // start get time
        memset(DeviceID,0,sizeof(DeviceID));
        dataDump(DeviceID, sizeof(DeviceID), "initial condition");

        Get_Time(DeviceID);
        dataDump(DeviceID, sizeof(DeviceID), "Get time");

        // start to create DID 
        //Create_DID(fuse_id,DeviceID);
        RandInfoLen = 8;
        Add_Random_Info(DeviceID,DeviceID,RandInfoLen);
                dataDump(DeviceID, sizeof(DeviceID), "device id after adding randinfo");

        minute = ((DeviceID[3]&0x1f)<<1)|((DeviceID[4]>>7)&0x1);
        second = ((DeviceID[4]>>1)&0x3f);
        //printf("miunte=%x\n",minute);
        //printf("second=%x\n",second);
        residue=(minute*60+second) %3600;
        lookup_table[0]= (unsigned char)(residue & 0x000000ff);
        lookup_table[1] = (unsigned char)((residue & 0x0000ff00)>>8);
        //printf("residue=%lx\n",residue);
        //printf("lookup_table[0]=%x\n",lookup_table[0]);
        //printf("lookup_table[1]=%x\n",lookup_table[1]);
        
        cc_prng_set_seed( pu8Seed );
        cc_prng_didin(lookup_table,LOOKUP_ROOT_INFO,&lookup_table[LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO*8 );

        // copy look up table to DID
        memcpy(&DeviceID[DID_LEN],&lookup_table[LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO);

 
        cc_prng_didin(DeviceID,sizeof(DeviceID),MagicDeviceID,sizeof(MagicDeviceID)*8 );
#if 1
        printf("MagicDeviceID\n");
        for(j=0;j<OTP_INFO_LEN;j++)
        {
            printf("%x ",MagicDeviceID[j]);
        }
        printf("\n");
#endif

        fwrite(DeviceID,sizeof(unsigned char),sizeof(DeviceID),test_file);
        fwrite(MagicDeviceID,sizeof(unsigned char),OTP_INFO_LEN,test_magicfile);

        memcpy(ReleaseData,DeviceID,DID_LEN);
        memcpy(&ReleaseData[DID_LEN],MagicDeviceID,OTP_INFO_LEN);
        memcpy(&ReleaseData[DID_LEN+OTP_INFO_LEN],&MagicDeviceID[KSS_LEN+KSH_LEN],DB_PWD_LEN);

        unsigned int u32CRC = 0;
        u32CRC = ~cal_crc32( ReleaseData, DID_LEN+KSS_LEN+KSH_LEN);
        printf("~CRC32: 0x%X\r\n", u32CRC);
        
        memcpy(&ReleaseData[DID_LEN+OTP_INFO_LEN+DB_PWD_LEN],&u32CRC,CRC32_LEN);
        memcpy(&ReleaseData[RELEASE_DATA],aligned_data,ALIGNED_LEN);//for beautiful

        fwrite(&ReleaseData,sizeof(unsigned char),sizeof(ReleaseData),releasefile);

        // tranfer byte to string ex: 0xab => "AB"
        unsigned char strdeviceid [(2*RELEASE_DATA)+1]={0};
        char strpattern[17] = "0123456789ABCDEF";
        int multiple=0;
        residue = 0;

        for(j=0;j<RELEASE_DATA;j++)
        {
            multiple = ReleaseData[j]/(0x10);
            residue = ReleaseData[j]%(0x10);
            strdeviceid[2*j]=strpattern[multiple];
            strdeviceid[(2*j)+1]=strpattern[residue];
        }
        
        fprintf(strreleasefile,"%s",strdeviceid);
        putc('\n',strreleasefile);

    }
    fclose(strreleasefile);
    fclose(test_file);
    fclose(test_magicfile);
    fclose(releasefile);
    if(unittestflag==0)
    {
        remove("test_file");
        remove("test_magicfile");
    }
}


int GenPresharedKey(int argc, char *argv[])
{
    unsigned char pu8Input[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    unsigned char pu8Seed[16]={0};

    unsigned int j=0;
    unsigned long k=0;
    int ret=0;
    int EsnBase64Len=0x100,KphBase64Len=0x100, KpeBase64Len=0x100;
    int EsnBinLen=0;

    unsigned char ModelID[ESN_MODELID_LEN+1] = {0};
//    unsigned char DecodedModelID[ESN_MODELID_LEN+1] = {0};
    unsigned char u8DecodedEsnBase32Buf[ESN_BASE32_LEN+1] = {0};
    unsigned char DeviceID[ESN_DEVICEID_LEN+1] = {0};
    unsigned char shiftbuf= 0;
    unsigned char DeviceNumber[4]={0};
    unsigned long number=0;
    unsigned char mode[128]={0};
    FILE *keysets;
    FILE *keysets_table;
    
    struct hr_time t;

    if(argc>2)
        strncpy(mode,argv[argc-1],strlen(argv[argc-1])) ;
    //Esn declaration
#if 0
    unsigned char* pu8EsnBinBuf=NULL;
    pu8EsnBinBuf =(unsigned char*) malloc(sizeof(unsigned char)*ESN_LEN);
    memset(pu8EsnBinBuf,0,ESN_LEN);
#endif
    unsigned char* pu8EsnBase32Buf=NULL;
    pu8EsnBase32Buf =(unsigned char*) malloc(sizeof(unsigned char)*(ESN_BASE32_LEN+1));
    memset(pu8EsnBase32Buf,0,ESN_BASE32_LEN);


    //kpe declaration
    unsigned char* pu8KpeBinBuf=NULL;
    pu8KpeBinBuf =(unsigned char*) malloc(sizeof(unsigned char)*KPE_LEN);
    memset(pu8KpeBinBuf,0,KPE_LEN);


    //kph declaration
    unsigned char* pu8KphBinBuf=NULL;
    pu8KphBinBuf =(unsigned char*) malloc(sizeof(unsigned char)*KPH_LEN);
    memset(pu8KphBinBuf,0,KPH_LEN);
#if 0
    printf("argc=%d\n",argc);
    for(k=0;k<argc;k++)
    {
        printf("%s\n",argv[k]);
    }
#endif

    // open file for writing
    keysets= fopen("key_sets","w+");
    if(keysets == NULL)
    {
        printf(" keysets is NULL\n");
    }
    
    keysets_table= fopen("key_sets_table","w+");
    if(keysets_table == NULL)
    {
        printf(" keysets_table is NULL\n");
    }
    
    //open file end
    //input set number
    printf("How Many sets in MP ( < 2^30 ): ");
    scanf("%ld",&number);
    if(number > (1073741824))
    {
        printf("set number is larger 2^30");
        return 0;
    }
    
    //input model name
    printf("Enter model name( < 10 characters ): ");
    scanf("%s",ModelID);
    //printf("%s\n",ModelID);

//    strncpy(DecodedModelID,ModelID,strlen(ModelID));
    if(strlen(ModelID)<=ESN_MODELID_LEN)
    {
        strncat(ModelID,"==========",(ESN_MODELID_LEN-strlen(ModelID)));
    }
    else
    {
        return 0;
    }

    cc_prng_set_seed( pu8Seed );
    
    if(strncmp(mode,"compare",7) == 0) // mode 1 compare kpe and kph
    {
        printf("compare mode\n");
        unsigned long x, y;

        //malloc array for Kpe
        unsigned long KpeSizex = KPE_BASE64_LEN+1;
        unsigned long KpeSizey = number;
       
        //malloc dynamic array for kpe
        unsigned char** pu8KpeBase64Buf = (unsigned char** )malloc(KpeSizey * sizeof(void *));
        if(pu8KpeBase64Buf == NULL)
        {
            printf("*pu8KpeBase64Buf = NULL\n");
        }
        for(y = 0; y != KpeSizey; ++y)
        {
            pu8KpeBase64Buf[y] = (unsigned char*)malloc(KpeSizex * sizeof(int *));
           if(*pu8KpeBase64Buf == NULL)
            {
                printf("*pu8KpeBase64Buf = NULL\n");
            }
        }
        
#if 0
       for(y = 0; y != sizey; ++y) {
         for(x = 0; x != sizex; ++x)
           ia[y][x] = y + x;
       }
#endif

        //malloc dynamic array for kph
        unsigned long KphSizex = KPH_BASE64_LEN+1;
        unsigned long KphSizey = number;

       unsigned char** pu8KphBase64Buf = (unsigned char** )malloc(KphSizey * sizeof(void *));
       if(pu8KphBase64Buf == NULL)
        {
            printf("*pu8KphBase64Buf = NULL\n");
        }
        for(y = 0; y != KphSizey; ++y)
        {
            pu8KphBase64Buf[y] = (unsigned char*)malloc(KphSizex * sizeof(int *));
           if(*pu8KphBase64Buf == NULL)
            {
                printf("*pu8KphBase64Buf = NULL\n");
            }
        }
        //malloc dynamic array for kph end

        printf("start to generate keys table \n");
            get_timer( &t, 1 );
#if 1
        for(k = 0;k < number;k++)
        {
            //printf("\n>>>>>>>>>>%d<<<<<<<<<<<\n",k);
            //printf("COMPARE MODE\n");
            // generate key
            if(number>=50000)
            {
                if((k+1)%(number/100) == 0)
                {
                    printf(" progress %ld %%\n",(k+1)/(number/100));
                }
            }
            else if((number>=10000)&&(number<50000))
            {
                if((((k+1)%(number/100)) == 0)&&(((k+1)%(number/2))==0))
                {
                    printf(" progress %ld %%\n",(k+1)/(number/100));
                }
            }
            EsnBinLen=0x100;
            KpeBase64Len=0x100;
            KphBase64Len=0x100;

            //add index in table
            //sprintf(EsnBase64Buf,"%d", k);
            //fwrite(EsnBase64Buf,sizeof(unsigned char),strlen(EsnBase64Buf),keysets_table);
            //putc(',',keysets_table);

            memcpy(DeviceNumber,&k,4);
#if 0
            for(j=0;j<sizeof(DeviceNumber);j++)
            {
                printf("%x",DeviceNumber[j]);
            }
            printf("\n");
#endif
            //printf("DeviceNumber[0]=%lx\n",DeviceNumber[0]);
            shiftbuf=DeviceNumber[3];
            DeviceNumber[3]=((shiftbuf & 0x3f) |(shiftbuf<<6)) ;
            //printf("DeviceNumber[0]=%lx\n",DeviceNumber[0]);
            ret=base32_encode(DeviceNumber, sizeof(DeviceNumber),  DeviceID, ESN_DEVICEID_LEN) ;
            if(ret != ESN_DEVICEID_LEN)
            {
                //printf("ret=%d\n",ret);
                printf("the esn device id is decoded failed\n ");
                return 0;
            }
#if 0
            for(j=0;j<sizeof(DeviceID);j++)
            {
                printf("%c",DeviceID[j]);
            }
            printf("\n");

            printf("DeviceID = %s\n",DeviceID);
            printf(" ModelID = %s\n",ModelID);
#endif
            //write esn into file
            sprintf(pu8EsnBase32Buf,"%s%s",ModelID, DeviceID);
            fwrite(pu8EsnBase32Buf,sizeof(unsigned char),strlen(pu8EsnBase32Buf),keysets);
            fwrite(pu8EsnBase32Buf,sizeof(unsigned char),strlen(pu8EsnBase32Buf),keysets_table);
            putc(',',keysets);
            putc(',',keysets_table);
#if 1

#if 0
            for(j=0;j<0x10;j++)
            {
                printf(" %02x ",*(pu8EsnBase32Buf+j));
            }
            printf("\n");
            printf("strlen(pu8EsnBase32Buf)=%d\n",strlen(pu8EsnBase32Buf));
#endif
            // create kpe and encode with base64

            cc_prng_didin(pu8EsnBase32Buf,strlen(pu8EsnBase32Buf),pu8KpeBinBuf,KPE_LEN*8 );
#if 0
            for(j=0;j<KPE_LEN;j++)
            {
                printf(" %02x ",*(pu8KpeBinBuf+j));
            }
            printf("\n");
#endif

            ret=base64_encode(pu8KpeBase64Buf[k],&KpeBase64Len,pu8KpeBinBuf,  KPE_LEN );
            if(ret != 0)
            {
                //printf("ret=%d\n",ret);
                printf("the kpe base64 is  failed\n ");
                return 0;
            }
            
            //printf("k = %d,  %s \n",k,pu8KpeBase64Buf[k]);
            fwrite(pu8KpeBase64Buf[k],sizeof(unsigned char),strlen(pu8KpeBase64Buf[k]),keysets);
            fwrite(pu8KpeBase64Buf[k],sizeof(unsigned char),strlen(pu8KpeBase64Buf[k]),keysets_table);
            putc(',',keysets);    
            putc(',',keysets_table);   
            
            // create kpe and encode with base64
            cc_prng_didin(pu8KpeBinBuf,KPE_LEN,pu8KphBinBuf,KPH_LEN*8 );
#if 0
            for(j=0;j<KPH_LEN;j++)
            {
                printf(" %x ",*(pu8KphBinBuf+j));
            }
            printf("\n");
#endif
            ret=base64_encode( pu8KphBase64Buf[k],&KphBase64Len,pu8KphBinBuf,  KPH_LEN );
            if(ret != 0)
            {
                //printf("ret=%d\n",ret);
                printf("the kph base64 is  failed\n ");
                return 0;
            }

            //printf("KphBase64Len=%x\n",KphBase64Len);
    //        printf("%s \n",pu8KphBase64Buf);
            fwrite(pu8KphBase64Buf[k],sizeof(unsigned char),strlen(pu8KphBase64Buf[k]),keysets);
            fwrite(pu8KphBase64Buf[k],sizeof(unsigned char),strlen(pu8KphBase64Buf[k]),keysets_table);

            putc(',',keysets_table);    

            putc('\n',keysets);
            putc('\n',keysets_table);

#endif    
        }
#endif
        printf("%ld seconds\n",get_timer( &t, 0 )/1000);

        printf("Keys table was done\n");
        printf("Compare Kpe & Kph Start\n");
        get_timer( &t, 1 );
        //printf("number=%d\n",number);
        unsigned char* pRet=NULL;
        for(k=0;k<number;k++)
        {
            // compare progress
            if(number>=10000)
            {
                if((k+1)%(number/100) == 0)
                {
                    printf(" progress %ld %%\n",(k+1)/(number/100));
                }
            }

            // start to compare kpe and kph
            for(j = k;j<number-1;j++)
            {
                pRet = strstr(pu8KpeBase64Buf[k],pu8KpeBase64Buf[j+1]);
                if(pRet != NULL)
                {
                    printf("Kpe pRet !=NULL k =%ld , j+1=%d\n",k,j+1);
                    return 0;
                }
                    
                pRet = strstr(pu8KphBase64Buf[k],pu8KphBase64Buf[j+1]);
                if(pRet != NULL)
                {
                    printf("Kph pRet !=NULL k =%ld , j+1=%d\n",k,j+1);
                    return 0;
                }
            }
        }
        printf("%ld seconds\n",get_timer( &t, 0 )/1000);

        for(y = 0; y != KpeSizey; ++y)
            free(pu8KpeBase64Buf[y]);
       
        free(pu8KpeBase64Buf);

        for(y = 0; y != KphSizey; ++y)
            free(pu8KphBase64Buf[y]);
       
        free(pu8KphBase64Buf);

        printf("comparison is Done\n");

    }

    else
    {
        //printf("normal mode\n");
        unsigned char* pu8KpeBase64Buf=NULL;
        pu8KpeBase64Buf =(unsigned char*) malloc(sizeof(unsigned char)*KPE_BASE64_LEN);
        memset(pu8KpeBase64Buf,0,KPE_BASE64_LEN);

        unsigned char* pu8KphBase64Buf=NULL;
        pu8KphBase64Buf =(unsigned char*) malloc(sizeof(unsigned char)*KPH_BASE64_LEN);
        memset(pu8KphBase64Buf,0,KPH_BASE64_LEN);
    
        printf("start to generate keys table \n");
        get_timer( &t, 1 );

#if 1
        for(k = 0;k < number;k++)
        {
            //printf("\n>>>>>>>>>>%d<<<<<<<<<<<\n",k);
            // generate key
            if(number>=50000)
            {
                if((k+1)%(number/100) == 0)
                {
                    printf(" progress %ld \n",(k+1)/(number/100));
                }
            }
            else if((number>=10000)&&(number<50000))
            {
                if((((k+1)%(number/100)) == 0)&&(((k+1)%(number/2))==0))
                {
                    printf(" progress %ld \n",(k+1)/(number/100));
                }
            }
            
            EsnBinLen=0x100;
            KpeBase64Len=0x100;
            KphBase64Len=0x100;
            
            //add index in table
            //sprintf(EsnBase64Buf,"%d", k);
            //fwrite(EsnBase64Buf,sizeof(unsigned char),strlen(EsnBase64Buf),keysets_table);
            //putc(',',keysets_table);

            memcpy(DeviceNumber,&k,4);

#if 0
            for(j=0;j<sizeof(DeviceNumber);j++)
            {
                printf("%x",DeviceNumber[j]);
            }
            printf("\n");
#endif
            //printf("DeviceNumber[0]=%lx\n",DeviceNumber[0]);
            shiftbuf=DeviceNumber[3];
            DeviceNumber[3]=((shiftbuf & 0x3f) |(shiftbuf<<6)) ;
            //printf("DeviceNumber[0]=%lx\n",DeviceNumber[0]);

            ret=base32_encode(DeviceNumber, sizeof(DeviceNumber),  DeviceID, ESN_DEVICEID_LEN) ;
            if(ret != ESN_DEVICEID_LEN)
            {
                //printf("ret=%d\n",ret);
                printf("the esn device id is decoded failed\n ");
                return 0;
            }

#if 0
            for(j=0;j<sizeof(DeviceID);j++)
            {
                printf("%c",DeviceID[j]);
            }
            printf("\n");

            printf("DeviceID = %s\n",DeviceID);
            printf(" ModelID = %s\n",ModelID);
#endif

            //write esn into file
            sprintf(pu8EsnBase32Buf,"%s%s",ModelID, DeviceID);

            fwrite(pu8EsnBase32Buf,sizeof(unsigned char),strlen(pu8EsnBase32Buf),keysets);
            fwrite(pu8EsnBase32Buf,sizeof(unsigned char),strlen(pu8EsnBase32Buf),keysets_table);
            putc(',',keysets);
            putc(',',keysets_table);

#if 0
            for(j=0;j<0x10;j++)
            {
                printf(" %02x ",*(pu8EsnBase32Buf+j));
            }
            printf("\n");
            printf("strlen(pu8EsnBase32Buf)=%d\n",strlen(pu8EsnBase32Buf));
#endif
            // create kpe and encode with base64

            cc_prng_didin(pu8EsnBase32Buf,strlen(pu8EsnBase32Buf),pu8KpeBinBuf,KPE_LEN*8 );
#if 0
            for(j=0;j<KPE_LEN;j++)
            {
                printf(" %02x ",*(pu8KpeBinBuf+j));
            }
            printf("\n");
#endif

            ret=base64_encode(pu8KpeBase64Buf,&KpeBase64Len,pu8KpeBinBuf,  KPE_LEN );
            if(ret != 0)
            {
                //printf("ret=%d\n",ret);
                printf("the kpe base64 is  failed\n ");
                return 0;
            }
            
            //printf("k = %d,  %s \n",k,pu8KpeBase64Buf[k]);
            fwrite(pu8KpeBase64Buf,sizeof(unsigned char),strlen(pu8KpeBase64Buf),keysets);
            fwrite(pu8KpeBase64Buf,sizeof(unsigned char),strlen(pu8KpeBase64Buf),keysets_table);
            putc(',',keysets);    
            putc(',',keysets_table);   
            
            // create kpe and encode with base64
            cc_prng_didin(pu8KpeBinBuf,KPE_LEN,pu8KphBinBuf,KPH_LEN*8 );
#if 0
            for(j=0;j<KPH_LEN;j++)
            {
                printf(" %x ",*(pu8KphBinBuf+j));
            }
            printf("\n");
#endif
            ret=base64_encode( pu8KphBase64Buf,&KphBase64Len,pu8KphBinBuf,  KPH_LEN );
            if(ret != 0)
            {
                //printf("ret=%d\n",ret);
                printf("the kph base64 is  failed\n ");
                return 0;
            }

            //printf("KphBase64Len=%x\n",KphBase64Len);
    //        printf("%s \n",pu8KphBase64Buf);
            fwrite(pu8KphBase64Buf,sizeof(unsigned char),strlen(pu8KphBase64Buf),keysets);
            fwrite(pu8KphBase64Buf,sizeof(unsigned char),strlen(pu8KphBase64Buf),keysets_table);

            // key the empty space for DID
            char DID_space[] = ",                ";
            fwrite(DID_space,sizeof(unsigned char),strlen(DID_space),keysets_table);
            putc(',',keysets_table);   

            // write the status of key (on going)
            char KeyStatus[]="ongoing";
            fwrite(KeyStatus,sizeof(unsigned char),strlen(KeyStatus),keysets_table);
            //change line of both tables  
            putc('\n',keysets);
            putc('\n',keysets_table);

        }
    printf("%ld seconds\n",get_timer( &t, 0 )/1000);
#endif
    free(pu8KpeBase64Buf);
    free(pu8KphBase64Buf);
    
    printf("Keys table was done\n");
    
    }
    free(pu8EsnBase32Buf);
    free(pu8KpeBinBuf);
    free(pu8KphBinBuf);

    fclose(keysets);
    fclose(keysets_table);
#if 0
    printf("\n");

    //memcpy(number,&DeviceNumber,4);
    //DeviceNumber[3]=0x02;
    for(j=0;j<sizeof(DeviceNumber);j++)
    {
        printf("%x \n",DeviceNumber[j]);
    }
    base32_encode(DeviceNumber, sizeof(DeviceNumber),  DeviceID, sizeof(DeviceID)) ;
    
    printf("\n");
   
    for(j=0;j<sizeof(DeviceID);j++)
    {
        printf("%c ",DeviceID[j]);
    }
    printf("\n");
       
   //    printf("%s\n",DeviceID);
   // DeviceNumber=12;
#if 0
    for(j=0;j<sizeof(DeviceNumber);j++)
    {
        DeviceNumber[j]=0;
    }


    //printf("DeviceNumber=%08lx\n",DeviceNumber);
    for(j=0;j<sizeof(DeviceNumber);j++)
    {
        printf("%x \n",DeviceNumber[j]);
    }
    printf("sizeof(DeviceNumber)=%d\n",sizeof(DeviceNumber));
    ret=base32_decode(DeviceID ,DeviceNumber, sizeof(DeviceNumber)) ;
    printf("ret=%d\n",ret);
    //printf("number=%x\n",number);

    for(j=0;j<sizeof(DeviceNumber);j++)
    {
        printf("%x \n",DeviceNumber[j]);
    }
#endif

#endif

#if 0
    printf("EsnBinLen=%d\n",EsnBinLen);
    for(j=0;j<EsnBinLen;j++)
    {
        printf(" %02x ",*(pu8EsnBinBuf+j));
    }
    printf("\n");
#endif

#if 0
    fseek(esnfile,0,SEEK_SET);
 //   printf("sizeof(esn)=%d\n",sizeof(esn));
    unsigned char* ch_esn = NULL;
    ch_esn=(unsigned char*)malloc(sizeof(unsigned char)*ESN_LEN);
    memset(ch_esn,0,ESN_LEN);
#endif
#if 0
    for(k=0;k<sizeof(esn);k++)
    {

    	*(ch_esn+k)=getc(esnfile);
    	printf("%c ",*(ch_esn+k));
    	if(*(ch_esn+k) == '\0')
    	{
    		break;
    	}
    }
    printf("\n");
#endif
#if 0
    fwrite(esn,sizeof(unsigned char),sizeof(esn),esnfile);
    fseek(esnfile,0,SEEK_SET);    
    for(k=0;k<sizeof(esn);k++)
    {

    	*(ch_esn+k)=getc(esnfile);
    	printf("%c ",*(ch_esn+k));

    }
    printf("\n");
    unsigned int filesize = 0;
#endif
//    esnfile = fopen(argv[1],"r+");
//    if(esnfile == NULL)
//    {
//        printf(" esnfile is NULL\n");
//    }
#if 0    
    fseek(esnfile,0,SEEK_END);
    filesize=ftell(esnfile);
    fseek(esnfile,0,SEEK_SET);


    unsigned char* ch_esn = NULL;
    ch_esn=(unsigned char*)malloc(sizeof(unsigned char)*ESN_LEN);
    memset(ch_esn,0,ESN_LEN);



    for(k=0 ;k<filesize;k++)
    {	
    	*(ch_esn+k)=getc(esnfile);
    	printf("%c",*(ch_esn+k));
    	if(*(ch_esn+k) == '\n')
    	{
    		break;
    	}
    }
    printf("k=%d\n",k);
    //fwrite(ch1,sizeof(char),i,fout1);

    printf("1 %s\n", ch_esn);
#endif
 //   cc_prng_set_seed( pu8Seed );

#if 0

    cc_prng_didin(pu8Input,ESN_LEN,pu8KpeBinBuf,KPE_LEN*8 );

    for(k=0;k<KPE_LEN;k++)
    {
        printf(" %02x ",*(pu8KpeBinBuf+k));
    }
    printf("\n");
    //memcpy(Buffer,pu8KpeBinBuf,KPE_LEN);
    base64_encode( pu8KpeBase64Buf,&KpeBase64Len,pu8KpeBinBuf,  KPE_LEN );
    printf("len1=%x\n",KpeBase64Len);
    printf("%s \n",pu8KpeBase64Buf);

    

 //   memset(u8pOutput,0,0x32);
    cc_prng_didin(pu8KpeBinBuf,KPE_LEN,pu8KphBinBuf,KPH_LEN*8 );

    for(k=0;k<KPH_LEN;k++)
    {
        printf(" %x ",*(pu8KphBinBuf+k));
    }
    printf("\n");
    base64_encode( pu8KphBase64Buf,&KphBase64Len,pu8KphBinBuf,  KPH_LEN );
    printf("KphBase64Len=%x\n",KphBase64Len);
    printf("%s \n",pu8KphBase64Buf);

#endif
#if 0
//parameters declaration
    int len1=0, len2=0, len3=0;
    unsigned char buffer1[256];
    unsigned char buffer2[256];
    unsigned char buffer3[256];        
    memset(buffer1,0,0x20);
    memset(buffer2,0,0x20);
    memset(buffer3,0,0x20);
    len1 = sizeof( buffer1 );

    len2 = sizeof( buffer2 );
    len2 = sizeof( buffer3 );

//create kpe
#if 1
    printf("\nKpe base64_encode\n");
    memset(u8pOutput,0,KPE_LEN);

    cc_prng(u8pOutput, KPE_LEN*8);
#if 1
    printf("\n");
    for(k=0;k<16;k++)
    {
        printf("%02x ",*(u8pOutput+k));
    }
    printf("\n");
#endif


    base64_encode( buffer1,&len1,u8pOutput,  KPE_LEN );
    //printf("%s \n",buffer1);
    //printf("len1=%d\n",len1);
    strncpy(base_enc, buffer1,len1);

    printf("%s \n",base_enc);
#endif



//create kph
#if 1
    printf("\nKph base64_encode\n");
    memset(u8pOutput,0,KPH_LEN);
    cc_prng(u8pOutput, KPH_LEN*8);
#if 1
    printf("\n");
    for(k=0;k<32;k++)
    {
        printf("%02x ",*(u8pOutput+k));
    }
    printf("\n");
#endif
    //printf("\nKph base64_encode\n");
    base64_encode( buffer2,&len2,u8pOutput,  KPH_LEN );
    strncpy(base_enc, buffer2,len2);
    printf("%s \n",base_enc);
#endif

#endif

        #if 0
    	cc_prng(u8pOutput, 256);
	printf("\n");
        for(k=0;k<32;k++)
        {
            printf(" %x",*(u8pOutput+k));
        }

        printf("\n");
        len=0;
        memset(buffer,0,0x20);

        base64_encode( buffer,&len,u8pOutput,  0x20 );
        printf("111\n");
        printf("%s \n",buffer);
        printf("222\n");
#endif
	
	
	
#if 0
	unsigned char* u8pOutput = NULL;
	unsigned int filesize = 0;
	unsigned char* ch1 = NULL;
	const char pFileName1[]="test1.dat";        
	const char pFileName2[]="test2.dat";        
	const char pFileName3[]="test3.dat";        
	const char pFileName4[]="test4.dat"; 
	unsigned char* ch2=NULL;
	unsigned char* ch3=NULL;
	int i = 0;
	FILE *fin;
	FILE *fout1;
	FILE *fout2;
	FILE *fout3;
	FILE *fout4;
	//u8pOutput=(unsigned char*)malloc(sizeof(unsigned char)*1024); 
	ch1=(unsigned char*)malloc(sizeof(unsigned char)*1024);
	ch2=(unsigned char*)malloc(sizeof(unsigned char)*1024);
	ch3=(unsigned char*)malloc(sizeof(unsigned char)*1024);
	fin=fopen(argv[1],"rb+");
	fout1=fopen(pFileName1,"w+");
	fout2=fopen(pFileName2,"w+");
	fout3=fopen(pFileName3,"w+");
	fout4=fopen(pFileName4,"w+");
	if(fin == NULL)
	{
		return 0;
	}
	printf("stupid\n");

#if 1
{
	//fread(u8pOutput,sizeof(unsigned char),80,fin);
	//printf("%s \n",u8pOutput);
}
#endif
fseek(fin,0,SEEK_END);
filesize=ftell(fin);
fseek(fin,0,SEEK_SET);
//filesize=strlen(u8pOutput);
//printf("filesize= %d\n",filesize);

for(i=0 ;i<filesize;i++)
{	
	*(ch1+i)=getc(fin);
	printf("%c",*(ch1+i));
	if(*(ch1+i) == '\n')
	{
		break;
	}
}
printf("i=%d\n",i);
fwrite(ch1,sizeof(char),i,fout1);

printf("1 %s\n", ch1);



for(i=0 ;i<filesize;i++)
{	
	*(ch2+i)=getc(fin);
	printf("%c",*(ch2+i));
	if(*(ch2+i) == '\n')
	{
		break;
	}
}
fwrite(ch2,sizeof(unsigned char),i,fout2);
printf("i=%d\n",i);
printf("2 %s\n", ch2);



for(i=0 ;i<filesize;i++)
{	
	*(ch3+i)=getc(fin);
	if((char)(*(ch3+i)) == EOF)
	{
		printf("\n");
		printf("break\n");
		break;
	}
	printf("%c",*(ch3+i));
}
fwrite(ch3,sizeof(unsigned char),i,fout3);

fwrite(ch1,sizeof(unsigned char),9,fout4);
putc('\n',fout4);
fwrite(ch2,sizeof(unsigned char),24,fout4);
putc('\n',fout4);
fwrite(ch3,sizeof(unsigned char),44,fout4);

 //cc_prng(*u8pOutput, 0x20 );

#endif
return 0;
}

#if 0
void unittest(void)
{
    FILE* test_magicfile;
    FILE* test_file;
    unsigned char PWDbuf[DB_PWD_LEN]={0};
    unsigned char DIDbuf[DATA_IN]={0};
    int i,j,k;
    unsigned long filesize=0;    
    Generate_ReleaseData();

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
}
#endif
int main(int argc, char *argv[])
{
    //printf("%s\n",argv[1]);
    int i,j,k;
        //system("./PWD_OUT.exe 00112233445566778899AABBCCDDEEFF");

    if(argc == 1)
    {
        printf(PRODUCTION_USAGE);
        return 0;
    }

    if(argc >= 2)
    {  
        if(strncmp(argv[1],"GenKssKshPwd",12)==0)
        {
            printf("Gen KssKshPwd\n");
            Generate_ReleaseData();
        }
        else if(strncmp(argv[1],"KEY_PWD",7)==0)
        {
            printf("\nGen KEY_PWD\n");
            GenKss_Pwd();
        }
        else if(strncmp(argv[1],"PreSharedKey",12)==0)
        {
            printf("PreSharedKey\n");
            GenPresharedKey(argc,argv);
        }
        else if (strncmp(argv[1],"test",4)==0)
        {
            printf("unit_test\n");
            unittestflag = 1;
            //test();
//            dataDump(array, sizeof(array), "array");
        }
        else if (strncmp(argv[1],"crc_check",8)==0)
        {
            printf("\n****crc 8 test****\n\n");
            unsigned char test_pat1[]={0x80,0x53,0xB9,0x3D,0xA1,0xE8,0xCD,0x2E,0xF2,0x19,0x77,0xCB,0xB8,0xFA,0x5C,0x00,0xff,0xff,0xff,0x80};
            unsigned char test_pat2[]={0x80,0x53,0xB9,0x3D,0xA1,0xE8,0xCD,0x2E,0xF2,0x19,0x77,0xCC,0xB8,0xFA,0x5C,0x00,0xff,0xff,0xff,0x80};
            unsigned long ret=0;

            crc8_clear();
            for(i=0; i<sizeof(test_pat1) ;i++)
            {
                crc8_addbyte(test_pat1[i]);
            }
            ret = crc8_getcrc();
            printf("test_pat1 ret =%lx \n",ret);

            crc8_clear();
            for(i=0; i<sizeof(test_pat2) ;i++)
            {
                crc8_addbyte(test_pat2[i]);
            }
            ret = crc8_getcrc();
            printf("test_pat2 ret =%lx \n",ret);

            crc8_clear();
            for(i=0; i<sizeof(test_pat1) ;i++)
            {
                crc8_addbyte(test_pat1[i]);
            }
            ret = crc8_getcrc();
            printf("test_pat1 ret =%lx \n",ret);

        
            printf("\n****crc 32 test****\n\n");
            ret = cal_crc32(test_pat1, sizeof(test_pat1));
            printf("test_pat1 ret =%lx \n",ret);
            ret = cal_crc32(test_pat2, sizeof(test_pat2));
            printf("test_pat2 ret =%lx \n",ret);
            ret = cal_crc32(test_pat1, sizeof(test_pat1));
            printf("test_pat1 ret =%lx \n",ret);

            
        }
        else
        {
            printf(PRODUCTION_USAGE);
        }

#if 0

        else if(strlen(argv[1]) == 34)
        {
            printf("Gen PWD\n");
            unsigned char DeviceID[32]={0};

            convertStrtoHex(argv[1],DeviceID);            
            PWD_OUT(DeviceID,sizeof(DeviceID));
        }
#endif
    }
    else
    {
        printf(PRODUCTION_USAGE);
    }
        printf("exit\n");
    return 0;
}

