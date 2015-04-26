#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#include "prng.h"
#include "timing.h"
//#include "CommonUtility.h"
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
    "\n   <mode>: 1. KEY_PWD  2. PreSharedKey 3. crc_check\n" \
    "\n  example: ./GenDataBase KEY_PWD\n" \
    "\n  example: ./GenDataBase PreSharedKey\n" \
    "\n  example: ./GenDataBase crc_check\n" \
    "\n"


void HextoAcsi(unsigned char* hexbuf, unsigned int hexlen,unsigned char* textbuf);
#if 1

unsigned long cal_crc32(const unsigned char *octets, int len)
{
  unsigned long crc = 0xFFFFFFFF;
  unsigned long temp;
  int j;

  while (len--)
  {
    temp = (unsigned long)((crc & 0xFF) ^ *octets++);
    for (j = 0; j < 8; j++)
    {
      if (temp & 0x1)
        temp = (temp >> 1) ^ 0xEDB88320;
      else
        temp >>= 1;
    }
    crc = (crc >> 8) ^ temp;
  }
  return crc ^ 0xFFFFFFFF;
}
#endif
static unsigned char crc;

void crc8_clear(void)
{
    crc = 0;
}

void crc8_addbyte(unsigned char data)
{
    unsigned char                bit_counter;
    unsigned char                feedback_bit;

      bit_counter = 8;
      do
        {
         feedback_bit = (crc ^ data) & 0x01;
        if (feedback_bit == 0x01)
            {
            crc = crc ^ 0x18; //0X18 = X^8+X^5+X^4+X^0
            }
         crc = (crc >> 1) & 0x7F;
         if (feedback_bit == 0x01)
            {
            crc = crc | 0x80;
            }

         data = data >> 1;

         bit_counter--;

        }while (bit_counter > 0);
        
 }

unsigned char crc8_getcrc(void)
{
    return crc;
}



void  dataDump(unsigned char* const data,const unsigned int len, const char *str)
{
 unsigned int i=0;
 if(str!=NULL)
    printf("\033[0;32mdump %s\033[0m\n",str);
 for(i=0;i<len;i++){
     if(((i%16)==0)&&(i!=0))
         printf("\n");

         printf("0x%x ",data[i]);

 }
 printf("..\n");
}


void SwapFunc(unsigned char* const pu8Data,const unsigned long u32LEN)
{
    unsigned char u8SwapBuf;
     
    if(pu8Data==NULL) return;
    
    //MAPI_U8 *pU8Data = (MAPI_U8*)(pu32Data);
    unsigned char idx=0;//, idx_max=sizeof(pu32Data)*4;

    for(idx=0; idx<(u32LEN/2) ; idx++)
    {
        u8SwapBuf= pu8Data[u32LEN-idx-1];
        pu8Data[u32LEN-idx-1]=pu8Data[idx];
        pu8Data[idx]=u8SwapBuf;
    }
}

void Convert_Add_Micro_into_Time(int *fuse_id,unsigned char* Timebuf)
{
    int i,j,k;
//DID 0~38 bits start    did[0]~did[3] and bit 1~ bit 7 in did[4]
    for(i=0;i<8;i++)
    {
        for(j=0;j<8;j++)
        {
            if(((i*8)+j) < 39)
            {   
                //printf(" %d *",(int)pow(2,(7-j)));
                //printf(" %d\n",fuse_id[(i*8)+j]);
                Timebuf[i]+= fuse_id[(i*8)+j]*((int)pow(2,(7-j)));
            }
            else
            {

                break;
            }
        }
//        printf("DeviceID[%d]=%x\n",i,DeviceID[i]);
        if(((i*8)+j) == 39)
        {
            //    printf("i=%d , j=%d \n",i,j);
            break;
        }
    }

//DID 0~38 bits end did[0]~did[3] and bit 1~ bit 7 in did[4]


// did [5]~ did [7] start
    struct timeval offset;
    
    gettimeofday( &offset, NULL );
    memcpy(&Timebuf[6],&offset.tv_usec,sizeof(offset.tv_usec));
    //printf("offset.tv_usec=%d\n",offset.tv_usec);
   // printf("DeviceID[5]=%ld\n",DeviceID[6]);
#if 0
    for(j=0;j<4;j++)
    {
        printf("DeviceID[%d]=%x\n",5+j,DeviceID[5+j]);
    }
#endif
    SwapFunc(&Timebuf[5],4);

    //dataDump(Timebuf, 8, "Efuse_Kss_Key first 8 bytes");
#if 0
    unsigned char random_info[8]={0};
 
    //    dataDump(random_info, 8, "random_info");

    cc_prng_didin(&KeyBuf[5],3,random_info,sizeof(random_info)*8 );
    memcpy(&KeyBuf[8],random_info,8);
//    dataDump(random_info, 8, "random_info based on time");
#endif
}

void Get_Time(unsigned char* Time)
{

    int fuse_id[64]={0};
    int error_flag=0;

    int k,i,num; 
    int j,a,n=2;
    int p[64]; 

    int year_h,year_m,year_l;

    /***************************************************************************
    for day, month, year ID processs
    ***************************************************************************/

    time_t secs=time(0);
    struct tm *t=localtime(&secs);
    
    memset(fuse_id,0,64);


    year_h = (t->tm_year / 100) + 19;
    year_m = (t->tm_year % 100) / 10;
    year_l = t->tm_year % 10;

    //printf("year_h= %d \n",year_h);
    //printf("year_m= %d \n",year_m);
    //printf("year_l= %d \n",year_l);

    //========================= Year thousand 5bit ===================================
    j=4;  //total - 1
    a=year_h;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=0;
    for(j=0;j<5;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[4] is LSB*/



    //========================= Year ten 4bit ===================================
    j=3;  //total - 1
    a=year_m;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=5;
    for(j=0;j<4;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[3] is LSB*/


    //========================= Year single 4bit ===================================
    j=3;  //total - 1
    a=year_l;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=9;
    for(j=0;j<4;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[3] is LSB*/


    //========================= month 4bit ===================================
    j=3;  //total - 1
    a= t->tm_mon + 1;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=13;
    for(j=0;j<4;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[3] is LSB*/



    //========================= days 5bit ===================================
    j=4;  //total - 1
    a= t->tm_mday;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=17;
    for(j=0;j<5;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[4] is LSB*/



    //========================= hours 5bit ===================================
    j=4;  //total - 1
    a= t->tm_hour;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=22;
    for(j=0;j<5;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[4] is LSB*/



    //========================= minute 6bit ===================================
    j=5;  //total - 1
    a= t->tm_min;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=27;
    for(j=0;j<6;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[5] is LSB*/



    //========================= second 6bit ===================================
    j=5;  //total - 1
    a= t->tm_sec;
    while(a)
    {
        p[j--]=a%n;
        a/=n;
    }
    while(j != -1)  p[j--]=0;

    k=33;
    for(j=0;j<6;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[5] is LSB*/

    //========================================================================


    Convert_Add_Micro_into_Time(fuse_id, Time);

#if 0
    printf("year 13 bit: [0:12] = ");
    for(i=0;i<13;i++)
    {
        printf("%x",fuse_id[i]);
    }
    printf("\n");
    printf("month 4 bit: [13:16]  = ");
    for(i=13;i<17;i++)
    {
       printf("%x",fuse_id[i]);
    }
    printf("\n");
    printf("days 5 bit: [17:21] = ");
    for(i=17;i<22;i++)
    {
        printf("%x",fuse_id[i]);
    }
    printf("\n");
    printf("hours 5 bit: [22:26] = ");
    for(i=22;i<27;i++)
    {
        printf("%x",fuse_id[i]);
    }
    printf("\n");
    printf("minute 6 bit: [27:32]= ");
    for(i=27;i<33;i++)
    {
        printf("%x",fuse_id[i]);
    }
    printf("\n");
    printf("second 6 bit: [33:38] = ");
    for(i=33;i<39;i++)
    {
        printf("%x",fuse_id[i]);
    }
    printf("\n");

    for(i=0;i<64;i++)              
    {
        if (i==63)
        {
            printf("%d",fuse_id[63-i]);
            printf("\n\n");
        }
        else if (((63-i)%8)==0)
        {
            printf("%d",fuse_id[63-i]);
            printf(",");
        }
        else
            printf("%d",fuse_id[63-i]);
    }

    printf("%x\n",(int)pow(2,3));
#endif
}

void Create_DID(int *fuse_id,unsigned char* DeviceID)
{
    int i,j,k;

    
//DID 0~38 bits start    did[0]~did[3] and bit 1~ bit 7 in did[4]
    for(i=0;i<8;i++)
    {
        for(j=0;j<8;j++)
        {
            if(((i*8)+j) < 39)
            {   
                //printf(" %d *",(int)pow(2,(7-j)));
                //printf(" %d\n",fuse_id[(i*8)+j]);
                DeviceID[i]+= fuse_id[(i*8)+j]*((int)pow(2,(7-j)));
            }
            else
            {

                break;
            }
        }
//        printf("DeviceID[%d]=%x\n",i,DeviceID[i]);
        if(((i*8)+j) == 39)
        {
            //    printf("i=%d , j=%d \n",i,j);
            break;
        }
    }

//DID 0~38 bits end did[0]~did[3] and bit 1~ bit 7 in did[4]


// did [5]~ did [7] start
    struct timeval offset;
    
    gettimeofday( &offset, NULL );
    memcpy(&DeviceID[6],&offset.tv_usec,sizeof(offset.tv_usec));
    //printf("offset.tv_usec=%d\n",offset.tv_usec);
   // printf("DeviceID[5]=%ld\n",DeviceID[6]);
#if 0
    for(j=0;j<4;j++)
    {
        printf("DeviceID[%d]=%x\n",5+j,DeviceID[5+j]);
    }
#endif
    SwapFunc(&DeviceID[5],4);
//    printf("offset.tv_usec=%d\n",offset.tv_usec);
//    printf("DeviceID[6]=%ld\n",DeviceID[6]);
#if 0
    for(j=0;j<4;j++)
    {
        printf("DeviceID[%d]=%x\n",5+j,DeviceID[5+j]);
    }
#endif
// did [5]~ did [7] end


//did [8]~ did [10] start
    strncpy(&DeviceID[8],"t12",3);
//did [8]~ did [10] end
#if 0
    for(j=0;j<3;j++)
    {
        printf("DeviceID[%d]=%x\n",8+j,DeviceID[8+j]);
    }
#endif


// did [11] start
    DeviceID[11]=0;
// did [11] end


// did [12] ~ did[15] start
    unsigned char random_info[16]={0};
#if 0
    printf("Device ID\n");
    for(k=0;k<16; k++)
    {
        printf("%x ",DeviceID[k]);
    }
    printf("\n");
#endif 
    cc_prng_didin(&DeviceID[5],3,random_info,sizeof(random_info)*8 );
#if 0
    printf("random_info\n");
    for(k=0;k<16; k++)
    {
        printf("%x ",random_info[k]);
    }
    printf("\n");
#endif
    memcpy(&DeviceID[12],random_info,4);
// did [12] ~did [15] end    
}

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
#if 0
void PWD_OUT(unsigned char *DeviceID, unsigned long DID_Len)
{
    int i,j,k;
    unsigned char lookup_table[ONE_YEAR][LOOKUP_INFO]={0};
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
    GenLookupTable(lookup_table[0],ONE_YEAR,LOOKUP_INFO);

    minute = ((DeviceID[3]&0x1f)<<1)|((DeviceID[4]>>7)&0x1);
    second = ((DeviceID[4]>>1)&0x3f);
    //printf("miunte=%x\n",minute);
    //printf("second=%x\n",second);
    residue=(minute*60+second) %3600;

    memcpy(&DeviceID[DID_LEN],&lookup_table[residue][LOOKUP_ROOT_INFO],LOOKUP_RAND_INFO);
    cc_prng_set_seed( pu8Seed );

#if 0
        printf("DeviceID\n");
        for(j=0;j<32;j++)
        {
            printf("%x ",DeviceID[j]);
        }
        printf("\n");

#endif

    cc_prng_didin(DeviceID,DID_Len,MagicDeviceID,sizeof(MagicDeviceID)*8 );

#if 0
        printf("MagicDeviceID\n");
        for(j=0;j<32;j++)
        {
            printf("%x ",MagicDeviceID[j]);
        }
        printf("\n");
#endif

    printf("debug password\n");
    for(j=0;j<DB_PWD_LEN;j++)
    {
        printf("%x ",MagicDeviceID[KSS_LEN+KSH_LEN+j]);
    }
    printf("\n");
}
#endif
void HextoAcsii(unsigned char* hexbuf, unsigned int hexlen,unsigned char* textbuf)
{
#if 1

    // tranfer byte to string ex: 0xab => "AB"
    //unsigned char strdeviceid [(512)+1]={0};
    
    char strpattern[17] = "0123456789ABCDEF";
    int multiple=0;
    int residue = 0;
    int j=0;
    for(j=0;j<hexlen;j++)
    {
        multiple = hexbuf[j]/(0x10);
        residue = hexbuf[j]%(0x10);
        textbuf[2*j]=strpattern[multiple];
        textbuf[(2*j)+1]=strpattern[residue];
        textbuf[(2*j)+2]='\0';
    }
    
    //printf("%s \n",textbuf);
#if 0
    FILE* PWD_file;
    PWD_file=fopen("pwd_file","w+");
    if(PWD_file==NULL)
    {
        return;
    }
    
    printf("%d\n",__LINE__);
    fprintf(PWD_file,"%s",hexbuf);
        printf("%d\n",__LINE__);

    fclose(f_ciphertext);
        printf("%d\n",__LINE__);
#endif
#endif

}

#define KSS_PWD_DEBUG 0
#if KSS_PWD_DEBUG
#define KSS_PWD_DBG(x) x
#else
#define KSS_PWD_DBG(x)
#endif
void Add_Random_Info(unsigned char *Time,unsigned char *TimeWInfo,unsigned int InfoLen)
{
    unsigned char random_info[16]={0};
 
    //dataDump(random_info, 8, "random_info");
    //dataDump(Time, 8, "Time");

    cc_prng_didin(&Time[5],3,random_info,sizeof(random_info)*InfoLen );
    memcpy(&TimeWInfo[8],random_info,InfoLen);
    //dataDump(random_info, 8, "random_info based on time");
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

    hexflag = 1;

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
void test(void)
{
    FILE* release_file;
    unsigned char release_data[128]={0};
    unsigned int u32CRC=0;
    unsigned long filesize=0;    
    int i,j,k;

    release_file = fopen("releasefile","r");
    if(release_file == NULL)        
    {
        return;
    }
    fseek(release_file,0,SEEK_END);
    filesize=ftell(release_file);
    fseek(release_file,0,SEEK_SET);
    
    //printf("(filesize%(RELEASE_DATA+ALIGNED_LEN))=%d\n",(filesize%(RELEASE_DATA+ALIGNED_LEN)));
    //printf("(filesize/(RELEASE_DATA+ALIGNED_LEN))=%d\n",(filesize/(RELEASE_DATA+ALIGNED_LEN)));
    
    for(i=0;i<(filesize/(RELEASE_DATA+ALIGNED_LEN));i++)
    {
        fread(release_data,sizeof(unsigned char),DID_LEN+KSS_LEN+KSH_LEN,release_file);
        fseek(release_file,DB_PWD_LEN+DB_PWD_LEN+CRC32_LEN+ALIGNED_LEN,SEEK_CUR);
        u32CRC = ~crc32_encode( release_data, DID_LEN+KSS_LEN+KSH_LEN);
        printf("~CRC32: 0x%X\r\n", u32CRC);
    }
    return;
}
#endif

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


