#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>


#define KSS_LEN 16 //bytes
#define KSH_LEN 32 //bytes
#define DB_PWD_LEN 5 //bits
#define OTHERS_LEN 75 //bites
#define OTP_INFO_LEN (KSS_LEN+KSH_LEN +DB_PWD_LEN+OTHERS_LEN)

int main(int argc, char *argv[])
{

    FILE *otp_table;
    unsigned char Key[OTP_INFO_LEN]={0};
    
    otp_table= fopen("OTP_table","r");
    if(otp_table == NULL)
    {
        printf(" OTP_table is NULL\n");
    }

    //Kss 128 bits
    fread(Key,sizeof(unsigned char),KSS_LEN,otp_table);
    //Ksh 256 bits
    fread(Key,sizeof(unsigned char),KSH_LEN,otp_table);
    // password 40 bits
    fread(Key,sizeof(unsigned char),DB_PWD_LEN,otp_table);
    //seek to next block
    fseek(otp_table,75,SEEK_CUR);

    fclose(otp_table);
}
