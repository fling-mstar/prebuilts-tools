#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
	const char array[10]={0};
	    printf("array=%d \n",sizeof(array));
	
	const char FilePathArray[][128] =
{"/OAD/en_KeyBox.bin", 
  "/OAD/en_cert_hmac.pem"};

	    printf("FilePathArray=%d \n",sizeof(FilePathArray));
			//printf("FilePathArray=%d \n",sizeof(FilePathArray[][]));
    FILE *fin1;
    //unsigned char a[10]={0,1,2,3,4,5,6,7,8,9};
    //unsigned char b[7]={6,5,4,3,2,1,0};    
    //unsigned long filesize = 0 ;
    //unsigned long ret;
    //unsigned char first_read[128]={0};
    //unsigned char second_read[128]={0};
    //unsigned char third_read[128]={0};
    
    fin1=fopen("abcde","w+");
    if(fin1==NULL)
    {
        return;
    }

    system("cp -rf abcde efgh");
//		fwrite(a,sizeof(char),sizeof(a),fin1);
//		fseek(fin1, 3 ,SEEK_END);
//		fwrite(b,sizeof(char),sizeof(b),fin1);
		#if 0

//filesize = ftell(fin1);
//read all data
    fread(pu8DecryptedData,sizeof(unsigned char),u32ReadSize , fin1);
    printf("%s\n",pu8DecryptedData);	

    // first    
    ret = strcspn(pu8DecryptedData,"\n");
    printf("ret=%d\n",ret);
    strncpy(first_read,pu8DecryptedData,ret);
    printf("first_read=%s\n",first_read);


    pu8DecryptedData = strchr(pu8DecryptedData,'\n');
    //printf("filesize=%d\n",filesize);
    ret = strcspn(pu8DecryptedData+1,"\n");
    printf("ret=%d\n",ret);
    strncpy(second_read,pu8DecryptedData+1,ret);
    printf("second_read=%s\n",second_read);


    pu8DecryptedData = strrchr(pu8DecryptedData,'\n');
    //printf("filesize=%d\n",filesize);		
    ret = strcspn(pu8DecryptedData+1,"\0");
    printf("ret=%d\n",ret);
    strncpy(third_read,pu8DecryptedData+1,ret);    
    printf("third_read=%s\n",third_read);

    printf("%s \n",pu8DecryptedData);
    fclose(fin1);

    
    fin1 = fopen("test_idfile","w+");
    if(fin1 == NULL)
    {
        return 0;
    }

    char Key[]= "SDK-00661\nzt2R6daqG0RtbSuSk2Xk9Q==\nZtSxVJmjzXrlsja4Qmxu89w6NHhmhuDhyhtle51IQSY=\0";
    fwrite(Key,sizeof(unsigned char), strlen(Key), fin1);
    fclose(fin1);
    #endif
#if 0
    fin1=fopen("file1","r+");
    if(fin1==NULL)
    {
        return;
    }
    fwrite(b,sizeof(unsigned char), sizeof(b), fin1);
    fclose(fin1);
#endif
    return 0;
}
