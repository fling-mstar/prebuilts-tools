HRESULT CMST6XXXX::EFUSE_UNIQUE_CODE(double _results[4])
{
    // add your code
  int fuse_id[64], fuse_id2[64];
  int error_flag=0;

  int k,i,num; 
  int j,a,n=2;
  int p[64]; 

  ARRAY_I dataIn1(4), dataIn2(4), dataIn3(4), dataIn4(4);
  ARRAY_I dataOut1(4), dataOut2(4), dataOut3(4), dataOut4(4);
  Boolean rslt=0;

  //char tester_name[20]="hp93k11\n";
  char tester_name[20]="";
  char testhouse[1],testID[3]="";

  int year_h,year_m,year_l;

  int data_flag;
  GET_USER_FLAG("Ref_data", &data_flag);

  FILE *fp;
  fp = popen("hostname","r");
  fgets(tester_name, sizeof tester_name, fp);
  pclose(fp); 



  for (i=0;i<64;i++)
  {
     fuse_id[i]=0;
     fuse_id2[i]=0;
  }
/***************************************************************************
          for day, month, year ID processs
***************************************************************************/

  time_t secs=time(0);
  tm *t=localtime(&secs);


  year_h = (t->tm_year / 100) + 19;
  year_m = (t->tm_year % 100) / 10;
  year_l = t->tm_year % 10;

  if(data_flag==1)
  {
    cout << "Current Site" << CURRENT_SITE_NUMBER() << ": now time ==> " << t->tm_year+1900 << "/" << t->tm_mon+1 << "/" << t->tm_mday << " " << t->tm_hour << ":" << t->tm_min << ":" << t->tm_sec << endl;
    cout << "Current Site" << CURRENT_SITE_NUMBER() << ": year_h==> " << year_h << ", year_m==> " << year_m << ", year_l==> " << year_l << endl;
  }

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



/***************************************************************************
          for testhouse, tester ID processs
***************************************************************************/


   if (strncmp(tester_name,"hp93k_",6)==0){
    strcpy(testhouse,"K"); //KYEC
     if (strlen(tester_name) == 9){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 10){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"hp93k",5)==0){
     strcpy(testhouse,"L"); //TCLN
     if (strlen(tester_name) == 8){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"hp93e",5)==0){
     strcpy(testhouse,"A"); //ASET
     if (strlen(tester_name) == 7){
      testID[0]='0';
      testID[1]='0';
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 8){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 9){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"hp93",4)==0){
     strcpy(testhouse,"T"); //SCTS
     if (strlen(tester_name) == 7){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 8){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"H93K",4)==0){
     strcpy(testhouse,"G"); //GTTW
     if (strlen(tester_name) == 8){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"TCE",3)==0){
     strcpy(testhouse,"P"); //SPIL
     if (strlen(tester_name) == 6){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 7){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"ag93k",5)==0){
     strcpy(testhouse,"E"); //ASEK
     if (strlen(tester_name) == 8){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 9){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else if  (strncmp(tester_name,"TAG",3)==0){
     strcpy(testhouse,"S"); //SIGD
     if (strlen(tester_name) == 6){
      testID[0]='0';
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else if (strlen(tester_name) == 7){
      testID[0]=tester_name[strlen(tester_name)-4];
      testID[1]=tester_name[strlen(tester_name)-3];
      testID[2]=tester_name[strlen(tester_name)-2];
      testID[3]='\0';
     }
     else{
      error_flag=1;
     }
   }

   else {
     error_flag=1;
   }


     if(isalnum(testhouse[0]))
     {
      num=int(toupper(testhouse[0]));
      if(isalpha(testhouse[0]))	
      	num=num-55;
      else
      	num=num-48;
     }
     else {
      error_flag=1;
     }
 



     if(data_flag==1)
     {
       cout << "Current Site" << CURRENT_SITE_NUMBER() << ": host name ==> " << tester_name << endl;
       cout << "Current Site" << CURRENT_SITE_NUMBER() << ": testing house ==> " << testhouse << " ascii num ==> " << num << endl;
       cout << "Current Site" << CURRENT_SITE_NUMBER() << ": testID 0==> " << testID[0] << endl;
       cout << "Current Site" << CURRENT_SITE_NUMBER() << ": testID 1==> " << testID[1] << endl;
       cout << "Current Site" << CURRENT_SITE_NUMBER() << ": testID 2==> " << testID[2] << endl;
       cout << "Current Site" << CURRENT_SITE_NUMBER() << ": error flag ==> " << error_flag << endl;
     }

     TEST("ATE_ERROR", "error", error_flag);

//========================= Test House 6bit ===================================
            j=5;  //total - 1
            a= num;
            while(a)
            {
                p[j--]=a%n;
                a/=n;
            }
            while(j != -1)  p[j--]=0;

            k=39;
            for(j=0;j<6;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[5] is LSB*/

//========================================================================

//========================= Tester hundred ID 1bit ===================================

            fuse_id[45]=int(testID[0])-48;
                if(fuse_id[45] >= 1) fuse_id[45]=1;

//========================================================================

//========================= Tester ten ID 4bit ===================================
            j=3;  //total - 1
            a= int(testID[1])-48;
            while(a)
            {
                p[j--]=a%n;
                a/=n;
            }
            while(j != -1)  p[j--]=0;

            k=46;
            for(j=0;j<4;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[3] is LSB*/

//========================================================================


//========================= Tester ID 4bit ===================================
            j=3;  //total - 1
            a= int(testID[2])-48;
            while(a)
            {
                p[j--]=a%n;
                a/=n;
            }
            while(j != -1)  p[j--]=0;

            k=50;
            for(j=0;j<4;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[3] is LSB*/

//========================================================================


            srand(t->tm_sec*t->tm_min);
            a=rand();

            if(data_flag==1)
            {
             cout << "Current Site" << CURRENT_SITE_NUMBER() << ": randon num ==> " << a << ", mod 512 ==> " << a%512 << endl;
            }

//========================= randon num 9bit ===================================
            j=8;  //total - 1
            a=a%512;
            while(a)
            {
                p[j--]=a%n;
                a/=n;
            }
            while(j != -1)  p[j--]=0;

            k=54;
            for(j=0;j<9;j++) fuse_id[k++]=p[j]; /*p[0] is MSB ; p[8] is LSB*/

//========================================================================

//========================= suscess bit 1bit =============================
            k=63;
            fuse_id[k]=1;
//========================================================================

            // inverse
            for(i=0;i<64;i++)              
              fuse_id2[i]=fuse_id[63-i];

            if(data_flag==1)
            {
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": year 13 bit: [0:12] = ";
              for(i=0;i<13;i++)              cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": month 4 bit: [13:16] = ";
              for(i=13;i<17;i++)             cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": days 5 bit: [17:21] = ";
              for(i=17;i<22;i++)             cout << fuse_id[i];
              cout << endl;
              
              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": hours 5 bit: [22:26] = ";
              for(i=22;i<27;i++)             cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": minute 6 bit: [27:32] = ";
              for(i=27;i<33;i++)             cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": second 6 bit: [33:38] = ";
              for(i=33;i<39;i++)             cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": test House 6 bit: [39:44] = ";
              for(i=39;i<45;i++)             cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": tester ID 9 bit: [45:53] = ";
              for(i=45;i<54;i++)             cout << fuse_id[i];
              cout << endl;
              
              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": randon num 9 bit: [54:62] = ";
              for(i=54;i<63;i++)             cout << fuse_id[i];
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": suscess bit 1 bit: [63] = ";
              for(i=63;i<64;i++)             cout << fuse_id[i];
              cout << endl;
              cout << endl;

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": fuse_id_c [63:0] = ";
              for(i=0;i<64;i++)              
              {
               if (i==63)
                 cout << fuse_id[63-i] << endl << endl;
               else if (((63-i)%8)==0)
                 cout << fuse_id[63-i] << ",";
               else
                 cout << fuse_id[63-i];
              }

              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": fuse_id_d [63:0] = ";
              for(i=0;i<64;i++)              
              {
               if (i==63)
                 cout << fuse_id[i] << endl << endl;
               else if (((63-i)%8)==0)
                 cout << fuse_id[i] << ",";
               else
                 cout << fuse_id[i];
              }
            }

    
    for(i=0;i<8;i++)
    {
     if (i<=3)
     {
       dataIn1[i] = (fuse_id[i*8+0] *(int)pow(2.0,0)) + (fuse_id[i*8+1] *(int)pow(2.0,1)) + (fuse_id[i*8+2] *(int)pow(2.0,2)) + (fuse_id[i*8+3] *(int)pow(2.0,3)) + (fuse_id[i*8+4] *(int)pow(2.0,4)) + (fuse_id[i*8+5] *(int)pow(2.0,5)) + (fuse_id[i*8+6] *(int)pow(2.0,6)) + (fuse_id[i*8+7] *(int)pow(2.0,7));
       dataOut1[i] = dataIn1[i];
       dataIn3[i] = (fuse_id2[i*8+0]*(int)pow(2.0,0)) + (fuse_id2[i*8+1]*(int)pow(2.0,1)) + (fuse_id2[i*8+2]*(int)pow(2.0,2)) + (fuse_id2[i*8+3]*(int)pow(2.0,3)) + (fuse_id2[i*8+4]*(int)pow(2.0,4)) + (fuse_id2[i*8+5]*(int)pow(2.0,5)) + (fuse_id2[i*8+6]*(int)pow(2.0,6)) + (fuse_id2[i*8+7] *(int)pow(2.0,7));
       dataOut3[i] = dataIn3[i];
     }
     else
     {
       dataIn2[i-4] = (fuse_id[i*8+0] *(int)pow(2.0,0)) + (fuse_id[i*8+1] *(int)pow(2.0,1)) + (fuse_id[i*8+2] *(int)pow(2.0,2)) + (fuse_id[i*8+3] *(int)pow(2.0,3)) + (fuse_id[i*8+4] *(int)pow(2.0,4)) + (fuse_id[i*8+5] *(int)pow(2.0,5)) + (fuse_id[i*8+6] *(int)pow(2.0,6)) + (fuse_id[i*8+7] *(int)pow(2.0,7));
       dataOut2[i-4] = dataIn2[i-4];
       dataIn4[i-4] = (fuse_id2[i*8+0]*(int)pow(2.0,0)) + (fuse_id2[i*8+1]*(int)pow(2.0,1)) + (fuse_id2[i*8+2]*(int)pow(2.0,2)) + (fuse_id2[i*8+3]*(int)pow(2.0,3)) + (fuse_id2[i*8+4]*(int)pow(2.0,4)) + (fuse_id2[i*8+5]*(int)pow(2.0,5)) + (fuse_id2[i*8+6]*(int)pow(2.0,6)) + (fuse_id2[i*8+7] *(int)pow(2.0,7));
       dataOut4[i-4] = dataIn4[i-4];
     } 
    }
              
       if(data_flag==1)
       {
         for(i=0;i<8;i++)
         {
           if (i<=3)
              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": Efuse data_c " << i << " [" << (i+1)*8-1 << ":" << (i+1)*8-8 << "] = " << dataIn1[i] << "(W), " << dataOut1[i] << "(R)" << endl;
           else
              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": Efuse data_c " << i << " [" << (i+1)*8-1 << ":" << (i+1)*8-8 << "] = " << dataIn2[i-4] << "(W), " << dataOut2[i-4] << "(R)" << endl;
         }
         cout << endl;

         for(i=0;i<8;i++)
         {
           if (i<=3)
              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": Efuse data_d " << i << " [" << (i+1)*8-1 << ":" << (i+1)*8-8 << "] = " << dataIn3[i] << "(W), " << dataOut3[i] << "(R)" << endl;
           else
              cout << "Current Site" << CURRENT_SITE_NUMBER() << ": Efuse data_d " << i << " [" << (i+1)*8-1 << ":" << (i+1)*8-8 << "] = " << dataIn4[i-4] << "(W), " << dataOut4[i-4] << "(R)" << endl;
         }
         cout << endl;
       }

  ON_FIRST_INVOCATION_BEGIN();  
   FOR_EACH_SITE_BEGIN();
     VECTOR("DSM_IN1_ADBUS").format("BIN").bits(8).setVectors(dataIn1);
     VECTOR("DSM_IN2_ADBUS").format("BIN").bits(8).setVectors(dataIn2);
     VECTOR("DSM_IN3_ADBUS").format("BIN").bits(8).setVectors(dataIn3);
     VECTOR("DSM_IN4_ADBUS").format("BIN").bits(8).setVectors(dataIn4);
     VECTOR("DSM_OUT1_ADBUS").format("BIN").bits(8).setVectors(dataOut1);
     VECTOR("DSM_OUT2_ADBUS").format("BIN").bits(8).setVectors(dataOut2);
     VECTOR("DSM_OUT3_ADBUS").format("BIN").bits(8).setVectors(dataOut3);
     VECTOR("DSM_OUT4_ADBUS").format("BIN").bits(8).setVectors(dataOut4);
     FW_TASK("UPTD VEC,1\n");
   FOR_EACH_SITE_END();

     Primary.level(LEVEL_SPEC(3, 1));
     Primary.label("reset");
     EXECUTE_TEST();
     Primary.label("efuse_program_c_l32b");
     EXECUTE_TEST();  
     Primary.level(LEVEL_SPEC(3, 4));
     Primary.label("efuse_write");
     EXECUTE_TEST();  

     Primary.level(LEVEL_SPEC(3, 1));
     Primary.label("reset");
     EXECUTE_TEST();
     Primary.label("efuse_program_c_h32b");
     EXECUTE_TEST();
     Primary.level(LEVEL_SPEC(3, 4));
     Primary.label("efuse_write");
     EXECUTE_TEST();  

     Primary.level(LEVEL_SPEC(3, 1));
     Primary.label("reset");
     EXECUTE_TEST();
     Primary.label("efuse_program_d_l32b");
     EXECUTE_TEST();
     Primary.level(LEVEL_SPEC(3, 4));
     Primary.label("efuse_write");
     EXECUTE_TEST();  

     Primary.level(LEVEL_SPEC(3, 1));
     Primary.label("reset");
     EXECUTE_TEST();
     Primary.label("efuse_program_d_h32b");
     EXECUTE_TEST();
     Primary.level(LEVEL_SPEC(3, 4));
     Primary.label("efuse_write");
     EXECUTE_TEST();  

     Primary.level(LEVEL_SPEC(3, 1));
     Primary.label("efuse_read_cd_128b");
     //Primary.label("efuse_read_c_64b");
     FUNCTIONAL_TEST();  
  ON_FIRST_INVOCATION_END();

  rslt=GET_FUNCTIONAL_RESULT();   // if pass rslt=1

  if(data_flag==1)
  { 
    if (rslt==1)
     cout << "Current Site" << CURRENT_SITE_NUMBER() << ": efuse read result ==> PASS" << endl;
    else
     cout << "Current Site" << CURRENT_SITE_NUMBER() << ": efuse read result ==> FAIL" << endl;
    cout << endl;
  }

    TEST("EFUSE_CODE", "pass_fail", rslt, TRUE);

    return S_OK;
}
