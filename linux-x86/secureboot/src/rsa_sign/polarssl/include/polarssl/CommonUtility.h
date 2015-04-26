#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

#include "prng.h"
#include "timing.h"


void HextoAcsi(unsigned char* hexbuf, unsigned int hexlen,unsigned char* textbuf);
unsigned long cal_crc32(const unsigned char *octets, int len);
void crc8_clear(void);
void crc8_addbyte(unsigned char data);
unsigned char crc8_getcrc(void);
void  dataDump(unsigned char* const data,const unsigned int len, const char *str);
void SwapFunc(unsigned char* const pu8Data,const unsigned long u32LEN);
void Get_Time(unsigned char *Time);
void Convert_Add_Micro_into_Time(int *fuse_id,unsigned char* Timebuf);
void Create_DID(int *fuse_id,unsigned char* DeviceID);
void GenLookupTable(unsigned char lookup_table[],int d1,int d2 );
void HextoAcsii(unsigned char* hexbuf, unsigned int hexlen,unsigned char* textbuf);
void Add_Random_Info(unsigned char *Time,unsigned char *TimeWInfo,unsigned int InfoLen);
unsigned int  _atoi(char *str, int hexflag);

