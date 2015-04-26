#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>


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

int main(void)
{
        unsigned char test_pat1[]={0x80,0x53,0xB9,0x3D,0xA1,0xE8,0xCD,0x2E,0xF2,0x19,0x77,0xCB,0xB8,0xFA,0x5C,0x00,0xff,0xff,0xff,0x80};
        unsigned long ret=0;

        crc8_clear();
        for(i=0; i<sizeof(test_pat1) ;i++)
        {
            crc8_addbyte(test_pat1[i]);
        }
        ret = crc8_getcrc();
        printf("test_pat1 ret =%lx \n",ret);
}


