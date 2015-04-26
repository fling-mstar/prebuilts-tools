#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

unsigned long crc32_encode(const unsigned char *octets, int len)
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

int main(void)
{
    unsigned int u32CRC = 0;
    u32CRC = ~crc32_encode(ReleaseData, datalen);
    printf("~CRC32: 0x%X\r\n", u32CRC);
}


