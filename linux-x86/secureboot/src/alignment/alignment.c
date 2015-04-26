#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
    FILE *t_fpin;
    FILE *t_fpout;
    int t_filesize = 0;
    unsigned char *t_buf;
    int t_i;

    t_fpin = fopen(argv[1], "rb");
    if (NULL == t_fpin)
    {
        printf("[Error]cannot open %s\n", argv[1]);
        return -1;
    }
    else
		{
		    // get file size
    	  fseek(t_fpin, 0, SEEK_END);
    	  t_filesize = ftell(t_fpin);
    	  fseek(t_fpin, 0, SEEK_SET);
    
			  t_buf = (unsigned char*)malloc(t_filesize + 16);
    	  if (NULL == t_buf)
    	  {
      	    printf("[Error]memory allocation.\n");
            return -1;
        }
        else
        {
        		unsigned char patch = t_filesize%16;
        		unsigned char i;
            fread(t_buf, 1, t_filesize, t_fpin);
            fclose(t_fpin);
            if(patch != 0)
            {
                for(i=0;i<(16-patch);i++)
                {
                    t_buf[t_filesize + i] = 0xFF;	
                }
                t_filesize = t_filesize + (16 - patch);
            }	
        }
    }

    t_fpout = fopen(argv[1], "wb");
    if (NULL == t_fpout)
    {
        printf("[Error]cannot open %s\n", argv[1]);
        return -1;
    }
    else
    {
        fwrite(t_buf, sizeof(unsigned char), t_filesize, t_fpout);
    }

    free(t_buf);
    fclose(t_fpout);
    return 0;
}
