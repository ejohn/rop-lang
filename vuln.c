#include <stdio.h>
#include <stdlib.h>	
#include <string.h>

char bss[10240];
char *buffer;

int main(int argc, char *argv[])
{
	long length;

	if(argc < 2) {
		printf("usage: %s filename", argv[0]);
		exit(1);
	}

	FILE * f = fopen (argv[1], "rb");

	if (f)
	{
	  fseek (f, 0, SEEK_END);
	  length = ftell (f);
	  fseek (f, 0, SEEK_SET);
	  buffer = malloc (length);
	  if (buffer)
	  {
	    fread (buffer, 1, length, f);
	  }
	  fclose (f);
	}

    __asm__ ("movl buffer, %esp; ret" );

	return 0;
}

