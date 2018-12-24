/* Calculate two session keys as per LoRaWAN spec*/
/*Add more comments*/
/*First commit*/
#include "mbedtls/mbedtls/aes.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	int argcount = 5;
	if(argcount!=argc)
		{
			printf("Usage\n");
		}
	else 
		printf("Number of arguments=%d",argc-1);

	return 0;

}

