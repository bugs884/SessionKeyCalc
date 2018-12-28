/* 
 *	Calculate two session keys as per LoRaWAN spec
 *	https://lora-alliance.org/resource-hub/lorawantm-specification-v11
 *	
 *	Written for Embedded Dev Assignment at Things Networks
 */

#include "mbedtls/aes.h"
#include "main.h"

#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
	/* AES variables*/
	mbedtls_aes_context context_in;
	unsigned char FNwkSIntKey[16],SNwkSIntKey[16];
	unsigned char input[16],key[16];

	int argcount = 5;

	/*
	 * Validate encryption by decrypting it with same key/IV
	 * Use VALIDATE compiler switch for turning ON/OFF feature
	 */
	#if VALIDATE
	mbedtls_aes_context context_out;
	unsigned char decrypt1[16],decrypt2[16];
	#endif
	/*End VALIDATE*/

	/*
     * Parse the command-line arguments.
     * Expects exactly 4 arguments.
     */
	if(argcount!=argc)
	{
		printf("\n   USAGE:\n");
		printf(USAGE);
		return 1;
	}
	else if(parseinput((uchar)argv[1])!=32||parseinput((uchar)argv[2])!=6||parseinput((uchar)argv[3])!=16||parseinput((uchar)argv[4])!=4)
	{	
		printf("\n   Wrong input argument size or Unknown character in arguments");
		printf(INSIZE);
		printf("\n   %s accepts only HEX arguments (0-9,A-F,a-f)\n",argv[0]);
		return 1;
	}
	else 
	{
		/* Copy key as hex into variable key*/
		strtohex((uchar)argv[1],key,parseinput((uchar)argv[1]));

		/* Set key for encryption in AES context*/
		mbedtls_aes_setkey_enc( &context_in, key, 128 );

		/* CALCLULATE FNwkSIntKey
		 *
		 *	Merge arguments to form the data block for encryption
		 *	Follows the specification of LoRAWAN 1.1 line 1604
		 *	FNwkSIntKey = aes128_encrypt(NwkKey, 0x01 | JoinNonce | JoinEUI | DevNonce | pad 16 )
		 *	Pads zeros at the end to make the lenght multiple of 16
		 */
		mergeargs((uchar)"01",(uchar)argv[2],(uchar)argv[3],(uchar)argv[4],input);

		/* AES ECB mode used for Encryption.*/
		mbedtls_aes_crypt_ecb( &context_in, MBEDTLS_AES_ENCRYPT, input, FNwkSIntKey );
  		
  		printf("\nFNwkSIntKey:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%.2X",FNwkSIntKey[i]);
  		} 	
  		
		/* CALCLULATE SNwkSIntKey
		 *
		 *	Follows the specification of LoRAWAN 1.1 line 1605
		 *	SNwkSIntKey = aes128_encrypt(NwkKey, 0x03 | JoinNonce | JoinEUI | DevNonce | pad 16 )
		 *	Pads zeros at the end to make the lenght multiple of 16
		 */
  		mergeargs((uchar)"03",(uchar)argv[2],(uchar)argv[3],(uchar)argv[4],(uchar)input);

		mbedtls_aes_crypt_ecb( &context_in, MBEDTLS_AES_ENCRYPT, input, SNwkSIntKey );

		printf("\nSNwkSIntKey:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%.2X",SNwkSIntKey[i]);
  		} 
  		printf("\n");
  		/* Validation Code. Decrypt of encrypted keys. */
  		#if VALIDATE
  		/* Validate encrypted data*/
  		mbedtls_aes_setkey_dec( &context_out, key, 128 );
  		mbedtls_aes_crypt_ecb( &context_out, MBEDTLS_AES_DECRYPT, FNwkSIntKey, decrypt1 ); 
      	printf("\n\nFNwkSIntKey_DataPayload:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%.2X",decrypt1[i]);
  		}
  		mbedtls_aes_setkey_dec( &context_out, key, 128 );
  		mbedtls_aes_crypt_ecb( &context_out, MBEDTLS_AES_DECRYPT, SNwkSIntKey, decrypt2 ); 
      	printf("\nSNwkSIntKey_DataPayload:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%.2X",decrypt2[i]);
  		}
  		printf("\n");
  		#endif 
  		/*End VALIDATE*/
  		return 0;
	}
}

/*	
 *	Function to convert input string to hex byte array
 */
void strtohex(unsigned char *ascii_ptr,unsigned char *hex_ptr, int len)
{
    int i;
    for(i = 0; i < (len / 2); i++)
    {

        *(hex_ptr+i)   = (*(ascii_ptr+(2*i)) <= '9') ? ((*(ascii_ptr+(2*i)) - '0') * 16 ) :  (((*(ascii_ptr+(2*i)) - 'A') + 10) << 4);
        *(hex_ptr+i)  |= (*(ascii_ptr+(2*i)+1) <= '9') ? (*(ascii_ptr+(2*i)+1) - '0') :  (*(ascii_ptr+(2*i)+1) - 'A' + 10);

    }
}

/*	
 *	Function to merge multiple arguments(inputs) into a data block for encryption
 */
void mergeargs(unsigned char *Stype,unsigned char *arg1,unsigned char *arg2,unsigned char *arg3, unsigned char *ret)
{
		int index=1;
		strtohex(Stype,ret,2);
		int len1,len2,len3;
		/*
		 *	Convert each byte equivalent in string to HEX
		 *	Takes care of endianness for the data that is used for encryption
		 */
		len1 = parseinput((uchar)arg1);
		for(int i=0;i<len1;)
		{
			strtohex(arg1+len1-2-i,ret+index+(i/2),2);
			i+=2;
		}
		/*Update index to point to next location in Byte array*/
		index += len1/2;
		len2 = parseinput((uchar)arg2);
		for(int i=0;i<len2;)
		{
			strtohex(arg2+len2-2-i,ret+index+(i/2),2);
			i+=2;
		}
		index += len2/2;
		len3 = parseinput((uchar)arg3);
		for(int i=0;i<len3;)
		{
			strtohex(arg3+len3-2-i,ret+index+(i/2),2);
			i+=2;
		}
		index += len3/2;
		/*
		 *	Pad16 equivalent
		 *	Pads 2 octets of 00s to make it 16 size
		 *	Since all arguments are fixed length padding is fixed and simple
		 */
		strtohex((uchar)"0000",ret+index,4);
}
/*	
 *	Function that validates if the string is a valid hex number and returns its length
 */
int parseinput(unsigned char *input)
{
    unsigned char *checkinp = input;
    int len=0;
    while (*checkinp != 0)
    {
        if (('A' <= *checkinp && *checkinp <= 'F') || ('a' <= *checkinp && *checkinp <= 'f') || ('0' <= *checkinp && *checkinp <= '9'))
        {
            ++checkinp;
            len++;
        } 
        else 
        {
            return -1;
        }
    }
    return len;
}