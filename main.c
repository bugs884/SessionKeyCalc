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

#define USAGE   \
    "\n  ./nwksintkeys <NwkKey> <JoinNonce> <JoinEUI> <DevNonce>\n" \
    "\n  example: ./nwksintkeys 01020304050607080102030405060708 010203 0102030405060708 0102\n" \
    "\n"


int main(int argc, char *argv[])
{
	/* AES variables*/
	mbedtls_aes_context context_in,context_out;
	unsigned char FNwkSIntKey[16],SNwkSIntKey[16];
	unsigned char input[16],key[16];
	/*Random Hardcoded IV. IV is changed after every use. Hence fresh IV is used to keep consistency for validation*/
	unsigned char iv[16] = { 14, 31, 6, 126, 18, 12, 36, 70, 100, 9, 42, 51, 111, 84, 3, 25 };
	unsigned char iv2[16] = { 14, 31, 6, 126, 18, 12, 36, 70, 100, 9, 42, 51, 111, 84, 3, 25 };
	
	int argcount = 5;

	/*
	 * Validate encryption by decrypting it with same key/IV
	 * Use VALIDATE compiler switch for turning ON/OFF feature
	 */
	#if VALIDATE
	/*IV for decryption */
	unsigned char decrypt1[16],decrypt2[16];
	/*Same IV as encryption to validate the program*/
	unsigned char iv3[16] = { 14, 31, 6, 126, 18, 12, 36, 70, 100, 9, 42, 51, 111, 84, 3, 25 };
	unsigned char iv4[16] = { 14, 31, 6, 126, 18, 12, 36, 70, 100, 9, 42, 51, 111, 84, 3, 25 };
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
	else 
	{
		/* Copy key as hex into variable key*/
		strtohex(argv[1],key,strlen(argv[1]));
		/* Set key for encryption in AES context*/
		mbedtls_aes_setkey_enc( &context_in, key, 128 );

		/* CALCLULATE FNwkSIntKey
		 *
		 *	Merge arguments to form the data block for encryption
		 *	Follows the specification of LoRAWAN 1.1 line 1604
		 *	FNwkSIntKey = aes128_encrypt(NwkKey, 0x01 | JoinNonce | JoinEUI | DevNonce | pad 16 )
		 *	Pads zeros at the end to make the lenght multiple of 16
		 */
		mergeargs("01",argv[2],argv[3],argv[4],input);
		
		/* AES CBC mode used for Encryption. IV is hardcoded into the application and reset before reuse*/
		mbedtls_aes_crypt_cbc( &context_in, MBEDTLS_AES_ENCRYPT, 16, iv, input, FNwkSIntKey );
  		
  		printf("\nFNwkSIntKey:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%x",FNwkSIntKey[i]);
  		} 	
  		
		/* CALCLULATE SNwkSIntKey
		 *
		 *	Follows the specification of LoRAWAN 1.1 line 1605
		 *	SNwkSIntKey = aes128_encrypt(NwkKey, 0x03 | JoinNonce | JoinEUI | DevNonce | pad 16 )
		 *	Pads zeros at the end to make the lenght multiple of 16
		 */
  		mergeargs("03",argv[2],argv[3],argv[4],input);
  		/*Use a fresh IV*/
		mbedtls_aes_crypt_cbc( &context_in, MBEDTLS_AES_ENCRYPT, 16, iv2, input, SNwkSIntKey );

		printf("\nSNwkSIntKey:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%x",SNwkSIntKey[i]);
  		} 
  		printf("\n");
  		/* Validation Code. Decrypt of encrypted keys. */
  		#if VALIDATE
  		/* Validate encrypted data*/
  		/*Use same IV for decryption*/   
  		mbedtls_aes_setkey_dec( &context_out, key, 128 );
  		mbedtls_aes_crypt_cbc( &context_out, MBEDTLS_AES_DECRYPT, 16, iv3, FNwkSIntKey, decrypt1 ); 
      	printf("\n\nFNwkSIntKey_DataPayload:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%x",decrypt1[i]);
  		}
  		mbedtls_aes_setkey_dec( &context_out, key, 128 );
  		mbedtls_aes_crypt_cbc( &context_out, MBEDTLS_AES_DECRYPT, 16, iv4, SNwkSIntKey, decrypt2 ); 
      	printf("\nSNwkSIntKey_DataPayload:");
  		for(int i=0;i<16;i++)
  		{
  			printf("%x",decrypt2[i]);
  		}
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
		strtohex(arg1,ret+index,strlen(arg1));
		index += (strlen(arg1)/2);
		strtohex(arg2,ret+index,strlen(arg2));
		index += (strlen(arg2)/2);
		strtohex(arg3,ret+index,strlen(arg3));
		index += (strlen(arg3)/2);
		strtohex("0000",ret+index,4);
}