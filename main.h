/**
 * \file aes.h
 *
 * \brief   This file contains function definitions and compiler switches
 *
 */

#define VALIDATE_YES 1	/* Validate encryption*/
#define VALIDATE_NO 0	/* DONT validate encryption*/
#define VALIDATE VALIDATE_NO 

/**
 * \brief          		This Function is called to convert input string to hex byte array.
 *
 *
 * \param *ascii_ptr    Pointer to the string that needs to be converted. 
 *
 * \param *hex_ptr     	Pointer to output string that has byte array in hex/int
 *
 * \param len    		Lenght of the input string. This allows to parse strings of any length
 *						i.e. it is independent of end of string character. 
 */
void strtohex(unsigned char *ascii_ptr,unsigned char *hex_ptr, int len);

/**
 * \brief          		Function to merge multiple arguments(inputs) into a data block for encryption
 *
 *
 * \param *Stype 	    Pointer to the char array that containes ID for FNwkSIntKey(0x01) and SNwkSIntKey(0x03) 
 *
 * \param *arg1     	Pointer to char array up for merger. 
 *						Merging will be done in order of the arguments
 *
 * \param *arg2     	Pointer to char array up for merger. 
 *
 * \param *arg3     	Pointer to char array up for merger. 
 *
 * \param *ret    		Pointer to merged output char array 
 *						
 */
void mergeargs(unsigned char *Stype,unsigned char *arg1,unsigned char *arg2,unsigned char *arg3, unsigned char *ret);
