# LoRaWAN 1.1 Network session integrity key calculator 
A program is developed that calculates the FNwkSIntKey (Forwarding Network Session Integrity Key) and SNwkSIntKey (Serving Network Session Integrity Key).  
## Getting Started

This program uses mbedtls for AES encryption. 

Details of mbedTLS can be found at
* [Github link for mbedTLS](https://github.com/ARMmbed/mbedtls)
* [ARMmbed Dev corner](https://tls.mbed.org/dev-corner)

To quickly setup mbedTLS , get the source code from github as below
```
git clone https://github.com/ARMmbed/mbedtls.git
```
Using Make and Make install compile and setup the includes that will be used later in the project. Move to the folder of mbedTLS and run make as below
```
make
make install
```

## Usage

This program takes following as inputs (hex)
Encryptio key:
* NwkKey - Network key(16 octets)
Data block for encryption:
* JoinNonce - 3 octets
* JoinEUI - 8 octets
* DevNonce - 2 octets
The keys are calculated as below:

FNwkSIntKey = aes128_encrypt(NwkKey, 0x01 | JoinNonce | JoinEUI | DevNonce | pad 16 )

SNwkSIntKey = aes128_encrypt(NwkKey, 0x03 | JoinNonce | JoinEUI | DevNonce | pad 16 )

To run the program, clone the repository and make as follows

```
make
```

Program takes four command line arguments as inputs as defined above.
Example input and output shown below.

```
./nwksintkeys 01020304050607080102030405060708 010203 0102030405060708 0102

FNwkSIntKey:5de339b2a6c06c2633c49a3e861fb170
SNwkSIntKey:f5606d63eca5ea4c3372406f2f3fcd2b
```
