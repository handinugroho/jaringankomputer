#include "mbedtls/aes.h"
#include <stdio.h>
#include <string.h>

void encrypt(char *plainText, unsigned char *key, unsigned char *outputBuffer, unsigned char *iv){
    //Decrypting 16 bytes string using AES-128 (CBC mode)
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, 128 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv ,(const unsigned char*)plainText, outputBuffer);
    mbedtls_aes_free( &aes );
}

void decrypt(unsigned char * chipherText, unsigned char * key, unsigned char * outputBuffer, unsigned char *iv) {
    //Decrypting 16 bytes string using AES-128 (CBC mode)
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_dec( &aes, (const unsigned char*) key, 128 );
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, (const unsigned char*)chipherText, outputBuffer);
    mbedtls_aes_free( &aes );
}

int main () {
    // Arbitrary key
    char *key = "abcdefghijklmnop";

    // Arbitrary string
    char *plainText = "Test stringabcde";
    
    // Arbitrary initial vector
    unsigned char iv[16] = "1234567812345678";
    unsigned char iv1[16] = "1234567812345678"; // encrypt does changes in iv, so we need to declare the same iv twice

    unsigned char cipherTextOutput[16];
    unsigned char decipheredTextOutput[16];
    
    encrypt(plainText, key, cipherTextOutput, iv);

    printf("Original text: %s\n", plainText);
    printf("\nCiphered text: \n");
    for (int i = 0; i < 16; i++) {
        char str[10];
        sprintf(str, "%02x", (int)cipherTextOutput[i]);
        printf("%s",str);
    }

    decrypt(cipherTextOutput, key, decipheredTextOutput, iv1);
    printf("\n\nDeciphered text: ");
    printf("%s", decipheredTextOutput);
    printf("\n");
    return 0;
}

