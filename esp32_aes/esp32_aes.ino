#include "mbedtls/aes.h"

void encrypt(char *plainText, char *key, unsigned char *outputBuffer, unsigned char *iv){
    // Encrypting 16 bytes string using AES-128 (CBC mode)
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, 128 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv ,(const unsigned char*)plainText, outputBuffer);
    mbedtls_aes_free( &aes );
}

void decrypt(unsigned char * chipherText,char * key, unsigned char * outputBuffer, unsigned char *iv) {
    // Decrypting 16 bytes string using AES-128 (CBC mode)
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_dec( &aes, (const unsigned char*) key, 128 );
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, 16, iv, (const unsigned char*)chipherText, outputBuffer);
    mbedtls_aes_free( &aes );
}

void setup() {

  Serial.begin(115200);

  char *key = "abcdefghijklmnop";
  char *plainText = "Test stringabcd";
  // Arbitrary initial vector
  unsigned char iv[64] = "1234567812345678";
  unsigned char iv1[64] = "1234567812345678"; // encrypt does changes in iv, so we need to declare the same iv twice
  unsigned char cipherTextOutput[16];
  unsigned char decipheredTextOutput[16];

  encrypt(plainText, key, cipherTextOutput, iv);
  decrypt(cipherTextOutput, key, decipheredTextOutput, iv1);

  for (int i = 0; i < 16; i++) {
        char str[10];
        sscanf(str, "%02x", (int)cipherTextOutput[i]);
        printf("%s",str);
    }
  Serial.println("\nOriginal plain text:");
  Serial.println(plainText);

  Serial.println("\nCiphered text:");
  for (int i = 0; i < 16; i++) {

    char str[3];

    sprintf(str, "%02x", (int)cipherTextOutput[i]);
    Serial.print(str);
  }

  Serial.println("\n\nDeciphered text:");
  for (int i = 0; i < 15; i++) {
    Serial.print((char)decipheredTextOutput[i]);
  }
}

void loop() {}
