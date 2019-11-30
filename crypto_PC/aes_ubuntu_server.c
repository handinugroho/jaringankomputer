#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h>
#define MAX 80 
#define PORT 8888 
#define SA struct sockaddr 

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
  
// Driver function 
int main() 
{ 
    int sockfd, connfd, len; 
    struct sockaddr_in servaddr, cli; 
  
    // socket create and verification 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        printf("socket creation failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully created..\n"); 
    bzero(&servaddr, sizeof(servaddr)); 
  
    // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 
  
    // Binding newly created socket to given IP and verification 
    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 
    else
        printf("Socket successfully binded..\n"); 
  
    // Now server is ready to listen and verification 
    if ((listen(sockfd, 5)) != 0) { 
        printf("Listen failed...\n"); 
        exit(0); 
    } 
    else
        printf("Server listening..\n"); 
    len = sizeof(cli); 
  
    // Accept the data packet from client and verification 
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("server acccept failed...\n"); 
        exit(0); 
    } 
    else
        printf("server acccept the client...\n"); 
  
    // Function designed for chat between client and server. 

    unsigned char buff[10];
    unsigned char temp[100];
    char str[3];

    printf("Ciphered text received: ");
    for (int i=0;i<16;i++) {
        read(connfd, buff, 1);
        printf("%02x", (int) buff[0]);
        temp[i] = buff[0];
    }

    char *key = "abcdefghijklmnop";
    unsigned char iv[64] = "1234567812345678";
    unsigned char cipherTextOutput[16];
    decrypt(temp, key, cipherTextOutput, iv);
    printf("\nDeciphered text: ");
    for (int i=0;i<16;i++) {
        printf("%c", cipherTextOutput[i]);
    }
    printf("\n\n");
  
    // After chatting close the socket 
    close(sockfd);
} 
