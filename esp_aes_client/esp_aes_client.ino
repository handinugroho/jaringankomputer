#include <WiFi.h>
#include "mbedtls/aes.h"
#include <string.h>

void encrypt(char *plainText, char *key, unsigned char *outputBuffer, unsigned char *iv){
    // Encrypting 16 bytes string using AES-128 (CBC mode)
    mbedtls_aes_context aes;
    mbedtls_aes_setkey_enc( &aes, (const unsigned char*) key, 128 );
    mbedtls_aes_crypt_cbc( &aes, MBEDTLS_AES_ENCRYPT, 16, iv ,(const unsigned char*)plainText, outputBuffer);
    mbedtls_aes_free( &aes );
}

/* change ssid and password according to yours WiFi*/
const char* ssid     = "Hotspot LSKK";
const char* password = "lskkhotspot";
/*
 * This is the IP address of your PC
 * [Wins: use ipconfig command, Linux: use ifconfig command]
*/


const char* host = "167.205.66.148";
const int port = 8888;
void setup()
{
    Serial.begin(115200);
    Serial.print("Connecting to ");
    Serial.println(ssid);
    /* connect to your WiFi */
    WiFi.begin(ssid, password);
    /* wait until ESP32 connect to WiFi*/
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.println("WiFi connected with IP address: ");
    Serial.println(WiFi.localIP());
    Serial.print("connecting to ");
    Serial.println(host);
    /* Use WiFiClient class to create TCP connections */
    WiFiClient client;
    
    if (!client.connect(host, port)) {
        Serial.println("connection failed");
        return;
    }

    char *key = "abcdefghijklmnop";
    char *plainText = "Test stringabcdg";
    unsigned char iv[64] = "1234567812345678";
    unsigned char cipherTextOutput[16];
    encrypt(plainText, key, cipherTextOutput, iv);
    
    for (int i = 0; i < 16; i++) {
        client.write(cipherTextOutput[i]);
    }
    
    client.stop();
    /* This will send the data to the server */
}
void loop()
{
    

}
