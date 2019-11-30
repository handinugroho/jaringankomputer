#include <WiFi.h>
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include <string.h>

void encryptRSA (unsigned char *plainText, unsigned char *cipheredText, char *n_buf, char *e_buf) {
  mbedtls_mpi N, E;
  mbedtls_rsa_context rsa;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_mpi_init( &N ); 
  mbedtls_mpi_init( &E );
  const char *pers_encrypt = "rsa_encrypt";

  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
  mbedtls_mpi_init( &N ); mbedtls_mpi_init( &E );
  mbedtls_entropy_init( &entropy );

  mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers_encrypt,
                                        strlen( pers_encrypt ) );
  mbedtls_mpi_read_string(&N, 16, n_buf);
  mbedtls_mpi_read_string(&E, 16, e_buf);

  mbedtls_rsa_import( &rsa, &N, NULL, NULL, NULL, &E );
  mbedtls_rsa_pkcs1_encrypt( &rsa, mbedtls_ctr_drbg_random,
                                     &ctr_drbg, MBEDTLS_RSA_PUBLIC,
                                     16, plainText, cipheredText );

  mbedtls_mpi_free( &N ); mbedtls_mpi_free( &E );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  mbedtls_rsa_free( &rsa );                                   
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

    char *n_buf = "B2D5AE8C7EBD036BEE035AFA542D59DF92FB393A4167B24C7DE330EA07EA0C4E42318DA663EA20CBFB9BBDD3E4E7B7072CA810DBE7C0BFCD64ADE190FEB613291FEB128D27B7CDB8B5C8BC1A8C8A3BF85955C1C3BAF27BB55908AFA54D0043EDA75777E96003B523FD5BC7794BBBF07DD359170984A4B77B59B39C4E30E9C396E601437A729673A636608B048144F005DC650A03F19D4295F7F33F827670CECABA551CE9DEBC3404E2C0FEE2D129E07999CB8EDFC5F09F3EE825E0AB2139B723E73E006F67230EA3AC3BE47B17FCDE9543605C134FDFAA084716C6F4EF7217C77D675443DD7BFBB552F6B84D23BF50BE97537695DA0EE7A15918C992E7F7626B";
    char *e_buf = "010001";
    
    unsigned char plainText[1024] = "Test stringabcd";
    unsigned char cipheredText[1024];

    encryptRSA(plainText, cipheredText, n_buf, e_buf);
    
    for (int i = 0; i < 1024; i++) {
        client.write(cipheredText[i]);
        Serial.printf("%02X%s", cipheredText[i],
                      ( i + 1 ) % 32 == 0 ? "\r\n" : " " );
    }

    
    client.stop();
    /* This will send the data to the server */
}
void loop()
{
    

}
