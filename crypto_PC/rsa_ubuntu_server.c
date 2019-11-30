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

#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/config.h"
#include "mbedtls/platform.h"
#include <string.h>

void decryptRSA (unsigned char *cipheredText, unsigned char *outputText, char *n_buf, char *e_buf, char *d_buf, char *p_buf, char *q_buf, char *dp_buf, char *dq_buf, char *qp_buf) {

  mbedtls_rsa_context rsa;
  mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char *pers_decrypt = "rsa_decrypt";

  size_t i = 256;

  mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  mbedtls_entropy_init( &entropy );
  mbedtls_mpi_init( &N ); 
  mbedtls_mpi_init( &E );
  mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
  mbedtls_mpi_init( &D ); mbedtls_mpi_init( &DP );
  mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

  mbedtls_mpi_read_string(&N, 16, n_buf);
  mbedtls_mpi_read_string(&E, 16, e_buf);
  mbedtls_mpi_read_string(&D, 16, d_buf);
  mbedtls_mpi_read_string(&P, 16, p_buf);
  mbedtls_mpi_read_string(&Q, 16, q_buf);
  mbedtls_mpi_read_string(&DP, 16, dp_buf);
  mbedtls_mpi_read_string(&DQ, 16, dq_buf);
  mbedtls_mpi_read_string(&QP, 16, qp_buf);

  mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                        &entropy, (const unsigned char *) pers_decrypt,
                                        strlen( pers_decrypt ) );
   
  mbedtls_rsa_import( &rsa, &N, &P, &Q, &D, &E );
  mbedtls_rsa_complete( &rsa );
  mbedtls_rsa_pkcs1_decrypt( &rsa, mbedtls_ctr_drbg_random,
                                            &ctr_drbg, MBEDTLS_RSA_PRIVATE, &i,
                                            cipheredText, outputText, 1024);
  mbedtls_rsa_free( &rsa );
  mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
  mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
  mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  mbedtls_rsa_free( &rsa );                                                            
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

    char *n_buf = "B2D5AE8C7EBD036BEE035AFA542D59DF92FB393A4167B24C7DE330EA07EA0C4E42318DA663EA20CBFB9BBDD3E4E7B7072CA810DBE7C0BFCD64ADE190FEB613291FEB128D27B7CDB8B5C8BC1A8C8A3BF85955C1C3BAF27BB55908AFA54D0043EDA75777E96003B523FD5BC7794BBBF07DD359170984A4B77B59B39C4E30E9C396E601437A729673A636608B048144F005DC650A03F19D4295F7F33F827670CECABA551CE9DEBC3404E2C0FEE2D129E07999CB8EDFC5F09F3EE825E0AB2139B723E73E006F67230EA3AC3BE47B17FCDE9543605C134FDFAA084716C6F4EF7217C77D675443DD7BFBB552F6B84D23BF50BE97537695DA0EE7A15918C992E7F7626B";
    char *e_buf = "010001";
    char *d_buf = "6A39A2C4B1437494D77C06BE4AE1E55077EDE1C048B95F9F2FE793566FFD05F2363F58F44CC4F55634CDFDA3AF8433A37F5315308A2863C58CD7FBF43457D269CB1BC69931CE6BD41BA670951485C7B96CD713913FAA68F0FF41B993667991DFC8569C537344C083F02A6402188A39FF835A97E47F7597C71D3122D70F16CBA604CD6294D1DEA2EE5140E179A85D02239068EBA936FDD19EC20B7A22066B3A3A9F0415775F8E255A5877151461F49C927E22614F98D6A39A0F710DC8C1889F81F5E41BE0CE75C321E0BCF235371A4B5A32476BDAA491BB7E69FE152073C87AA7090D355CD872FD92071388B652CF3A46926BB4EDCB15B2AE5927EBAD8368B281";
    char *p_buf = "FBACE48FDBDC4CEF61637E4C5FD09BBB53B353AF81CDC7D722A7F49E78EF50AC52D888C11A6A8EE2EBDDA6EE490166F45CA5681DBDB0C8B93284B84D5F5EB463FD3A60F3892763A632685DEA66775DD9A9D7802C747AF99B478097847C3FA5FF0A106C9A85FF831686A023BD3DE293A41E154BC06256E2D26A19F32510AE4D9D";
    char *q_buf = "B5E85DD9838DED63AE45D80A3E22B6FBD00E6FD18698D04FCD55D6F466A379735C7272BAAC80C0542B2C46F07CBC368DCBE67F3C2032D06A3A222CEE7067FFA0F1A7C11F34A41D505D1BE5C6664AE115AEFD23A5EEFCF1229264362ED6E3038408836C62045D137892A420F740D74952C9B8984E279F9F598919F3DADAD275A7";
    char *dp_buf = "9B1C1075D5342E3A6E944A37B9E9B0C14031CA86E58235031379DE1A79404D4117821AAEA0A041D5FB364D76988A03B0E1149459981A476B548655AC61F5D549B6BCEF19C952FC6866B2CA06F805E3528E09A21643E7B2C48FC9E2182617782FFA3CEB22452997DA1F38BD2E19E0F5CB753AFCC7E213D8918410E038DCD20045";
    char *dq_buf = "87834156E6EFF626CA0EF1F03F75B1074A6956D7AA03713BE1E5CEAA6743E518118898FB83C2AE84855D08C3E2C87B838AA07DAC96F803D6FED3B2D1361FE3894C3D025B72E5C788B4B431AA694DE2FC3A4E0E1E71393191E5A88DCCBAFC8703F72BA0B42C3802675226BF0032E7AE91E4008645C2B2E10CDC5BDF13ECEBD805";
    char *qp_buf = "C55E838381C296C0D92549164AB6B2C47E2BEE338AE770FD7C0CEDE374C6155EF1A9118D71BA07AEA5527B657CCB0C02C3409D89226992FA9EBFD84C69C4E38D311DC54291EE6DF661CD498D6DA603F239773C62A63E9CABCAC15104E3D3605159267ABDEC59EC6B03B1E0991C5099FEE18CAF03A748336401D298F445F1923D";
    
    
    unsigned char buff[10];
    unsigned char cipheredText[1024];
    char str[3];

    for (int i=0;i<1024;i++) {
        read(connfd, buff, 1);
        cipheredText[i] = buff[0];
    }

    for(int i = 0; i < 1024; i++ )
        printf("%02X%s", cipheredText[i],
                       ( i + 1 ) % 32 == 0 ? "\r\n" : " " );

    char outputText[1024];

    decryptRSA(cipheredText, outputText, n_buf, e_buf, d_buf, p_buf, q_buf, dp_buf, dq_buf, qp_buf);
    printf("\n\nDeciphered text: ");
    printf("%s\n",outputText);
    // After chatting close the socket 
    close(sockfd);
} 
