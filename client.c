#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tchar.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <strings.h>
#include <sys/time.h>

#define FAIL    -1
int OpenConnection(const char *hostname, int port)
{
    WSADATA wsaData;
    int wsaerr;
    WORD wVersionRequested = MAKEWORD(2,2);
    wsaerr = WSAStartup(wVersionRequested, &wsaData);
    //WSAStartup
    if(wsaerr != 0){ 
        printf("The Winsock dll not found!");
        return 0;
    } else  {
        printf("The Winsock dll  found!");
    }

    SOCKET sd;
    struct hostent *host;
    struct sockaddr_in addr;
    sd = INVALID_SOCKET;
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(55555);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}
SSL_CTX* InitCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* Load algorithms */
    SSL_load_error_strings();   /* load all error messages */
    ctx = SSL_CTX_new(TLS_client_method());  
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    printf("LoadCertificates 1\n");
    //set certificate
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set private key */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    printf("LoadCertificates 2 \n");
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       
        X509_free(cert);    
    }
    else
        printf("Info: No client certificates configured.\n");
}
int main(int count, char *strings[])
{
    struct timeval time1, time2, time3;
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    char acClientRequest[1024] = {0};
    int bytes;
    char *hostname, *portnum;
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];
    ctx = InitCTX();
    LoadCertificates(ctx, "clientCert.pem", "clientCert.pem");
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);    
    SSL_set_fd(ssl, server);    
    if ( SSL_connect(ssl) == FAIL )  
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
                               <UserName>%s<UserName>\
                 <Password>%s<Password>\
                 <Body>";
        printf("Enter the User Name : ");
        scanf("%s",acUsername);
        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);
        sprintf(acClientRequest, cpRequestMessage, acUsername,acPassword);
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        gettimeofday(&time1, NULL);
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
        gettimeofday(&time2, NULL);
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        gettimeofday(&time3, NULL);
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        printf("ssl_write time difference is: %lu ms, \n ssl_read time difference is: %lu ms", ((time2.tv_sec- time1.tv_sec)*1000000 + time2.tv_usec-time1.tv_usec), ((time3.tv_sec- time2.tv_sec)*1000000 + time3.tv_usec-time2.tv_usec));
        SSL_free(ssl);       
    }
    close(server);      
    SSL_CTX_free(ctx);      
    return 0;
}