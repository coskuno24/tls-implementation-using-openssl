#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sys/types.h>
#include <tchar.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <strings.h>
#define FAIL    -1

int OpenListener(int port)
{
    WSADATA wsaData;
    int wsaerr;
    WORD wVersionRequested = MAKEWORD(2,2);
    wsaerr = WSAStartup(wVersionRequested, &wsaData);
    //WSAStartup init

    if(wsaerr != 0){ 
        printf("The Winsock dll not found!");
        return 0;
    } else  {
        printf("The Winsock dll  found!");
    }

    SOCKET sd;
    struct sockaddr_in addr;
    sd = INVALID_SOCKET;
    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(55555);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

SSL_CTX* InitServerCTX(void)
{
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load algorithms */
    SSL_load_error_strings();   /* load all error messages */
    ctx = SSL_CTX_new(TLS_server_method());  
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
    cert = SSL_get_peer_certificate(ssl); /* Get certificate*/
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
        printf("No certificate.\n");
}
void Servlet(SSL* ssl)
{
    char buf[1024] = {0};
    int sd, bytes;
    const char* ServerResponse="<Body>\
                               <Name>3th project</Name>\
                 <year>2024</year>\
                 <BlogType>BLG520E<BlogType>\
                 <Author>omer<Author>\
                 <Body>";
    const char *cpValidMessage = "<Body>\
                               <UserName>omer<UserName>\
                 <Password>123456<Password>\
                 <Body>";
    if ( SSL_accept(ssl) == FAIL )    
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl); 
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        if ( bytes > 0 )
        {
            if(strcmp(cpValidMessage,buf) == 0)
            {
                SSL_write(ssl, ServerResponse, strlen(ServerResponse)); 
            }
            else
            {
                SSL_write(ssl, "Invalid Message", strlen("Invalid Message"));
            }
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);
    SSL_free(ssl);    
    close(sd);        
}
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();    
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");
    server = OpenListener(atoi(portnum));
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);           
        SSL_set_fd(ssl, client);     
        Servlet(ssl);       
    }
    close(server);    
    SSL_CTX_free(ctx);    
}