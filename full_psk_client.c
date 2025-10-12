#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define PORT 4433
#define BUFFER_SIZE 1024
unsigned int psk_client_callback(SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len, unsigned char *psk, unsigned int max_psk_len) {
    const char *client_identity = "client1";
    const char *key = "rickyraccoon";
    size_t identity_len = strlen(client_identity);
    size_t key_len = strlen(key);
    if (identity_len >= max_identity_len || key_len > max_psk_len) return 0;
    strcpy(identity, client_identity);
    memcpy(psk, key, key_len);
    return key_len;
}

SSL_CTX* create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return NULL;
    SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "PSK-AES256-GCM-SHA384:PSK-AES128-GCM-SHA256:PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA:PSK-AES128-CBC-SHA:PSK-3DES-EDE-CBC-SHA:PSK-RC4-SHA");
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    return ctx;
}

int create_connection(const char *hostname) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT)};
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0 || connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

void communicate_with_server(SSL *ssl) {
    const char *msg = "hello raccoon\n";
    SSL_write(ssl, msg, strlen(msg));
    printf(">> %s", msg);
    
    char buf[BUFFER_SIZE];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("<< %s", buf);
    }
}

int main(int argc, char *argv[]) {
    const char *hostname = argc > 1 ? argv[1] : "127.0.0.1";
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = create_ssl_context();
    if (!ctx) return 1;
    int sockfd = create_connection(hostname);
    if (sockfd < 0) { SSL_CTX_free(ctx); return 1; }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) > 0) communicate_with_server(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}