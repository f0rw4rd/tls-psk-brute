#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#define PORT 4433
#define BUFFER_SIZE 1024
static volatile int server_running = 1;
void signal_handler(int sig) { server_running = 0; }
unsigned int psk_server_callback(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len) {
    const char *key = "rickyraccoon";
    size_t key_len = strlen(key);
    if (key_len > max_psk_len) return 0;
    memcpy(psk, key, key_len);
    return key_len;
}

SSL_CTX* create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;
    SSL_CTX_set_psk_server_callback(ctx, psk_server_callback);
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    const char *cipher_list = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:PSK-AES256-GCM-SHA384:PSK-CHACHA20-POLY1305:PSK-AES128-GCM-SHA256:PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA256:PSK-AES256-CBC-SHA:PSK-AES128-CBC-SHA:PSK-3DES-EDE-CBC-SHA:PSK-RC4-SHA:DHE-PSK-AES256-GCM-SHA384:DHE-PSK-CHACHA20-POLY1305:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES256-CBC-SHA:DHE-PSK-AES128-CBC-SHA:DHE-PSK-3DES-EDE-CBC-SHA:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES256-CBC-SHA:ECDHE-PSK-AES128-CBC-SHA:ECDHE-PSK-3DES-EDE-CBC-SHA:RSA-PSK-AES256-GCM-SHA384:RSA-PSK-CHACHA20-POLY1305:RSA-PSK-AES128-GCM-SHA256:RSA-PSK-AES256-CBC-SHA384:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES256-CBC-SHA:RSA-PSK-AES128-CBC-SHA:RSA-PSK-3DES-EDE-CBC-SHA";
    SSL_CTX_set_cipher_list(ctx, cipher_list);
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_CIPHER_SERVER_PREFERENCE);
    return ctx;
}

int create_socket() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(PORT), .sin_addr.s_addr = INADDR_ANY};
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(sockfd, 5) < 0) {
        close(sockfd);
        return -1;
    }
    return sockfd;
}

void handle_client(SSL *ssl) {
    char buf[BUFFER_SIZE];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    
    if (n > 0) {
        buf[n] = '\0';
        if (strstr(buf, "raccoon")) {
            SSL_write(ssl, "ricky says hi!\n", 15);
        } else {
            SSL_write(ssl, "who?\n", 5);
        }
    }
}

int main() {
    signal(SIGINT, signal_handler);
    SSL_library_init();
    SSL_load_error_strings();
    SSL_CTX *ctx = create_ssl_context();
    if (!ctx) return 1;
    int server_fd = create_socket();
    if (server_fd < 0) { SSL_CTX_free(ctx); return 1; }
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    while (server_running) {
        int client_fd = accept(server_fd, (struct sockaddr*)&addr, &len);
        if (client_fd < 0) continue;
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) > 0) handle_client(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}