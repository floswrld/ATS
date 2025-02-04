#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <time.h>
#include "../include/kyber_utils/api.h"

/* ---------------- DEFINITIONS ---------------- */
#define ITERATIONS 100
#define URL "https://ogcapi.hft-stuttgart.de/sta/icity_data_security/v1.1"
#define CSV_FILE "kyber.csv"
#define LOG_FILE "kyber_client_log.txt"
#define BUFFER_SIZE 256
#define UNUSED(x) (void)(x)
/* ---------------- DEFINITIONS ---------------- */

/* ---------------- GLOBAL VARIABLES ---------------- */
char API_BASE_URL[256] = "http://";
/* ---------------- GLOBAL VARIABLES ---------------- */

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t totalSize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + totalSize + 1);
    if (ptr == NULL) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, totalSize);
    mem->size += totalSize;
    mem->memory[mem->size] = 0;
    return totalSize;
}

size_t load_from_file(const char *filename, uint8_t **data) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Could not open file %s for reading.\n", filename);
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    *data = malloc(size);
    if (!*data) {
        fprintf(stderr, "Error: Could not allocate memory for reading data.\n");
        exit(EXIT_FAILURE);
    }
    fread(*data, 1, size, file);
    fclose(file);
    return size;
}

void send_post_request(const char *url, const char *post_data, struct MemoryStruct *response) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return;
    }

    response->memory = malloc(1);
    response->size = 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() in send_post_request failed: %s\n", curl_easy_strerror(res));
    }
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

void send_get_request(const char *url, struct MemoryStruct *response) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize curl\n");
        return;
    }

    response->memory = malloc(1);  // initial allocation
    response->size = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() send_get_request failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
}

int aes_encrypt(char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Fehler: EVP_CIPHER_CTX_new() schlug fehl.\n");
        return -1;
    }
    int len;
    int ciphertext_len = 0;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Fehler: EVP_EncryptInit_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char *)plaintext, plaintext_len)) {
        fprintf(stderr, "Fehler: EVP_EncryptUpdate() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Fehler: EVP_EncryptFinal_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

unsigned char *base64_encode(const unsigned char *input, int length) {
    int encoded_length = 4 * ((length + 2) / 3);
    unsigned char *encoded = malloc(encoded_length + 1);
    if (encoded == NULL) {
        fprintf(stderr, "Fehler: malloc in base64_encode() schlug fehl.\n");
        return NULL;
    }
    int actual_length = EVP_EncodeBlock(encoded, input, length);
    if (actual_length < 0) {
        fprintf(stderr, "Fehler: EVP_EncodeBlock schlug fehl.\n");
        free(encoded);
        return NULL;
    }
    encoded[actual_length] = '\0';
    return encoded;
}

int main() {
    /* -------- Init files -------- */
    char input[64];
    char buffer[BUFFER_SIZE];
    int a, b, c, d, port;
    int valid = 0;
    /* -------- Init files -------- */

    /* -------- Dialog to determine <ip-address>:<port> to connect to -------- */
    while (!valid) {
        printf("Bitte geben Sie die Adresse im Format <IP:Port> ein (z.B. 127.0.0.1:8080): ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            continue;
        }
        input[strcspn(input, "\n")] = '\0';
        if (sscanf(input, "%d.%d.%d.%d:%d", &a, &b, &c, &d, &port) == 5) {
            if (a >= 0 && a <= 255 && b >= 0 && b <= 255 &&
                c >= 0 && c <= 255 && d >= 0 && d <= 255 && port > 0 && port <= 65535) {
                valid = 1;
                }
        }
        if (!valid) {
            printf("Eingabe ist nicht korrekt formatiert. Bitte versuchen Sie es erneut.\n");
        }
    }
    strcat(API_BASE_URL, input);
    /* -------- Dialog to determine <ip-address>:<port> to connect to -------- */

    /* -------- Get Data to encrypt via AES256 -------- */
    uint8_t *plaintext;
    size_t plaintext_len = 0;
    plaintext_len = load_from_file("../Data-Preprocessing/CLEANED_UP_SHORTEND_20241111_alle_Datenpunkte.json", &plaintext);
    struct MemoryStruct chunk;
    chunk.memory = malloc(plaintext_len + 1);
    memcpy(chunk.memory, plaintext, plaintext_len);
    chunk.memory[plaintext_len] = '\0';  // Sicherstellen, dass der String terminiert ist
    chunk.size = plaintext_len;
    printf("%s\n", chunk.memory);
    /* -------- Get Data to encrypt via AES256 -------- */

    /* -------- Init files -------- */
    FILE *csv_file = fopen(CSV_FILE, "w");
    FILE *log_file = fopen(LOG_FILE, "w");
    if (csv_file == NULL || log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }
    fprintf(csv_file, "Iteration,Encapsulation (microseconds),AES256 Encryption (microseconds),Decapsulation (microseconds),AES256 Decryption (microseconds)\n");
    /* -------- Init files -------- */

    /* -------- Init POST Request -------- */
    struct MemoryStruct responseInit;
    snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/init");
    send_post_request(buffer, "", &responseInit);
    free(responseInit.memory);
    /* -------- Init POST Request -------- */

    /* -------- Iterations -------- */
    for (int i = 0; i < ITERATIONS; i++) {

        /* ---- GET Public Key from Server ---- */
        struct MemoryStruct response;
        struct timespec start_encap, end_encap, start_encrypt, end_encrypt;
        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/get_public_key");
        send_get_request(buffer, &response);
        if (response.size == 0) {
            fprintf(log_file, "Failed to retrieve public key (iteration %d).\n", i + 1);
            free(response.memory);
            continue;
        }
        uint8_t public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
        memcpy(public_key, response.memory, PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES);
        free(response.memory);
        /* ---- GET Public Key from Server ---- */

        /* ---- Kyber Encapsulation ---- */
        uint8_t ciphertext[PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];

        clock_gettime(CLOCK_MONOTONIC_RAW, &start_encap);
        PQCLEAN_KYBER1024_CLEAN_crypto_kem_enc(ciphertext, shared_secret, public_key);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_encap);
        uint64_t encap_time = (end_encap.tv_sec - start_encap.tv_sec) * 1000000 + (end_encap.tv_nsec - start_encap.tv_nsec) / 1000;
        /* ---- Kyber Encapsulation ---- */

        /* ---- SHA256 ---- */
        unsigned char aes_key[32];
        SHA256(shared_secret, sizeof(shared_secret), aes_key);
        unsigned char iv[16];
        RAND_bytes(iv, sizeof(iv));
        /* ---- SHA256 ---- */

        /* ---- AES256 Encryption ---- */
        int block_size = EVP_CIPHER_block_size(EVP_aes_256_cbc());
        // Puffergröße: Klartextlänge + Blockgröße
        int ciphertext_buffer_len = chunk.size + block_size;
        unsigned char *encrypted_data = malloc(ciphertext_buffer_len);
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_encrypt);
        int encrypted_data_len = aes_encrypt(chunk.memory, chunk.size, aes_key, iv, encrypted_data);
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_encrypt);
        uint64_t encrypt_time = (end_encrypt.tv_sec - start_encrypt.tv_sec) * 1000000 + (end_encrypt.tv_nsec - start_encrypt.tv_nsec) / 1000;
        /* ---- AES256 Encryption ---- */

        /* ---- Encode Base64 ---- */
        unsigned char *ba64_ciphertext = base64_encode(ciphertext, sizeof(ciphertext));
        unsigned char *ba64_iv = base64_encode(iv, sizeof(iv));
        unsigned char *ba64_encrypted_data = base64_encode(encrypted_data, encrypted_data_len);
        /* ---- Encode Base64 ---- */

        /* ---- Build JSON to POST to Server ---- */
        size_t needed = strlen((const char *)ba64_ciphertext) + strlen((const char *)ba64_iv) + strlen((const char *)ba64_encrypted_data) + 100;
        char *post_data = malloc(needed);
        if (!post_data) {
            fprintf(stderr, "Fehler bei malloc für post_data\n");
            exit(EXIT_FAILURE);
        }
        sprintf(post_data, "{ \"ciphertext\": \"%s\", \"iv\": \"%s\", \"data\": \"%s\" }", ba64_ciphertext, ba64_iv, ba64_encrypted_data);
        /* ---- Build JSON to POST to Server ---- */

        /* ---- POST Request ---- */
        snprintf(buffer, BUFFER_SIZE, "%s%s", API_BASE_URL, "/send_encrypted_data");
        send_post_request(buffer, post_data, &response);
        fprintf(log_file, "Server response (iteration %d): %s\n", i + 1, response.memory);
        printf("Server response (iteration %d): Decap,Decrypt: %s\n", i + 1, response.memory);
        /* ---- POST Request ---- */

        /* ---- Print Meassured Times in csv ---- */
        fprintf(csv_file, "%d,%lu,%lu,%s\n", i + 1, encap_time, encrypt_time, response.memory);
        /* ---- Print Meassured Times in csv ---- */

        /* ---- Free memory ---- */
        free(response.memory);
        free(ba64_ciphertext);
        free(ba64_iv);
        free(ba64_encrypted_data);
        free(encrypted_data);
        /* ---- Free memory ---- */
    }
    /* -------- Iterations -------- */

    /* -------- Close files -------- */
    fclose(csv_file);
    fclose(log_file);
    /* -------- Close files -------- */
    return 0;
}