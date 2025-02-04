#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <microhttpd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <time.h>
#include <ctype.h>
#include "../include/kyber_utils/api.h"
#include "../include/cJSON/cJSON.h"

/* ---------------- DEFINITIONS ---------------- */
#define PORT 8080
#define MAX_POST_SIZE 262144
#define UNUSED(x) (void)(x)
#define LOG_FILE "kyber_server_log.txt"
/* ---------------- DEFINITIONS ---------------- */

/* ---------------- GLOBAL VARIABLES ---------------- */
uint8_t CSV_COUNTER = 0;
uint8_t global_secret_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_SECRETKEYBYTES];
uint8_t global_public_key[PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES];
FILE *log_file;
/* ---------------- GLOBAL VARIABLES ---------------- */

struct MHD_Response *create_response(const char *message) {
    return MHD_create_response_from_buffer(strlen(message), (void *)message, MHD_RESPMEM_MUST_COPY);
}

struct connection_info_struct {
    char *data;
    size_t size;
};

unsigned char *base64_decode(const char *input, int *out_len) {
    int input_len = strlen(input);
    int max_decoded_length = (input_len * 3) / 4;
    unsigned char *decoded = malloc(max_decoded_length + 1); // +1 für den Nullterminator
    if (decoded == NULL) {
        fprintf(stderr, "Fehler: malloc in base64_decode() schlug fehl.\n");
        return NULL;
    }
    int decoded_length = EVP_DecodeBlock(decoded, (const unsigned char *)input, input_len);
    if (decoded_length < 0) {
        fprintf(stderr, "Fehler: EVP_DecodeBlock schlug fehl.\n");
        free(decoded);
        return NULL;
    }
    if (input_len > 0 && input[input_len - 1] == '=')
        decoded_length--;
    if (input_len > 1 && input[input_len - 2] == '=')
        decoded_length--;
    decoded[decoded_length] = '\0';
    if (out_len)
        *out_len = decoded_length;
    return decoded;
}

int aes_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Fehler: EVP_CIPHER_CTX_new() schlug fehl.\n");
        return -1;
    }
    int len;
    int plaintext_len = 0;
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Fehler: EVP_DecryptInit_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Fehler: EVP_DecryptUpdate() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Fehler: EVP_DecryptFinal_ex() schlug fehl.\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/**
    Request Handler
    - handles HTTP Requests:
        - POST with Route: /init                   -    Sets CVS_COUNTER to zero
        - POST with Route: /send_encrypted_data    -    Gets JSON {"ciphertext":"test","iv":"123","data":"hereIsData"}
        - GET with Route: /get_public_key          -    Sends Public Key to requesting device
*/
static int request_handler(void *cls,
                           struct MHD_Connection *connection,
                           const char *url,
                           const char *method,
                           const char *version,
                           const char *upload_data,
                           size_t *upload_data_size,
                           void **con_cls) {
    UNUSED(cls);
    UNUSED(version);
    struct MHD_Response *response;
    int ret;

    /* ---------------------- Initialisierung von con_cls ---------------------- */
    if (*con_cls == NULL) {
        struct connection_info_struct *con_info = malloc(sizeof(struct connection_info_struct));
        if (con_info == NULL)
            return MHD_NO;
        con_info->data = malloc(1);
        if (con_info->data == NULL) {
            free(con_info);
            return MHD_NO;
        }
        con_info->data[0] = '\0';
        con_info->size = 0;
        *con_cls = (void *)con_info;
        return MHD_YES;
    }
    struct connection_info_struct *con_info = *con_cls;
    /* -------------------- Ende Initialisierung von con_cls -------------------- */

    /* -------------------- Init POST Method -------------------- */
    if (strcmp(url, "/init") == 0 && strcmp(method, "POST") == 0) {
        char response_msg[32];
        snprintf(response_msg, sizeof(response_msg), "CSV_COUNTER SET TO 0");
        response = create_response(response_msg);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        CSV_COUNTER = 0;
        return ret;
    }
    /* -------------------- Init POST Method -------------------- */


    /* -------------------- Public Key GET Method -------------------- */
    if (strcmp(url, "/get_public_key") == 0 && strcmp(method, "GET") == 0) {
        response = MHD_create_response_from_buffer(PQCLEAN_KYBER1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
                                                   global_public_key, MHD_RESPMEM_PERSISTENT);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
    /* -------------------- Public Key GET Method -------------------- */

    /* -------------------- Send Encrypted Data POST Method -------------------- */
    if (strcmp(url, "/send_encrypted_data") == 0 && strcmp(method, "POST") == 0) {

        /* -------- Load all POST Request Data -------- */
        if (*upload_data_size > 0) {
            size_t new_size = con_info->size + *upload_data_size;
            if (new_size > MAX_POST_SIZE) {
                response = create_response("{\"error\": \"POST data too large\"}");
                ret = MHD_queue_response(connection, MHD_HTTP_CONTENT_TOO_LARGE, response);
                MHD_destroy_response(response);
                free(con_info->data);
                free(con_info);
                return ret;
            }
            char *new_data = realloc(con_info->data, new_size + 1);
            if (new_data == NULL)
                return MHD_NO;
            memcpy(new_data + con_info->size, upload_data, *upload_data_size);
            new_data[new_size] = '\0';
            con_info->data = new_data;
            con_info->size = new_size;
            *upload_data_size = 0;
            return MHD_YES;
        }
        /* -------- Load all POST Request Data -------- */

        /* -------- Parse JSON with cJSON -------- */
        cJSON *json = cJSON_Parse(con_info->data);
        if (json == NULL) {
            fprintf(stderr, "DEBUG: cJSON_Parse Fehler: %s\n", cJSON_GetErrorPtr());
            response = create_response("{\"error\": \"Invalid JSON\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            *con_cls = NULL;
            return ret;
        }
        cJSON *ciphertext_json = cJSON_GetObjectItem(json, "ciphertext");
        cJSON *iv_json         = cJSON_GetObjectItem(json, "iv");
        cJSON *encrypted_data_json = cJSON_GetObjectItem(json, "data");
        if (!cJSON_IsString(ciphertext_json) ||
                    !cJSON_IsString(iv_json) ||
                    !cJSON_IsString(encrypted_data_json)) {
            cJSON_Delete(json);
            response = create_response("{\"error\": \"Missing attribute\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            *con_cls = NULL;
            return ret;
        }
        /* -------- Parse JSON with cJSON -------- */

        /* -------- Decode Base64 -------- */
        int ciphertext_len = 0, iv_len = 0, encrypted_data_len = 0;
        unsigned char *decoded_ciphertext = base64_decode(ciphertext_json->valuestring, &ciphertext_len);
        unsigned char *decoded_iv = base64_decode(iv_json->valuestring, &iv_len);
        unsigned char *decoded_encrypted_data = base64_decode(encrypted_data_json->valuestring, &encrypted_data_len);
        if (!decoded_ciphertext ||
                    ciphertext_len != PQCLEAN_KYBER1024_CLEAN_CRYPTO_CIPHERTEXTBYTES ||
                    !decoded_iv || iv_len != 16 ||
                    !decoded_encrypted_data) {
            cJSON_Delete(json);
            response = create_response("{\"error\": \"Oops! Something went wrong with base64_decode.\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            free(decoded_ciphertext);
            free(decoded_iv);
            free(decoded_encrypted_data);
            *con_cls = NULL;
            return ret;
        }
        /* -------- Decode Base64 -------- */

        /* ######## Kyber Algorithm Start ######## */

        /* --- Init variables --- */
        uint8_t shared_secret[PQCLEAN_KYBER1024_CLEAN_CRYPTO_BYTES];
        unsigned char aes_key[32];
        unsigned char decrypted_data[encrypted_data_len];
        struct timespec start_decap, end_decap, start_decrypt, end_decrypt;
        /* --- Init variables --- */

        /* --- Decapsulation --- */
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_decap);
        if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_dec(shared_secret, decoded_ciphertext, global_secret_key) != 0) {
            cJSON_Delete(json);
            response = create_response("{\"error\": \"Decapsulation failed\"}");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            free(con_info->data);
            free(con_info);
            free(decoded_ciphertext);
            free(decoded_iv);
            free(decoded_encrypted_data);
            *con_cls = NULL;
            return ret;
        }
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_decap);
        uint64_t decap_time = (end_decap.tv_sec - start_decap.tv_sec) * 1000000 + (end_decap.tv_nsec - start_decap.tv_nsec) / 1000;
        /* --- Decapsulation --- */

        /* --- SHA256 --- */
        SHA256(shared_secret, sizeof(shared_secret), aes_key);
        /* --- SHA256 --- */

        /* --- AES256 Decryption --- */
        clock_gettime(CLOCK_MONOTONIC_RAW, &start_decrypt);
        int decrypted_data_len = aes_decrypt(decoded_encrypted_data, encrypted_data_len, aes_key, decoded_iv, decrypted_data);
        (void)decrypted_data_len;
        clock_gettime(CLOCK_MONOTONIC_RAW, &end_decrypt);
        uint64_t decrypt_time = (end_decrypt.tv_sec - start_decrypt.tv_sec) * 1000000 + (end_decrypt.tv_nsec - start_decrypt.tv_nsec) / 1000;
        /* --- AES256 Decryption --- */

        /* ######## Kyber Algorithm End ######## */

        /* -------- Build and send HTTP Response -------- */
        char response_msg[256];
        snprintf(response_msg, sizeof(response_msg), "%ld,%ld", decap_time, decrypt_time);
        response = create_response(response_msg);
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        /* -------- Build and send HTTP Response -------- */

        /* -------- Free memory -------- */
        cJSON_Delete(json);
        free(con_info->data);
        free(con_info);
        free(decoded_ciphertext);
        free(decoded_iv);
        free(decoded_encrypted_data);
        *con_cls = NULL;
        return ret;
        /* -------- Free memory -------- */
    }
    /* -------------------- Send Encrypted Data POST Method -------------------- */

    /* -------------------- Standard: Unbekannte Route -------------------- */
    response = create_response("{\"error\": \"Not found\"}");
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    return ret;
    /* -------------------- Standard: Unbekannte Route -------------------- */
}

int printIpAddress() {
    FILE *fp;
    char ip[64] = {0};
    fp = popen("ifconfig | grep 'inet ' | grep -m 1 -Po '192\\.(?!255\\b)\\d{1,3}\\.(?!255\\b)\\d{1,3}\\.(?!255\\b)\\d{1,3}'", "r");
    if (fp == NULL) {
        perror("popen failed");
        return EXIT_FAILURE;
    }
    if (fgets(ip, sizeof(ip), fp) != NULL)
        ip[strcspn(ip, "\n")] = '\0';
    else {
        fprintf(stderr, "Keine IP-Adresse gefunden.\n");
        pclose(fp);
        return EXIT_FAILURE;
    }
    pclose(fp);
    printf("Server is running on %s:%d\n", ip, PORT);
    return EXIT_SUCCESS;
}

int main() {
    /* -------- Init files -------- */
    log_file = fopen(LOG_FILE, "w");
    if (log_file == NULL) {
        printf("Unable to create output files.\n");
        return 1;
    }
    /* -------- Init files -------- */

    /* -------- Generate Keypair -------- */
    if (PQCLEAN_KYBER1024_CLEAN_crypto_kem_keypair(global_public_key, global_secret_key) != 0) {
        fprintf(stderr, "Failed to generate Kyber key pair.\n");
        return 1;
    }
    /* -------- Generate Keypair -------- */

    /* -------- Generate DAEMON -------- */
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, PORT, NULL, NULL,
                              (MHD_AccessHandlerCallback)request_handler, NULL,
                              MHD_OPTION_END);
    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return 1;
    }
    /* -------- Generate DAEMON -------- */

    /* -------- Print IP Address -------- */
    printIpAddress();
    /* -------- Print IP Address -------- */

    /* -------- Stop condition -------- */
    char input[128];
    while (1) {
        printf("Geben Sie 'stop' ein, um den Server zu beenden:\n");
        if (fgets(input, sizeof(input), stdin) == NULL)
            break;
        input[strcspn(input, "\r\n")] = '\0';
        for (int i = 0; input[i]; i++)
            input[i] = tolower((unsigned char)input[i]);
        if (strcmp(input, "stop") == 0)
            break;
    }
    /* -------- Stop condition -------- */

    /* -------- End server -------- */
    MHD_stop_daemon(daemon);
    printf("Stopped Server\n");
    fclose(log_file);
    return 0;
    /* -------- End server -------- */
}