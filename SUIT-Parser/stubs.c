// ----------------------------------------------------------------------------
// Copyright 2021 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

//#include "cli.h"
#include "suit_platform.h"
#include "suit_parser.h"
#include "bm_cbor.h"
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/pem.h"
#include "mbedtls/error.h"
#include "mbedtls/base64.h"
#include "mbedtls/rsa.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>     /* printf */
#include <stdlib.h>    /* exit */
#include <unistd.h> 
#include <libgen.h>   /* basename */
#include "base64.h"

#include <curl/curl.h> // Include the libcurl header
#include <coap3/coap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>      // For getaddrinfo, gai_strerror
#include <arpa/inet.h>
#include <unistd.h>     // For close()
#include <errno.h>      // For errno

#define SUCCESS 0
#define ERROR_INVALID_SIGNATURE 1
#define ERROR_INVALID_PROOF 2
#define ERROR_INVALID_MANIFEST 3
#define ERROR_NET 4
#define ERROR_MEM 5
#define ERROR_SBOM_VALIDATION_FAILED 6 // New error code for SBOM
#define ERROR_SYSTEM 7 // System error (e.g. file operations)
#define ERROR_PROOF_VALIDATION_FAILED 8 // New error code for Proof validation

// --- Error Codes (Example) --- TODO harmonize with the above
#define SUIT_ERR_OK                   0
#define SUIT_ERR_FETCH               -1
#define SUIT_ERR_MEMORY              -2
#define SUIT_ERR_UNSUPPORTED_SCHEME  -3
#define SUIT_ERR_NOT_IMPLEMENTED     -4
#define SUIT_ERR_SIZE_MISMATCH       -5 // Added for size check
#define SUIT_ERR_URI_PARSE           -6
#define SUIT_ERR_DNS_RESOLVE         -7
#define SUIT_ERR_COAP_CLIENT         -8
#define SUIT_ERR_TIMEOUT             -9
#define SUIT_ERR_SOCKET              -10 // Though libcoap handles sockets internally

// Constants for CoAP fetch
#define MAX_COAP_URI_HOST_LEN 256
#define MAX_COAP_URI_PATH_LEN 256 // Used for path buffer
#define COAP_FETCH_TOTAL_TIMEOUT_S 30
#define COAP_IO_PROCESS_TIMEOUT_MS 1000

// Payload Accumulator Structure (same as before)
typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
    int completed;
    coap_pdu_code_t error_code;
} coap_payload_accumulator_t;

const uint8_t vendor_id[16] = {
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe
};
const uint8_t class_id[16] = {
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45
};

// Store the SBOM extracted from the SUIT manifest
uint8_t *update_SBOM = NULL;
size_t update_SBOM_size = 0;

// Store the update image extracted from the SUIT manifest
uint8_t *update_image = NULL;
size_t update_image_size = 0;

// Store the property IDs and their locality constraints extracted from the Certification Manifest
property_uuid_t *property_ids = NULL;
size_t property_ids_count = 0;
size_t property_ids_size = 0;

// Default public key (hardcoded one used for examples)
const uint8_t default_public_key[] = {
    0x04, 0x07, 0x30, 0xc9, 0xc4, 0xae, 0x4b, 0x76, 0x7a, 0xb6, 
    0x9c, 0x4b, 0xab, 0xac, 0x00, 0x85, 0x8d, 0x07, 0x52, 0x90, 
    0x2a, 0xcb, 0x52, 0x33, 0x75, 0x1b, 0x92, 0xfe, 0x38, 0xe9, 
    0xdb, 0x32, 0xd9, 0xd4, 0x8b, 0xcd, 0x61, 0x7b, 0x6c, 0x45, 
    0x9f, 0xc1, 0xa0, 0x89, 0xc7, 0x7f, 0xcd, 0x60, 0x6d, 0x6c, 
    0x02, 0x8c, 0x0c, 0xce, 0x04, 0xc8, 0xef, 0x42, 0x5a, 0xe7, 
    0x3f, 0x38, 0xa8, 0x89, 0x8d
};
const size_t default_public_key_size = sizeof(default_public_key);

// Dynamic key that can be loaded from PEM
uint8_t *dynamic_public_key = NULL;
size_t dynamic_public_key_size = 0;

// Get the active public key (dynamic or default)
const uint8_t *get_active_public_key(size_t *size) {
    if (dynamic_public_key != NULL) {
        *size = dynamic_public_key_size;
        return dynamic_public_key;
    } else { 
        *size = default_public_key_size;
        return default_public_key;
    }
}

// Load a public key from a PEM file
int load_public_key_from_pem(const char *pem_file) {
    FILE *f = fopen(pem_file, "r");
    if (f == NULL) {
        perror("Failed to open PEM file");
        return -1;
    }
    
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    int ret = mbedtls_pk_parse_public_keyfile(&pk, pem_file);
    if (ret != 0) {
        char error_buf[200];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        printf("Failed to parse public key: %s\n", error_buf);
        fclose(f);
        mbedtls_pk_free(&pk);
        return -1;
    }
    
    // Make sure it's an EC key
    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) {
        printf("The provided key is not an EC key\n");
        fclose(f);
        mbedtls_pk_free(&pk);
        return -1;
    }
    
    // Extract the raw EC public key
    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
    
    // Allocate memory for the key
    size_t key_len;
    ret = mbedtls_ecp_point_write_binary(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, &key_len, NULL, 0);
    
    // Free any previously loaded key
    if (dynamic_public_key != NULL) {
        free(dynamic_public_key);
        dynamic_public_key = NULL;
        dynamic_public_key_size = 0;
    }
    
    dynamic_public_key = malloc(key_len);
    if (dynamic_public_key == NULL) {
        printf("Failed to allocate memory for public key\n");
        fclose(f);
        mbedtls_pk_free(&pk);
        return -1;
    }
    
    ret = mbedtls_ecp_point_write_binary(&ec->MBEDTLS_PRIVATE(grp), &ec->MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED, &dynamic_public_key_size, 
                                         dynamic_public_key, key_len);
    
    fclose(f);
    mbedtls_pk_free(&pk);
    
    if (ret != 0) {
        printf("Failed to extract EC public key\n");
        free(dynamic_public_key);
        dynamic_public_key = NULL;
        dynamic_public_key_size = 0;
        return -1;
    }
    
    printf("Successfully loaded EC public key (%zu bytes)\n", dynamic_public_key_size);
    return 0;
}

// Add function to clean up resources
void cleanup_resources() {
    // Clean up public key
    if (dynamic_public_key != NULL) {
        free(dynamic_public_key);
        dynamic_public_key = NULL;
        dynamic_public_key_size = 0;
    }

    // Clean up SBOM
    if (update_SBOM != NULL) {
        free(update_SBOM);
        update_SBOM = NULL;
        update_SBOM_size = 0;
    }

    // Free property_ids
    if (property_ids != NULL) {
        free(property_ids);
        property_ids = NULL;
        property_ids_count = 0;
        property_ids_size = 0;
    }    
}

void compute_sha256(uint8_t *hash, const uint8_t *msg, size_t msg_len) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, msg, msg_len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
}

// Print property ids 
void print_property_ids() {
    printf("Property IDs: ");
    for (size_t i = 0; i < property_ids_count; i++) {
        for (size_t j = 0; j < UUID_SIZE; j++) {
            printf("%02x", property_ids[i].bytes[j]);
        }
        printf(" ");
    }
    printf("\n");
}

// --- SBOM Verifier ---
#define SBOM_VERIFIER_URL "http://sbomverifier.com:8000/verify-sbom"
#define PROOF_VERIFIER_URL "http://sbomverifier.com:8001/verify-proof"

// Structure for libcurl response for SBOM verifier
struct MemoryStructForResponse {
    char *memory;
    size_t size;
};

int verify_server_response(const char *response, size_t response_size, const uint8_t *expected_hash, char **decoded_payload_out) {

    int ret_val = ERROR_INVALID_MANIFEST;

    char *payload_b64 = NULL;
    char *sig_b64 = NULL;
    const char *pstart = response + 1; // exclude starting quote
    char *pend = strchr(pstart, '.');
    if (!pend) {
        fprintf(stderr, "ERROR: SBOM verifier response format invalid (missing signature part). Response: %s\n", response);
        return ERROR_INVALID_MANIFEST;
    } else {
        payload_b64 = strndup(pstart, pend - pstart); // Exclude the dot

        char *sstart = pend + 1;
        sig_b64 = strdup(sstart);
        sig_b64[strcspn(sig_b64, "\"")] = '\0'; // Exclude trailing quote

        printf("Extracted payload (base64): %s\n", payload_b64);
        printf("Extracted signature (base64): %s\n", sig_b64);

        uint8_t *payload_dec;
        uint8_t *sig_dec;
        if (payload_b64 && sig_b64) {
            // Decode payload and signature using mbedtls_base64_decode (gives lengths)
            size_t payload_b64_len = strlen(payload_b64);
            size_t payload_max = payload_b64_len * 3 / 4 + 4;
            payload_dec = malloc(payload_max + 1);
            size_t payload_len = 0;
            int bret = mbedtls_base64_decode(payload_dec, payload_max, &payload_len, (const unsigned char*)payload_b64, payload_b64_len);
            if (bret != 0) {
                char errbuf[200];
                mbedtls_strerror(bret, errbuf, sizeof(errbuf));
                fprintf(stderr, "ERROR: Failed to base64-decode payload: %s\n", errbuf);
                free(payload_dec);
                free(payload_b64);
                free(sig_b64);
                ret_val = ERROR_INVALID_MANIFEST;
            } else {
                payload_dec[payload_len] = '\0'; // Null-terminate in case it's textual JSON

                size_t sig_b64_len = strlen(sig_b64);
                size_t sig_max = sig_b64_len * 3 / 4 + 4;
                sig_dec = malloc(sig_max);
                size_t sig_len = 0;
                bret = mbedtls_base64_decode(sig_dec, sig_max, &sig_len, (const unsigned char*)sig_b64, sig_b64_len);
                if (bret != 0) {
                    char errbuf[200];
                    mbedtls_strerror(bret, errbuf, sizeof(errbuf));
                    fprintf(stderr, "ERROR: Failed to base64-decode signature: %s\n", errbuf);
                    free(payload_dec);
                    free(sig_dec);
                    free(payload_b64);
                    free(sig_b64);
                    ret_val = ERROR_INVALID_SIGNATURE;
                } else {
                    // Compute SHA-256 over decoded payload
                    uint8_t hash[32];
                    compute_sha256(hash, payload_dec, payload_len);

                    // Load RSA public key from PEM file (expected at keys/rsa_public.pem)
                    mbedtls_pk_context pk;
                    mbedtls_pk_init(&pk);
                    int pret = mbedtls_pk_parse_public_keyfile(&pk, "keys/rsa_public.pem");
                    if (pret != 0) {
                        char errbuf[200];
                        mbedtls_strerror(pret, errbuf, sizeof(errbuf));
                        fprintf(stderr, "ERROR: Failed to parse RSA public key (keys/rsa_public.pem): %s\n", errbuf);
                        ret_val = ERROR_INVALID_SIGNATURE;
                    } else {
                        // Verify signature. Server signs using RSA-PSS (Python: padding.PSS + MGF1(SHA256)).
                        // Use mbedtls_pk_verify_ext with RSASSA-PSS options. Fall back to PKCS#1 v1.5 if needed.
                        int pss_ret = MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
                        mbedtls_pk_rsassa_pss_options pss_opts;
                        pss_opts.MBEDTLS_PRIVATE(mgf1_hash_id) = MBEDTLS_MD_SHA256;
                        pss_opts.MBEDTLS_PRIVATE(expected_salt_len) = MBEDTLS_RSA_SALT_LEN_ANY; // accept any salt (matches PSS.MAX_LENGTH behavior)

                        pss_ret = mbedtls_pk_verify_ext(MBEDTLS_PK_RSASSA_PSS, &pss_opts, &pk,
                                                    MBEDTLS_MD_SHA256, hash, sizeof(hash),
                                                    sig_dec, sig_len);

                        if (pss_ret == 0) {
                            printf("RSA-PSS signature verified successfully.\n");
                            if (memcmp(payload_dec, expected_hash, 32) != 0) {
                                fprintf(stderr, "ERROR: Payload hash does not match expected hash.\n");
                                ret_val = ERROR_INVALID_MANIFEST;
                            } else {
                                *decoded_payload_out = payload_dec + 32; // Return decoded payload
                                ret_val = SUCCESS;
                            }
                        }
                    }
                    mbedtls_pk_free(&pk);
                }
            }
        } else {
            fprintf(stderr, "ERROR: response missing 'payload' or 'signature' fields. Response: %s\n", response);
            if (payload_b64) free(payload_b64);
            if (sig_b64) free(sig_b64);
            ret_val = ERROR_INVALID_MANIFEST;
        }

        // Free decoded buffers and base64 strings now that parsing is done
        if (payload_b64) { free(payload_b64); payload_b64 = NULL; }
        if (sig_b64) { free(sig_b64); sig_b64 = NULL; }
        if (sig_dec) { free(sig_dec); sig_dec = NULL; }
    }

    return ret_val;
}

static size_t WriteMemoryCallbackForSBOMResponse(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStructForResponse *mem = (struct MemoryStructForResponse *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        fprintf(stderr, "ERROR: Not enough memory (realloc returned NULL) for SBOM response\n");
        return 0; // Signal error to libcurl
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0'; // Null-terminate

    return realsize;
}

// Function to send SBOM to the verifier server
int send_sbom_to_verifier(const uint8_t *base64_sbom_data, size_t base64_sbom_size) {
    if (base64_sbom_data == NULL || base64_sbom_size == 0) {
        printf("No Base64 SBOM data to send for verification.\n");
        return SUCCESS; // Or an error if SBOM is mandatory for validation
    }

    // Step 2: Decode the Base64 SBOM
    size_t decoded_max_size = base64_sbom_size * 3 / 4 + 4; // Approximate size after base64 decoding
    uint8_t *decoded = (uint8_t *)malloc(decoded_max_size);
    size_t decoded_size = 0;
    int bret = mbedtls_base64_decode(decoded, decoded_max_size, &decoded_size, base64_sbom_data, base64_sbom_size);
    if (bret != 0) {
        char errbuf[200];
        mbedtls_strerror(bret, errbuf, sizeof(errbuf));
        printf("Failed to decode SBOM from base64: %s\n", errbuf);
        free(decoded);
        return ERROR_INVALID_MANIFEST;
    }

    uint8_t sbom_sha256[32];
    compute_sha256(sbom_sha256, decoded, decoded_size);

    CURL *curl;
    CURLcode res_curl;
    int ret_val = ERROR_NET; // Default to network/fetch error

    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    struct curl_slist *headerlist = NULL;
    static const char expect_buf[] = "Expect:"; // To disable Expect: 100-continue

    struct MemoryStructForResponse chunk;
    chunk.memory = malloc(1); // Will be grown by realloc in callback
    chunk.size = 0;

    if (chunk.memory == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate initial memory for SBOM verifier response.\n");
        free(decoded);
        return ERROR_MEM;
    }

    // curl_global_init should ideally be called once per program.
    // Calling it here for simplicity makes the function self-contained.
    // If this function is called many times, move curl_global_init/cleanup outside.
    curl_global_init(CURL_GLOBAL_ALL);

    // Prepare multipart form data
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "file",              // Name of the form field
                 CURLFORM_BUFFER, "sbom_file",          // "filename" for the server
                 CURLFORM_BUFFERPTR, decoded,
                 CURLFORM_BUFFERLENGTH, decoded_size, // Use the (approximated) actual decoded length
                 CURLFORM_END);

    curl = curl_easy_init();
    if (curl) {
        headerlist = curl_slist_append(headerlist, expect_buf);

        curl_easy_setopt(curl, CURLOPT_URL, SBOM_VERIFIER_URL);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist); // Optional: if suppressing Expect
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallbackForSBOMResponse);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "suit-client/1.0-sbom");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45L); // 45 seconds timeout for SBOM verification
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); // Set to 1L for curl debug output

        printf("Sending SBOM to: %s\n", SBOM_VERIFIER_URL);
        res_curl = curl_easy_perform(curl);

        if (res_curl != CURLE_OK) {
            fprintf(stderr, "ERROR: SBOM verification curl_easy_perform() failed: %s\n", curl_easy_strerror(res_curl));
            ret_val = ERROR_NET;
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("SBOM Verifier Response - HTTP Code: %ld\n", http_code);
            printf("SBOM Verifier Response - Body: %s\n", chunk.memory ? chunk.memory : "[empty]");

            if (http_code == 200 && chunk.memory) {
                // Basic JSON parsing
                // Expected response format:
                // base64_encoded_payload.base64_encoded_signature
                
                char *payload_str = NULL;

                int signature_verification_status = verify_server_response(chunk.memory, chunk.size, sbom_sha256, &payload_str);

                if (signature_verification_status != SUCCESS) {
                    fprintf(stderr, "ERROR: SBOM verifier response signature verification failed.\n");
                    ret_val = ERROR_SBOM_VALIDATION_FAILED;
                } else {

                    // The base64_encoded_payload contains binary fields:
                    // success: (byte) 1 | (uint32_t) vulnerability_count
                    // error: (byte) 0 | (string) error_message

                    uint8_t status = (uint8_t)(*payload_str);

                    if (status) {

                        uint32_t vulnerability_count = (uint32_t)(*(uint32_t *)(payload_str + 1));
                        
                        if (vulnerability_count == 0) {
                            ret_val = SUCCESS;
                            printf("SBOM successfully verified with 0 vulnerabilities. ✅\n");
                        } else if (vulnerability_count > 0) {
                            fprintf(stderr, "ERROR: SBOM verification found %d vulnerabilities. ⚠️\n", vulnerability_count);
                            ret_val = ERROR_SBOM_VALIDATION_FAILED;
                        }

                    } else {
                        char *error_message = payload_str + 1;
                        fprintf(stderr, "ERROR: SBOM verification failed. Server error message: %s\n", error_message);
                        ret_val = ERROR_SBOM_VALIDATION_FAILED;
                    }
                    
                    if (payload_str) { free(payload_str); payload_str = NULL; }
                }
            } else {
                 fprintf(stderr, "ERROR: SBOM verification failed with HTTP code %ld or no response body. 🌐💥\n", http_code);
                 ret_val = ERROR_NET; // Or map specific HTTP errors
            }
        }

        curl_easy_cleanup(curl);
        curl_formfree(formpost); // Clean up the formpost chain
        curl_slist_free_all(headerlist); // Clean up the header list
    } else {
        fprintf(stderr, "ERROR: curl_easy_init() failed for SBOM verification.\n");
        // ret_val is already ERROR_NET or could be ERROR_MEM
    }

    curl_global_cleanup(); // Counterpart to curl_global_init
    if (chunk.memory) free(chunk.memory);
    free(decoded); // Free the buffer allocated by base64_decode

    return ret_val;
}

int send_proof_to_verifier(const uint8_t *proof_data, size_t proof_size) {
    // printf("Sending %zu bytes of proof data to verifier.\n", proof_size);
    // for(int i = 0; i < proof_size; i++) {
    //     printf("%c", proof_data[i]);
    // }
    // printf("\n");

    if (proof_data == NULL || proof_size == 0) {
        printf("No proof data to send for verification.\n");
        return ERROR_INVALID_PROOF;
    }

    uint8_t proof_sha256[32];
    compute_sha256(proof_sha256, proof_data, proof_size);

    CURL *curl;
    CURLcode res_curl;
    int ret_val = ERROR_NET; // Default to network/fetch error

    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    struct curl_slist *headerlist = NULL;
    static const char expect_buf[] = "Expect:"; // To disable Expect: 100-continue

    struct MemoryStructForResponse chunk;
    chunk.memory = malloc(1); // Will be grown by realloc in callback
    chunk.size = 0;

    if (chunk.memory == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate initial memory for Proof verifier response.\n");
        return ERROR_MEM;
    }

    // curl_global_init should ideally be called once per program.
    // Calling it here for simplicity makes the function self-contained.
    // If this function is called many times, move curl_global_init/cleanup outside.
    curl_global_init(CURL_GLOBAL_ALL);

    // Prepare multipart form data
    curl_formadd(&formpost, &lastptr,
                 CURLFORM_COPYNAME, "file",              // Name of the form field
                 CURLFORM_BUFFER, "proof_file",          // "filename" for the server
                 CURLFORM_BUFFERPTR, proof_data,
                 CURLFORM_BUFFERLENGTH, proof_size, // Use the (approximated) actual decoded length
                 CURLFORM_END);

    curl = curl_easy_init();
    if (curl) {
        headerlist = curl_slist_append(headerlist, expect_buf);

        curl_easy_setopt(curl, CURLOPT_URL, PROOF_VERIFIER_URL);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist); // Optional: if suppressing Expect
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallbackForSBOMResponse);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "suit-client/1.0-proof");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45L); // 45 seconds timeout for SBOM verification
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L); // Set to 1L for curl debug output

        printf("Sending Proof to: %s\n", PROOF_VERIFIER_URL);
        res_curl = curl_easy_perform(curl);

        if (res_curl != CURLE_OK) {
            fprintf(stderr, "ERROR: Proof verification curl_easy_perform() failed: %s\n", curl_easy_strerror(res_curl));
            ret_val = ERROR_NET;
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            printf("Proof Verifier Response - HTTP Code: %ld\n", http_code);
            printf("Proof Verifier Response - Body: %s\n", chunk.memory ? chunk.memory : "[empty]");

            if (http_code == 200 && chunk.memory) {
                // Basic JSON parsing
                // Expected response format:
                // base64_encoded_payload.base64_encoded_signature
                
                char *payload_str = NULL;

                int signature_verification_status = verify_server_response(chunk.memory, chunk.size, proof_sha256, &payload_str);

                if (signature_verification_status != SUCCESS) {
                    fprintf(stderr, "ERROR: Proof verifier response signature verification failed.\n");
                    ret_val = ERROR_PROOF_VALIDATION_FAILED;
                } else {

                    // The base64_encoded_payload contains binary fields:
                    // success: (byte) 1
                    // error: (byte) 0 | (string) error_message

                    uint8_t status = (uint8_t)(*payload_str);

                    if (status) {

                        printf("Proof successfully verified. ✅\n");
                        ret_val = SUCCESS;

                    } else {
                        char *error_message = payload_str + 1;
                        fprintf(stderr, "ERROR: Proof verification failed. Server error message: %s\n", error_message);
                        ret_val = ERROR_PROOF_VALIDATION_FAILED;
                    }
                    
                    if (payload_str) { free(payload_str); payload_str = NULL; }
                }
            } else {
                 fprintf(stderr, "ERROR: Proof verification failed with HTTP code %ld or no response body. 🌐💥\n", http_code);
                 ret_val = ERROR_NET; // Or map specific HTTP errors
            }
        }

        curl_easy_cleanup(curl);
        curl_formfree(formpost); // Clean up the formpost chain
        curl_slist_free_all(headerlist); // Clean up the header list
    } else {
        fprintf(stderr, "ERROR: curl_easy_init() failed for Proof verification.\n");
        // ret_val is already ERROR_NET or could be ERROR_MEM
    }

    curl_global_cleanup(); // Counterpart to curl_global_init
    if (chunk.memory) free(chunk.memory);

    return ret_val;
}


// TA API to validate the manifest and the proofs inside it
// The proofs are validated either on the device or on the server, based on the locality constraint
uint8_t TA_CROSSCON_VALIDATE_MANIFEST(const uint8_t *manifest, size_t manifest_size) {
    int rc = suit_do_process_manifest(manifest, manifest_size);

    // Check if there was an error during parsing
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_err_info_t *err = bm_cbor_get_err_info();
        printf("bm_cbor_err_info raw data:\n");
        printf("Error occured at: %p\n", err->ptr);
        printf("Error code: %d\n", err->cbor_err);
        if (err->cbor_err < 0) {
            char buf[64];
            //mbedtls_strerror(err->cbor_err,buf, sizeof(buf));
            printf("mbedtls error: %s\n", buf);
        }
        printf("Source File Name: %s\n", err->file);
        printf("Source Line Number: %lu\n", (unsigned long) err->line);
        printf("----------------\n");
        intptr_t offset = (intptr_t)err->ptr - (intptr_t)manifest;
        printf("Manifest offset: %ld\n", offset);

        if (rc == CBOR_ERR_KEY_MISMATCH) {
            return ERROR_INVALID_SIGNATURE;
        } else {
            return ERROR_INVALID_MANIFEST;
        }
    } 

    printf("update_SBOM: %p, size: %zu\n", update_SBOM, update_SBOM_size);
    // SBOM validation
    // update_SBOM and update_SBOM_size are global and should be populated by suit_do_process_manifest
    if (update_SBOM != NULL && update_SBOM_size > 0) {
        printf("INFO: Base64 encoded SBOM found in manifest (size: %zu bytes).\n", update_SBOM_size);
        printf("INFO: Proceeding with SBOM verification via server.\n");

        int sbom_verification_status = send_sbom_to_verifier(update_SBOM, update_SBOM_size);

        if (sbom_verification_status != SUCCESS) {
            fprintf(stderr, "ERROR: SBOM verification failed with code %d.\n", sbom_verification_status);
            // Note: update_SBOM (global) should be managed by cleanup_resources or subsequent manifest processing.
            // send_sbom_to_verifier frees its internal allocations.
            return ERROR_SBOM_VALIDATION_FAILED;
        }
        printf("INFO: SBOM verification successful.\n");
    } else {
        printf("INFO: No SBOM found in manifest, or SBOM size is zero. Skipping server verification.\n");
        // Depending on policy, this could be an error. For now, it's a notice.
    }

    // Verify the proofs 
    for (size_t i = 0; i < property_ids_count; i++) {
        // Check the locality constraint
        // Build the filename starting from the property ID: file name start is on path out/proofs/
        char filename[100];
        size_t offset = snprintf(filename, sizeof(filename), "out/proofs/");
        for (size_t j = 0; j < UUID_SIZE; j++) {
            offset += snprintf(filename + offset, sizeof(filename) - offset, "%02x", property_ids[i].bytes[j]);
        }
        offset += snprintf(filename + offset, sizeof(filename) - offset, ".cpc.gz");
        printf("Proof Certificate Filename: %s\n", filename);

        // Load the proof certificate
        FILE *f = fopen(filename, "rb");
        if (f == NULL) {
            printf("Failed to open proof certificate file\n");
            return ERROR_INVALID_PROOF;
        }

        // Read the proof certificate
        fseek(f, 0, SEEK_END);
        size_t proof_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *proof = malloc(proof_size);
        if (proof == NULL) {
            printf("Failed to allocate memory for proof certificate\n");
            fclose(f);
            return ERROR_INVALID_PROOF;
        }
        size_t read = fread(proof, 1, proof_size, f);
        fclose(f);

        if (read != proof_size) {
            printf("Failed to read proof certificate\n");
            free(proof);
            return ERROR_INVALID_PROOF;
        }

        size_t decoded_max_size = proof_size * 3 / 4 + 4; // Approximate size after base64 decoding
        uint8_t *decoded = (uint8_t *)malloc(decoded_max_size);
        size_t decoded_size = 0;
        int bret = mbedtls_base64_decode(decoded, decoded_max_size, &decoded_size, proof, proof_size);
        if (bret != 0) {
            char errbuf[200];
            mbedtls_strerror(bret, errbuf, sizeof(errbuf));
            printf("Failed to decode proof certificate from base64: %s\n", errbuf);
            free(proof);
            free(decoded);
            return ERROR_INVALID_PROOF;
        }

        if (property_ids[i].locality_constraint == 1) {
            printf("Verification of the proof on device\n");

            // Decode the proof certificate from base64 and write it to the same file
            f = fopen(filename, "wb");
            fwrite(decoded, decoded_size, 1, f);
            fclose(f);
                        
            // Free the proof memory as we've written it to file
            free(proof);

            // Unzip the proof certificate
            char command[300];
            char uncompressed_filename[200];
            const char *last_slash = strrchr(filename, '/');
            const char *base_name = (last_slash != NULL) ? last_slash + 1 : filename;
            snprintf(uncompressed_filename, sizeof(uncompressed_filename), "../ethos/%.*s", (int)(strlen(base_name) - 3), base_name);
            snprintf(command, sizeof(command), "gunzip -c %s > %s", filename, uncompressed_filename);
            printf("Unzipping proof certificate\n");
            int status = system(command);
            if (status != 0) {
                perror("Error unzipping proof certificate");
                free(decoded);
                return ERROR_INVALID_PROOF;
            }

            // Verify the proof certificate
            char verification_command[500];
            snprintf(verification_command, sizeof(verification_command), "../ethos/ethos_check.sh %s", uncompressed_filename);
            printf("Verifying proof certificate with command: %s\n", verification_command);
            // Execute the command to invoke the proof check (ethos) when the locality constraint is 1
            status = system(verification_command);
            printf("Verification status: %d\n", status);
            if (status == 0) {
                printf("Proof certificate verified successfully\n");
            } else {
                printf("Proof certificate verification failed -- skipped!! --\n");
                free(decoded);
                return ERROR_INVALID_PROOF;
            }
        } else {
            printf("Verification of the proof on server\n");

            int proof_verification_status = send_proof_to_verifier(decoded, decoded_size);

            if (proof_verification_status != SUCCESS) {
                fprintf(stderr, "ERROR: Proof verification failed with code %d.\n", proof_verification_status);
                free(decoded);
                return ERROR_INVALID_PROOF;
            }
            printf("INFO: Proof verification successful.\n");
        }
        free(decoded);
    }

    return SUCCESS;
}

// TA API to extract the SBOM from the manifest
uint8_t *TA_CROSSCON_GET_SBOM(const uint8_t *manifest, size_t manifest_size) {

    int rc = suit_do_process_manifest(manifest, manifest_size);  

    if (rc != CBOR_ERR_NONE) {
        bm_cbor_err_info_t *err = bm_cbor_get_err_info();
        printf("bm_cbor_err_info raw data:\n");
        printf("Error occured at: %p\n", err->ptr);
        printf("Error code: %d\n", err->cbor_err);
        if (err->cbor_err < 0) {
            char buf[64];
            //mbedtls_strerror(err->cbor_err,buf, sizeof(buf));
            printf("mbedtls error: %s\n", buf);
        }
        printf("Source File Name: %s\n", err->file);
        printf("Source Line Number: %lu\n", (unsigned long) err->line);
        printf("----------------\n");
        intptr_t offset = (intptr_t)err->ptr - (intptr_t)manifest;
        printf("Manifest offset: %ld\n", offset);
        return NULL;
    }

    //printf("SBOM content: %s\n", update_SBOM);

    // Decode the SBOM from base64, if present
    if (update_SBOM != NULL) {
        uint8_t *decoded = base64_decode(update_SBOM);
        if (decoded == NULL) {
            printf("Failed to decode SBOM\n");
            return NULL;
        }

        return decoded;
    } else {
        return NULL;
    }
}

// TA API to extract the image from the manifest
uint8_t TA_CROSSCON_GET_IMAGE(const uint8_t *manifest, size_t manifest_size, uint8_t **image, size_t *image_size) {

    int rc = suit_do_process_manifest(manifest, manifest_size);

    if (rc != CBOR_ERR_NONE) {
        printf("Error during parsing.\n");
        return ERROR_INVALID_MANIFEST;
    }

    if (update_image == NULL) {
        printf("No image available.\n");
        return ERROR_NET;
    }

    *image = update_image;
    *image_size = update_image_size;

    return SUCCESS;

}

// TA API to install the image
uint8_t TA_CROSSCON_INSTALL_IMAGE(const uint8_t *image, size_t image_size) {

    // Install the updated OP-TEE OS image
    printf("Installing image of size %zu bytes\n", image_size);

    FILE *bl_file = fopen("/boot/bl31-bl32.bin", "wb");
    if (bl_file == NULL) {
        printf("Failed to open bootloader file for writing, is the boot partition mounted?\n");
        return ERROR_SYSTEM;
    }

    // Move to 128KB offset
    fseek(bl_file, 128 * 1024, SEEK_SET);
    size_t written = fwrite(image, 1, image_size, bl_file);
    fclose(bl_file);

    if (written != image_size) {
        printf("Failed to write the complete image to bootloader file\n");
        return ERROR_SYSTEM;
    }

    return SUCCESS;
}

// TA API to update the image. It should be atomic in order to avoid TOCTOU attacks
uint8_t TA_CROSSCON_UPDATE(const uint8_t *manifest, size_t manifest_size) {

    // perform manifest, sbom and proof validation
    int rc = TA_CROSSCON_VALIDATE_MANIFEST(manifest, manifest_size);

    // Exit early if there was an error processing the manifest
    if (rc != CBOR_ERR_NONE) {
        printf("Update failed with erorr code: %d\n",rc);
        return ERROR_INVALID_MANIFEST;
    }

    if (update_image == NULL) {
        printf("No image available.\n");
        return ERROR_NET;
    }

    // TODO: remove this temporary installation step and call TA_CROSSCON_INSTALL_IMAGE instead
    rc = TA_CROSSCON_INSTALL_IMAGE(update_image, update_image_size);
    if (rc != SUCCESS) {
        printf("Image installation failed with error code: %d\n", rc);
        return rc;
    }
    printf("Image installed successfully.\n");
    // Free the allocated memory for the image
    free(update_image);

    return SUCCESS;
}

// TA API to extract the properties from the manifest and return them as strings
size_t TA_CROSSCON_GET_PROPERTIES(const uint8_t *manifest, size_t manifest_size, char** properties) {
    int rc = suit_do_process_manifest(manifest, manifest_size);
    
    // Exit early if there was an error processing the manifest
    if (rc != CBOR_ERR_NONE) {
        return ERROR_INVALID_MANIFEST;
    }
    
    // Process each property ID and convert it to a string
    for (size_t i = 0; i < property_ids_count && properties != NULL; i++) {
        // Allocate memory for the string representation (2 chars per byte + null terminator)
        properties[i] = (char*)malloc(UUID_SIZE * 2 + 1);
        if (properties[i] == NULL) {
            // Handle memory allocation failure
            fprintf(stderr, "Failed to allocate memory for property ID string\n");
            
            // Free previously allocated strings
            for (size_t j = 0; j < i; j++) {
                free(properties[j]);
                properties[j] = NULL;
            }
            return 0;
        }
        
        // Convert the binary UUID to a hex string
        for (size_t j = 0; j < UUID_SIZE; j++) {
            sprintf(&properties[i][j*2], "%02x", property_ids[i].bytes[j]);
        }
        properties[i][UUID_SIZE * 2] = '\0'; // Ensure null termination
    }
    
    // For debugging: print out what we've stored
    printf("Stored %zu property IDs in string array\n", property_ids_count);
    
    return property_ids_count;
}

void s_print(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%c", p[i]);
    }
}
void x_print(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}

int mbedtls_md_helper(
    const uint8_t *msg, size_t msg_len,
    uint8_t *hash, mbedtls_md_type_t mdtype)
{
    int ret = 0;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(mdtype), 0);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    ret = mbedtls_md_starts(&md_ctx);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    ret = mbedtls_md_update(&md_ctx, msg, msg_len);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    ret = mbedtls_md_finish(&md_ctx, hash);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    return ret;
}

int mbedtls_ecdsa_helper(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *pub, size_t pub_len,
                mbedtls_ecp_group_id grpid,
                mbedtls_md_type_t mdtype)
{
    uint8_t hash[64] = {0};
    int ret = mbedtls_md_helper(msg, msg_len, hash, mdtype);
    mbedtls_ecdsa_context ctx_verify;
    mbedtls_ecdsa_init( &ctx_verify );
    ret = mbedtls_ecp_group_load( &ctx_verify.MBEDTLS_PRIVATE(grp), grpid);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    //printf("pub_len: %d\n", pub_len);
    ret = mbedtls_ecp_point_read_binary( &ctx_verify.MBEDTLS_PRIVATE(grp), &ctx_verify.MBEDTLS_PRIVATE(Q), pub, pub_len);
    //printf("Ret: %d\n", ret);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);    
	ret = mbedtls_mpi_read_binary( &r, sig, sig_len / 2 );
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
	ret = mbedtls_mpi_read_binary( &s, sig + sig_len/2, sig_len / 2 );
	    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
	ret = mbedtls_ecdsa_verify(
        &ctx_verify.MBEDTLS_PRIVATE(grp),
        hash,
        mbedtls_md_get_size(mbedtls_md_info_from_type(mdtype)),
        &ctx_verify.MBEDTLS_PRIVATE(Q),
        &r,
        &s);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }

    return CBOR_ERR_NONE;
}

int ES256_verify(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *pub, size_t pub_len)
{
    return mbedtls_ecdsa_helper(
        msg, msg_len,
        sig, sig_len,
        pub, pub_len,
        MBEDTLS_ECP_DP_SECP256R1,
        MBEDTLS_MD_SHA256);
}

int COSEAuthVerify(
    const uint8_t *msg, size_t msg_len,
    const uint8_t *sig, size_t sig_len,
    const uint8_t *kid, size_t kid_len,                
    int alg)
{
    int rc;
    //TODO: Lookup public key by key-id
    size_t key_size;
    const uint8_t *key_data = get_active_public_key(&key_size);
    // Print the key and key size
    //printf("Key: ");
    //x_print(key_data, key_size);
    //printf("\n");
    //printf("Key Size: %zu\n", key_size);

    switch (alg) {
        case COSE_ES256:
            rc = ES256_verify(
                msg, msg_len,
                sig, sig_len,
                key_data, key_size);
            if (rc == CBOR_ERR_NONE) {
                printf("ES256 Signature Verified\n");
            } else {
                printf("ES256 Signature Verification Failed\n");
            }
            break;
        default:
            SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED, NULL);
            break;
    }
    return rc;
}

int mbedtls_md_verify_helper256(
    const uint8_t *msg, size_t msg_len,
    const uint8_t *exp, size_t exp_len,
    mbedtls_md_type_t mdtype)
{
    uint8_t hash[32];
    if (exp_len != 32) {
        RETURN_ERROR( SUIT_ERROR_DIGEST_MISMATCH, NULL);
    }
    int ret;
    ret = mbedtls_md_helper(msg, msg_len, hash, mdtype);

    if (0==memcmp(hash, exp, sizeof(hash))) {
        return CBOR_ERR_NONE;
    }
    else {
        RETURN_ERROR( SUIT_ERROR_DIGEST_MISMATCH, NULL);
    }

}
// int mbedtls_md_verify_helper512(
//     const uint8_t *msg, size_t msg_len,
//     const uint8_t *exp, size_t exp_len,
//     mbedtls_md_type_t mdtype)

int suit_platform_verify_digest(
    const uint8_t *data, size_t data_len,
    const uint8_t *exp, size_t exp_len,
    int alg)
{

    switch (alg) {
        // TODO: expected digest length.
        case SUIT_DIGEST_TYPE_SHA256:
            printf("Matching SHA256: ");
            x_print(exp,exp_len);
            printf("\n");
            return mbedtls_md_verify_helper256(data, data_len, exp, exp_len, MBEDTLS_MD_SHA256);
    }
    RETURN_ERROR(SUIT_ERROR_DIGEST_MISMATCH, NULL);
}

void print_component_id(uint8_t *cid, uint8_t* end) {

}

int suit_platform_get_image_ref(
    suit_reference_t *component_id,
    const uint8_t **image) {
    //TODO: open/create component_id with mmap
    return 0;
}


// Structure to hold data during curl download
struct MemoryStruct {
    uint8_t *memory;
    size_t size;
};

// libcurl write callback function (remains the same)
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    uint8_t *ptr = realloc(mem->memory, mem->size + realsize); // Allocate exact needed size
    if (ptr == NULL) {
        fprintf(stderr, "ERROR: Not enough memory (realloc returned NULL)\n");
        return 0; // Signal error to libcurl
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;

    return realsize;
}

// -----------------------------------------------------------------------------
// Helper function for fetching via HTTP/HTTPS using libcurl
// -----------------------------------------------------------------------------
static int fetch_http_image(const char *url, size_t expected_size, uint8_t **out_buffer, size_t *out_size) {
    CURL *curl_handle;
    CURLcode res;
    struct MemoryStruct chunk;
    int ret = SUIT_ERR_FETCH; // Default to generic fetch error

    *out_buffer = NULL;
    *out_size = 0;

    // Use calloc for zero-initialization, useful for buffer safety
    chunk.memory = calloc(1, 1); // Start with 1 byte, will grow
    if (chunk.memory == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate initial memory for HTTP download.\n");
        return SUIT_ERR_MEMORY;
    }
    chunk.size = 0;

    // Initialize libcurl session (assuming curl_global_init was called elsewhere)
    fprintf(stderr, "curl_easy_init\n");
    curl_handle = curl_easy_init();
    if (curl_handle) {
        fprintf(stderr, "curl_easy_setopt\n");
        curl_easy_setopt(curl_handle, CURLOPT_URL, url);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-suit-agent/1.0");
        curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L); // Fail on 4xx/5xx errors
        curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 60L);    // 60 seconds timeout
        curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 20L); // 20 seconds connection timeout

        // --- Security Warning ---
        // Disable SSL verification for example simplicity ONLY. DO NOT USE IN PRODUCTION.
        #ifndef PRODUCTION_BUILD
        fprintf(stderr, "WARNING: Disabling SSL/TLS certificate verification for fetch!\n");
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
        #else
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
        // Potentially set CURLOPT_CAINFO or CURLOPT_CAPATH here
        #endif
        // --- End Security Warning ---

        fprintf(stderr, "curl_easy_perform\n");
        res = curl_easy_perform(curl_handle);

        if (res != CURLE_OK) {
            fprintf(stderr, "ERROR: curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            ret = SUIT_ERR_FETCH;
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
            curl_easy_getinfo(curl_handle, CURLINFO_SIZE_DOWNLOAD_T, &chunk.size); // Get final size

            printf("  HTTP Fetch successful (Code: %ld). Downloaded %zu bytes.\n", http_code, chunk.size);

            if (expected_size > 0 && chunk.size != expected_size) {
                 fprintf(stderr, "WARNING: Downloaded size (%zu) does not match manifest size (%zu).\n", chunk.size, expected_size);
                 // Decide if this is a hard error or just a warning
                 // ret = SUIT_ERR_SIZE_MISMATCH; // Uncomment if size mismatch is fatal
            }

            // If no fatal error occurred yet, assign the output buffer
            if (ret == SUIT_ERR_FETCH) { // Check if it wasn't set to SIZE_MISMATCH already
                 *out_buffer = chunk.memory; // Transfer ownership
                 *out_size = chunk.size;
                 ret = SUIT_ERR_OK; // Success
                 chunk.memory = NULL; // Prevent double free by cleanup code below
            }
        }

        // Cleanup curl handle
        curl_easy_cleanup(curl_handle);
    } else {
        fprintf(stderr, "ERROR: curl_easy_init() failed.\n");
        ret = SUIT_ERR_FETCH;
    }

    // Free chunk memory ONLY if it wasn't transferred to out_buffer
    if (chunk.memory != NULL) {
        free(chunk.memory);
    }

    return ret;
}

static int append_payload(coap_payload_accumulator_t *acc, const uint8_t *chunk, size_t chunk_len) {
    if (acc->len + chunk_len > acc->capacity) {
        size_t new_capacity = (acc->capacity == 0) ? chunk_len + 256 : acc->capacity * 2; // Start with a bit more
        if (new_capacity < acc->len + chunk_len) {
            new_capacity = acc->len + chunk_len;
        }
        uint8_t *new_data = realloc(acc->data, new_capacity);
        if (!new_data) {
            fprintf(stderr, "ERROR: Failed to realloc for CoAP payload accumulation.\n");
            if(acc->data) free(acc->data); // Free old data if realloc fails
            acc->data = NULL; acc->len = 0; acc->capacity = 0;
            return 0;
        }
        acc->data = new_data;
        acc->capacity = new_capacity;
    }
    memcpy(acc->data + acc->len, chunk, chunk_len);
    acc->len += chunk_len;
    return 1;
}

// URI Parser (same as before)
static int parse_coap_url(const char *url, char *host, size_t host_len_max, uint16_t *port, char *path, size_t path_len_max) {
    const char *scheme_end;
    const char *host_start;
    const char *port_start;
    const char *path_start;

    if (strncmp(url, "coap://", 7) != 0) return SUIT_ERR_URI_PARSE;
    scheme_end = url + 7;
    host_start = scheme_end;

    path_start = strchr(host_start, '/');
    port_start = strchr(host_start, ':');

    const char *host_end;
    if (port_start && (!path_start || port_start < path_start)) {
        host_end = port_start;
    } else if (path_start) {
        host_end = path_start;
    } else {
        host_end = url + strlen(url);
    }

    size_t current_host_len = host_end - host_start;
    if (current_host_len >= host_len_max || current_host_len == 0) return SUIT_ERR_URI_PARSE;
    memcpy(host, host_start, current_host_len);
    host[current_host_len] = '\0';

    *port = COAP_DEFAULT_PORT;
    if (port_start && (!path_start || port_start < path_start)) {
        long p = strtol(port_start + 1, NULL, 10);
        if (p <= 0 || p > 65535) return SUIT_ERR_URI_PARSE;
        *port = (uint16_t)p;
    }

    if (path_start) {
        size_t current_path_len = strlen(path_start);
        if (current_path_len >= path_len_max) return SUIT_ERR_URI_PARSE; // Ensure space for null terminator
        strncpy(path, path_start, path_len_max -1);
        path[path_len_max-1] = '\0'; // Ensure null termination
    } else {
        if (path_len_max < 2) return SUIT_ERR_URI_PARSE;
        strcpy(path, "/");
    }
    return SUIT_ERR_OK;
}

// libcoap Response Handler (same as before, check coap_get_data_large behavior)
static coap_response_handler_t
coap_fetch_response_handler(coap_session_t *session,
                            const coap_pdu_t *sent_pdu,
                            const coap_pdu_t *received_pdu,
                            const coap_mid_t mid) {
    (void)sent_pdu; (void)mid;

    coap_payload_accumulator_t *acc = (coap_payload_accumulator_t *)coap_session_get_app_data(session);
    if (!acc) return COAP_RESPONSE_OK;

    coap_pdu_code_t rcv_code = coap_pdu_get_code(received_pdu);

    if (COAP_RESPONSE_CLASS(rcv_code) == 2) { // Success class
        size_t data_len = 0;
        const uint8_t *data_ptr = NULL;
        size_t offset = 0, total = 0; // For coap_get_data_large

        // coap_get_data_large is preferred for block-wise as it gives the full payload
        // once all blocks are received.
        if (coap_get_data_large(received_pdu, &data_len, &data_ptr, &offset, &total)) {
            if (data_len > 0) { // It's possible to get a 0-length final payload indication
                 if (!append_payload(acc, data_ptr, data_len)) {
                    acc->completed = -1;
                    acc->error_code = 0; // Internal memory error
                    return COAP_RESPONSE_OK;
                }
            }
            // If coap_get_data_large returns true, libcoap has handled the block assembly.
            // We need to know if this is THE final chunk.
            // The M bit in Block2 option of the *received_pdu* indicates if server has more.
            // If libcoap calls this handler with the very last block, M bit will be 0.
            coap_opt_iterator_t opt_iter;
            coap_opt_t *block_opt = coap_check_option(received_pdu, COAP_OPTION_BLOCK2, &opt_iter);
            if (block_opt) {
                unsigned int blk_val = coap_decode_var_bytes(coap_opt_value(block_opt), coap_opt_length(block_opt));
                if (! (blk_val & 0x08) ) { // M bit (is_more flag, 4th bit from LSB) is 0
                    acc->completed = 1; // All data received
                }
                // If M bit is 1, libcoap will fetch the next block. This handler might be called
                // for intermediate blocks too if not using specific coap_block_get_data functions.
                // However, with COAP_BLOCK_USE_LIBCOAP, this handler should ideally be called
                // when the *entire* resource is ready via coap_get_data_large, or for the very last block.
            } else {
                // No block2 option means it was not a blockwise transfer from server's perspective for this PDU.
                acc->completed = 1; // Transfer complete
            }
        } else {
            // coap_get_data_large returning false might mean it's an intermediate block
            // and the full payload isn't ready yet, or an error.
            // libcoap should transparently handle this, so this path might indicate
            // an issue if we expect coap_get_data_large to give the full data.
            // However, it's safer to check the M-bit if available.
            coap_opt_iterator_t opt_iter;
            coap_opt_t *block_opt = coap_check_option(received_pdu, COAP_OPTION_BLOCK2, &opt_iter);
            if (block_opt) {
                unsigned int blk_val = coap_decode_var_bytes(coap_opt_value(block_opt), coap_opt_length(block_opt));
                 if (! (blk_val & 0x08) ) { 
                    // Even if coap_get_data_large failed (e.g. no payload in this specific ack for a block)
                    // if M=0, the server says it's done.
                    acc->completed = 1; 
                }
            } else {
                 // No block option, and coap_get_data_large failed, assume completion or error.
                 // If there was no payload at all, might be an empty success response.
                 if (data_len == 0 && acc->len > 0) acc->completed = 1; // Already got data, now empty success.
                 else if (data_len == 0 && acc->len == 0) acc->completed = 1; // Empty success.
                 // else some other condition, might be an error not caught by class check.
            }
        }
    } else { // Error class
        fprintf(stderr, "  CoAP: Request failed with code %d\n",
                COAP_RESPONSE_CLASS(rcv_code));
        acc->completed = -1;
        acc->error_code = rcv_code;
    }
    return COAP_RESPONSE_OK;
}


// fetch_coap_image implementation using libcoap3
static int fetch_coap_image_libcoap(const char *url, size_t expected_size, uint8_t **out_buffer, size_t *out_size) {
    char host[MAX_COAP_URI_HOST_LEN];
    char path_for_options[MAX_COAP_URI_PATH_LEN]; // This buffer is filled by parse_coap_url
    uint16_t port_val;
    int ret = SUIT_ERR_FETCH;

    coap_context_t *ctx = NULL;
    coap_session_t *session = NULL;
    coap_address_t dst_addr;
    coap_pdu_t *pdu = NULL;
    coap_mid_t mid;
    // coap_addr_info_t *addr_info_list = NULL; // No longer needed with getaddrinfo directly

    coap_optlist_t *optlist_chain = NULL; // Moved here for broader scope if errors occur

    coap_payload_accumulator_t acc = {0,0,0,0,0};
    *out_buffer = NULL; *out_size = 0;

    // ... (startup logging, parse_coap_url, getaddrinfo for dst_addr - same as before) ...
    // Make sure parse_coap_url correctly fills path_for_options.
    // The getaddrinfo block should correctly fill dst_addr.

    if (parse_coap_url(url, host, sizeof(host), &port_val, path_for_options, sizeof(path_for_options)) != SUIT_ERR_OK) {
        return SUIT_ERR_URI_PARSE;
    }
    printf("  CoAP (libcoap3) Fetch: Host='%s', Port=%u, Path='%s'\n", host, port_val, path_for_options);

    // --- Address Resolution using getaddrinfo (from previous correct version) ---
    coap_address_init(&dst_addr);
    struct addrinfo hints = {0};
    struct addrinfo *serv_info_list = NULL;
    struct addrinfo *p_serv_info = NULL;
    char port_str_buf[6];
    snprintf(port_str_buf, sizeof(port_str_buf), "%u", port_val);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    int gai_ret = getaddrinfo(host, port_str_buf, &hints, &serv_info_list);
    if (gai_ret != 0) {
        fprintf(stderr, "ERROR: getaddrinfo failed for host '%s': %s\n", host, gai_strerror(gai_ret));
        if (serv_info_list) freeaddrinfo(serv_info_list);
        ret = SUIT_ERR_DNS_RESOLVE;
        goto cleanup;
    }
    int addr_set_success = 0;
    for (p_serv_info = serv_info_list; p_serv_info != NULL; p_serv_info = p_serv_info->ai_next) {
        if (p_serv_info->ai_addr && (p_serv_info->ai_family == AF_INET || p_serv_info->ai_family == AF_INET6)) {
            dst_addr.size = p_serv_info->ai_addrlen;
            memcpy(&dst_addr.addr, p_serv_info->ai_addr, p_serv_info->ai_addrlen);
            addr_set_success = 1;
            break;
        }
    }
    freeaddrinfo(serv_info_list);
    serv_info_list = NULL;
    if (!addr_set_success) {
        fprintf(stderr, "ERROR: No suitable (IPv4/IPv6 UDP) address found for host '%s'.\n", host);
        ret = SUIT_ERR_DNS_RESOLVE;
        goto cleanup;
    }
    // --- End Address Resolution ---

    ctx = coap_new_context(NULL);
    if (!ctx) { ret = SUIT_ERR_COAP_CLIENT; goto cleanup; }

    unsigned int block_mode_flags = COAP_BLOCK_USE_LIBCOAP;
    #ifdef COAP_BLOCK_TRY_CLEAR_PAYLOAD
        block_mode_flags |= COAP_BLOCK_TRY_CLEAR_PAYLOAD;
    #endif
    coap_context_set_block_mode(ctx, block_mode_flags);

    session = coap_new_client_session(ctx, NULL, &dst_addr, COAP_PROTO_UDP);
    if (!session) { ret = SUIT_ERR_COAP_CLIENT; goto cleanup; }
    coap_session_set_app_data(session, &acc);

    coap_register_response_handler(ctx, coap_fetch_response_handler);

    pdu = coap_new_pdu(COAP_MESSAGE_CON, COAP_REQUEST_GET, session);
    if (!pdu) { ret = SUIT_ERR_COAP_CLIENT; goto cleanup; }

    // --- START: Corrected Uri-Path option handling ---
    size_t path_input_len = strlen(path_for_options);
    if (path_input_len > 0) {
        const char *path_to_process_const;
        if (path_for_options[0] == '/') {
            path_to_process_const = (path_input_len == 1) ? "" : path_for_options + 1;
        } else {
            path_to_process_const = path_for_options;
        }
        size_t len_to_split = strlen(path_to_process_const);

        if (len_to_split > 0) {
            uint8_t path_segments_buf[MAX_COAP_URI_PATH_LEN];
            size_t path_segments_buflen_io = sizeof(path_segments_buf);
            uint8_t *current_segment_in_buf = path_segments_buf;

            int num_segments = coap_split_path(
                (const uint8_t *)path_to_process_const,
                len_to_split,
                path_segments_buf,
                &path_segments_buflen_io
            );

            if (num_segments < 0) {
                fprintf(stderr, "ERROR: coap_split_path failed (%d) for path '%s'.\n", num_segments, path_to_process_const);
                ret = SUIT_ERR_COAP_CLIENT;
                goto cleanup_options_path;
            }

            for (int i = 0; i < num_segments; i++) {
                size_t segment_data_len = coap_opt_length(current_segment_in_buf);
                const uint8_t* segment_data_val = coap_opt_value(current_segment_in_buf);
                coap_optlist_t *new_opt_node = coap_new_optlist(COAP_OPTION_URI_PATH, segment_data_len, segment_data_val);

                if (!new_opt_node) {
                    fprintf(stderr, "ERROR: coap_new_optlist failed for Uri-Path segment.\n");
                    ret = SUIT_ERR_MEMORY;
                    goto cleanup_options_path;
                }
                if (!coap_insert_optlist(&optlist_chain, new_opt_node)) {
                    fprintf(stderr, "ERROR: coap_insert_optlist failed.\n");
                    coap_delete_optlist(new_opt_node);
                    ret = SUIT_ERR_MEMORY;
                    goto cleanup_options_path;
                }
                current_segment_in_buf += coap_opt_size(current_segment_in_buf);
            }
        }
    }

    if (optlist_chain) {
        if (!coap_add_optlist_pdu(pdu, &optlist_chain)) {
            fprintf(stderr, "ERROR: coap_add_optlist_pdu failed.\n");
            ret = SUIT_ERR_COAP_CLIENT;
            goto cleanup_options_path; // This will also delete the optlist_chain
        }
        optlist_chain = NULL; // Consumed by coap_add_optlist_pdu
    }
    goto send_pdu_label; // Skip cleanup_options_path if successful

cleanup_options_path:
    if (optlist_chain) {
        coap_delete_optlist(optlist_chain);
        optlist_chain = NULL;
    }
    if (ret != SUIT_ERR_OK) { // If any error during option processing
        goto cleanup; // Jump to main PDU cleanup
    }
send_pdu_label:
    // --- END: Corrected Uri-Path option handling ---

    mid = coap_send(session, pdu);
    if (mid == COAP_INVALID_MID) {
        fprintf(stderr, "ERROR: coap_send failed.\n");
        // pdu is still owned by us if coap_send fails this way
        ret = SUIT_ERR_FETCH; goto cleanup; // pdu will be freed in main cleanup
    }
    pdu = NULL; // libcoap has taken ownership if mid is valid (for CON/NON that expect response/ACK)

    // ... (I/O processing loop, success checks, main cleanup - same as before) ...
    time_t operation_start_time = time(NULL);
    while (!acc.completed && (time(NULL) - operation_start_time < COAP_FETCH_TOTAL_TIMEOUT_S)) {
        int result = coap_io_process(ctx, COAP_IO_PROCESS_TIMEOUT_MS);
        if (result < 0) {
            fprintf(stderr, "ERROR: coap_io_process returned %d.\n", result);
            ret = SUIT_ERR_FETCH; goto cleanup;
        }
    }

    if (!acc.completed) {
        fprintf(stderr, "ERROR: CoAP fetch operation timed out.\n");
        ret = SUIT_ERR_TIMEOUT; goto cleanup;
    }
    if (acc.completed == -1) { // Error set by response handler
        // Error message already printed by handler or will be if not.
        fprintf(stderr, "CoAP response handler indicated an error for MID %u.\n", mid);
        ret = SUIT_ERR_FETCH; goto cleanup;
    }

    *out_buffer = acc.data; *out_size = acc.len;
    acc.data = NULL; // Ownership transferred
    ret = SUIT_ERR_OK;

    if (expected_size > 0 && *out_size != expected_size) {
         fprintf(stderr, "WARNING: CoAP (libcoap3) Downloaded size (%zu) != manifest size (%zu).\n", *out_size, expected_size);
    }

cleanup:
    if (acc.data) free(acc.data);
    if (pdu) coap_delete_pdu(pdu); // Free PDU if coap_send failed and didn't take ownership, or if created but not sent
    // if (optlist_chain) coap_delete_optlist(optlist_chain); // Handled by cleanup_options_path or consumption by coap_add_optlist_pdu
    if (session) coap_session_release(session);
    if (ctx) coap_free_context(ctx);
    // coap_cleanup(); // Call once per application lifecycle
    return ret;
}

// -----------------------------------------------------------------------------
// Placeholder/Stub function for fetching via CoAP
// Replace with actual implementation using a CoAP library (e.g., libcoap)
// -----------------------------------------------------------------------------
static int fetch_coap_image(const char *url, size_t expected_size, uint8_t **out_buffer, size_t *out_size) {
    fprintf(stderr, "INFO: CoAP fetch requested for URL: %s\n", url);

    *out_buffer = NULL;
    *out_size = 0;

    return fetch_coap_image_libcoap(url, expected_size, out_buffer, out_size);
}

// Decrypts an AES-256-GCM encrypted image in place.
// The encrypted buffer is expected to be in the format:
// [12-byte nonce][16-byte tag][ciphertext]
// On success, the image_ptr and image_size_ptr will be updated to point
// to the new buffer containing the decrypted plaintext.
int decrypt_image_inplace(uint8_t **image_ptr, size_t *image_size_ptr) {
    // THIS SECRET MUST MATCH THE ONE USED FOR ENCRYPTION.
    // In a real product, this must be provisioned securely (e.g., via HSM, secure element).
    const char *secret_str = "my-super-secret-key-123";
    const unsigned char *salt = (const unsigned char *)"suit-encryption-salt";

    const size_t NONCE_SIZE = 12;
    const size_t TAG_SIZE = 16;

    mbedtls_gcm_context aes_ctx;
    int ret = 1; // Default to error
    uint8_t key[32]; // 256-bit key

    uint8_t *encrypted_image = *image_ptr;
    size_t encrypted_size = *image_size_ptr;

    if (encrypted_image == NULL || encrypted_size <= NONCE_SIZE + TAG_SIZE) {
        fprintf(stderr, "ERROR (Decrypt): Image buffer is NULL or too small to be encrypted.\n");
        return -1;
    }

    // Step 1: Derive the 32-byte key from the secret string, just like in Python.
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0); // 0 for SHA-256
    mbedtls_sha256_update(&sha_ctx, salt, strlen((const char*)salt));
    mbedtls_sha256_update(&sha_ctx, (const unsigned char *)secret_str, strlen(secret_str));
    mbedtls_sha256_finish(&sha_ctx, key);
    mbedtls_sha256_free(&sha_ctx);

    // Step 2: Parse the encrypted buffer to get pointers to nonce, tag, and ciphertext.
    const uint8_t *nonce_ptr = encrypted_image;
    const uint8_t *tag_ptr = encrypted_image + NONCE_SIZE;
    const uint8_t *ciphertext_ptr = encrypted_image + NONCE_SIZE + TAG_SIZE;
    size_t ciphertext_size = encrypted_size - NONCE_SIZE - TAG_SIZE;

    if (ciphertext_size == 0) {
        fprintf(stderr, "ERROR (Decrypt): Ciphertext size is zero.\n");
        return -1;
    }

    // Step 3: Allocate memory for the plaintext (decrypted data).
    uint8_t *plaintext_ptr = malloc(ciphertext_size);
    if (plaintext_ptr == NULL) {
        fprintf(stderr, "ERROR (Decrypt): Failed to allocate memory for plaintext.\n");
        return -1;
    }

    // Step 4: Perform decryption using Mbed TLS.
    mbedtls_gcm_init(&aes_ctx);
    ret = mbedtls_gcm_setkey(&aes_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        fprintf(stderr, "ERROR (Decrypt): mbedtls_gcm_setkey failed with %d\n", ret);
        goto cleanup;
    }

    // This single call decrypts the data AND verifies the authentication tag.
    ret = mbedtls_gcm_auth_decrypt(&aes_ctx, ciphertext_size,
                                   nonce_ptr, NONCE_SIZE,
                                   NULL, 0, // No Additional Authenticated Data (AAD)
                                   tag_ptr, TAG_SIZE,
                                   ciphertext_ptr, plaintext_ptr);

    if (ret != 0) {
        fprintf(stderr, "\nERROR: DECRYPTION FAILED! Authentication tag mismatch or other error. Code: %d\n", ret);
        fprintf(stderr, "       The image is corrupt, tampered with, or was encrypted with a different key. ❌\n\n");
        // Do not use the output in plaintext_ptr, it is not authenticated.
        goto cleanup;
    }

    // Step 5: On success, update the caller's pointers and size.
    printf("Decryption successful. ✅\n");
    free(*image_ptr); // Free the old buffer with the encrypted data
    *image_ptr = plaintext_ptr; // Point to the new buffer with the plaintext
    *image_size_ptr = ciphertext_size; // Update the size
    plaintext_ptr = NULL; // Avoid double free in cleanup

cleanup:
    if (plaintext_ptr != NULL) {
        free(plaintext_ptr); // Free plaintext buffer only if decryption failed
    }
    mbedtls_gcm_free(&aes_ctx);
    return ret; // 0 on success, non-zero on failure
}

int suit_platform_do_fetch(
    suit_reference_t *component_id,
    int digest_type,
    const uint8_t *digest_bytes,
    size_t digest_len,
    size_t image_size,
    const uint8_t* uri,
    size_t uri_len) 
{
    int result = SUIT_ERR_FETCH; // Default error
    //uint8_t *out_image_ptr; // Pointer to receive the allocated buffer
    //size_t out_image_size; // Pointer to receive the size of the buffer

    printf("Fetching ");
    if (component_id == NULL) {
        printf("<only component>\n");
    } else {
        //TODO
    }
    printf("  Target digest type %i\n", digest_type);
    printf("  Target digest bytes: ");
    x_print(digest_bytes, digest_len);
    printf("\n");
    printf("  Expected Size: %zu bytes\n", image_size);
    printf("  Source URI: ");
    s_print((char*) uri, uri_len);
    printf("\n");

    // If uri size is greater than 0, the image is fetched remotely
    if (uri_len > 0) {
        // Create a null-terminated version for string functions
        char *url_str = malloc(uri_len + 1);
        if (!url_str) {
            fprintf(stderr, "ERROR: Failed to allocate memory for URL string.\n");
            return SUIT_ERR_MEMORY;
        }
        memcpy(url_str, uri, uri_len);
        url_str[uri_len] = '\0';

        printf("  Attempting fetch for: %s\n", url_str);

        // Check the scheme
        if (strncmp(url_str, "https://", 8) == 0 || strncmp(url_str, "http://", 7) == 0) {
            printf("  Detected HTTP/HTTPS scheme.\n");
            result = fetch_http_image(url_str, image_size, &update_image, &update_image_size);
        } else if (strncmp(url_str, "coap://", 7) == 0) {
            printf("  Detected CoAP scheme.\n");
            result = fetch_coap_image(url_str, image_size, &update_image, &update_image_size);
        } else {
            fprintf(stderr, "ERROR: Unsupported URI scheme in '%s'. Only http, https, coap are supported.\n", url_str);
            result = SUIT_ERR_UNSUPPORTED_SCHEME;

            update_image = NULL;
            update_image_size = 0;
        }

        // Free the temporary URL string
        free(url_str);
    } 
    // --- POST-FETCH VALIDATION ---
    // If the download was successful, verify the hash of the image.
    if (result == SUIT_ERR_OK) {
        printf("Fetch successful. Downloaded %zu bytes.\n", update_image_size);

        // Check if the manifest provided a digest to verify against.
        if (digest_bytes && digest_len > 0) {
            printf("Verifying digest of fetched image...\n");

            // Call the existing helper function to compute the hash and compare it.
            int verify_res = suit_platform_verify_digest(update_image, update_image_size, digest_bytes, digest_len, digest_type);

            // Check if verification failed.
            if (verify_res != SUIT_ERR_OK) { // SUIT_ERR_OK is typically 0
                fprintf(stderr, "\nERROR: HASH MISMATCH! The downloaded image is corrupt or incorrect. ❌\n");
                fprintf(stderr, "       Verification failed with code: %d\n\n", verify_res);
                free(update_image); // Discard the invalid image
                update_image = NULL;
                update_image_size = 0;
                return SUIT_ERROR_DIGEST_MISMATCH; // Return a specific error
            }

            printf("Digest verification successful. The image is authentic. ✅\n");
        } else {
            printf("WARNING: No digest provided in the manifest to verify the downloaded image against.\n");
        }

        printf("Attempting to decrypt the image...\n");
        int decrypt_res = decrypt_image_inplace(&update_image, &update_image_size);

        if (decrypt_res != 0) {
            // Error is printed inside the decrypt function.
            // Decryption failed, so discard the image.
            if (update_image != NULL) {
                free(update_image);
                update_image = NULL;
                update_image_size = 0;
            }
            return -1; // Return a generic decryption error
        }

    } else {
        fprintf(stderr, "Fetch failed with error code: %d\n", result);
        if (update_image != NULL) {
            free(update_image);
            update_image = NULL;
        }
        update_image_size = 0;
    }
    // --- END VALIDATION ---

    printf("\n");
    // The suit_do_process_manifest expects 0 for success from callbacks.
    return result == SUIT_ERR_OK ? SUCCESS : result;
}

int suit_platform_do_run(const uint8_t *component_id) {
    printf("booted\n");
    //TODO
    return 0;
}


static uint8_t *suit_report_buf = NULL;
static uint8_t *suit_report_p = NULL;
static uint8_t *suit_report_end = NULL;

int suit_platform_report_init(
    uint8_t *report_buffer,
    size_t report_buffer_size,
    bm_cbor_reference_t *manifest_digest

) {
    suit_report_buf = suit_report_p = report_buffer;
    suit_report_end = suit_report_buf + report_buffer_size;
    return CBOR_ERR_NONE;
}

int suit_platform_report_set_digest(
    bm_cbor_reference_t *digest
) {
    printf("Manifest Digest is: ");
    printf("\n");
    // *(suit_report_p++) = SUIT_RECORD_MANIFEST_ID;
    // TODO: Copy  in the digest
    return 0;
}

int suit_platform_report_set_URI(
    bm_cbor_reference_t *uri
) {
    return 0;
}

int suit_platform_start_records()
{
    // Start indefinite length list of SUIT records
    // *(suit_report_p++) = SUIT_RECORD_M | 31;
    // *(suit_report_p++) = CBOR_TYPE_LIST | 31;
    return 0;
}

//    suit-record = {
//        suit-record-manifest-id        => [* uint ],
//        suit-record-manifest-section   => int,
//        suit-record-section-offset     => uint,
//        (
//            suit-record-component-index  => uint //
//            suit-record-dependency-index => uint
//        ),
//        suit-record-failure-reason     => SUIT_Parameters / int,
//    }
// #define SUIT_RECORD_MANIFEST_ID 
int suit_platform_report_record(
    suit_parse_context_t *ctx,
    char **p,
    int section_id, 
    int idx,
    int key,
    suit_vars_t* vars
) {
    // *(suit_report_p++) = SUIT_RECORD_MANIFEST_ID;

    return CBOR_ERR_NONE;
}
