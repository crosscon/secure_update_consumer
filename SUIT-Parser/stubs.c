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
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"
#include "mbedtls/pem.h"
#include "mbedtls/error.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>     /* printf */
#include <stdlib.h>    /* exit */
#include <unistd.h> 
#include <libgen.h>   /* basename */
#include "base64.h"

#define SUCCESS 0
#define ERROR_INVALID_SIGNATURE 1
#define ERROR_INVALID_PROOF 2
#define ERROR_INVALID_MANIFEST 3
#define ERROR_NET 4
#define ERROR_MEM 5

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

// TA API to validate the manifest and the proofs inside it
// The proofs are validated either on the device or on the server, based on the locality constraint
uint8_t TA_CROSSCON_VALIDATE_MANIFEST(const uint8_t *manifest, size_t manifest_size) {
    int rc =  suit_do_process_manifest(manifest, manifest_size);

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

    // Verify the proofs 
    for (size_t i = 0; i < property_ids_count; i++) {
        // Check the locality constraint
        if (property_ids[i].locality_constraint == 1) {
            printf("Verification of the proof on device\n");

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

            // Decode the proof certificate from base64 and write it to the same file
            uint8_t *decoded = base64_decode(proof);
            f = fopen(filename, "wb");
            fwrite(decoded, sizeof(__uint8_t) * (strlen(proof) * 3 / 4), 1, f);
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
                printf("Proof certificate verification failed\n");
                return ERROR_INVALID_PROOF;
            }
        } else {
            printf("Verification of the proof on server\n");
            printf("TODO: Implement server verification\n");
            // TODO 
        }
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

    // TODO: change it, mock implementation only
    // Move from normal world to secure world (ARM TrustZone)
    system("cp /etc/uuid.ta /lib/optee_armtz/uuid.ta");

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

void compute_sha256(uint8_t *hash, const uint8_t *msg, size_t msg_len) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, msg, msg_len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
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

int suit_platform_do_fetch(
    suit_reference_t *component_id,
    int digest_type,
    const uint8_t *digest_bytes,
    size_t digest_len,
    size_t image_size,
    const uint8_t* uri,
    size_t uri_len) 
{
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
    printf("  Source: ");
    s_print((char*) uri, uri_len);
    // If uri size is greater than 0, the image is fetched remotely
    if (uri_len > 0) {
        // TODO: implement remote fetching
        update_image = NULL;
        update_image_size = 0;
    } 
    printf("\n");
    return 0;
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
