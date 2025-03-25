// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
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
#ifndef _SUIT_PARSER_H_
#define _SUIT_PARSER_H_

#define MAX_COMPONENTS 2

#include "bm_cbor.h"
#include "pull_cbor.h"
#include <stdint.h>
#include <stddef.h>

#define CBOR_TYPE_UINT (0 << 5)
#define CBOR_TYPE_NINT (1 << 5)
#define CBOR_TYPE_BSTR (2 << 5)
#define CBOR_TYPE_TSTR (3 << 5)
#define CBOR_TYPE_LIST (4 << 5)
#define CBOR_TYPE_MAP (5 << 5)
#define CBOR_TYPE_TAG (6 << 5)
#define CBOR_TYPE_SIMPLE (7 << 5)
#define CBOR_TYPE_MASK (7 << 5)

#define CBOR_FALSE (CBOR_TYPE_SIMPLE | 20)
#define CBOR_TRUE (CBOR_TYPE_SIMPLE | 21)
#define CBOR_NULL (CBOR_TYPE_SIMPLE | 22)

#define SUIT_SUPPORTED_VERSION 1

#define SIGNATURE1 "Signature1"

// Signature1 is never more than 256 bytes long.
#define SUIT_SIGNATURE1_BSTR_START_MAX (1+1)
// Signature1 is always 4 elements
#define SUIT_SIGNATURE1_ARRAY_START_LEN 1
// Signature1 context length
#define SUIT_SIGNATURE1_CONTEXT_LEN (sizeof(SIGNATURE1)-1)
// There are fewer than 23 header fields, so only 1 byte for header map
#define SUIT_SIGNATURE1_HDRMAP_START_LEN 1
// Each header field consists of 1 integer field identifier with a value
// below 23 and one field with a size dependent on the field.
// Typically, only the algorithm is defined in protected headers.
#define SUIT_SIGNATURE1_HDR_ALG_LEN (2)

#define SUIT_BODYPROTECTED_MAX_LEN (\
    SUIT_SIGNATURE1_BSTR_START_MAX +\
    SUIT_SIGNATURE1_HDRMAP_START_LEN +\
    SUIT_SIGNATURE1_HDR_ALG_LEN \
)
// AAD is not used in SUIT
#define SUIT_SIGNATURE1_AAD_LEN 1

// The payload contains a BSTR-encoded SUIT Digest
// Since a digest itself is always at least 28 bytes (SHA224) and never
// more than 64 bytes (SHA512), the bstr header is always 2 bytes
#define SUIT_DIGEST_BSTR_START_MAX SUIT_SIGNATURE1_BSTR_START_MAX
// The array is always fewer than 24 elements, so the array is 1 byte
#define SUIT_DIGEST_ARRAY_START_LEN SUIT_SIGNATURE1_ARRAY_START_LEN
// The type identifier of the digest should always be 1 byte
#define SUIT_DIGEST_TYPE_MAX_LEN 1
#ifndef SUIT_DIGEST_SIZE
// The longest digest supported is SHA512 (64 bytes)
#define SUIT_DIGEST_SIZE 64
#endif

#define SUIT_SIGNATURE1_PAYLOAD_LEN (\
    SUIT_DIGEST_BSTR_START_MAX +\
    SUIT_DIGEST_ARRAY_START_LEN +\
    SUIT_DIGEST_TYPE_MAX_LEN +\
    SUIT_DIGEST_BSTR_START_MAX +\
    SUIT_DIGEST_SIZE \
)

#define SUIT_SIGNATURE1_MAX_LEN (\
    SUIT_SIGNATURE1_BSTR_START_MAX +\
    SUIT_SIGNATURE1_ARRAY_START_LEN +\
    SUIT_SIGNATURE1_CONTEXT_LEN +\
    SUIT_BODYPROTECTED_MAX_LEN +\
    SUIT_SIGNATURE1_AAD_LEN +\
    SUIT_SIGNATURE1_PAYLOAD_LEN \
)

#define UUID_SIZE (128/8)
#define COSE_SIGN1_TAG (18)
#define COSE_HDR_ALG (1)
#define COSE_HDR_KID (4)
#define COSE_ES256 (-7)

#define SUIT_ENVELOPE_TAG 107

#define SUIT_ENVELOPE_AUTH 2
#define SUIT_ENVELOPE_MANIFEST 3
#define SUIT_ENVELOPE_INSTALL 17
#define SUIT_ENVELOPE_TEXT 23

#define SUIT_MANIFEST_VERSION 1
#define SUIT_MANIFEST_SEQUCENCE_NUMBER 2
#define SUIT_MANIFEST_COMMON 3
#define SUIT_MANIFEST_INSTALL 17
#define SUIT_MANIFEST_VALIDATE 7
#define SUIT_MANIFEST_LOAD 8
#define SUIT_MANIFEST_RUN 9
// Key for the certification-manifest field in the manifest
#define SUIT_MANIFEST_CERTIFICATION_MANIFEST 25
#define SUIT_MANIFEST_TEXT 23

// Keys for the certification manifest entry fields
#define SUIT_CERT_MAN_PROPERTY_ID          1
#define SUIT_CERT_MAN_LANGUAGE_ID          2
#define SUIT_CERT_MAN_COMPONENT_ID         3
#define SUIT_CERT_MAN_PROOF_CERTIFICATE    4
#define SUIT_CERT_MAN_LOCALITY_CONSTRAINT  5
#define SUIT_CERT_MAN_VERIFICATION_SERVERS 6

#define SUIT_COMMON_DEPENDENCIES 1
#define SUIT_COMMON_COMPONENTS 2
#define SUIT_COMMON_SEQUENCE 4

#define SUIT_CONDITION_VENDOR_ID 1
#define SUIT_CONDITION_CLASS_ID 2
#define SUIT_CONDITION_IMAGE_MATCH 3

#define SUIT_DIRECTIVE_SET_COMP_IDX 12
#define SUIT_DIRECTIVE_SET_PARAMETERS 19
#define SUIT_DIRECTIVE_OVERRIDE_PARAMETERS 20
#define SUIT_DIRECTIVE_FETCH 21
#define SUIT_DIRECTIVE_INVOKE 23
//#define SUIT_DIRECTIVE_TRY_EACH 15

#define SUIT_PARAMETER_VENDOR_ID 1
#define SUIT_PARAMETER_CLASS_ID 2
#define SUIT_PARAMETER_IMAGE_DIGEST 3
#define SUIT_PARAMETER_IMAGE_SIZE 14
#define SUIT_PARAMETER_URI 21
#define SUIT_PARAMETER_SOURCE_COMPONENT 22

#define SUIT_DIGEST_TYPE_SHA256 -16
#define SUIT_DIGEST_TYPE_SHA384 -17

#define SUIT_SUPPORT_VAR(VAR)  (1L <<((VAR)-1))
#define SUIT_SUPPORTED_VARS ( \
    SUIT_SUPPORT_VAR(SUIT_PARAMETER_VENDOR_ID) | \
    SUIT_SUPPORT_VAR(SUIT_PARAMETER_CLASS_ID) | \
    SUIT_SUPPORT_VAR(SUIT_PARAMETER_IMAGE_DIGEST) | \
    SUIT_SUPPORT_VAR(SUIT_PARAMETER_IMAGE_SIZE) | \
    SUIT_SUPPORT_VAR(SUIT_PARAMETER_URI) | \
    SUIT_SUPPORT_VAR(SUIT_PARAMETER_SOURCE_COMPONENT) | \
    0)

#define COUNT_BITS_2(X)  ((X) - (((X)>>1) & 0x55555555))
#define COUNT_BITS_4(X)  (((COUNT_BITS_2(X) >> 2) & 0x33333333UL) + ((COUNT_BITS_2(X)) & 0x33333333UL))
#define COUNT_BITS_8(X)  (((COUNT_BITS_4(X) >> 4) + COUNT_BITS_4(X)) & 0x0F0F0F0F)
#define COUNT_BITS_16(X) ((COUNT_BITS_8(X) >> 8) + COUNT_BITS_8(X))
#define COUNT_BITS_32(X) (((COUNT_BITS_16(X) >> 16) + COUNT_BITS_16(X)) & 0x3F)


#define SUIT_VAR_COUNT (COUNT_BITS_32(SUIT_SUPPORTED_VARS))



    // int          key:16;
    // unsigned int resvd:8;
    // unsigned int type:3;
    // unsigned int has_handler:1;
    // unsigned int bstr_wrap:1;
    // unsigned int repeat:1;
    // unsigned int choice:1;
    // unsigned int null_opt:1;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t bytes[UUID_SIZE];
    uint8_t locality_constraint;
} property_uuid_t;

extern const uint8_t vendor_id[16];
extern const uint8_t class_id[16];
extern uint8_t *update_SBOM;
extern size_t update_SBOM_size;
extern property_uuid_t *property_ids;
extern size_t property_ids_count;
extern size_t property_ids_size;


enum {
    SUIT_ERR_VERSION = CBOR_ERR_MAX,
    SUIT_ERR_SIG,
    SUIT_ERROR_DIGEST_MISMATCH,
    SUIT_MFST_ERR_AUTH_MISSING,
    SUIT_MFST_ERR_MANIFEST_ENCODING,
    SUIT_MFST_UNSUPPORTED_ENTRY,
    SUIT_MFST_CONDITION_FAILED,
    SUIT_MFST_UNSUPPORTED_COMMAND,
    SUIT_MFST_UNSUPPORTED_ARGUMENT,
    SUIT_MFST_ERR_VENDOR_MISMATCH,
    SUIT_MFST_ERR_CLASS_MISMATCH,
    SUIT_ERR_PARAMETER_KEY,

};

typedef struct suit_reference_t {
    const uint8_t *ptr;
    const uint8_t *end;
} suit_reference_t;


typedef suit_reference_t suit_vars_t[SUIT_VAR_COUNT];

typedef struct suit_parse_context_s {
    suit_reference_t envelope;
    suit_reference_t manifest_digest;
    uint8_t manifest_suit_digest[SUIT_SIGNATURE1_PAYLOAD_LEN];
    union {
        struct {
            suit_reference_t search_result;
            suit_vars_t vars[MAX_COMPONENTS];
            suit_reference_t manifest;
            suit_reference_t common;
            uint16_t cidx;
            uint16_t didx;
        };
        struct {
            uint8_t Signature1[SUIT_SIGNATURE1_MAX_LEN];
            size_t offset;
            int alg;
            suit_reference_t kid;
        } Sign1;
    };
} suit_parse_context_t;

typedef PARSE_HANDLER((*suit_handler_t));


int suit_do_process_manifest(const uint8_t *manifest, size_t manifest_size);

int suit_get_seq(const uint8_t *manifest, size_t manifest_size, uint64_t *seqnum);
int do_cose_auth(
    const uint8_t *auth_buffer,
    const uint8_t *data, size_t data_size);
int verify_suit_digest(
    const uint8_t *digest,
    const uint8_t *digest_end,
    const uint8_t *data,
    size_t data_len);

int COSEAuthVerify(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *kid, size_t kid_len,
                int alg);
int suit_get_component_id(suit_reference_t *id, suit_parse_context_t *ctx, bm_cbor_uint_t idx);

#ifdef __cplusplus
}
#endif

#endif // _SUIT_PARSER_H_
