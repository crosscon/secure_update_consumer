// ----------------------------------------------------------------------------
// Copyright 2020-2021 ARM Ltd.
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

#ifndef _PULL_CBOR_H_
#define _PULL_CBOR_H_

#include <stddef.h>
// #define FLEXARRAY_HELPER(STRUCT_TYPE, TYPE, NAME, TMPNAME, ...)\
//     const TYPE TMPNAME [] = { \
//         __VA_ARGS__\
//     };\
//     union {\
//         const STRUCT_TYPE elements;\
//         const uint8_t raw [sizeof(TMPNAME) + sizeof(STRUCT_TYPE)];\
//     } NAME = {{.count = ARRAY_SIZE(TMPNAME), elements={ \
//         __VA_ARGS__\
//     }}}
// #define FLEXARRAY(STRUCT_TYPE, TYPE, NAME, ...) FLEXARRAY_HELPER(STRUCT_TYPE, TYPE, NAME, _flexarray_ ## NAME ## _tmp, __VA_ARGS__)
// #define CBOR_KPARSE_ELEMENT_LIST(NAME, ...) \
//     FLEXARRAY(cbor_keyed_parse_elements_t, cbor_keyed_parse_element_t, NAME, __VA_ARGS__)

#ifdef PARSER_DEBUG
#define CBOR_KPARSE_ELEMENT_C_BWRAP_KV(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, .is_kv = 1, .bstr_wrap = 1, 0, 0, 0, .ptr = (CHILDREN), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_C_BWRAP(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .bstr_wrap = 1, 0, 0, 0, .ptr = (CHILDREN), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_A_BWRAP(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .bstr_wrap = 1, .is_array = 1, 0, 0, .ptr = (CHILDREN), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_C(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, 0, 0, .ptr = (CHILDREN), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_H(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, .has_handler = 1, 0, 0, 0, 0, .ptr = (HANDLER), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_H_BWRAP(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, .has_handler = 1, .bstr_wrap = 1, 0, 0, 0, .ptr = (HANDLER), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_EX(KEY, TYPE, VAL, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, .extract = 1, 0, .ptr = (VAL), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_EX_BWRAP(KEY, TYPE, VAL, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .bstr_wrap = 1, 0, .extract = 1, 0, .ptr = (VAL), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, .ptr=(HANDLER), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_NULL(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, .null_opt = 1, .ptr=(HANDLER), .desc=(DESC)}
#define CBOR_KPARSE_ELEMENT_C_CHOICE(KEY, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = CBOR_TYPE_LIST >> 5, 0, 0, 0, .choice = 1, 0, .ptr = (CHILDREN), .desc=(DESC)}
#define PD_PRINTF(...)\
    printf(__VA_ARGS__)
#else
#define CBOR_KPARSE_ELEMENT_C_BWRAP_KV(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, .is_kv = 1, .bstr_wrap = 1, 0, 0, 0, .ptr = (CHILDREN)}
#define CBOR_KPARSE_ELEMENT_C_BWRAP(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .bstr_wrap = 1, 0, 0, 0, .ptr = (CHILDREN)}
#define CBOR_KPARSE_ELEMENT_A_BWRAP(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .bstr_wrap = 1, .is_array = 1, 0, 0, .ptr = (CHILDREN)}
#define CBOR_KPARSE_ELEMENT_C(KEY, TYPE, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, 0, 0, .ptr = (CHILDREN)}
#define CBOR_KPARSE_ELEMENT_H(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, .has_handler = 1, 0, 0, 0, 0, .ptr = (HANDLER)}
#define CBOR_KPARSE_ELEMENT_H_BWRAP(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, .has_handler = 1, .bstr_wrap = 1, 0, 0, 0, .ptr = (HANDLER)}
#define CBOR_KPARSE_ELEMENT_EX(KEY, TYPE, VAL, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, .extract = 1, 0, .ptr = (VAL)}
#define CBOR_KPARSE_ELEMENT_EX_BWRAP(KEY, TYPE, VAL, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, .bstr_wrap = 1, 0, .extract = 1, 0, .ptr = (VAL)}
#define CBOR_KPARSE_ELEMENT(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, 0, .ptr = (HANDLER)}
#define CBOR_KPARSE_ELEMENT_NULL(KEY, TYPE, HANDLER, DESC)\
    {.key = (KEY), 0, .type = (TYPE) >> 5, 0, 0, .null_opt = 1, .ptr = (HANDLER)}
#define CBOR_KPARSE_ELEMENT_C_CHOICE(KEY, CHILDREN, DESC)\
    {.key = (KEY), 0, .type = CBOR_TYPE_LIST >> 5, 0, 0, 0, .choice = 1, 0, .ptr = (CHILDREN)}
#define PD_PRINTF(...)
#endif

#define ARRAY_SIZE(X) (sizeof(X)/sizeof((X)[0]))


#define FLEXARRAY_HELPER(STRUCT_TYPE, TYPE, NAME, TMPNAME, ...)\
    const TYPE TMPNAME [] = { \
        __VA_ARGS__\
    };\
    const union { \
        STRUCT_TYPE elements;\
        struct { \
            size_t count; \
            TYPE elements [ARRAY_SIZE(TMPNAME)]; \
        } raw; \
    } NAME = {.raw = {.count = ARRAY_SIZE(TMPNAME), .elements={ \
        __VA_ARGS__\
    }}}
#define FLEXARRAY(STRUCT_TYPE, TYPE, NAME, ...) FLEXARRAY_HELPER(STRUCT_TYPE, TYPE, NAME, _flexarray_ ## NAME ## _tmp, __VA_ARGS__)
#define CBOR_KPARSE_ELEMENT_LIST(NAME, ...) \
    FLEXARRAY(cbor_keyed_parse_elements_t, cbor_keyed_parse_element_t, NAME, __VA_ARGS__)

    // int          key:16;
    // unsigned int resvd:8;
    // unsigned int type:3;
    // unsigned int has_handler:1;
    // unsigned int bstr_wrap:1;
    // unsigned int repeat:1;
    // unsigned int choice:1;
    // unsigned int null_opt:1;

#define PARSE_HANDLER(N)\
    int N( \
        const uint8_t **p, \
        const uint8_t *end, \
        void* ctx, \
        bm_cbor_value_t *val, \
        const int key,\
        const uint8_t cbor_type \
    )

typedef PARSE_HANDLER((*pull_cbor_handler_t));

struct cbor_keyed_parse_elements_s;

typedef struct cbor_keyed_parse_element_s {
    int          key:16;
    unsigned int resvd:6;
    unsigned int type:3;
    unsigned int is_kv:1;
    unsigned int has_handler:1;
    unsigned int bstr_wrap:1;
    unsigned int is_array:1; // array of like items. If 0, list.
    unsigned int extract:1;
    unsigned int null_opt:1;
    const void* ptr;
#ifdef PARSER_DEBUG
    const char* desc;
#endif
} cbor_keyed_parse_element_t;

typedef struct cbor_keyed_parse_elements_s {
    size_t count;
    cbor_keyed_parse_element_t elements[];
} cbor_keyed_parse_elements_t;

int pull_cbor_process_kv(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    const uint8_t type
);

int pull_cbor_handle_keyed_element(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    int32_t key
);

int pull_cbor_handle_array(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
);
int pull_cbor_handle_list(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
);
int pull_cbor_handle_pairs(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
);
int pull_cbor_handle_tag(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers
);
#endif // _PULL_CBOR_H_