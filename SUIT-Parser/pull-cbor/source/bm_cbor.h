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
#ifndef _BM_CBOR_H_
#define _BM_CBOR_H_
/**
 * @file Basic Minimal CBOR (bm_cbor)
 * @brief A minimalist CBOR parser.
 * 
 */
#include <stdint.h>

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

enum {
    CBOR_ERR_NONE = 0,
    CBOR_ERR_TYPE_MISMATCH,
    CBOR_ERR_KEY_MISMATCH,
    CBOR_ERR_OVERRUN,
    CBOR_ERR_INTEGER_DECODE_OVERFLOW,
    CBOR_ERR_INTEGER_ENCODING,
    CBOR_ERR_UNIMPLEMENTED,
    CBOR_ERR_MAX,
};

#ifndef PRINT_ON_ERROR
#define PRINT_ON_ERROR 1
#endif

#ifndef BM_CBOR_ERR_INFO
#define BM_CBOR_ERR_INFO 1
#endif

#ifndef BM_CBOR_ERR_INFO_DGB
#define BM_CBOR_ERR_INFO_DGB 1
#endif

#if BM_CBOR_ERR_INFO != 0
typedef struct bm_cbor_err_info_s {
    const uint8_t *ptr;
    int cbor_err;
#if BM_CBOR_ERR_INFO_DGB != 0
    unsigned line;
    const char* file;
#endif
} bm_cbor_err_info_t;
extern bm_cbor_err_info_t bm_cbor_err_info;
static inline bm_cbor_err_info_t* bm_cbor_get_err_info() { return & bm_cbor_err_info;}
#endif

#define SET_ERROR(RC, VAL, PTR)\
    do{\
        (RC)=(VAL);\
        if ((VAL) && BM_CBOR_ERR_INFO){\
            bm_cbor_err_info.ptr = (PTR);\
            bm_cbor_err_info.cbor_err = (VAL);\
            if (BM_CBOR_ERR_INFO_DGB) {\
                bm_cbor_err_info.line = (__LINE__);\
                bm_cbor_err_info.file = (__FILE__);\
            }\
    }}while(0)

#define RETURN_ERROR(VAL, PTR)\
    do{\
        if ((VAL) && BM_CBOR_ERR_INFO){\
            bm_cbor_err_info.ptr = (PTR);\
            bm_cbor_err_info.cbor_err = (VAL);\
            if (BM_CBOR_ERR_INFO_DGB) {\
                bm_cbor_err_info.line = (__LINE__);\
                bm_cbor_err_info.file = (__FILE__);\
            }\
        }\
        return (VAL);}while(0)


#ifndef BM_CBOR_INT_SIZE
#define BM_CBOR_INT_SIZE 64
#endif

#if BM_CBOR_INT_SIZE == 64
typedef uint64_t bm_cbor_uint_t;
typedef int64_t bm_cbor_int_t;
#elif BM_CBOR_INT_SIZE == 32
typedef uint32_t bm_cbor_uint_t;
typedef int32_t bm_cbor_int_t;
#else
#error integer size is not supported.
#endif

typedef struct bm_cbor_value_s {
    const uint8_t *cbor_start;
    union {
        bm_cbor_uint_t u;
        bm_cbor_int_t i;
        struct {
            bm_cbor_uint_t uival;
            const uint8_t *ptr;
        } ref;
        uint8_t primitive;
    };
} bm_cbor_value_t;

typedef struct bm_cbor_reference_s {
    bm_cbor_value_t v;
    const uint8_t *s;
} bm_cbor_reference_t;

extern int (*bm_cbor_extractors[])(
    const uint8_t **p,
    const uint8_t *end,
    bm_cbor_value_t *val);

int bm_cbor_get_as_uint(const uint8_t** p, const uint8_t* end, bm_cbor_uint_t* n);
int bm_cbor_get_uint(const uint8_t** p, const uint8_t* end, bm_cbor_uint_t* n);
int bm_cbor_get_int(const uint8_t** p, const uint8_t* end, bm_cbor_int_t* n);

int bm_cbor_extract_uint(const uint8_t **p, const uint8_t *end, bm_cbor_value_t *val);
int bm_cbor_extract_int(const uint8_t **p, const uint8_t *end, bm_cbor_value_t *val);
int bm_cbor_extract_ref(const uint8_t **p, const uint8_t *end, bm_cbor_value_t *val);
int bm_cbor_extract_primitive(const uint8_t **p, const uint8_t *end, bm_cbor_value_t *val);
int bm_cbor_check_type_extract_ref(
        const uint8_t **p,
        const uint8_t *end,
        bm_cbor_value_t *o_val,
        const uint8_t cbor_type
);
int bm_cbor_skip(const uint8_t **p, const uint8_t *end);
#endif // _BM_CBOR_H_
