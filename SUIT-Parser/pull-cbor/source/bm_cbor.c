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
#include "bm_cbor.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#if BM_CBOR_ERR_INFO != 0
bm_cbor_err_info_t bm_cbor_err_info = {0};
#endif

int bm_cbor_get_as_uint(const uint8_t** p, const uint8_t* end, bm_cbor_uint_t* n)
{
    if (*p >= end) {
        RETURN_ERROR(CBOR_ERR_OVERRUN, *p);
    }
    uint8_t iv = **p & ~CBOR_TYPE_MASK;
    if (iv >= 28){
        RETURN_ERROR(CBOR_ERR_INTEGER_ENCODING, *p);
    }
    (*p)++;
    //TODO: do not increment p until size check is good
    //TODO: check for integer decode overflow
    if (iv < 24) {
        *n = iv;
    } else {
        const uint8_t* uend = *p + (1 << (iv-24));
        if (uend > end) {
            --(*p);
            RETURN_ERROR(CBOR_ERR_OVERRUN, *p);
        }
        for (*n = 0; *p < uend; (*p)++) {
            *n = *n << 8 | **p;
        }
    }
    return CBOR_ERR_NONE;
}

int bm_cbor_get_uint(const uint8_t** p, const uint8_t* end, bm_cbor_uint_t* n){
    uint8_t type = **p & CBOR_TYPE_MASK;
    if (type != CBOR_TYPE_UINT) {
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH, *p);
    }
    return bm_cbor_get_as_uint(p, end, n);
}

int bm_cbor_get_int(const uint8_t** p, const uint8_t* end, bm_cbor_int_t* n) {
    uint8_t type = **p & CBOR_TYPE_MASK;
    if (type != CBOR_TYPE_NINT && type != CBOR_TYPE_UINT) {
        //printf("Type mismatch: given type is %d - expected is %d or %d\n", type, CBOR_TYPE_NINT, CBOR_TYPE_UINT);
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH, *p);
    }
    bm_cbor_uint_t uv;
    int rc = bm_cbor_get_as_uint(p, end, &uv);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    if (uv & (1UL << (BM_CBOR_INT_SIZE -1))) {
        // Valid CBOR, but requires larger integers to decode
        RETURN_ERROR(CBOR_ERR_INTEGER_DECODE_OVERFLOW, *p);
    }
    if (type == CBOR_TYPE_NINT) {
        *n = -1 - (bm_cbor_int_t)uv;
    } else {
        *n = uv;
    }
    return rc;
}

int bm_cbor_extract_uint(
    const uint8_t **p,
    const uint8_t *end,
    bm_cbor_value_t *val)
{
    return bm_cbor_get_uint(p, end, &(val->u));
}
int bm_cbor_extract_int(
    const uint8_t **p,
    const uint8_t *end,
    bm_cbor_value_t *val)
{
    return bm_cbor_get_int(p, end, &(val->i));
}

int bm_cbor_extract_ref(
    const uint8_t **p,
    const uint8_t *end,
    bm_cbor_value_t *val
    )
{
    int rc = bm_cbor_get_as_uint(p, end, &(val->ref.uival));
    if (rc == CBOR_ERR_NONE) {
        val->ref.ptr = *p;
    }
    return rc;
}

int bm_cbor_extract_primitive(
    const uint8_t **p,
    const uint8_t *end,
    bm_cbor_value_t *val)
{
    val->primitive = (**p & (~CBOR_TYPE_MASK));
    (*p)++;
    RETURN_ERROR(CBOR_ERR_NONE, *p);
}

int bm_cbor_check_type_extract_ref(
        const uint8_t **p,
        const uint8_t *end,
        bm_cbor_value_t *o_val,
        const uint8_t cbor_type
) {
    if ((**p & CBOR_TYPE_MASK) != cbor_type) {
        // BM_CBOR_ERR_PRINT("Expected: %u Actual %u\n", (unsigned) cbor_type>>5, (unsigned)(**p & CBOR_TYPE_MASK)>>5);
        //printf("Expected: %u Actual %u\n", (unsigned) cbor_type>>5, (unsigned)(**p & CBOR_TYPE_MASK)>>5);
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH, *p);
    }
    o_val->cbor_start = *p;
    return bm_cbor_extract_ref(p, end, o_val);
}

int (*bm_cbor_extractors[])(
    const uint8_t **p,
    const uint8_t *end,
    bm_cbor_value_t *val) =
{
    bm_cbor_extract_uint,
    bm_cbor_extract_int,
    bm_cbor_extract_ref,
    bm_cbor_extract_ref,
    bm_cbor_extract_ref,
    bm_cbor_extract_ref,
    bm_cbor_extract_ref,
    bm_cbor_extract_primitive
};

int bm_cbor_skip(const uint8_t **p, const uint8_t *end)
{
    uint8_t ct = **p & CBOR_TYPE_MASK;
    size_t handler_index = ct >> 5;
    bm_cbor_value_t val;
    int rc = bm_cbor_extractors[handler_index](p, end, &val);
    if ((*p) > end) {
        SET_ERROR(rc, CBOR_ERR_OVERRUN,*p);
    }
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    switch (ct) {
        case CBOR_TYPE_UINT:
        case CBOR_TYPE_NINT:
            break;
        case CBOR_TYPE_TSTR:
        case CBOR_TYPE_BSTR:
            if ((*p) + val.ref.uival <= end) {
                (*p) += val.ref.uival;
            } else {
                SET_ERROR(rc, CBOR_ERR_OVERRUN, *p);
            }
            break;
        case CBOR_TYPE_MAP:
            val.ref.uival *= 2;
            // no break;
        case CBOR_TYPE_LIST:
            for (size_t count = val.ref.uival; count && rc == CBOR_ERR_NONE; count--) {
                rc = bm_cbor_skip(p, end);
            }
            break;
        case CBOR_TYPE_TAG:
            *p = val.ref.ptr;
            rc = bm_cbor_skip(p, end);
            break;
        case CBOR_TYPE_SIMPLE:
            if (val.primitive == (CBOR_NULL & ~CBOR_TYPE_MASK)) {
                break;
            } else {
                // BM_CBOR_ERR_PRINT("primitive : %02x\n", val.primitive);
            }

        default:
            // BM_CBOR_ERR_PRINT("Skip Unimplemented for type %u\n", (unsigned) ct>>5);
            SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED, *p);
    }
    return rc;
}

