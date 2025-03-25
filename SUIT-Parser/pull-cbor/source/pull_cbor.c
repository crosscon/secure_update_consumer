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
#include "pull_cbor.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#ifdef PARSER_DEBUG
#include <stdio.h>
#endif
#include <stdio.h>

// TODO: Further unit tests for units below this line
//===================================================

static int get_handler(
    const uint8_t cbor_b1,
    const uint8_t cbor_sub,
    const cbor_keyed_parse_element_t** h,
    const cbor_keyed_parse_elements_t* handlers,
    const int32_t key
) {
    //printf("Key: %d\n", key);
    size_t i;
    // Step 1: find the first key that matches
    int success = 0;
    for (i = 0; i < handlers->count; i++)
    {
        if (handlers->elements[i].key == key) {
            success = 1;
            break;
        }
    }

    if (!success ) {
        printf("Couldn't find a handler for key %d\n", (int) key);
        RETURN_ERROR(CBOR_ERR_KEY_MISMATCH, NULL);
    }
    //printf("Key Matched, Matching major %u, sub:%u\n", (unsigned) cbor_b1>>5, (unsigned)cbor_sub >> 5);
    // Step 2: Loop through handlers until a matching handler is found or a key mismatch is found
    // const cbor_keyed_parse_element_t* h;
    for (; i < handlers->count && handlers->elements[i].key == key; i++) {
    // do {
        uint8_t cbor_type = (cbor_b1 & CBOR_TYPE_MASK) >> 5;
        *h = &handlers->elements[i];
        if ((*h)->bstr_wrap) {
            if (cbor_type != CBOR_TYPE_BSTR >> 5) {
                continue;
            }
            cbor_type = (cbor_sub & CBOR_TYPE_MASK) >> 5;
        }
        if ((*h)->type == cbor_type) {
            return CBOR_ERR_NONE;
        }
        if (cbor_type == CBOR_TYPE_UINT >> 5 && (*h)->type == CBOR_TYPE_NINT >> 5)
        {
            return CBOR_ERR_NONE;
        }
        if ((*h)->null_opt && cbor_b1 == CBOR_NULL) {
            return CBOR_ERR_NONE;
        }
    } // while (++i < handlers->count && (*h)->key == key);
    printf("Type Mismatch for key: %d with type %d\n", key, ((cbor_b1 & CBOR_TYPE_MASK) >> 5));
    RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH, NULL);
}


/**
 * 
 * Step 1: get the handler.
 * Step 2: Unwrap if bstr-wrapped.
 * Step 3: Invoke the appropriate handler.
 */
int pull_cbor_handle_keyed_element(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    int32_t key
) {

    // TODO: Add pre-call-function?
    // printf("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), key);

    bm_cbor_value_t val;
    val.cbor_start =  *p;

    // Perform the extract in advance.
    uint8_t cbor_b1 = **p;
    int rc = bm_cbor_extractors[(cbor_b1 & CBOR_TYPE_MASK)>>5](p, end, &val);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // printf("Extract done\r\n");
    uint8_t cbor_sub = **p;

    const cbor_keyed_parse_element_t *handler;
    //printf("Key: %d\n", key);
    rc = get_handler(cbor_b1, cbor_sub, &handler, handlers, key);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
        return rc;
    }
    //printf("%s\n", handler); //->desc);

    uint8_t cbor_type = cbor_b1 & CBOR_TYPE_MASK;
    if (handler->bstr_wrap) {
        // printf("parse offset: %zu. Unwrapping BSTR\n", (size_t)((*p)-ctx->envelope.ptr));
        //printf("Unwrapping BSTR\n");
        val.cbor_start =  *p;

        end = val.ref.ptr + val.ref.uival;
        rc = bm_cbor_extractors[(cbor_sub & CBOR_TYPE_MASK)>>5](p, end, &val);
        if (rc != CBOR_ERR_NONE) {
            return rc;
        }
        cbor_type = cbor_sub & CBOR_TYPE_MASK;
        //printf("Next type: %u\n", (unsigned)cbor_type >> 5);
    }

    //printf("[%s:%d] Invoking: %s\n", __FUNCTION__, __LINE__, handler);//->desc?handler->desc:"NULL");
    
    //printf("handler->ptr: %p\n", handler->ptr);
    if (handler->ptr == NULL) {
        // Nothing to do.
        //printf("Skipping...\n");
        *p = val.cbor_start;
        rc = bm_cbor_skip(p, end);
    }
    else if (handler->extract) {
        //printf("Extracting...\n");
        memcpy((void *)handler->ptr, &val, sizeof(bm_cbor_value_t));
        // If the extracted content was a reference, skip over it.
        if (bm_cbor_extractors[handler->type] == bm_cbor_extract_ref) {
            *p = val.cbor_start;
            rc = bm_cbor_skip(p, end);
        }
    }
    else if (handler->has_handler) {
        pull_cbor_handler_t handler_fn = (pull_cbor_handler_t) handler->ptr;
        //printf("Invoking explicit handler for CBOR Major %u\r\n", (unsigned)cbor_type >> 5);
        rc = handler_fn(p, end, ctx, &val, key, cbor_type);
    } else {
        //printf("Invoking default handler for CBOR Major %u\r\n", (unsigned)cbor_type >> 5);
        const cbor_keyed_parse_elements_t *children = (const cbor_keyed_parse_elements_t *) handler->ptr;
        switch(cbor_type) {
            case CBOR_TYPE_LIST:{
                int (*handler_fn)(
                    const uint8_t** p,
                    const uint8_t* end,
                    void *ctx,
                    const cbor_keyed_parse_elements_t *handlers,
                    size_t n_elements
                ) = NULL;
                if (handler->is_array) {
                    handler_fn = pull_cbor_handle_array;
                }
                else if (handler->is_kv) {
                    handler_fn = pull_cbor_handle_pairs;
                }
                else {
                    handler_fn = pull_cbor_handle_list;
                }
                rc = handler_fn(p, end, ctx, children, val.ref.uival);
                break;
            }
            case CBOR_TYPE_MAP:
                rc = pull_cbor_handle_pairs(p, end, ctx, children, val.ref.uival*2);
                break;
            case CBOR_TYPE_TAG:
                rc = pull_cbor_handle_keyed_element(p, end, ctx, children, val.ref.uival);
                break;
        }
    }
    if (rc == CBOR_ERR_NONE) {
        if (handler->bstr_wrap) {
            *p = end;
        }
        else if ((cbor_b1 & CBOR_TYPE_MASK) == CBOR_TYPE_BSTR) {
            *p = val.ref.ptr+val.ref.uival;
        }
    }
    return rc;
}

int pull_cbor_handle_array(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
) {
    int rc = CBOR_ERR_NONE;
    for (; rc == CBOR_ERR_NONE && n_elements; n_elements--) {
        // printf("[%s:%d] ",__FUNCTION__, __LINE__);
        // printf("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), 0LL);
        rc = pull_cbor_handle_keyed_element(p, end, ctx, handlers, 0);
    }
    return rc;
}

int pull_cbor_handle_list(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
) {
    int rc = CBOR_ERR_NONE;
    for (size_t i = 0; rc == CBOR_ERR_NONE && i < n_elements; i++) {
        // printf("[%s:%d] ",__FUNCTION__, __LINE__);
        // printf("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), (int64_t)i);
        rc = pull_cbor_handle_keyed_element(p, end, ctx, handlers, i);
    }
    return rc;
}

int pull_cbor_handle_pairs(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    size_t n_elements
) {
    size_t n_pairs = n_elements/2;
    // printf("Handling %zu pairs\n", n_pairs);

    int rc = CBOR_ERR_NONE;
    for (; rc == CBOR_ERR_NONE && n_pairs; n_pairs--) {
        bm_cbor_int_t key;
        // Get Key
        rc = bm_cbor_get_int(p, end, &key);
        if (rc != CBOR_ERR_NONE) {
            break;
        }
        //TODO: range-check key64
        // Find handler
        // printf("[%s:%d] ",__FUNCTION__, __LINE__);
        // printf("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), (int64_t)key64);
        rc = pull_cbor_handle_keyed_element(p, end, ctx, handlers, key);
    }
    return rc;
}

int pull_cbor_handle_tag(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers
) {
    bm_cbor_value_t tag;
    int rc = bm_cbor_check_type_extract_ref(
        p, end, &tag, CBOR_TYPE_TAG
    );
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // printf("[%s:%d] ",__FUNCTION__, __LINE__);
    // printf("parse offset: %zu, key: %" PRIi64 "\n", (size_t)((*p)-ctx->envelope.ptr), (int64_t)tag.ref.uival);
    // printf("Choosing betwen %zu tags\n", handlers->count);
    return pull_cbor_handle_keyed_element(p, end, ctx, handlers, tag.ref.uival);
}

int pull_cbor_process_kv(
    const uint8_t** p,
    const uint8_t* end,
    void *ctx,
    const cbor_keyed_parse_elements_t *handlers,
    const uint8_t type
) {
    // Ensure that the wrapper is a map.
    if ((**p & CBOR_TYPE_MASK) != type) {
        //printf("Expected: %u Actual %u\n", (unsigned)type >> 5, (unsigned)(**p & CBOR_TYPE_MASK) >> 5);
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH, *p);
    }
    bm_cbor_value_t val;
    int rc = bm_cbor_extract_ref(p, end, &val);
    if (rc == CBOR_ERR_NONE) {
        uint32_t n_keys = type == CBOR_TYPE_LIST ? val.ref.uival : val.ref.uival*2;
        rc = pull_cbor_handle_pairs(p, end, ctx, handlers, n_keys);
    }
    return rc;
}