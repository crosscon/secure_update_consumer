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

#include "bm_cbor.h"


#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define DEBUG 1

#ifndef DEBUG
#define DEBUG 0
#endif

#define TEST_EQ_INT(X, Y, R)\
    do { if((X) != (Y)) {\
        if (DEBUG)\
            printf("\nAt: %s:%d> Expected: %ld. Actual %ld\n", __FILE__, __LINE__, (long int)(X), (long int)(Y));\
        return (R);\
    }} while (0)

struct test_s {
    int (*fn)();
    const char* desc;
};

void print_test(size_t width, const char* desc) {
    size_t maxdesc = width - 6 - 1;
    char buf[80+2];
    for (; width < 80; width++) {
        printf(" ");
    }
    strncpy(buf, desc, maxdesc);
    int dotlen = maxdesc - strlen(desc);
    printf("%s.", buf);
    for (;dotlen>0;dotlen--) {
        printf(".");
    }
}

int hello_test() {
    return 0;
}

struct uint_test_case_s {
    const uint8_t* ip;
    size_t len;
    int rc;
    bm_cbor_uint_t expect;
    int offset;
    const char* name;
};

#define MK_UINT_TEST(S, RC, E, O, NAME)\
    {(const uint8_t *)(S), sizeof(S)-1, (RC), (E), ((O) < 0 ? sizeof(S)-1 : (O)), (NAME)}

struct uint_test_case_s as_uint_test_cases[] = {
    MK_UINT_TEST("", CBOR_ERR_OVERRUN, 0L, 0, "Empty String"),
    MK_UINT_TEST("\xff", CBOR_ERR_INTEGER_ENCODING, 0L, 0, "Bad Encoding"),
    MK_UINT_TEST("\x00", CBOR_ERR_NONE, 0L, -1, "Positive 0"),
    MK_UINT_TEST("\x20", CBOR_ERR_NONE, 0L, -1, "Negative 0"),
    MK_UINT_TEST("\x40", CBOR_ERR_NONE, 0L, -1, "Bstr 0"),
    MK_UINT_TEST("\x60", CBOR_ERR_NONE, 0L, -1, "Tstr 0"),
    MK_UINT_TEST("\x80", CBOR_ERR_NONE, 0L, -1, "List 0"),
    MK_UINT_TEST("\xA0", CBOR_ERR_NONE, 0L, -1, "Map 0"),
    MK_UINT_TEST("\xC0", CBOR_ERR_NONE, 0L, -1, "Tag 0"),
    MK_UINT_TEST("\xE0", CBOR_ERR_NONE, 0L, -1, "Simple 0"),
    MK_UINT_TEST("\x18\x00", CBOR_ERR_NONE, 0L, -1, "00"),
    MK_UINT_TEST("\x19\x00\x00", CBOR_ERR_NONE, 0L, -1, "0000"),
    MK_UINT_TEST("\x1A\x00\x00\x00\x00", CBOR_ERR_NONE, 0L, -1, "00000000"),
#if BM_CBOR_INT_SIZE == 64
    MK_UINT_TEST("\x1B\x00\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_NONE, 0L, -1, "0000000000000000"),
#elif BM_CBOR_INT_SIZE == 32
    MK_UINT_TEST("\x1B\x00\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0L, 0, "0000000000000000"),
#endif
    MK_UINT_TEST("\x18", CBOR_ERR_OVERRUN, 0L, 0, "00-Overrun"),
    MK_UINT_TEST("\x19\x00", CBOR_ERR_OVERRUN, 0L, 0, "0000-Overrun"),
    MK_UINT_TEST("\x1A\x00\x00\x00", CBOR_ERR_OVERRUN, 0L, 0, "00000000-Overrun"),
#if BM_CBOR_INT_SIZE == 64
    MK_UINT_TEST("\x1B\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_OVERRUN, 0L, 0, "0000000000000000-Overrun"),
#endif
    MK_UINT_TEST("\x17", CBOR_ERR_NONE, 0x17L, -1, "0x17"),
    MK_UINT_TEST("\x18\x18", CBOR_ERR_NONE, 0x18L, -1, "0x18"),
    MK_UINT_TEST("\x18\xFF", CBOR_ERR_NONE, 0xFFL, -1, "0xFF"),
    MK_UINT_TEST("\x19\x00\xFF", CBOR_ERR_NONE, 0xFFL, -1, "0x00FF"),
    MK_UINT_TEST("\x19\x01\x00", CBOR_ERR_NONE, 0x100L, -1, "0x0100"),
    MK_UINT_TEST("\x19\x12\x34", CBOR_ERR_NONE, 0x1234L, -1, "0x1234"),
    MK_UINT_TEST("\x19\xFF\xFF", CBOR_ERR_NONE, 0xFFFFL, -1, "0xFFFF"),
    MK_UINT_TEST("\x1A\x00\x00\xFF\xFF", CBOR_ERR_NONE, 0xFFFFL, -1, "0x0000FFFF"),
    MK_UINT_TEST("\x1A\x00\x01\x00\x00", CBOR_ERR_NONE, 0x10000L, -1, "0x00010000"),
    MK_UINT_TEST("\x1A\x12\x34\x56\x78", CBOR_ERR_NONE, 0x12345678L, -1, "0x12345678"),
    MK_UINT_TEST("\x1A\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFL, -1, "0xFFFFFFFF"),
#if BM_CBOR_INT_SIZE == 64
    MK_UINT_TEST("\x1B\x00\x00\x00\x00\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFL, -1,  "0x00000000FFFFFFFF"),
    MK_UINT_TEST("\x1B\x00\x00\x00\x01\x00\x00\x00\x00", CBOR_ERR_NONE, 0x100000000L, -1, "0x0000000100000000"),
    MK_UINT_TEST("\x1B\x12\x34\x56\x78\x9A\xBC\xDE\xF0", CBOR_ERR_NONE, 0x123456789ABCDEF0L, -1, "0x123456789ABCDEF0"),
    MK_UINT_TEST("\x1B\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFFFFFFFFFL, -1, "0xFFFFFFFFFFFFFFFF"),
#endif
};
const size_t as_uint_test_cases_n = sizeof(as_uint_test_cases)/sizeof(as_uint_test_cases[0]);

int get_as_uint_test()
{
    const uint8_t *p;
    const uint8_t *end;
    bm_cbor_uint_t n;
    int rc;

    p = NULL;
    end = NULL;
    printf("\nRunning %lu tests in %s\n", as_uint_test_cases_n, __PRETTY_FUNCTION__ );

    for (size_t i = 0; i < as_uint_test_cases_n; i++) {
        n = 0;
        print_test(76, as_uint_test_cases[i].name);
        p = as_uint_test_cases[i].ip;
        end = p + as_uint_test_cases[i].len;
        const uint8_t* exp_p = p + as_uint_test_cases[i].offset;

        rc = bm_cbor_get_as_uint(&p, end, &n);

        // Check RC
        TEST_EQ_INT(as_uint_test_cases[i].rc, rc, 1);
        // Check n
        TEST_EQ_INT(as_uint_test_cases[i].expect, n, 1);
        // check p
        TEST_EQ_INT(exp_p, p, 1);
        printf("[%s]\n", "PASS");
    }

    return 0;
}


struct uint_test_case_s uint_test_cases[] = {
    MK_UINT_TEST("\x00", CBOR_ERR_NONE, 0L, -1, "Positive 0"),
    MK_UINT_TEST("\x20", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Negative 0"),
    MK_UINT_TEST("\x40", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Bstr 0"),
    MK_UINT_TEST("\x60", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Tstr 0"),
    MK_UINT_TEST("\x80", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "List 0"),
    MK_UINT_TEST("\xA0", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Map 0"),
    MK_UINT_TEST("\xC0", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Tag 0"),
    MK_UINT_TEST("\xE0", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Simple 0"),
};
const size_t uint_test_cases_n = sizeof(uint_test_cases)/sizeof(uint_test_cases[0]);

int get_uint_test() {
    const uint8_t *p;
    const uint8_t *end;
    bm_cbor_uint_t n;
    int rc;

    p = NULL;
    end = NULL;
    printf("\nRunning %lu tests in %s\n", uint_test_cases_n, __PRETTY_FUNCTION__ );

    for (size_t i = 0; i < uint_test_cases_n; i++) {
        n = 0;
        print_test(76, uint_test_cases[i].name);
        p = uint_test_cases[i].ip;
        end = p + uint_test_cases[i].len;
        const uint8_t* exp_p = p + uint_test_cases[i].offset;

        rc = bm_cbor_get_uint(&p, end, &n);

        // Check RC
        TEST_EQ_INT(uint_test_cases[i].rc, rc, 1);
        // Check n
        TEST_EQ_INT(uint_test_cases[i].expect, n, 1);
        // check p
        TEST_EQ_INT(exp_p, p, 1);
        printf("[%s]\n", "PASS");
    }

    return 0;
}

struct int_test_case_s {
    const uint8_t* ip;
    size_t len;
    int rc;
    bm_cbor_int_t expect;
    int offset;
    const char* name;
};

#define MK_INT_TEST(S, RC, E, O, NAME)\
    {(const uint8_t *)(S), sizeof(S)-1, (RC), (RC) && !(E)?0:((S)[0]&CBOR_TYPE_MASK) == CBOR_TYPE_NINT?-1-(E):(E), ((O) < 0 ? sizeof(S)-1 : (O)), (NAME)}

struct int_test_case_s int_test_cases[] = {
    MK_INT_TEST("\x00", CBOR_ERR_NONE, 0L, -1, "Positive 0"),
    MK_INT_TEST("\x20", CBOR_ERR_NONE, 0L, -1, "Negative 1"),
    MK_INT_TEST("\x40", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Bstr 0"),
    MK_INT_TEST("\x60", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Tstr 0"),
    MK_INT_TEST("\x80", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "List 0"),
    MK_INT_TEST("\xA0", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Map 0"),
    MK_INT_TEST("\xC0", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Tag 0"),
    MK_INT_TEST("\xE0", CBOR_ERR_TYPE_MISMATCH, 0L, 0, "Simple 0"),
    MK_INT_TEST("\x18\x00", CBOR_ERR_NONE, 0L, -1, "00"),
    MK_INT_TEST("\x19\x00\x00", CBOR_ERR_NONE, 0L, -1, "0000"),
    MK_INT_TEST("\x1A\x00\x00\x00\x00", CBOR_ERR_NONE, 0L, -1, "00000000"),
#if BM_CBOR_INT_SIZE == 64
    MK_INT_TEST("\x1B\x00\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_NONE, 0L, -1, "0000000000000000"),
#elif BM_CBOR_INT_SIZE == 32
    MK_INT_TEST("\x1B\x00\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0L, 0, "0000000000000000"),
#endif
    MK_INT_TEST("\x38\x00", CBOR_ERR_NONE, 0L, -1, "-01"),
    MK_INT_TEST("\x39\x00\x00", CBOR_ERR_NONE, 0L, -1, "-0001"),
    MK_INT_TEST("\x3A\x00\x00\x00\x00", CBOR_ERR_NONE, 0L, -1, "-00000001"),
#if BM_CBOR_INT_SIZE == 64
    MK_INT_TEST("\x3B\x00\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_NONE, 0L, -1, "-0000000000000001"),
#elif BM_CBOR_INT_SIZE == 32
    MK_INT_TEST("\x3B\x00\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0L, 0, "-0000000000000001"),
#endif
    MK_INT_TEST("\x18", CBOR_ERR_OVERRUN, 0L, 0, "00-Overrun"),
    MK_INT_TEST("\x19\x00", CBOR_ERR_OVERRUN, 0L, 0, "0000-Overrun"),
    MK_INT_TEST("\x1A\x00\x00\x00", CBOR_ERR_OVERRUN, 0L, 0, "00000000-Overrun"),    MK_INT_TEST("\x38", CBOR_ERR_OVERRUN, 0L, 0, "-00-Overrun"),
#if BM_CBOR_INT_SIZE == 64
    MK_INT_TEST("\x1B\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_OVERRUN, 0L, 0, "0000000000000000-Overrun"),
#endif
    MK_INT_TEST("\x39\x00", CBOR_ERR_OVERRUN, 0L, 0, "-0000-Overrun"),
    MK_INT_TEST("\x3A\x00\x00\x00", CBOR_ERR_OVERRUN, 0L, 0, "-00000000-Overrun"),
#if BM_CBOR_INT_SIZE == 64
    MK_INT_TEST("\x3B\x00\x00\x00\x00\x00\x00\x00", CBOR_ERR_OVERRUN, 0L, 0, "-0000000000000000-Overrun"),
#endif
    MK_INT_TEST("\x17", CBOR_ERR_NONE, 0x17L, -1, "0x17"),
    MK_INT_TEST("\x18\x18", CBOR_ERR_NONE, 0x18L, -1, "0x18"),
    MK_INT_TEST("\x18\xFF", CBOR_ERR_NONE, 0xFFL, -1, "0xFF"),
    MK_INT_TEST("\x19\x00\xFF", CBOR_ERR_NONE, 0xFFL, -1, "0x00FF"),
    MK_INT_TEST("\x19\x01\x00", CBOR_ERR_NONE, 0x100L, -1, "0x0100"),
    MK_INT_TEST("\x19\x12\x34", CBOR_ERR_NONE, 0x1234L, -1, "0x1234"),
    MK_INT_TEST("\x19\xFF\xFF", CBOR_ERR_NONE, 0xFFFFL, -1, "0xFFFF"),
    MK_INT_TEST("\x1A\x00\x00\xFF\xFF", CBOR_ERR_NONE, 0xFFFFL, -1, "0x0000FFFF"),
    MK_INT_TEST("\x1A\x00\x01\x00\x00", CBOR_ERR_NONE, 0x10000L, -1, "0x00010000"),
    MK_INT_TEST("\x1A\x12\x34\x56\x78", CBOR_ERR_NONE, 0x12345678L, -1, "0x12345678"),
#if BM_CBOR_INT_SIZE == 32
    MK_INT_TEST("\x1A\x7F\xFF\xFF\xFF", CBOR_ERR_NONE, 0x7FFFFFFFL, -1, "0x7FFFFFFF"),
    MK_INT_TEST("\x1A\x80\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Positive Overflow (0x80000000)"),
    MK_INT_TEST("\x1A\x80\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Positive Overflow (0xFFFFFFFF)"),
#elif BM_CBOR_INT_SIZE == 64
    MK_INT_TEST("\x1A\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFL, -1,  "0xFFFFFFFF"),
    MK_INT_TEST("\x1B\x00\x00\x00\x00\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFL, -1,  "0x00000000FFFFFFFF"),
    MK_INT_TEST("\x1B\x00\x00\x00\x01\x00\x00\x00\x00", CBOR_ERR_NONE, 0x100000000L, -1, "0x0000000100000000"),
    MK_INT_TEST("\x1B\x12\x34\x56\x78\x9A\xBC\xDE\xF0", CBOR_ERR_NONE, 0x123456789ABCDEF0L, -1, "0x123456789ABCDEF0"),
    MK_INT_TEST("\x1B\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0x7FFFFFFFFFFFFFFFL, -1, "0x7FFFFFFFFFFFFFFF"),
    MK_INT_TEST("\x1B\x80\x00\x00\x01\x00\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Positive Overflow (-0x8000000000000000)"),
    MK_INT_TEST("\x1B\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Positive Overflow (-0xFFFFFFFFFFFFFFFF)"),
#endif

    MK_INT_TEST("\x37", CBOR_ERR_NONE, 0x17L, -1, "-0x18"),
    MK_INT_TEST("\x38\x18", CBOR_ERR_NONE, 0x18L, -1, "-0x19"),
    MK_INT_TEST("\x38\xFF", CBOR_ERR_NONE, 0xFFL, -1, "-0x100"),
    MK_INT_TEST("\x39\x00\xFF", CBOR_ERR_NONE, 0xFFL, -1, "-0x0100"),
    MK_INT_TEST("\x39\x01\x00", CBOR_ERR_NONE, 0x100L, -1, "-0x0101"),
    MK_INT_TEST("\x39\x12\x34", CBOR_ERR_NONE, 0x1234L, -1, "-0x1235"),
    MK_INT_TEST("\x39\xFF\xFF", CBOR_ERR_NONE, 0xFFFFL, -1, "-0x10000"),
    MK_INT_TEST("\x3A\x00\x00\xFF\xFF", CBOR_ERR_NONE, 0xFFFFL, -1, "-0x00010000"),
    MK_INT_TEST("\x3A\x00\x01\x00\x00", CBOR_ERR_NONE, 0x10000L, -1, "-0x00010001"),
    MK_INT_TEST("\x3A\x12\x34\x56\x78", CBOR_ERR_NONE, 0x12345678L, -1, "-0x12345679"),
#if BM_CBOR_INT_SIZE == 32
    MK_INT_TEST("\x1A\x7F\xFF\xFF\xFF", CBOR_ERR_NONE, 0x7FFFFFFFL, -1, "0x7FFFFFFF"),
    MK_INT_TEST("\x3A\x80\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Negative Overflow (-0x80000001)"),
    MK_INT_TEST("\x3A\xFF\xFF\xFF\xFF", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Negative Overflow (-0x100000000)"),
#elif BM_CBOR_INT_SIZE == 64
    MK_INT_TEST("\x3A\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFL, -1, "-0x100000000"),
    MK_INT_TEST("\x3B\x00\x00\x00\x00\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0xFFFFFFFFL, -1,  "-0x0000000100000000"),
    MK_INT_TEST("\x3B\x00\x00\x00\x01\x00\x00\x00\x00", CBOR_ERR_NONE, 0x100000000L, -1, "-0x0000000100000001"),
    MK_INT_TEST("\x3B\x12\x34\x56\x78\x9A\xBC\xDE\xF0", CBOR_ERR_NONE, 0x123456789ABCDEF0L, -1, "-0x123456789ABCDEF1"),
    MK_INT_TEST("\x1B\x7F\xFF\xFF\xFF\xFF\xFF\xFF\xFF", CBOR_ERR_NONE, 0x7FFFFFFFFFFFFFFFL, -1, "-0x8000000000000000"),
    MK_INT_TEST("\x3B\x80\x00\x00\x01\x00\x00\x00\x00", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Negative Overflow (-0x8000000000000001)"),
    MK_INT_TEST("\x3B\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", CBOR_ERR_INTEGER_DECODE_OVERFLOW, 0, -1, "Negative Overflow (-0x10000000000000000)"),
#endif

};
const size_t int_test_cases_n = sizeof(int_test_cases)/sizeof(int_test_cases[0]);

int get_int_test() {
    const uint8_t *p;
    const uint8_t *end;
    bm_cbor_int_t n;
    int rc;

    p = NULL;
    end = NULL;
    printf("\nRunning %lu tests in %s\n", int_test_cases_n, __PRETTY_FUNCTION__ );

    for (size_t i = 0; i < int_test_cases_n; i++) {
        n = 0;
        print_test(76, int_test_cases[i].name);
        p = int_test_cases[i].ip;
        end = p + int_test_cases[i].len;
        const uint8_t* exp_p = p + int_test_cases[i].offset;

        rc = bm_cbor_get_int(&p, end, &n);

        // Check RC
        TEST_EQ_INT(int_test_cases[i].rc, rc, 1);
        // Check n
        TEST_EQ_INT(int_test_cases[i].expect, n, 1);
        // check p
        TEST_EQ_INT(exp_p, p, 1);
        printf("[%s]\n", "PASS");
    }

    return 0;
}

struct test_s test_cases[] = {
    {get_as_uint_test, "get_as_uint_test"},
    {get_uint_test, "get_uint_test"},
    {get_int_test, "get_int_test"},
};

#define MAXDESC (80 - 6 - 1 - 2)
int main(int argc, char* argv[])
{
    printf("Running %lu tests\n", (sizeof(test_cases)/sizeof(test_cases[0])));
    for (size_t i = 0; i < (sizeof(test_cases)/sizeof(test_cases[0])); i++) {
        char buf[MAXDESC + 1];
        strncpy(buf, test_cases[i].desc, MAXDESC);
        int dotlen = MAXDESC - strlen(test_cases[i].desc);
        printf("  %s.", buf);
        for (;dotlen>0;dotlen--) {
            printf(".");
        }
        int rc = test_cases[i].fn();
        printf("[%s]\n", rc?"FAIL":"PASS");
    }
    return 0;
}
