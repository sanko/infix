/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file 004_signatures.c
 * @brief Tests the high-level string-based signature API.
 *
 * @details This test suite verifies the functionality and robustness of the
 * `ffi_create_forward_trampoline_from_signature` API. It covers:
 * 1.  Happy Paths: Correctly parsing and generating trampolines for simple
 *     primitive, pointer, and variadic function signatures.
 * 2.  Advanced Packed Structs: Verifying the parsing of the complex
 *     `p(size,align){type:offset;...}` syntax.
 * 3.  Error Handling: Ensuring the parser correctly rejects a wide variety of
 *     malformed and invalid signature strings.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Native C Target Functions
int add_ints(int a, int b) {
    return a + b;
}
#pragma pack(push, 1)
typedef struct {
    char a;
    uint64_t b;
} PackedStruct;
#pragma pack(pop)
int process_packed_struct(PackedStruct p) {
    if (p.a == 'X' && p.b == 0xDEADBEEFCAFEBABE)
        return 42;
    return -1;
}

// Handler and harness for reverse trampoline test
int multiply_handler(int a, int b) {
    return a * b;
}
void call_int_int_cb(int (*func)(int, int)) {
    int result = func(10, 5);
    ok(result == 50, "Callback returned correct result (10 * 5 = 50)");
}

TEST {
    plan(4);

    subtest("Simple and Variadic Signatures") {
        plan(2);

        subtest("Simple signature: 'ii => i'") {
            plan(2);
            ffi_trampoline_t * trampoline = NULL;
            ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, "ii => i");
            ok(status == FFI_SUCCESS, "Trampoline created successfully from 'ii => i'");
            if (trampoline) {
                int a = 30, b = 12;
                int result = 0;
                void * args[] = {&a, &b};
                ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void *)add_ints, &result, args);
                ok(result == 42, "add_ints(30, 12) returned 42");
            }
            else {
                skip(1, "Test skipped due to creation failure");
            }
            ffi_trampoline_free(trampoline);
        }

        subtest("Variadic signature: 'c*.d => i'") {
            plan(2);
            ffi_trampoline_t * trampoline = NULL;
            // Use 'c*' for const char*
            ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, "c*.d => i");
            ok(status == FFI_SUCCESS, "Trampoline created successfully from 'c*.d => i'");
            if (trampoline) {
                const char * fmt = "Number is %.2f";
                double val = 3.14;
                void * args[] = {&fmt, &val};
                int ret = 0;
                ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void *)printf, &ret, args);
                ok(ret > 0, "Variadic call to printf executed without crashing");
            }
            else {
                skip(1, "Test skipped due to creation failure");
            }
            ffi_trampoline_free(trampoline);
        }
    }

    subtest("Packed Struct Signature") {
        plan(2);

        size_t total_size = sizeof(PackedStruct);
        size_t alignment = _Alignof(PackedStruct);
        size_t offset_a = offsetof(PackedStruct, a);
        size_t offset_b = offsetof(PackedStruct, b);

        char signature[256];
        snprintf(signature,
                 sizeof(signature),
                 "p(%llu,%llu){c:%llu;y:%llu} => i",
                 (unsigned long long)total_size,
                 (unsigned long long)alignment,
                 (unsigned long long)offset_a,
                 (unsigned long long)offset_b);

        note("Testing with generated signature: %s", signature);

        ffi_trampoline_t * trampoline = NULL;
        ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, signature);
        ok(status == FFI_SUCCESS, "Trampoline created successfully from packed struct signature");

        if (trampoline) {
            PackedStruct data = {'X', 0xDEADBEEFCAFEBABE};
            int result = 0;
            void * args[] = {&data};
            ((ffi_cif_func)ffi_trampoline_get_code(trampoline))((void *)process_packed_struct, &result, args);
            ok(result == 42, "Packed struct passed and processed correctly");
        }
        else {
            skip(1, "Test skipped due to creation failure");
        }
        ffi_trampoline_free(trampoline);
    }


    subtest("Reverse Trampoline Signatures") {
        plan(2);

        const char * signature = "ii => i";
        ffi_reverse_trampoline_t * rt = NULL;
        ffi_status status =
            ffi_create_reverse_trampoline_from_signature(&rt, signature, (void *)multiply_handler, NULL);

        ok(status == FFI_SUCCESS && rt != NULL, "Reverse trampoline created successfully from signature");

        if (rt) {
            typedef int (*native_func_ptr)(int, int);
            native_func_ptr func_ptr = (native_func_ptr)rt->exec_code.rx_ptr;
            call_int_int_cb(func_ptr);
        }
        else {
            skip(1, "Test skipped due to creation failure");
        }

        ffi_reverse_trampoline_free(rt);
    }

    subtest("Signature Parsing Error Handling") {
        const char * bad_signatures[] = {"i =>",
                                         "=> i",
                                         "i => z",
                                         "ii > i",
                                         "{i;j => i",
                                         "p{i:0;j:4} => v",
                                         "p(8,4){i:0;j} => v",
                                         "p(8,4){i:0:j:4} => v",
                                         "i[abc] => v",
                                         "i[] => v",
                                         NULL};

        int num_tests = 0;
        for (const char ** s = bad_signatures; *s != NULL; ++s)
            num_tests++;
        plan(num_tests);

        for (int i = 0; bad_signatures[i] != NULL; ++i) {
            ffi_trampoline_t * trampoline = NULL;
            ffi_status status = ffi_create_forward_trampoline_from_signature(&trampoline, bad_signatures[i]);
            ok(status == FFI_ERROR_INVALID_ARGUMENT && trampoline == NULL,
               "Correctly failed to parse invalid signature: \"%s\"",
               bad_signatures[i]);
            ffi_trampoline_free(trampoline);
        }
    }
}
