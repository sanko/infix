/**
 * @file 850_regression_cases.c
 * @brief A suite of regression tests for bugs discovered by fuzzing.
 * @ingroup test_suite
 *
 * @details This test file contains a collection of specific inputs that have been
 * identified by fuzzing tools (like libFuzzer and AFL) as causing a crash,
 * timeout, memory leak, or other bug in the past.
 *
 * Each test case consists of:
 * - A descriptive name of the bug it triggered.
 * - A Base64-encoded string representing the raw fuzzer input.
 * - The target component (`TARGET_TYPE_GENERATOR`, `TARGET_SIGNATURE_PARSER`, etc.)
 *   that the input should be sent to.
 *
 * By embedding these inputs into a permanent unit test, we can ensure that these
 * specific bugs do not reappear in future versions of the library. This forms a
 * crucial part of the project's quality assurance process. The `b64_decode`
 * helper from `fuzz_regression_helpers.h` is used to unpack the inputs at runtime.
 */

#define DBLTAP_IMPLEMENTATION
#include "common/double_tap.h"
#include "fuzz_helpers.h"
#include "fuzz_regression_helpers.h"
#include <infix/infix.h>

typedef enum { TARGET_TYPE_GENERATOR, TARGET_SIGNATURE_PARSER, TARGET_TRAMPOLINE_GENERATOR } fuzzer_target_t;

typedef struct {
    const char * name;
    const char * b64_input;
    fuzzer_target_t target;
    infix_status expected_status;
} regression_test_case_t;

static const regression_test_case_t regression_tests[] = {
    {.name = "Timeout in SysV ABI Classifier (Wide Structs)",
     .b64_input = "T09PT09OT/////8I//////////9sbARsbGwAbGxsbGxPT09PT09PT09PT+8=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Stack Overflow in Signature Parser (Deep Nesting)",
     .b64_input = "e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7e3t7aX19fX19fX19fX19fX19fX19fX19fX19f"
                  "X19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fX19fQ==",
     .target = TARGET_SIGNATURE_PARSER,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},
    {.name = "Timeout in SysV Classifier (Zero-Sized Array)",
     .b64_input = "A/oEAA==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Timeout in SysV Classifier (Recursive Packed Structs)",
     .b64_input = "/v7+/v7+/v///3///////wD+/v7+/v7+/v7+/qg=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Timeout in Type Generator (Wide Nested Aggregates)",
     .b64_input = "LP///////////wAAAAP//////////////////////////+Li4g==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (SSE/SSE case)",
     .b64_input = "zgAAzwDP////////////////////////////////////////////////////////T08PT09PT0////8POuJNT08=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (Mixed GPR/SSE case)",
     .b64_input = "LQAAAAAAAM8AQ/////////////////////////////////////////////////////////////////////////////////"
                  "////////////////////9DQ0MAAAA=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (XMM index bug)",
     .b64_input = "////////p6X/D36lAAAAAAABAAAAAAAAAEoAAAAAAAAIAAAAAAAAAP85AI4A/z//"
                  "KQA6AAAAAAAAvgAAAAAAVAAAAH4AAAAAAAAAAAAAAAAAAACnYP8PfqUAAAAAAAAAAAAAAAAAAAAAAOObggMAAAAAAAAAcB46JDjM"
                  "AQAAAAAAAAAAAAAAAAAAAAAAAAAQUwAAAP///wD//+np5+l6AA==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (SSE/INTEGER pair bug)",
     .b64_input = "Hh4eOh4eHh8AAABWHh4eHh4eAgs=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (Mixed pair bug 2)",
     .b64_input = "JCUlJSUlJQFNTaUl29qy/wAATU0vJRQA957pPwAuCQ==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds)",
     .b64_input = "qqqqqrgcCgAwUAAAqqo6FxcXLKqqLQCMAg==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (XMM out of bounds 2)",
     .b64_input = "ojQ6Ojo6AAAAAAAAEQA6Ojo6Ojo6Ojo=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds 2)",
     .b64_input = "qwEeHh4eHh4eAAEDAB4eHh4eHh4eHiT//w==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds 3)",
     .b64_input = "gAAASABPT09PT08VAAAAAAACEQAAAABPT08=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (GPR out of bounds 4)",
     .b64_input = "AQgB29vbATuIAIDb29vb2wAA29vb29s=",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (XMM index > 7)",
     .b64_input = "aAAAAA8AAAAAAAAAAAAAAAAAAAAgAPkA+f/////////+/////////////////yz//3///+lo",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Global buffer overflow in SysV classifier (XMM index bug)",
     .b64_input = "AQAAAAAAAAAAAAAAAAAAAAAAAAAQUwAAAP///wD//+np5+l6AA==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "SysV Classifier nullptr member type dereference",
     .b64_input = "/////////////////////////////////wDJAIAAAAAA/////////////////////////////////////7//////CA==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "nullptr type in arg_types for reverse trampoline (case 1)",
     .b64_input = "iAOysoiVA7L////////////////N////C////////////////4X/////////////9///////zf////8L////////////////////"
                  "////////9/8=",
     .target = TARGET_TRAMPOLINE_GENERATOR,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},
    {.name = "Timeout in SysV Classifier (Zero-Sized Array)",
     .b64_input = "PjL/gUAAAAAAAAAAAAAAAAAAAAAAAAAAAAoAAJWVlZWV/////////////////////////////////////5WVlZWFPg==",
     .target = TARGET_TYPE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "nullptr type in arg_types for reverse trampoline (case 2)",
     .b64_input = "0NT//////////wBo//3//9r//2n////////////+/////////////////yz//3///+lo",
     .target = TARGET_TRAMPOLINE_GENERATOR,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},
};

static void run_regression_case(const regression_test_case_t * test) {
    subtest(test->name) {
        plan(2);

        size_t data_size;
        unsigned char * data = b64_decode(test->b64_input, &data_size);

        ok(data != nullptr, "Base64 decoded successfully");
        if (!data) {
            fail("Skipping test due to Base64 decode failure.");
            return;
        }

        if (test->target == TARGET_TYPE_GENERATOR) {
            fuzzer_input in = {(const uint8_t *)data, data_size};
            infix_arena_t * arena = infix_arena_create(65536);
            if (!arena) {
                fail("Failed to create arena for type generator test.");
                free(data);
                return;
            }

            size_t total_fields = 0;
            infix_type * generated_type = generate_random_type(arena, &in, 0, &total_fields);

            if (test->expected_status == INFIX_SUCCESS) {
                if (arena->error) {
                    fail("Type generation failed due to internal arena error, but was expected to succeed.");
                }
                else {
                    pass("Successfully processed pathological input without timeout/crash.");
                }
            }
            else {
                ok(generated_type == nullptr || arena->error, "Generator correctly failed on invalid input.");
            }
            infix_arena_destroy(arena);
        }
        else if (test->target == TARGET_SIGNATURE_PARSER) {
            char * signature = (char *)malloc(data_size + 1);
            memcpy(signature, data, data_size);
            signature[data_size] = '\0';

            infix_type * type = nullptr;
            infix_arena_t * arena = nullptr;
            infix_status status = infix_type_from_signature(&type, &arena, signature, nullptr);

            ok(status == test->expected_status,
               "Parser returned correct status (expected %d, got %d)",
               test->expected_status,
               status);

            infix_arena_destroy(arena);
            free(signature);
        }
        else if (test->target == TARGET_TRAMPOLINE_GENERATOR) {
            fuzzer_input in = {(const uint8_t *)data, data_size};
            infix_arena_t * arena = infix_arena_create(65536);
            if (!arena) {
                fail("Failed to create arena for trampoline generator test.");
                free(data);
                return;
            }

            size_t total_fields = 0;
            infix_type * type_pool[1] = {generate_random_type(arena, &in, 0, &total_fields)};
            if (type_pool[0] == nullptr)
                type_pool[0] = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);

            infix_type * arg_types[] = {nullptr};

            infix_forward_t * fwd = nullptr;
            infix_status fwd_status = infix_forward_create_unbound_manual(&fwd, type_pool[0], arg_types, 1, 1);
            infix_forward_destroy(fwd);

            infix_reverse_t * rev = nullptr;
            infix_status rev_status =
                infix_reverse_create_callback_manual(&rev, type_pool[0], arg_types, 1, 1, nullptr);
            infix_reverse_destroy(rev);

            ok(fwd_status == test->expected_status && rev_status == test->expected_status,
               "Trampoline generators correctly returned expected status %d",
               test->expected_status);
            infix_arena_destroy(arena);
        }

        free(data);
    }
}

TEST {
    size_t num_tests = sizeof(regression_tests) / sizeof(regression_tests[0]);
    plan(num_tests);

    for (size_t i = 0; i < num_tests; ++i)
        run_regression_case(&regression_tests[i]);
}
