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
 * crucial part of the project's quality assurance process. The `infix_b64_decode`
 * helper from `fuzz_regression_helpers.h` is used to unpack the inputs at runtime.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "fuzz_helpers.h"
#include "fuzz_regression_helpers.h"
#include <infix/infix.h>

// Dummy handler for trampoline generation tests
void dummy_reg_handler(void) {}

// Dummy Handlers for Direct Marshalling (Addresses needed for JIT generation)
static infix_direct_value_t dummy_scalar_marshaller(void * src) {
    (void)src;
    return (infix_direct_value_t){0};
}
static void dummy_agg_marshaller(void * src, void * dest, const infix_type * type) {
    (void)src;
    (void)dest;
    (void)type;
}
static void dummy_writeback(void * src, void * c_data, const infix_type * type) {
    (void)src;
    (void)c_data;
    (void)type;
}
static void dummy_target_func(void) {}

typedef enum {
    TARGET_TYPE_GENERATOR,
    TARGET_SIGNATURE_PARSER,
    TARGET_TRAMPOLINE_GENERATOR,
    TARGET_DIRECT_TRAMPOLINE_GENERATOR
} fuzzer_target_t;
typedef struct {
    const char * name;
    const char * b64_input;
    fuzzer_target_t target;
    infix_status expected_status;
} regression_test_case_t;
static const regression_test_case_t regression_tests[] = {
    {.name = "Use-after-free in fuzzer due to registry arena reallocation",
     .b64_input = "PAlakABf",
     .target = TARGET_TRAMPOLINE_GENERATOR,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},
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
    {.name = "Roundtrip Fuzzer: Recursion depth mismatch",
     .b64_input = "XgD//yAgICAgICAgICAgICAgICAgICAgICAgICAgpQD/PwIg",
     .target = TARGET_SIGNATURE_PARSER,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},  // Expect parser error (Depth Exceeded), not crash
    {.name = "Roundtrip Fuzzer: Zero-sized FAM element",
     .b64_input =
         "J5FqATAwcDAwMDAwMDAwmjAwMDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMDAwMDAwMDAwMDAwMDAwMDD///8AAAAAADAwKgMwJw==",
     .target = TARGET_SIGNATURE_PARSER,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},  // Expect parser error (Invalid Member Type)
    {.name = "Roundtrip Fuzzer: Packed struct alignment lost",
     .b64_input = "BgAAAA==",  // "!\x02\x00\x00" -> "!2:{...}" (simplified input)
     .target = TARGET_TRAMPOLINE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Roundtrip Fuzzer: Packed struct alignment overwritten by member",
     .b64_input = "BgDOAOI=",  // "!2:{fuzz:[0:*void]}"
     .target = TARGET_TRAMPOLINE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
    {.name = "Roundtrip Fuzzer: Integer overflow in deep array nesting",
     .b64_input = "/////wMDAwMDAwMDAwMDAwMDIgADA///////////////Cyoq+Q==",
     .target = TARGET_SIGNATURE_PARSER,
     .expected_status = INFIX_ERROR_INVALID_ARGUMENT},  // Expect parser error (Integer Overflow)
    {.name = "Leak in direct trampoline due to uninitialized ref_count",
     .b64_input = "CQEAJA==",
     .target = TARGET_DIRECT_TRAMPOLINE_GENERATOR,
     .expected_status = INFIX_SUCCESS},
};

static void run_regression_case(const regression_test_case_t * test) {
    subtest(test->name) {
        plan(2);
        size_t data_size;
        unsigned char * data = infix_b64_decode(test->b64_input, &data_size);
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
            if (test->expected_status == INFIX_SUCCESS)
                if (arena->error)
                    fail("Type generation failed due to internal arena error, but was expected to succeed.");
                else
                    pass("Successfully processed pathological input without timeout/crash.");
            else
                ok(generated_type == nullptr || arena->error, "Generator correctly failed on invalid input.");
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
            infix_type * generated_type = generate_random_type(arena, &in, 0, &total_fields);

            // Ensure we have a valid type. If the fuzzer input was short/garbage,
            // generated_type might be NULL. Use a fallback to ensure the API call happens.
            if (generated_type == nullptr)
                generated_type = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);

            // If we expect success, use 0 arguments to avoid the hardcoded nullptr error.
            // If we expect failure (negative testing), use 1 argument which defaults to nullptr in arg_types[0].
            size_t num_args = (test->expected_status == INFIX_SUCCESS) ? 0 : 1;

            infix_type * arg_types[] = {nullptr};
            infix_forward_t * fwd = nullptr;
            infix_status fwd_status =
                infix_forward_create_unbound_manual(&fwd, generated_type, arg_types, num_args, num_args);
            if (fwd)
                infix_forward_destroy(fwd);

            infix_reverse_t * rev = nullptr;
            // For reverse callback, we need a handler. Passing nullptr is fine if we expect failure,
            // but for success we need a dummy.
            void * handler = (test->expected_status == INFIX_SUCCESS) ? (void *)dummy_reg_handler : nullptr;

            infix_status rev_status =
                infix_reverse_create_callback_manual(&rev, generated_type, arg_types, num_args, num_args, handler);
            if (rev)
                infix_reverse_destroy(rev);

            ok(fwd_status == test->expected_status && rev_status == test->expected_status,
               "Trampoline generators correctly returned expected status %d (Got Fwd:%d, Rev:%d)",
               test->expected_status,
               fwd_status,
               rev_status);
            infix_arena_destroy(arena);
        }
        else if (test->target == TARGET_DIRECT_TRAMPOLINE_GENERATOR) {
            fuzzer_input in = {(const uint8_t *)data, data_size};
            infix_arena_t * arena = infix_arena_create(65536);
            if (!arena) {
                fail("Failed to create arena for direct trampoline test.");
                free(data);
                return;
            }
            size_t total_fields = 0;
            infix_type * ret_type = generate_random_type(arena, &in, 0, &total_fields);
            if (!ret_type)
                ret_type = infix_type_create_void();

            uint8_t arg_count_byte;
            if (!consume_uint8_t(&in, &arg_count_byte))
                arg_count_byte = 0;

            size_t num_args = arg_count_byte % MAX_ARGS_IN_SIGNATURE;
            infix_type ** arg_types = (infix_type **)calloc(num_args, sizeof(infix_type *));
            infix_direct_arg_handler_t * handlers =
                (infix_direct_arg_handler_t *)calloc(num_args, sizeof(infix_direct_arg_handler_t));

            for (size_t i = 0; i < num_args; ++i) {
                arg_types[i] = generate_random_type(arena, &in, 0, &total_fields);
                if (!arg_types[i])
                    arg_types[i] = infix_type_create_primitive(INFIX_PRIMITIVE_SINT32);

                uint8_t handler_choice;
                if (!consume_uint8_t(&in, &handler_choice))
                    handler_choice = 0;

                if (arg_types[i]->category == INFIX_TYPE_STRUCT || arg_types[i]->category == INFIX_TYPE_UNION ||
                    arg_types[i]->category == INFIX_TYPE_ARRAY || arg_types[i]->category == INFIX_TYPE_COMPLEX) {
                    handlers[i].aggregate_marshaller = &dummy_agg_marshaller;
                }
                else
                    handlers[i].scalar_marshaller = &dummy_scalar_marshaller;

                if (arg_types[i]->category == INFIX_TYPE_POINTER && (handler_choice % 2 == 0))
                    handlers[i].writeback_handler = &dummy_writeback;
            }

            char signature[4096] = {0};
            char * p = signature;
            size_t remain = sizeof(signature) - 1;

            if (remain >= 1) {
                *p++ = '(';
                remain--;
            }
            for (size_t i = 0; i < num_args; ++i) {
                if (i > 0 && remain >= 1) {
                    *p++ = ',';
                    remain--;
                }
                (void)infix_type_print(p, remain + 1, arg_types[i], INFIX_DIALECT_SIGNATURE);
                size_t len = strlen(p);
                p += len;
                remain -= len;
            }
            if (remain >= 3) {
                memcpy(p, ")->", 3);
                p += 3;
                remain -= 3;
            }
            (void)infix_type_print(p, remain + 1, ret_type, INFIX_DIALECT_SIGNATURE);

            infix_forward_t * trampoline = NULL;
            infix_status status =
                infix_forward_create_direct(&trampoline, signature, (void *)&dummy_target_func, handlers, NULL);

            if (status == INFIX_SUCCESS)
                infix_forward_destroy(trampoline);

            ok(status == test->expected_status,
               "Direct trampoline generator returned expected status %d (Got: %d)",
               test->expected_status,
               status);

            free(arg_types);
            free(handlers);
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
