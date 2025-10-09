#pragma once
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
 * @file double_tap.h
 * @brief A simple, header-only TAP14-compatible testing framework for C.
 * @ingroup internal_testing
 *
 * @internal
 * This file provides a minimal but powerful testing harness inspired by the
 * Test Anything Protocol (TAP). It allows developers to write tests for the `infix`
 * library in a structured way, plan the number of tests, create subtests, and
 * produce standardized, machine-readable output. The entire framework is
 * controlled by preprocessor macros, allowing it to be completely compiled out
 * in non-test builds.
 *
 * **Usage:**
 * 1.  **Enable Testing:** Define `DBLTAP_ENABLE` before including this header.
 * 2.  **Create Implementation:** In *exactly one* source file, define
 *     `DBLTAP_IMPLEMENTATION` before including this header to generate the
 *     function bodies.
 *
 * **Thread Safety:** The implementation is thread-safe without locks. It uses
 * Thread-Local Storage (TLS) for all test state and lock-free atomics for the
 * global failure count.
 * @endinternal
 */

// The main toggle for the entire framework.
#ifdef DBLTAP_ENABLE

#define TAP_VERSION 13

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Platform-specific includes for one-time global initialization.
#if defined(_WIN32) || defined(__CYGWIN__)
#include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
#include <pthread.h>
#endif

// C11 atomics with fallbacks for lock-free global counters.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
#include <stdatomic.h>
#define TAP_ATOMIC_SIZE_T _Atomic size_t
#define TAP_ATOMIC_FETCH_ADD(ptr, val) atomic_fetch_add(ptr, val)
#elif defined(__GNUC__) || defined(__clang__)
#define TAP_ATOMIC_SIZE_T size_t
#define TAP_ATOMIC_FETCH_ADD(ptr, val) __sync_fetch_and_add(ptr, val)
#else
// Fallback for compilers without atomics: not thread-safe.
#define TAP_ATOMIC_SIZE_T size_t
#define TAP_ATOMIC_FETCH_ADD(ptr, val) ((*ptr) += (val))
#warning "Compiler does not support C11 atomics or GCC builtins; global counters will not be thread-safe."
#endif

// C11 thread-local storage with fallbacks for older compilers.
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_THREADS__)
#define TAP_THREAD_LOCAL _Thread_local
#elif defined(__GNUC__) || defined(__clang__)
#define TAP_THREAD_LOCAL __thread
#elif defined(_MSC_VER)
#define TAP_THREAD_LOCAL __declspec(thread)
#else
#define TAP_THREAD_LOCAL
#warning "Compiler does not support thread-local storage; tests will not be thread-safe."
#endif

// For printf-like format checking by GCC/Clang.
#if defined(__GNUC__) || defined(__clang__)
#define DBLTAP_PRINTF_FORMAT(fmt_index, arg_index) __attribute__((format(printf, fmt_index, arg_index)))
#else
#define DBLTAP_PRINTF_FORMAT(fmt_index, arg_index)
#endif

void tap_init(void);
void tap_plan(size_t count);
int tap_done(void);
void tap_bail_out(const char * reason, ...) DBLTAP_PRINTF_FORMAT(1, 2);
bool tap_ok(bool condition, const char * file, int line, const char * func, const char * expr, const char * name, ...)
    DBLTAP_PRINTF_FORMAT(6, 7);
bool tap_subtest_start(const char * name);
bool tap_subtest_end(void);
void tap_todo_start(const char * reason, ...) DBLTAP_PRINTF_FORMAT(1, 2);
void tap_todo_end(void);
void tap_skip(size_t count, const char * reason, ...) DBLTAP_PRINTF_FORMAT(2, 3);
void tap_skip_all(const char * reason, ...) DBLTAP_PRINTF_FORMAT(1, 2);
void diag(const char * fmt, ...) DBLTAP_PRINTF_FORMAT(1, 2);
void tap_note(const char * fmt, ...) DBLTAP_PRINTF_FORMAT(1, 2);

#define plan(count) tap_plan(count)
#define done() tap_done()
#define bail_out(...) tap_bail_out(__VA_ARGS__)
#define ok(cond, ...) tap_ok(!!(cond), __FILE__, __LINE__, __func__, #cond, __VA_ARGS__)
#define pass(...) ok(true, __VA_ARGS__)
#define fail(...) ok(false, __VA_ARGS__)
#define subtest(name) \
    for (bool _tap_subtest_once = tap_subtest_start(name); _tap_subtest_once; _tap_subtest_once = tap_subtest_end())
#define skip(count, ...) tap_skip(count, __VA_ARGS__)
#define skip_all(...) tap_skip_all(__VA_ARGS__)
#define TODO(reason) \
    for (int _tap_todo_once = (tap_todo_start(reason), 1); _tap_todo_once; _tap_todo_once = (tap_todo_end(), 0))
#define diag(...) diag(__VA_ARGS__)

#ifndef note
#define note(...) tap_note(__VA_ARGS__)
#endif

#define TEST void test_body(void)
void test_body(void);

#else  // DBLTAP_ENABLE is NOT defined

// No-Op Stubs for when testing is disabled.
#define plan(count) ((void)0)
#define done() (0)
#define bail_out(...)                  \
    do {                               \
        fprintf(stderr, "Bail out! "); \
        fprintf(stderr, __VA_ARGS__);  \
        fprintf(stderr, "\n");         \
        exit(1);                       \
    } while (0)
#define ok(cond, ...) (true)
#define pass(...) ((void)0)
#define fail(...) ((void)0)
#define subtest(name) if (0)
#define skip(count, ...) ((void)0)
#define skip_all(...) ((void)0)
#define TODO(reason, ...) if (0)
#define diag(...) ((void)0)
#ifndef note
#define note(...) ((void)0)
#endif
#define TEST         \
    int main(void) { \
        return 0;    \
    }

#endif  // DBLTAP_ENABLE

#if defined(DBLTAP_ENABLE) && defined(DBLTAP_IMPLEMENTATION)

/*
 * @internal
 * @brief Holds the complete state for a single test context (main test or subtest).
 * Each thread gets its own stack of these structures to manage nested subtests.
 */
typedef struct {
    size_t plan;
    size_t count;
    size_t failed;
    size_t failed_todo;
    int indent_level;
    bool has_plan;
    bool skipping;
    bool todo;
    char subtest_name[256];
    char todo_reason[256];
    char skip_reason[256];
} tap_state_t;

#define MAX_DEPTH 16
#define NO_PLAN ((size_t)-1)

// Thread-Safe State Management

/*
 * Each thread gets its own private state stack using Thread-Local Storage (TLS).
 * This is the key to achieving thread-safety without locks for most operations.
 * `current_state` points to the active state on the current thread's stack.
 */
static TAP_THREAD_LOCAL tap_state_t state_stack[MAX_DEPTH];
static TAP_THREAD_LOCAL tap_state_t * current_state = NULL;

/*
 * A global counter for the final exit code, updated using lock-free atomics.
 * This is the only piece of state shared between threads.
 */
static TAP_ATOMIC_SIZE_T g_total_failed = 0;

/*
 * One-time initialization for global setup (e.g., printing the TAP version header).
 * This uses platform-specific, thread-safe "once" mechanisms.
 */
#if defined(_WIN32) || defined(__CYGWIN__)
static INIT_ONCE g_tap_init_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK _tap_init_routine(PINIT_ONCE initOnce, PVOID param, PVOID * context) {
    (void)initOnce;
    (void)param;
    (void)context;
    printf("TAP version %d\n", TAP_VERSION);
    fflush(stdout);
    return TRUE;
}
#elif defined(__unix__) || defined(__APPLE__)
static pthread_once_t g_tap_init_once = PTHREAD_ONCE_INIT;
static void _tap_init_routine(void) {
    printf("TAP version %d\n", TAP_VERSION);
    fflush(stdout);
}
#endif

/*
 * This internal function must be called at the start of every public API function.
 * It ensures both global (TAP version) and thread-local (current_state) initialization
 * have occurred for the current thread.
 */
static void _tap_ensure_initialized(void) {
#if defined(_WIN32) || defined(__CYGWIN__)
    InitOnceExecuteOnce(&g_tap_init_once, _tap_init_routine, NULL, NULL);
#elif defined(__unix__) || defined(__APPLE__)
    pthread_once(&g_tap_init_once, _tap_init_routine);
#endif
    if (!current_state) {
        current_state = &state_stack[0];
        memset(current_state, 0, sizeof(tap_state_t));
        current_state->plan = NO_PLAN;
    }
}

// Private Helper Functions

static void print_indent(FILE * stream) {
    _tap_ensure_initialized();
    for (int i = 0; i < current_state->indent_level; ++i)
        fprintf(stream, "    ");
}

/*
 * Pushes a new, clean state onto the current thread's state stack.
 * Used when entering a subtest.
 */
static void push_state(void) {
    if (current_state >= &state_stack[MAX_DEPTH - 1])
        tap_bail_out("Exceeded maximum subtest depth of %d", MAX_DEPTH);
    tap_state_t * parent = current_state;
    current_state++;
    memset(current_state, 0, sizeof(tap_state_t));
    current_state->plan = NO_PLAN;
    current_state->indent_level = parent->indent_level + 1;
    // Inherit the 'todo' status from the parent.
    if (parent->todo) {
        current_state->todo = true;
        snprintf(current_state->todo_reason, sizeof(current_state->todo_reason), "%s", parent->todo_reason);
    }
}

/*
 * Pops the current state, returning to the parent's context.
 * Used when exiting a subtest.
 */
static void pop_state(void) {
    if (current_state <= &state_stack[0])
        tap_bail_out("Internal error: Attempted to pop base test state");
    current_state--;
}

// Public API Implementation

void tap_init(void) {
    _tap_ensure_initialized();
}

void tap_plan(size_t count) {
    _tap_ensure_initialized();
    if (current_state->has_plan || current_state->count > 0)
        tap_bail_out("Plan declared after tests have run or a plan was already set");
    current_state->plan = count;
    current_state->has_plan = true;
    print_indent(stdout);
    printf("1..%llu\n", (unsigned long long)count);
    fflush(stdout);
}

bool tap_ok(bool condition, const char * file, int line, const char * func, const char * expr, const char * name, ...) {
    _tap_ensure_initialized();
    if (current_state->skipping) {
        current_state->count++;  // Skipped tests still count towards the plan.
        return true;
    }

    char name_buffer[256] = {0};
    if (name && name[0] != '\0') {
        va_list args;
        va_start(args, name);
        vsnprintf(name_buffer, sizeof(name_buffer), name, args);
        va_end(args);
    }

    current_state->count++;

    if (!condition) {
        if (current_state->todo)
            current_state->failed_todo++;
        else {
            current_state->failed++;
            if (current_state == &state_stack[0])
                TAP_ATOMIC_FETCH_ADD(&g_total_failed, 1);
        }
    }

    print_indent(stdout);
    printf("%s %llu", condition ? "ok" : "not ok", (unsigned long long)current_state->count);
    if (name_buffer[0] != '\0')
        printf(" - %s", name_buffer);

    if (current_state->todo)
        printf(" # TODO %s", current_state->todo_reason);

    printf("\n");

    if (!condition && !current_state->todo) {
        // In case of failure, print diagnostic information in YAML block format.
        print_indent(stdout);
        fprintf(stdout, "#\n");
        print_indent(stdout);
        fprintf(stdout, "#   message: 'Test failed'\n");
        print_indent(stdout);
        fprintf(stdout, "#   severity: fail\n");
        print_indent(stdout);
        fprintf(stdout, "#   data:\n");
        print_indent(stdout);
        fprintf(stdout, "#     file: %s\n", file);
        print_indent(stdout);
        fprintf(stdout, "#     line: %d\n", line);
        print_indent(stdout);
        fprintf(stdout, "#     function: %s\n", func);
        print_indent(stdout);
        fprintf(stdout, "#     expression: '%s'\n", expr);
        print_indent(stdout);
        fprintf(stdout, "#   ...\n");
    }
    fflush(stdout);
    return condition;
}

void tap_skip(size_t count, const char * reason, ...) {
    _tap_ensure_initialized();
    char buffer[256];
    va_list args;
    va_start(args, reason);
    vsnprintf(buffer, sizeof(buffer), reason, args);
    va_end(args);
    for (size_t i = 0; i < count; ++i) {
        current_state->count++;
        print_indent(stdout);
        printf("ok %llu # SKIP %s\n", (unsigned long long)current_state->count, buffer);
    }
    fflush(stdout);
}

void tap_skip_all(const char * reason, ...) {
    _tap_ensure_initialized();
    current_state->skipping = true;
    va_list args;
    va_start(args, reason);
    vsnprintf(current_state->skip_reason, sizeof(current_state->skip_reason), reason, args);
    va_end(args);
}

void tap_todo_start(const char * reason, ...) {
    _tap_ensure_initialized();
    current_state->todo = true;
    va_list args;
    va_start(args, reason);
    vsnprintf(current_state->todo_reason, sizeof(current_state->todo_reason), reason, args);
    va_end(args);
}

void tap_todo_end(void) {
    _tap_ensure_initialized();
    current_state->todo = false;
    current_state->todo_reason[0] = '\0';
}

void diag(const char * fmt, ...) {
    _tap_ensure_initialized();
    print_indent(stderr);
    fprintf(stderr, "# ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputs("\n", stderr);
    fflush(stderr);
}

void tap_note(const char * fmt, ...) {
    _tap_ensure_initialized();
    print_indent(stdout);
    fprintf(stdout, "# ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);
    fputs("\n", stdout);
    fflush(stdout);
}

void tap_bail_out(const char * reason, ...) {
    fprintf(stderr, "Bail out! ");
    va_list args;
    va_start(args, reason);
    vfprintf(stderr, reason, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
    exit(1);
}

bool tap_subtest_start(const char * name) {
    _tap_ensure_initialized();
    print_indent(stdout);
    fprintf(stdout, "# Subtest: %s\n", name);
    fflush(stdout);
    push_state();
    snprintf(current_state->subtest_name, sizeof(current_state->subtest_name), "%s", name);
    return true;  // Allows use in a for-loop macro.
}

bool tap_subtest_end(void) {
    _tap_ensure_initialized();

    // If the subtest didn't have an explicit plan, create one from the count.
    if (!current_state->has_plan) {
        current_state->plan = current_state->count;
        print_indent(stdout);
        printf("1..%llu\n", (unsigned long long)current_state->plan);
    }
    bool plan_ok = (current_state->plan == current_state->count);
    bool subtest_ok = (current_state->failed == 0) && plan_ok;

    char name_buffer[256];
    snprintf(name_buffer, sizeof(name_buffer), "%s", current_state->subtest_name);

    // Return to parent's context before reporting the subtest's result.
    pop_state();

    // Report the success/failure of the entire subtest as a single test point.
    ok(subtest_ok, "%s", name_buffer);

    return false;  // Ensures the `subtest()` for-loop only runs once.
}

int tap_done(void) {
    _tap_ensure_initialized();
    // tap_done() should only be called from the main test context.
    if (current_state != &state_stack[0])
        tap_bail_out("tap_done() called inside a subtest");

    // If no plan was ever declared, create one from the total count.
    if (!current_state->has_plan) {
        current_state->plan = current_state->count;
        print_indent(stdout);
        printf("1..%llu\n", (unsigned long long)current_state->plan);
        fflush(stdout);
    }

    if (current_state->skipping) {
        print_indent(stdout);
        printf("1..%llu # SKIP %s\n", (unsigned long long)current_state->plan, current_state->skip_reason);
        fflush(stdout);
        return 0;
    }

    if (current_state->plan != current_state->count)
        fail("Test plan adherence (planned %llu, but ran %llu)",
             (unsigned long long)current_state->plan,
             (unsigned long long)current_state->count);

    size_t final_failed_count = (size_t)TAP_ATOMIC_FETCH_ADD(&g_total_failed, 0);
    if (final_failed_count > 0)
        diag("Looks like you failed %llu out of %llu tests.",
             (unsigned long long)final_failed_count,
             (unsigned long long)current_state->plan);

    return (int)final_failed_count;
}

/*
 * The entry point of the test program when DBLTAP_ENABLE is defined.
 */
int main(void) {
    tap_init();
    test_body();
    return (int)tap_done();
}

#endif  // defined(DBLTAP_ENABLE) && defined(DBLTAP_IMPLEMENTATION)
