/**
 * @file 852_rax_preservation.c
 * @brief Regression test to verify rax preservation across reverse trampolines.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include <infix/infix.h>
#include <stdio.h>

// This test aims to verify that the rax register is not unexpectedly clobbered
// by the reverse trampoline mechanism.
//
// The trampoline is expected to follow the System V ABI for the *caller*.
// However, the internal bridge implementation uses RAX, which must be preserved
// and restored, even if RAX is technically a scratch register for the *caller*.

// For this test, we create a callback that does not return anything, and we
// try to check if RAX is preserved across the call. This is tricky,
// because the trampoline MUST return a value.
//
// A better approach is to check if the dispatcher can rely on the original RAX
// if it needed to, or if the trampoline's *own* use of RAX clobbers something it shouldn't.
//
// Given the complexity of RAX as a return register, this test might be limited
// in what it can reliably check.

void handler_void(infix_context_t * ctx, void * ret, void ** args) {
    (void)ctx;
    (void)ret;
    (void)args;
    // Just a simple void handler
}

TEST {
    plan(1);
// MSVC doesn't support GCC inline assembly syntax (`__asm__`). On x64 MSVC
// there is no inline assembly at all — you need MASM or intrinsics.
#if !defined(_MSC_VER) && defined(__x86_64__)
    subtest("Reverse Trampoline: RAX Preservation") {
        plan(2);
        const char * signature = "() -> void";
        infix_reverse_t * ctx = NULL;
        infix_status status = infix_reverse_create_closure(&ctx, signature, handler_void, NULL, NULL);
        if (ok(status == INFIX_SUCCESS, "infix_reverse_create_closure created successfully")) {
            void (*func_ptr)(void) = (void (*)(void))infix_reverse_get_code(ctx);

            long long rax_val = 0xdeadbeef12345678L;
            long long rax_after = 0;

            // Use inline assembly to call the trampoline and attempt to check RAX preservation
            // We specifically want to see if the trampoline restores it *before* returning to the caller.

            __asm__ volatile(
                "sub $8, %%rsp\n"  // Align stack to 16 bytes
                "mov %1, %%rax\n"  // Put our target value in rax
                "call *%2\n"       // Call the trampoline
                "add $8, %%rsp\n"  // Clean up alignment
                "mov %%rax, %0"    // We'll get the value of RAX after the call
                : "=r"(rax_after)
                : "r"(rax_val), "r"(func_ptr)
                : "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");

            // Since the trampoline returns void, it SHOULD be returning the original RAX value.
            ok(rax_after == rax_val, "RAX value preserved (Got 0x%llx, expected 0x%llx)", (unsigned long long)rax_after, (unsigned long long)rax_val);
        }
        infix_reverse_destroy(ctx);
    }
#else
    skip(1, "RAX test is x86-64 only");
#endif
}
