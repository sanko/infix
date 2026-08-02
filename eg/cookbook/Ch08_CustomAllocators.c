/**
 * @file Ch08_CustomAllocators.c
 * @brief Cookbook Chapter 8: Using Custom Memory Allocators
 *
 * This example demonstrates how to integrate `infix` with a custom memory
 * manager. This is useful for applications that need to track allocations,
 * use a memory pool, or integrate with a garbage collector.
 *
 * The recommended mechanism is `infix_set_allocator()`, which redirects all of
 * infix's internal heap allocations to your callbacks at runtime. (A
 * compile-time alternative, defining the `infix_malloc`/`infix_free`/etc.
 * macros before including `infix.h`, is also supported for builds from source.)
 */

#include <infix/infix.h>
#include <stdio.h>
#include <stdlib.h>

// 1. Define your custom memory management callbacks.
//    These simple wrappers just print a message and track the total allocated memory.
static size_t g_total_allocated = 0;
static void * tracking_malloc(size_t size) {
    g_total_allocated += size;
    printf(">> Custom Malloc: Allocating %llu bytes (Total outstanding: %llu)\n",
           (unsigned long long)size,
           (unsigned long long)g_total_allocated);
    return malloc(size);
}

static void tracking_free(void * ptr) {
    // A real tracking allocator would need to know the size of the block being freed.
    // For this example, we just log the call.
    printf(">> Custom Free: Deallocating block at %p\n", ptr);
    free(ptr);
}

void dummy_func() {}

int main() {
    printf("Cookbook Chapter 8: Using Custom Memory Allocators\n");

    // 2. Install the allocator. Do this before any trampolines are created and
    //    before infix is used from more than one thread.
    static const infix_allocator_t tracking = {
        .malloc = tracking_malloc,
        .calloc = calloc,
        .realloc = realloc,
        .free = tracking_free,
    };
    infix_set_allocator(&tracking);

    printf("\nCreating trampoline with custom allocators...\n");
    infix_forward_t * trampoline = NULL;

    // All internal allocations for the trampoline will now use `tracking_malloc`.
    (void)infix_forward_create(&trampoline, "()->void", (void *)dummy_func, NULL);

    printf("\nDestroying trampoline...\n");
    // All free operations will now use `tracking_free`.
    infix_forward_destroy(trampoline);

    printf("\nDone.\n");

    return 0;
}
