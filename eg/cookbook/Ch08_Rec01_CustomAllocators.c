/**
 * @file Ch08_Rec01_CustomAllocators.c
 * @brief Cookbook Chapter 8, Recipe 1: Using Custom Memory Allocators
 *
 * This example demonstrates how to integrate `infix` with a custom memory
 * manager. This is useful for applications that need to track allocations,
 * use a memory pool, or integrate with a garbage collector.
 *
 * The mechanism is simple: define the `infix_malloc`, `infix_free`, etc.,
 * macros *before* including `infix.h`. All internal memory operations in the
 * library will then be redirected to your custom functions.
 */

#include <stdio.h>
#include <stdlib.h>

// 1. Define your custom memory management functions.
//    These simple wrappers just print a message and track the total allocated memory.
static size_t g_total_allocated = 0;
void * tracking_malloc(size_t size) {
    g_total_allocated += size;
    printf(">> Custom Malloc: Allocating %llu bytes (Total outstanding: %llu)\n",
           (unsigned long long)size,
           (unsigned long long)g_total_allocated);
    return malloc(size);
}

void tracking_free(void * ptr) {
    // A real tracking allocator would need to know the size of the block being freed.
    // For this example, we just log the call.
    printf(">> Custom Free: Deallocating block at %p\n", ptr);
    free(ptr);
}

// 2. Define the infix override macros BEFORE including infix.h
#define infix_malloc(size) tracking_malloc(size)
#define infix_free(ptr) tracking_free(ptr)
// You can also override infix_calloc and infix_realloc if needed.

#include <infix/infix.h>

void dummy_func() {}

int main() {
    printf("--- Cookbook Chapter 8, Recipe 1: Using Custom Memory Allocators ---\n");

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
