/**
 * @file 813_custom_allocator.c
 * @brief Unit test for the runtime pluggable allocator API (infix_set_allocator).
 * @ingroup test_suite
 *
 * @details infix routes every internal heap allocation through the
 * `infix_allocator` callback table, which hosts replace at runtime with
 * `infix_set_allocator()`. This test installs a tracking allocator and verifies
 * that a realistic infix lifecycle (registry creation, bulk type registration,
 * signature parsing, JIT emission, an actual FFI call, and teardown) allocates
 * and frees *exclusively* through the installed callbacks, that `calloc` and
 * `realloc` reach the table too, that nothing leaks, and that passing `NULL`
 * restores the libc defaults.
 *
 * This is the regression test for the "wrong pool" scenario that bit Affix:
 * memory handed to one allocator must always be released through the same
 * allocator. `tracked_free` flags any pointer it never allocated (which would
 * mean an allocation escaped the table), and the balance check flags any block
 * still live after teardown (which would mean a free escaped the table).
 *
 * Note on the trampoline cache: `infix_forward_create` deduplicates identical
 * trampolines in a process-wide, refcounted cache, and `infix_forward_destroy`
 * only releases the caller's reference, so a destroyed trampoline stays alive
 * until `_infix_cache_clear()`. The test flushes that cache (through the
 * currently installed allocator) so the balance check measures a complete
 * lifecycle.
 *
 * Unlike `811_fault_injection.c` (which overrides infix's allocator at compile
 * time with `#define infix_malloc ...`), this test uses the public runtime API
 * and links the real library, exercising exactly the table indirection that
 * consumers of a prebuilt libinfix rely on.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_internals.h"
#include <infix/infix.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/** @internal @brief A C function for the end-to-end FFI call. */
static int add_ints(int a, int b) { return a + b; }

// Tracking allocator. Counts every callback and keeps a live-set so a free of
// an untracked pointer (allocator mixing) is detected.
#define TRACKED_MAX_LIVE 4096

typedef struct {
    void * ptr;
} tracked_record_t;

static tracked_record_t tracked_live[TRACKED_MAX_LIVE];
static size_t tracked_live_count;
static size_t tracked_alloc_count;    // infix_malloc calls
static size_t tracked_calloc_count;   // infix_calloc calls
static size_t tracked_realloc_count;  // infix_realloc calls
static size_t tracked_free_count;     // infix_free calls
static bool tracked_unmatched_free;   // free of a pointer we never allocated

static void tracked_reset(void) {
    tracked_live_count = 0;
    tracked_alloc_count = 0;
    tracked_calloc_count = 0;
    tracked_realloc_count = 0;
    tracked_free_count = 0;
    tracked_unmatched_free = false;
}

static size_t tracked_find(void * ptr) {
    for (size_t i = 0; i < tracked_live_count; ++i)
        if (tracked_live[i].ptr == ptr)
            return i;
    return TRACKED_MAX_LIVE;
}

static void tracked_add(void * ptr) {
    if (ptr == NULL)
        return;
    if (tracked_live_count >= TRACKED_MAX_LIVE)
        return;  // Tracking table overflow; the counters are the real signal.
    tracked_live[tracked_live_count++].ptr = ptr;
}

static void tracked_remove(void * ptr) {
    if (ptr == NULL)
        return;
    size_t idx = tracked_find(ptr);
    if (idx == TRACKED_MAX_LIVE) {
        tracked_unmatched_free = true;  // Freeing a pointer we never allocated.
        return;
    }
    tracked_live[idx] = tracked_live[--tracked_live_count];
}

static void * tracked_malloc(size_t size) {
    void * p = malloc(size);
    tracked_alloc_count++;
    tracked_add(p);
    return p;
}

static void * tracked_calloc(size_t nelem, size_t size) {
    void * p = calloc(nelem, size);
    tracked_calloc_count++;
    tracked_add(p);
    return p;
}

static void * tracked_realloc(void * ptr, size_t new_size) {
    // realloc(NULL, n) acts like malloc; realloc(p, 0) frees p. Either way the
    // old block is invalidated on success, so it is retired from the live set
    // *before* calling realloc and never read afterwards - GCC's -Wuse-after-free
    // (on by default at -O2 since GCC 12) otherwise flags the comparison even
    // though the pointer is never dereferenced. A failed realloc leaves the old
    // block live but untracked; realloc cannot fail in this test, so that case
    // never occurs and is not part of the balance check.
    if (ptr != NULL)
        tracked_remove(ptr);
    void * p = realloc(ptr, new_size);
    tracked_realloc_count++;
    if (p != NULL)
        tracked_add(p);
    return p;
}

static void tracked_free(void * ptr) {
    if (ptr == NULL)
        return;
    tracked_remove(ptr);
    tracked_free_count++;
    free(ptr);
}

static const infix_allocator_t tracked_allocator = {
    .malloc = tracked_malloc, .calloc = tracked_calloc, .realloc = tracked_realloc, .free = tracked_free};

/** @brief Total blocks handed out by the tracking allocator (malloc + calloc). */
static size_t tracked_total_alloc(void) { return tracked_alloc_count + tracked_calloc_count; }

// The libc defaults are verified behaviorally rather than by pointer identity.
// With MSVC's incremental linking (/INCREMENTAL, the default whenever the
// linker emits a PDB under /Zi), a function pointer stored in a global's
// static initializer (allocator.c) can be fixed up to a different address than
// a local reference to the same symbol (e.g. `malloc` here), so
// `infix_allocator.malloc == malloc` is not reliably true. What the test
// actually needs - that the table is populated, that all four slots work, and
// that none of them route through the tracking allocator - is what this checks.
static void ok_libc_defaults(const char * label) {
    ok(infix_allocator.malloc != NULL && infix_allocator.calloc != NULL && infix_allocator.realloc != NULL &&
           infix_allocator.free != NULL,
       "%s: all four slots are populated",
       label);
    size_t before = tracked_total_alloc();
    void * probe = infix_allocator.malloc(64);
    infix_allocator.free(probe);
    probe = infix_allocator.calloc(2, 32);
    infix_allocator.free(probe);
    probe = infix_allocator.malloc(32);
    probe = infix_allocator.realloc(probe, 64);
    infix_allocator.free(probe);
    ok(tracked_total_alloc() == before, "%s: malloc/calloc/realloc roundtrip bypasses the tracking allocator", label);
    ok(infix_allocator.malloc != tracked_malloc && infix_allocator.free != tracked_free,
       "%s: slots are not the tracking allocator",
       label);
}

TEST {
    plan(3);
    subtest("installing and restoring the allocator") {
        plan(13);
        tracked_reset();

        // Before any install, the table must default to the C library.
        ok_libc_defaults("default");
        //
        infix_set_allocator(&tracked_allocator);
        ok(infix_allocator.malloc == tracked_malloc, "installed malloc slot is the tracking malloc");
        ok(infix_allocator.calloc == tracked_calloc, "installed calloc slot is the tracking calloc");
        ok(infix_allocator.realloc == tracked_realloc, "installed realloc slot is the tracking realloc");
        ok(infix_allocator.free == tracked_free, "installed free slot is the tracking free");

        // A minimal infix operation must now flow through the tracker. The
        // arena allocates its struct and backing buffer with infix_calloc, so
        // the total-alloc/free balance is what must hold.
        infix_arena_t * arena = infix_arena_create(4096);
        ok(arena != nullptr, "infix_arena_create succeeds under the tracking allocator");
        infix_arena_destroy(arena);
        ok(tracked_total_alloc() > 0 && tracked_total_alloc() == tracked_free_count && tracked_live_count == 0,
           "arena lifecycle balanced through the tracking allocator (%llu alloc, %llu free, %llu live)",
           (unsigned long long)tracked_total_alloc(),
           (unsigned long long)tracked_free_count,
           (unsigned long long)tracked_live_count);

        // Restoring with NULL must hand the table back to libc.
        infix_set_allocator(NULL);
        ok_libc_defaults("restored");
        size_t before = tracked_total_alloc();
        arena = infix_arena_create(512);
        infix_arena_destroy(arena);
        ok(tracked_total_alloc() == before, "post-restore allocations bypass the tracking allocator");
    }

    subtest("full lifecycle routed through the custom allocator") {
        plan(6);
        tracked_reset();
        infix_set_allocator(&tracked_allocator);
        _infix_cache_clear();  // Flush any leftover cached trampolines through the tracker.
        tracked_reset();       // Measure only this lifecycle.

        // Registry create + bulk type registration. Registering more than 64
        // definitions deterministically grows the defs array, so infix_realloc
        // must reach the tracking realloc slot.
        infix_registry_t * registry = infix_registry_create();
        ok(registry != nullptr, "registry created under the tracking allocator");
        //
        char defs[4096];
        size_t off = 0;
        for (int i = 0; i < 80 && off < sizeof(defs); ++i)
            off += (size_t)snprintf(defs + off, sizeof(defs) - off, "@T%d = int;", i);
        ok(infix_register_types(registry, defs) == INFIX_SUCCESS, "registered 80 type aliases (forces realloc)");
        //
        infix_forward_t * trampoline = nullptr;
        infix_status status = infix_forward_create(&trampoline, "(int, int) -> int", (void *)add_ints, registry);
        ok(status == INFIX_SUCCESS, "forward trampoline created from signature under the tracking allocator");
        //
        infix_cif_func cif = infix_forward_get_code(trampoline);
        int a = 10, b = 32, result = 0;
        void * args[] = {&a, &b};
        cif(&result, args);
        ok(result == 42, "FFI call is correct under the tracking allocator (10 + 32 == %d)", result);
        //
        infix_forward_destroy(trampoline);
        _infix_cache_clear();  // Release the cached trampoline through the tracker.
        infix_registry_destroy(registry);
        //
        ok(tracked_alloc_count > 0 && tracked_calloc_count > 0 && tracked_realloc_count > 0,
           "malloc/calloc/realloc all reached the tracking table (%llu/%llu/%llu)",
           (unsigned long long)tracked_alloc_count,
           (unsigned long long)tracked_calloc_count,
           (unsigned long long)tracked_realloc_count);
        ok(tracked_total_alloc() == tracked_free_count && tracked_live_count == 0 && !tracked_unmatched_free,
           "every allocation freed through the same custom allocator (%llu alloc, %llu free, %llu live)",
           (unsigned long long)tracked_total_alloc(),
           (unsigned long long)tracked_free_count,
           (unsigned long long)tracked_live_count);
        //
        infix_set_allocator(NULL);
    }

    subtest("switching allocators between objects, never mid-lifecycle") {
        plan(4);
        tracked_reset();
        infix_set_allocator(&tracked_allocator);
        _infix_cache_clear();
        tracked_reset();

        // Object A: created and destroyed entirely under the tracking allocator.
        infix_forward_t * a = nullptr;
        ok(infix_forward_create(&a, "(int, int) -> int", (void *)add_ints, nullptr) == INFIX_SUCCESS,
           "trampoline A created under the tracking allocator");
        infix_forward_destroy(a);
        _infix_cache_clear();  // Free A's cached trampoline through the tracker.
        ok(tracked_total_alloc() == tracked_free_count && tracked_live_count == 0 && !tracked_unmatched_free,
           "trampoline A fully balanced through the tracking allocator (%llu alloc, %llu free)",
           (unsigned long long)tracked_total_alloc(),
           (unsigned long long)tracked_free_count);

        // Switch allocators BETWEEN objects. Object B's whole life is under
        // libc, so the tracking counters must stay untouched.
        infix_set_allocator(NULL);
        size_t before = tracked_total_alloc();
        //
        infix_forward_t * b = nullptr;
        ok(infix_forward_create(&b, "(int, int) -> int", (void *)add_ints, nullptr) == INFIX_SUCCESS,
           "trampoline B created under the restored libc allocator");
        infix_forward_destroy(b);
        _infix_cache_clear();  // Free B's cached trampoline through libc.
                               //
        ok(tracked_total_alloc() == before && tracked_free_count == before,
           "trampoline B's lifecycle bypasses the tracking allocator entirely");
    }
}
