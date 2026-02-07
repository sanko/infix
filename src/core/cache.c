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
 * @file cache.c
 * @brief Implements trampoline deduplication and caching.
 * @ingroup internal_core
 */
#include "common/infix_internals.h"
#include <stdlib.h>
#include <string.h>

/** @internal Initial number of buckets for the global trampoline cache. */
#define CACHE_BUCKETS 1021

/** @internal A single entry in the global trampoline cache. */
typedef struct _cache_entry_t {
    infix_forward_t * trampoline; /**< The cached trampoline handle. */
    struct _cache_entry_t * next; /**< Next entry in the hash bucket chain. */
} _cache_entry_t;

/** @internal The global hash table for forward trampolines. */
static _cache_entry_t * g_trampoline_cache[CACHE_BUCKETS];
/** @internal Mutex to protect the global cache. */
static infix_mutex_t g_cache_mutex = INFIX_MUTEX_INITIALIZER;

/**
 * @internal
 * @brief Computes a hash for a cache lookup.
 */
static uint64_t _cache_hash(const char * sig, void * target_fn, bool is_safe) {
    uint64_t h = 5381;
    int c;
    while ((c = *sig++))
        h = ((h << 5) + h) + c;
    h ^= (uint64_t)(uintptr_t)target_fn;
    if (is_safe)
        h ^= 0x123456789ABCDEF0ULL;
    return h;
}

/**
 * @internal
 * @brief Searches the global cache for an existing trampoline.
 * @return The cached trampoline with its ref_count incremented, or NULL if not found.
 */
infix_forward_t * _infix_cache_lookup(const char * signature, void * target_fn, bool is_safe) {
    uint64_t h = _cache_hash(signature, target_fn, is_safe);
    size_t index = h % CACHE_BUCKETS;

    INFIX_MUTEX_LOCK(&g_cache_mutex);
    for (_cache_entry_t * entry = g_trampoline_cache[index]; entry; entry = entry->next) {
        if (entry->trampoline->target_fn == target_fn && entry->trampoline->is_safe == is_safe &&
            strcmp(entry->trampoline->signature, signature) == 0) {
            entry->trampoline->ref_count++;
            INFIX_MUTEX_UNLOCK(&g_cache_mutex);
            return entry->trampoline;
        }
    }
    INFIX_MUTEX_UNLOCK(&g_cache_mutex);
    return NULL;
}

/**
 * @internal
 * @brief Inserts a trampoline into the global cache.
 */
void _infix_cache_insert(infix_forward_t * trampoline) {
    uint64_t h = _cache_hash(trampoline->signature, trampoline->target_fn, trampoline->is_safe);
    size_t index = h % CACHE_BUCKETS;

    INFIX_MUTEX_LOCK(&g_cache_mutex);
    // Double check it's not already there
    for (_cache_entry_t * entry = g_trampoline_cache[index]; entry; entry = entry->next) {
        if (entry->trampoline->target_fn == trampoline->target_fn &&
            entry->trampoline->is_safe == trampoline->is_safe &&
            strcmp(entry->trampoline->signature, trampoline->signature) == 0) {
            INFIX_MUTEX_UNLOCK(&g_cache_mutex);
            return;
        }
    }

    _cache_entry_t * entry = infix_malloc(sizeof(_cache_entry_t));
    if (!entry) {
        INFIX_MUTEX_UNLOCK(&g_cache_mutex);
        return;
    }

    entry->trampoline = trampoline;
    trampoline->ref_count++;  // Cache reference
    entry->next = g_trampoline_cache[index];
    g_trampoline_cache[index] = entry;
    INFIX_MUTEX_UNLOCK(&g_cache_mutex);
}

/**
 * @internal
 * @brief Clears all entries from the global cache.
 */
void _infix_cache_clear(void) {
    INFIX_MUTEX_LOCK(&g_cache_mutex);
    for (size_t i = 0; i < CACHE_BUCKETS; ++i) {
        _cache_entry_t * entry = g_trampoline_cache[i];
        while (entry) {
            _cache_entry_t * next = entry->next;
            if (--entry->trampoline->ref_count == 0)
                _infix_forward_destroy_internal(entry->trampoline);
            infix_free(entry);
            entry = next;
        }
        g_trampoline_cache[i] = nullptr;
    }
    INFIX_MUTEX_UNLOCK(&g_cache_mutex);
}

/**
 * @internal
 * @brief Internal non-locking removal helper.
 */
static bool _cache_remove_no_lock(infix_forward_t * trampoline) {
    if (!trampoline->signature)
        return false;
    uint64_t h = _cache_hash(trampoline->signature, trampoline->target_fn, trampoline->is_safe);
    size_t index = h % CACHE_BUCKETS;

    _cache_entry_t ** p = &g_trampoline_cache[index];
    while (*p) {
        if ((*p)->trampoline == trampoline) {
            _cache_entry_t * to_free = *p;
            *p = to_free->next;
            infix_free(to_free);
            trampoline->ref_count--;  // Decrement since cache no longer holds it
            return true;
        }
        p = &((*p)->next);
    }
    return false;
}

/**
 * @internal
 * @brief Removes a trampoline from the global cache.
 * @return True if found and removed.
 */
bool _infix_cache_remove(infix_forward_t * trampoline) {
    INFIX_MUTEX_LOCK(&g_cache_mutex);
    bool result = _cache_remove_no_lock(trampoline);
    INFIX_MUTEX_UNLOCK(&g_cache_mutex);
    return result;
}

/**
 * @internal
 * @brief Releases a reference to a trampoline, destroying it if the count hits 0.
 */
void _infix_cache_release(infix_forward_t * trampoline) {
    if (!trampoline)
        return;

    INFIX_MUTEX_LOCK(&g_cache_mutex);
    if (--trampoline->ref_count > 0) {
        INFIX_MUTEX_UNLOCK(&g_cache_mutex);
        return;
    }

    // Reference count is 0. Remove from cache and destroy.
    _cache_remove_no_lock(trampoline);
    INFIX_MUTEX_UNLOCK(&g_cache_mutex);

    _infix_forward_destroy_internal(trampoline);
}
