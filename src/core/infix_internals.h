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
 * @file infix_internals.h
 * @brief Declarations for internal-only functions shared across compilation units.
 * @details This header is NOT part of the public API. It is used to expose
 * functions that are normally static within their own .c file to other parts
 * of the library, primarily for white-box testing and fuzzing.
 */

#include <infix.h>

// Forward declarations of the normally-static ABI spec getters from trampoline.c
const ffi_forward_abi_spec * get_current_forward_abi_spec(void);
const ffi_reverse_abi_spec * get_current_reverse_abi_spec(void);
