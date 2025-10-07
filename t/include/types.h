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
 * @file types.h
 * @brief Defines common data structures used across the entire test suite.
 *
 * @details This header provides a single, canonical source for all the structs
 * and unions needed to test various FFI scenarios. By centralizing these
 * definitions, we ensure consistency and avoid code duplication. Each type is
 * designed to exercise a specific feature or edge case of an ABI, such as:
 * - Small, register-passable aggregates (`Point`).
 * - Homogeneous Floating-point Aggregates (`Vector4`).
 * - Large, stack-passed aggregates (`LargeStruct`).
 * - Mixed-type aggregates for complex classification (`MixedIntDouble`).
 */

#include <inttypes.h>  // For uint64_t
#include <stddef.h>    // For offsetof

/**
 * @struct Point
 * @brief A simple struct with two doubles (16 bytes).
 * @details Used to test the passing and returning of small, simple aggregates.
 * On SysV x64 and AArch64, this should be passed in two floating-point registers.
 * On Windows x64, it will be passed by reference.
 */
typedef struct {
    double x;
    double y;
} Point;

/**
 * @struct Vector4
 * @brief A struct containing a fixed-size array of floats.
 * @details This is a textbook example of a Homogeneous Floating-point Aggregate
 * (HFA) on the AArch64 ABI, where it should be passed in four consecutive
 * floating-point registers (v0-v3). It also serves to test structs that
 * contain arrays on other platforms.
 */
typedef struct {
    float v[4];
} Vector4;

/**
 * @struct LargeData
 * @brief A struct guaranteed to be larger than two registers (32 bytes).
 * @details This struct will be passed by reference on all currently supported
 *          platforms, testing the "pass-by-reference" ABI logic.
 */
typedef struct {
    long long data[4];
} LargeData;

/**
 * @union Number
 * @brief A simple union of an integer and a float.
 * @details Used to verify that the library can correctly calculate the size
 * and alignment of unions and handle them according to ABI rules.
 */
typedef union {
    int i;
    float f;
} Number;

/**
 * @struct LargeStruct
 * @brief A struct with a size greater than 16 bytes.
 * @details This struct is guaranteed to be too large to be passed in registers
 * on any of the major 64-bit ABIs. It is used to test passing by reference
 * on the stack and returning via a hidden pointer argument.
 */
typedef struct {
    int a, b, c, d, e, f;
} LargeStruct;

/**
 * @struct MixedIntDouble
 * @brief A struct with mixed integer and floating-point members.
 * @details This struct is crucial for testing the complex classification rules
 * of the System V AMD64 ABI. An aggregate of this type should be split and
 * passed in one integer register (for `i`) and one floating-point register
 * (for `d`).
 */
typedef struct {
    int i;
    double d;
} MixedIntDouble;

/**
 * @struct PointerStruct
 * @brief A struct containing pointer members.
 * @details Used to test that pointers inside an aggregate are correctly
 * classified and passed according to the ABI (typically as `INTEGER` components).
 */
typedef struct {
    int * val_ptr;
    const char * str_ptr;
} PointerStruct;

/**
 * @struct PackedStruct
 * @brief A struct that will have different layouts when packed vs. non-packed.
 * @details Non-packed size on x64: 16 bytes (char a, 7 bytes padding, uint64_t b).
 * Packed size: 9 bytes (char a, uint64_t b)
 */
#pragma pack(push, 1)
typedef struct {
    char a;
    uint64_t b;
} PackedStruct;
#pragma pack(pop)

/**
 * @struct NonPowerOfTwoStruct
 * @brief A struct whose size is not a power of two (12 bytes on most 64-bit systems).
 * @details This is specifically for testing the Windows x64 ABI rule that requires
 *          such structs to be passed by reference.
 */
typedef struct {
    int a, b, c;
} NonPowerOfTwoStruct;
