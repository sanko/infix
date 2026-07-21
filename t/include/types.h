#pragma once
/**
 * @file types.h
 * @brief Defines common C structures used across the `infix` test suite.
 * @ingroup test_suite
 *
 * @internal
 * This header is not part of the main `infix` library. It serves as a centralized
 * place to define the C `struct` and `union` types that are used as targets for
 * FFI calls in multiple test files.
 *
 * By defining them here, we ensure that the layout (`sizeof`, `_Alignof`, `offsetof`)
 * is consistent and matches what the C compiler produces, which is essential for
 * validating the correctness of the `infix` type system and ABI classifiers.
 * @endinternal
 */
#include <inttypes.h>
#include <stddef.h>
/** @brief A simple struct with two doubles, often used to test pass-by-value on registers. */
typedef struct {
    double x;
    double y;
} Point;
/** @brief A struct containing an array, often used to test HFA (Homogeneous Floating-point Aggregate) rules. */
typedef struct {
    float v[4];
} Vector4;
/** @brief A larger struct used for testing pass-by-reference and stack arguments. */
typedef struct {
    long long data[4];
} LargeData;
/** @brief A simple union to test aggregate classification. */
typedef union {
    int i;
    float f;
} Number;
/** @brief A struct larger than 16 bytes, guaranteed to be passed by reference on most ABIs. */
typedef struct {
    int a, b, c, d, e, f;
} LargeStruct;
/** @brief A struct with mixed integer and float members, used to test complex classification rules on System V x64. */
typedef struct {
    int i;
    double d;
} MixedIntDouble;
/** @brief A struct containing pointers, used to test pointer argument handling. */
typedef struct {
    int * val_ptr;
    const char * str_ptr;
} PointerStruct;
/**
 * @brief A packed struct with an unusual size (9 bytes) and alignment (1).
 * @details This is used to test the handling of non-standard layouts and alignments.
 * The `#pragma pack` directives ensure a specific memory layout without padding.
 */
#pragma pack(push, 1)
typedef struct {
    char a;
    uint64_t b;
} PackedStruct;
#pragma pack(pop)
/** @brief A struct whose size (12 bytes) is not a power of two, used to test ABI rules for such types. */
typedef struct {
    int a, b, c;
} NonPowerOfTwoStruct;
/**
 * @brief Packed struct with size 9, used to test by-value return through forward trampolines.
 * @details On AAPCS64, a 9-byte struct is returned in X0 (bytes 0-7) and X1 (byte 8).
 *          The epilogue must correctly decompose the store into X0 and X1 parts.
 */
#pragma pack(push, 1)
typedef struct {
    int32_t a;
    int8_t b;
    int32_t c;
} PackedABC;
#pragma pack(pop)
/**
 * @brief Packed struct with size 3, used to test non-power-of-2 return sizes.
 */
#pragma pack(push, 1)
typedef struct {
    int8_t a;
    int16_t b;
} PackedTiny;
#pragma pack(pop)
/**
 * @brief Packed struct with size 6, used to test non-power-of-2 return sizes.
 */
#pragma pack(push, 1)
typedef struct {
    int8_t a;
    int8_t b;
    int32_t c;
} PackedSix;
#pragma pack(pop)
