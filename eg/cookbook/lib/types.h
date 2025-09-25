#pragma once
/**
 * @file types.h
 * @brief Defines common data structures used across the cookbook examples.
 */
#include <stddef.h>
#include <stdint.h>

/**
 * @struct Point
 * @brief A simple struct with two doubles. Small enough to be passed in registers on some ABIs.
 */
typedef struct {
    double x;
    double y;
} Point;

/**
 * @struct LargeStruct
 * @brief A struct larger than 16 bytes, guaranteed to be passed by reference.
 */
typedef struct {
    int a, b, c, d, e, f;
} LargeStruct;

/**
 * @union Number
 * @brief A simple union of an integer and a float.
 */
typedef union {
    int i;
    float f;
} Number;

/**
 * @struct PackedStruct
 * @brief A struct with a non-standard, packed memory layout.
 * @details Non-packed size on x64 would be 16 bytes due to padding.
 *          Packed size is 9 bytes.
 */
#pragma pack(push, 1)
typedef struct {
    char a;
    uint64_t b;
} PackedStruct;
#pragma pack(pop)
