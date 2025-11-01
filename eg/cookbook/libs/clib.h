/**
 * @file clib.h
 * @brief Header for a simple C library used in the C++ callback example.
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// A C function that takes a callback and user data.
void process_data(int * data, int count, void (*callback)(int item, void * user_data), void * user_data);

#ifdef __cplusplus
}
#endif
