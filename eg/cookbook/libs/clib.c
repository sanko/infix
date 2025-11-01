/**
 * @file clib.cdddddddddddddddd
 * @brief Implementation of a simple C library for the C++ callback example.
 */
#include "clib.h"
#include <stdio.h>

void process_data(int * data, int count, void (*callback)(int item, void * user_data), void * user_data) {
    printf("  -> C Library: Starting to process %d items.\n", count);
    for (int i = 0; i < count; ++i) {
        printf("  -> C Library: Invoking callback for item %d.\n", data[i]);
        callback(data[i], user_data);
    }
    printf("  -> C Library: Finished processing.\n");
}
