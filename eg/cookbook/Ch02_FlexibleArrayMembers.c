/**
 * @file Ch02_FlexibleArrayMembers.c
 * @brief Cookbook Chapter 2: Flexible Array Members (FAM)
 *
 * This example demonstrates how to interface with C structs that use
 * C99 Flexible Array Members (e.g., `double values[]` at the end of a struct).
 */
#include <infix/infix.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

//
typedef struct {
    uint32_t length;
    double values[];  // Unknown size at compile time
} DataSeries;

double average_series(DataSeries * series) {
    if (series->length == 0)
        return 0.0;
    double sum = 0.0;
    for (uint32_t i = 0; i < series->length; ++i)
        sum += series->values[i];
    return sum / series->length;
}

int main() {
    printf("--- Cookbook Chapter 2: Working with Bitfields ---\n");

    // Signature syntax: "[ ? : type ]" (Question mark indicates unknown size)
    // The struct is passed by pointer (*) because it has variable size.
    const char * series_sig = "(*{ len:uint32, data:[?:double] }) -> double";

    infix_forward_t * t_series = NULL;
    infix_status status = infix_forward_create(&t_series, series_sig, (void *)average_series, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Error: Failed to create trampoline (code %d)\n", status);
        return 1;
    }

    // Calculate the total size required for the struct header + data.
    // Note: In a real application, consider alignment padding between 'length' and 'values'.
    // sizeof(DataSeries) usually includes padding to align 'values'.
    size_t num_elements = 5;
    size_t total_size = sizeof(DataSeries) + (sizeof(double) * num_elements);

    DataSeries * series = (DataSeries *)malloc(total_size);
    series->length = num_elements;
    series->values[0] = 10.0;
    series->values[1] = 20.0;
    series->values[2] = 30.0;
    series->values[3] = 40.0;
    series->values[4] = 50.0;

    double avg_result;
    void * args[] = {&series};  // Pass the address of the pointer

    infix_cif_func cif_series = infix_forward_get_code(t_series);
    cif_series(&avg_result, args);

    printf("Average of 10, 20, 30, 40, 50 is: %.2f\n", avg_result);

    free(series);
    infix_forward_destroy(t_series);

    return 0;
}
