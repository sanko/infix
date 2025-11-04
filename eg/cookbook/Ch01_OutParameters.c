/**
 * @file Ch01_OutParameters.c
 * @brief Cookbook Chapter 1: Working with "Out" Parameters
 *
 * This example demonstrates a very common C pattern where a function returns
 * its primary output via a pointer argument (an "out" parameter) rather than
 * its direct return value. The signature simply represents this as a pointer
 * type (e.g., `*int`).
 */
#include <infix/infix.h>
#include <stdbool.h>
#include <stdio.h>

// The native C function we want to call.
// It returns a status code and writes its main results to the pointer arguments.
static bool get_user_stats(int user_id, int * out_posts, double * out_score) {
    if (user_id == 123) {
        if (out_posts)
            *out_posts = 50;
        if (out_score)
            *out_score = 99.8;
        return true;
    }
    return false;
}

int main() {
    printf("--- Cookbook Chapter 1: Working with \"Out\" Parameters ---\n");

    // 1. Signature for: bool get_user_stats(int, int*, double*);
    const char * signature = "(int, *int, *double) -> bool";

    // 2. Create the trampoline.
    infix_forward_t * t = NULL;
    infix_status status = infix_forward_create(&t, signature, (void *)get_user_stats, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }
    infix_cif_func cif = infix_forward_get_code(t);

    // 3. Prepare arguments. The "out" parameters start as local variables.
    int user_id = 123;
    int post_count = 0;
    double score = 0.0;
    bool success;

    // 4. For "out" parameters (which are pointers), we must create local
    //    variables to hold those pointers. The `args` array will then
    //    contain pointers TO those pointer variables.

    // Value for arg 1 is the integer `user_id`.
    // Value for arg 2 is the pointer `&post_count`.
    // Value for arg 3 is the pointer `&score`.
    int * p_post_count = &post_count;
    double * p_score = &score;

    // The `args` array contains pointers to our arguments' values.
    void * args[] = {
        &user_id,       // Pointer to the int value
        &p_post_count,  // Pointer to the int* value
        &p_score        // Pointer to the double* value
    };

    // 5. Call the function.
    cif(&success, args);

    printf("Calling get_user_stats for user ID 123...\n");
    if (success) {
        printf("Function succeeded. User stats retrieved:\n");
        printf("  Post Count: %d (Expected: 50)\n", post_count);
        printf("  Score: %.1f (Expected: 99.8)\n", score);
    }
    else
        printf("Function failed.\n");

    // 6. Clean up.
    infix_forward_destroy(t);

    return 0;
}
