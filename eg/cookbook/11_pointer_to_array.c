/**
 * @file 11_pointer_to_array.c
 * @brief Recipe: Working with Pointers to Arrays.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#recipe-working-with-pointers-to-arrays
 */
#include <infix/infix.h>
#include <stdio.h>

// This function expects a pointer to an array of 4 integers.
// This is a distinct type from `int**` or `int*[]`.
void process_matrix_row(int (*row_ptr)[4]) {
    printf("Processing row: ");
    for (int i = 0; i < 4; ++i) {
        printf("%d ", (*row_ptr)[i]);
    }
    printf("\n");
}

int main() {
    // 1. Signature for void(int(*)[4]).
<<<<<<< HEAD
    //    The type is a pointer `*` to an array `[4:int]`.
    const char * signature = "(*[4:int]) -> void";
=======
    //    We must group the array type `[4]i` in parentheses before adding the
    //    pointer modifier `*`. This overrides the default right-to-left precedence.
    const char * signature = "([4]i)*=>v";
>>>>>>> main
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // 2. Prepare arguments.
    int matrix[2][4] = {{1, 2, 3, 4}, {5, 6, 7, 8}};
    int(*ptr_to_first_row)[4] = &matrix[0];  // The argument is a pointer to the first row.

    void * args[] = {&ptr_to_first_row};

    // 3. Call the function.
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)process_matrix_row, NULL, args);

    infix_forward_destroy(trampoline);
    return 0;
}
