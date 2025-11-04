/**
 * @file Ch01_OpaquePointers.c
 * @brief Cookbook Chapter 1: Working with Opaque Pointers
 *
 * This example shows how to interact with C libraries that use opaque pointers
 * or "handles" (e.g., `FILE*`), where the internal structure is hidden. The
 * canonical `infix` signature for any such handle is `*void`. This recipe
 * also demonstrates using the Type Registry to create a readable alias for the
 * handle type.
 */
#include <infix/infix.h>
#include <stdio.h>

int main() {
    printf("--- Cookbook Chapter 1: Working with Opaque Pointers ---\n");

    // 1. Create a Type Registry to define a readable alias for our handle.
    infix_registry_t * reg = infix_registry_create();
    if (!reg) {
        fprintf(stderr, "Failed to create registry.\n");
        return 1;
    }
    // Define `@FileHandle` as a semantic alias for a generic pointer.
    if (infix_register_types(reg, "@FileHandle = *void;") != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to register types.\n");
        infix_registry_destroy(reg);
        return 1;
    }

    // 2. Create trampolines for the file I/O functions using our alias.
    infix_forward_t *t_fopen, *t_fputs, *t_fclose;
    if (infix_forward_create(&t_fopen, "(*char, *char) -> @FileHandle", (void *)fopen, reg) != INFIX_SUCCESS ||
        infix_forward_create(&t_fputs, "(*char, @FileHandle) -> int", (void *)fputs, reg) != INFIX_SUCCESS ||
        infix_forward_create(&t_fclose, "(@FileHandle) -> int", (void *)fclose, reg) != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create one or more trampolines.\n");
        infix_registry_destroy(reg);
        return 1;
    }

    // 3. Call the functions in sequence to open, write to, and close a file.
    void * file_handle = NULL;  // This will hold our opaque FILE*
    const char * filename = "cookbook_test.txt";
    const char * mode = "w";
    void * fopen_args[] = {&filename, &mode};

    printf("Attempting to open '%s' for writing...\n", filename);
    infix_forward_get_code(t_fopen)(&file_handle, fopen_args);

    if (file_handle) {
        printf("File opened successfully. Handle: %p\n", file_handle);

        const char * content = "Written by infix!";
        void * fputs_args[] = {&content, &file_handle};
        int fputs_result;
        infix_forward_get_code(t_fputs)(&fputs_result, fputs_args);
        printf("Wrote to file. fputs returned: %d\n", fputs_result);

        int fclose_result;
        // The argument to fclose is the value of file_handle.
        // The FFI needs a pointer TO that value, wrapped in an array.
        void * fclose_args[] = {&file_handle};
        infix_forward_get_code(t_fclose)(&fclose_result, fclose_args);  // Use the new args array
        printf("Closed file. fclose returned: %d\n", fclose_result);

        // Clean up the created file.
        remove(filename);
    }
    else
        fprintf(stderr, "Failed to open file.\n");

    // 4. Clean up all resources.
    infix_forward_destroy(t_fopen);
    infix_forward_destroy(t_fputs);
    infix_forward_destroy(t_fclose);
    infix_registry_destroy(reg);

    return 0;
}
