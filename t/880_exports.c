/**
 * @file 880_exports.c
 * @brief Unit test for the dynamic library loading and symbol access API.
 * @ingroup test_suite
 *
 * @details This test verifies the functionality of `infix_library_open`,
 * `infix_library_get_symbol`, `infix_read_global`, and `infix_write_global`.
 *
 * To perform a realistic test, the test runner opens *itself* as a dynamic
 * library (using `NULL` as the path). It then looks up exported symbols within
 * its own executable image.
 *
 * The test covers:
 * - **Library Loading:** Opening the main executable handle.
 * - **Symbol Lookup:** Finding the address of a known global variable (`g_test_export_var`).
 * - **Reading Globals:** Using `infix_read_global` with a signature string to read the variable's value.
 * - **Writing Globals:** Using `infix_write_global` with a signature string to modify the variable's value.
 *
 * @note This test relies on `g_test_export_var` being exported and visible to `dlsym`/`GetProcAddress`.
 * On some platforms/linkers (e.g., MSVC without `__declspec(dllexport)`), symbols in the
 * main executable are not exported by default. The test includes logic to skip gracefully
 * if the symbol cannot be found, rather than failing.
 */
#define DBLTAP_IMPLEMENTATION
#include "common/compat_c23.h"
#include "common/double_tap.h"
#include "common/infix_config.h"
#include <infix/infix.h>

// A global variable to test reading/writing.
// We try to force export it so dlsym/GetProcAddress can find it.
#if defined(INFIX_OS_WINDOWS)
__declspec(dllexport) int g_test_export_var = 12345;
#else
__attribute__((visibility("default"))) int g_test_export_var = 12345;
#endif
TEST {
    plan(6);

    // Open the current executable as a library.
    infix_library_t * lib = infix_library_open(nullptr);
    ok(lib != nullptr, "Opened self as library");
    if (!lib) {
        skip(5, "Cannot proceed");
        return;
    }

    // Look up the global variable.
    void * sym = infix_library_get_symbol(lib, "g_test_export_var");
    if (!sym) {
        // This is common on Windows executables or static builds where symbols aren't dynamic.
        // We skip the rest of the test instead of failing.
        skip(5, "Symbol 'g_test_export_var' not found (likely not exported). Skipping read/write tests.");
        infix_library_close(lib);
        return;
    }
    ok(sym == &g_test_export_var, "Symbol address matches global variable address");

    // Test reading the global.
    int read_val = 0;
    infix_status status = infix_read_global(lib, "g_test_export_var", "int32", &read_val, nullptr);
    ok(status == INFIX_SUCCESS, "infix_read_global succeeded");
    ok(read_val == 12345, "Read correct value %d", read_val);

    // Test writing the global.
    int write_val = 67890;
    status = infix_write_global(lib, "g_test_export_var", "int32", &write_val, nullptr);
    ok(status == INFIX_SUCCESS, "infix_write_global succeeded");
    ok(g_test_export_var == 67890, "Global variable was updated to %d", g_test_export_var);
    infix_library_close(lib);
}
