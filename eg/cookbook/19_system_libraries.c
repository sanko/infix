/**
 * @file 19_system_libraries.c
 * @brief Recipe: Calling System Libraries on Windows, macOS, and Linux.
 * @see https://github.com/sanko/infix/blob/master/docs/cookbook.md#chapter-6-calling-system-libraries
 */
#include <infix/infix.h>
#include <stdio.h>

#if defined(_WIN32)
// --- Windows: Calling User32.dll ---
#include <windows.h>

void run_windows_example() {
    printf("--- Windows Example: Calling MessageBoxW ---\n");
    HMODULE user32 = LoadLibraryA("user32.dll");
    if (!user32) {
        fprintf(stderr, "Failed to load user32.dll\n");
        return;
    }
    void * MessageBoxW_ptr = (void *)GetProcAddress(user32, "MessageBoxW");

<<<<<<< HEAD
    // Signature: int MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT)
    const char * signature = "(*void, *void, *void, uint) -> int";
=======
    // Signature: int(HWND, LPCWSTR, LPCWSTR, UINT)
    const char * signature = "v*,v*,v*,j=>i";  // v* for handles/pointers, j for UINT
>>>>>>> main
    infix_forward_t * trampoline = NULL;
    infix_forward_create(&trampoline, signature);

    // Prepare arguments. Windows uses UTF-16 for wide strings (L"").
    HWND hwnd = NULL;
    const wchar_t * text = L"This is a message from infix!";
    const wchar_t * caption = L"infix FFI Test";
    UINT type = MB_OK | MB_ICONINFORMATION;

    void * args[] = {&hwnd, &text, &caption, &type};
    int result = 0;
    ((infix_cif_func)infix_forward_get_code(trampoline))((void *)MessageBoxW_ptr, &result, args);
    printf("MessageBoxW returned: %d\n", result);

    infix_forward_destroy(trampoline);
    FreeLibrary(user32);
}

#elif defined(__APPLE__)
// --- macOS: Calling CoreFoundation ---
#include <dlfcn.h>

typedef const void * CFStringRef;
typedef const void * CFAllocatorRef;
typedef unsigned long CFStringEncoding;  // kCFStringEncodingUTF8 is 0x08000100
typedef long CFIndex;                    // On 64-bit macOS, CFIndex is a long

void run_macos_example() {
    printf("--- macOS Example: Calling CoreFoundation ---\n");
    void * cf = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_LAZY);
    if (!cf) {
        fprintf(stderr, "Failed to load CoreFoundation.\n");
        return;
    }

    void * CFStringCreateWithCString = dlsym(cf, "CFStringCreateWithCString");
    void * CFStringGetLength = dlsym(cf, "CFStringGetLength");
    void * CFRelease = dlsym(cf, "CFRelease");

    infix_forward_t *t_create, *t_getlen, *t_release;
    // CFStringRef CFStringCreateWithCString(CFAllocatorRef, const char *, CFStringEncoding)
<<<<<<< HEAD
    infix_forward_create(&t_create, "(*void, *char, ulong) -> *void");
    // CFIndex CFStringGetLength(CFStringRef)
    infix_forward_create(&t_getlen, "(*void) -> long");
    // void CFRelease(CFTypeRef)
    infix_forward_create(&t_release, "(*void) -> void");
=======
    infix_forward_create(&t_create, "v*,c*,l=>v*");
    // CFIndex CFStringGetLength(CFStringRef)
    infix_forward_create(&t_getlen, "v*=>l");
    // void CFRelease(CFTypeRef)
    infix_forward_create(&t_release, "v*=>v");
>>>>>>> main

    CFAllocatorRef allocator = NULL;
    const char * my_str = "Hello from macOS!";
    CFStringEncoding encoding = 0x08000100;  // kCFStringEncodingUTF8
    void * create_args[] = {&allocator, &my_str, &encoding};
    CFStringRef cf_str = NULL;
    ((infix_cif_func)infix_forward_get_code(t_create))(CFStringCreateWithCString, &cf_str, create_args);

    if (cf_str) {
        CFIndex length = 0;
        void * cf_str_arg[] = {&cf_str};
        ((infix_cif_func)infix_forward_get_code(t_getlen))(CFStringGetLength, &length, cf_str_arg);
        printf("String length from CoreFoundation: %ld\n", length);

        ((infix_cif_func)infix_forward_get_code(t_release))(CFRelease, NULL, cf_str_arg);
    }

    infix_forward_destroy(t_create);
    infix_forward_destroy(t_getlen);
    infix_forward_destroy(t_release);
    dlclose(cf);
}

#elif defined(__linux__)
// --- Linux/POSIX: Calling libc and libm ---
#include <dlfcn.h>
#include <unistd.h>

void run_linux_example() {
    printf("--- Linux/POSIX Example: Calling libc & libm ---\n");
    void * libc = dlopen("libc.so.6", RTLD_LAZY);
    void * gethostname_ptr = dlsym(libc, "gethostname");
    void * libm = dlopen("libm.so.6", RTLD_LAZY);
    void * pow_ptr = dlsym(libm, "pow");

    infix_forward_t *t_hostname, *t_pow;
    // int gethostname(char *name, size_t len);
<<<<<<< HEAD
    infix_forward_create(&t_hostname, "(*char, uint64) -> int");  // size_t is uint64 on 64-bit linux
    // double pow(double base, double exp);
    infix_forward_create(&t_pow, "(double, double) -> double");
=======
    infix_forward_create(&t_hostname, "c*,y=>i");  // y is uint64_t (size_t on 64-bit linux)
    // double pow(double base, double exp);
    infix_forward_create(&t_pow, "d,d=>d");
>>>>>>> main

    // Call gethostname
    char hostname_buf[256] = {0};
    size_t len = sizeof(hostname_buf);
    int result = 0;
<<<<<<< HEAD
    void * hostname_args[] = {hostname_buf, &len};  // Pass buffer by value (decays to pointer)
=======
    // Note: The first arg is the buffer itself, the second is a pointer to the length.
    void * hostname_args[] = {hostname_buf, &len};
>>>>>>> main
    ((infix_cif_func)infix_forward_get_code(t_hostname))(gethostname_ptr, &result, hostname_args);
    if (result == 0)
        printf("Linux Hostname: %s\n", hostname_buf);

    // Call pow
    double base = 2.0, exp = 10.0, pow_result = 0.0;
    void * pow_args[] = {&base, &exp};
    ((infix_cif_func)infix_forward_get_code(t_pow))(pow_ptr, &pow_result, pow_args);
    printf("2^10 = %f\n", pow_result);  // Expected: 1024.0

    infix_forward_destroy(t_hostname);
    infix_forward_destroy(t_pow);
    dlclose(libc);
    dlclose(libm);
}
#endif

int main() {
#if defined(_WIN32)
    run_windows_example();
#elif defined(__APPLE__)
    run_macos_example();
#elif defined(__linux__)
    run_linux_example();
#else
    printf("No system library example available for this platform.\n");
#endif
    return 0;
}
