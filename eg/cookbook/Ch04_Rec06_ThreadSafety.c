/**
 * @file Ch04_Rec06_ThreadSafety.c
 * @brief Cookbook Chapter 4, Recipe 6: Proving Thread Safety
 *
 * This example demonstrates that `infix` trampoline handles are thread-safe. A
 * trampoline handle (`infix_forward_t*` or `infix_reverse_t*`) is immutable
 * after creation and can be safely shared between threads. All mutable state
 * (like error details) is stored in thread-local storage, so calls from
 * different threads will not interfere with each other.
 *
 * This recipe creates a trampoline on the main thread and passes its callable
 * function pointer to a worker thread, which then executes the FFI call.
 */
#include <infix/infix.h>
#include <stdio.h>

// Platform-specific includes for threading.
#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#endif

// A simple C function to be the FFI target.
static int add(int a, int b) { return a + b; }

// A struct to pass data to our worker thread.
typedef struct {
    infix_cif_func cif;  // The callable trampoline function pointer.
    int result;
} thread_data_t;

// The function our worker thread will execute.
#if defined(_WIN32)
DWORD WINAPI worker_thread_func(LPVOID arg) {
#else
void * worker_thread_func(void * arg) {
#endif
    thread_data_t * data = (thread_data_t *)arg;

    printf("  -> Worker thread started.\n");

    int a = 20, b = 22;
    void * args[] = {&a, &b};

    // Call the trampoline function pointer that was created on the main thread.
    printf("  -> Worker thread making FFI call...\n");
    data->cif(&data->result, args);
    printf("  -> Worker thread finished FFI call.\n");

#if defined(_WIN32)
    return 0;
#else
    return NULL;
#endif
}

int main() {
    printf("--- Cookbook Chapter 4, Recipe 6: Proving Thread Safety ---\n");

    // 1. Main thread: Create the trampoline.
    printf("-> Main thread creating trampoline...\n");
    infix_forward_t * trampoline = NULL;
    infix_status status = infix_forward_create(&trampoline, "(int, int)->int", (void *)add, NULL);
    if (status != INFIX_SUCCESS) {
        fprintf(stderr, "Failed to create trampoline.\n");
        return 1;
    }

    // 2. Prepare the data struct to pass to the new thread.
    thread_data_t data = {infix_forward_get_code(trampoline), 0};

    // 3. Main thread: Spawn a worker thread, passing it the callable pointer.
    printf("-> Main thread spawning worker thread...\n");
#if defined(_WIN32)
    HANDLE thread_handle = CreateThread(NULL, 0, worker_thread_func, &data, 0, NULL);
    WaitForSingleObject(thread_handle, INFINITE);
    CloseHandle(thread_handle);
#else
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, worker_thread_func, &data);
    pthread_join(thread_id, NULL);
#endif
    printf("-> Main thread joined with worker thread.\n");

    // 4. Main thread: Check the result computed by the worker thread.
    printf("Result from worker thread: %d (Expected: 42)\n", data.result);

    // 5. Main thread: Clean up the trampoline.
    infix_forward_destroy(trampoline);

    return 0;
}
