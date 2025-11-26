/**
 * @file EventManager.cpp
 * @brief A C++ class that accepts a C-style callback, for the C-to-C++ callback example.
 *
 * This version includes all necessary components for robust, cross-platform FFI:
 * 1. A cross-platform API_EXPORT macro to ensure the class is visible.
 * 2. An extern "C" helper to provide the true size of the class to C code.
 * 3. A dummy extern "C" function to prevent the linker from discarding the
 *    class's methods as "dead code".
 */
#include <iostream>

// A robust, cross-platform macro for exporting symbols from a shared library.
#if defined(_WIN32)
#define API_EXPORT __declspec(dllexport)
#else
#define API_EXPORT __attribute__((visibility("default")))
#endif

// The entire class is marked for export, making all its public methods visible.
class API_EXPORT EventManager {
private:
    // We store the C-style callback as two separate parts:
    // the function pointer and the opaque user_data pointer.
    void (*handler_ptr)(int, void *);
    void * user_data;

public:
    EventManager();

    // A method to register a C-style callback.
    void set_handler(void (*h)(int, void *), void * data);

    // A method to trigger the stored callback.
    void trigger(int value);
};

// The constructor must also be public and exported.
EventManager::EventManager() : handler_ptr(nullptr), user_data(nullptr) {
    // std::cout << "  -> C++ EventManager constructed.\n";
}

void EventManager::set_handler(void (*h)(int, void *), void * data) {
    // std::cout << "  -> C++ EventManager received and stored the C callback.\n";
    this->handler_ptr = h;
    this->user_data = data;
}

void EventManager::trigger(int value) {
    if (handler_ptr) {
        // std::cout << "  -> C++ is triggering the C callback with value " << value << "...\n";
        //  When the callback is invoked, we pass back the opaque user_data pointer
        //  that was originally provided to set_handler.
        handler_ptr(value, user_data);
    }
    else
        std::cout << "  -> C++ trigger called, but no handler is registered.\n";
}

// Extern "C" Helpers for a Stable C ABI
extern "C" {
/**
 * @brief Provides the true, compiler-determined size of the EventManager class.
 * This is the ONLY safe way for C code to know how much memory to allocate.
 */
API_EXPORT size_t EventManager_get_size() { return sizeof(EventManager); }

/**
 * @brief A dummy function to force the linker to keep all class methods.
 * Its only purpose is to call every method, creating a dependency that
 * prevents the linker from discarding them as "dead code."
 */
API_EXPORT void _internal_force_export_all_eventmanager_methods() {
    EventManager * temp = new EventManager();
    temp->set_handler(nullptr, nullptr);
    temp->trigger(0);
    delete temp;
}
}
