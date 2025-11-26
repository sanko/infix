/**
 * @file Box.cpp
 * @brief C++ template class for the template interop example.
 *
 * This file demonstrates the complex and fragile technique of manually forcing
 * the compiler to generate and export specific template methods from a shared
 * library. This is necessary because the compiler will not generate code for
 * template methods unless they are explicitly used within the library itself
 * or explicitly instantiated.
 *
 * The technique shown here is to create dummy `extern "C"` functions whose only
 * purpose is to call the template methods we need. This creates a dependency
 * chain that forces the linker to keep the code for those methods.
 */

// Note that the `cout` calls won't work without the main executable being linked with the correct C++ runtime
#include <iostream>
#include <string>

// Cross-platform macro for exporting symbols from a shared library.
// On Windows, this is __declspec(dllexport).
// On Linux/macOS with GCC/Clang, this is __attribute__((visibility("default"))).
// This is necessary when compiling with the `-fvisibility=hidden` flag.
#if defined(_WIN32)
#define MYCLASS_API __declspec(dllexport)
#else
#define MYCLASS_API __attribute__((visibility("default")))
#endif

// The class template itself must be marked for export. This tells the compiler
// that instantiations of this template may need to be visible externally.
template <typename T>
class MYCLASS_API Box {
private:
    T m_value;

public:
    Box(T initial_value) : m_value(initial_value) {
        // std::cout << "  -> C++ Box<T>::Box() called. Storing value." << std::endl;
    }
    T get_value() const {
        // std::cout << "  -> C++ Box<T>::get_value() called. Returning value." << std::endl;
        return m_value;
    }
    void set_value(T new_value) {
        m_value = new_value;
        // std::cout << "  -> C++ Box<T>::set_value() called. New value stored." << std::endl;
    }
    ~Box() { std::cout << "  -> C++ Box<T>::~Box() called." << std::endl; }
};

// Extern "C" Helpers for C Interop
// These are the "clean" factory functions and helpers that the C code will use.
extern "C" {
// We use a void* handle to hide the C++ template type from the C code.
MYCLASS_API void * create_box_double(double val) { return new Box<double>(val); }
MYCLASS_API void * create_box_int(int val) { return new Box<int>(val); }
MYCLASS_API void destroy_box_double(void * box) { delete static_cast<Box<double> *>(box); }
MYCLASS_API void destroy_box_int(void * box) { delete static_cast<Box<int> *>(box); }

MYCLASS_API size_t get_sizeof_box_double() { return sizeof(Box<double>); }
MYCLASS_API size_t get_sizeof_box_int() { return sizeof(Box<int>); }

// Helpers to return the compiler-specific mangled names for the C code to look up.
MYCLASS_API const char * get_mangled_box_double_getvalue() {
#if defined(_MSC_VER)
    return "?get_value@?$Box@N@@QEBANXZ";  // MSVC mangling for Box<double>::get_value()
#else
    return "_ZNK3BoxIdE9get_valueEv";  // Itanium (GCC/Clang) mangling for Box<double>::get_value()
#endif
}

MYCLASS_API const char * get_mangled_box_int_getvalue() {
#if defined(_MSC_VER)
    return "?get_value@?$Box@H@@QEBAHXZ";  // MSVC mangling for Box<int>::get_value()
#else
    return "_ZNK3BoxIiE9get_valueEv";  // Itanium (GCC/Clang) mangling for Box<int>::get_value()
#endif
}
// Add more mangled name helpers for set_value, etc., as needed by the example.
}

// THE "HARD WAY": MANUALLY FORCING METHOD INSTANTIATION AND EXPORT
//
// To demonstrate the complexity, we create these dummy `extern "C"` functions.
// Their only purpose is to call the template methods we need from C.
// Because these dummy functions are exported (using MYCLASS_API), the compiler
// is forced to generate the code for the template methods they depend on.
// These functions are NOT meant to be called from the C example; they are a build-time trick.
extern "C" {
/**
 * @brief Dummy function to force the export of all methods for `Box<double>`.
 */
MYCLASS_API void _internal_force_export_all_methods_double() {
    Box<double> * temp = new Box<double>(0.0);  // Instantiates constructor
    temp->set_value(1.0);                       // Instantiates set_value
    temp->get_value();                          // Instantiates get_value
    delete temp;                                // Instantiates destructor
}

/**
 * @brief Dummy function to force the export of all methods for `Box<int>`.
 */
MYCLASS_API void _internal_force_export_all_methods_int() {
    Box<int> * temp = new Box<int>(0);  // Instantiates constructor
    temp->set_value(1);                 // Instantiates set_value
    temp->get_value();                  // Instantiates get_value
    delete temp;                        // Instantiates destructor
}
}
