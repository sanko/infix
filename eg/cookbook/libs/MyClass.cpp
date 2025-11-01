/**
 * @file MyClass.cpp
 * @brief A simple C++ class and the extern "C" helpers needed for the mangled name FFI example.
 */
#include <iostream>
#include <string>

// On Windows, we must explicitly export symbols we want to use in other modules.
#if defined(_WIN32)
#define EXPORT_API __declspec(dllexport)
#else
#define EXPORT_API __attribute__((visibility("default")))
#endif

class EXPORT_API MyClass {
private:
    int m_val;

public:
    EXPORT_API MyClass(int val) : m_val(val) {}
    EXPORT_API int getValue() const { return m_val; }
    EXPORT_API ~MyClass() {}
};

// This is the stable C Application Binary Interface (ABI) that our C code will use.
extern "C" {
/**
 * @brief A dummy factory function.
 * Its only purpose is to be exported and to call `new MyClass()`.
 * This creates a dependency that forces the C++ linker to include the
 * code for the constructor in the final shared library.
 * This function is NOT intended to be called by the C example.
 */
EXPORT_API MyClass * _internal_force_linker_to_keep_constructor(int val) { return new MyClass(val); }
/** @brief Returns the size of the C++ class, so C code can malloc() it. */
EXPORT_API size_t get_sizeof_myclass() { return sizeof(MyClass); }

/**
 * @brief Returns the compiler-specific mangled name for the constructor.
 */
EXPORT_API const char * get_mangled_constructor() {


#if defined(_MSC_VER)
    // MSVC Mangled Name for: public: __cdecl MyClass::MyClass(int)
    return "??0MyClass@@QEAA@H@Z";
#else
    // Itanium C++ ABI (GCC/Clang) Mangled Name for: MyClass::MyClass(int)
    return "_ZN7MyClassC1Ei";
#endif
}

/** @brief Returns the compiler-specific mangled name for the getValue method. */
EXPORT_API const char * get_mangled_getvalue() {
#if defined(_MSC_VER)
    // MSVC Mangled Name for: public: int __cdecl MyClass::getValue(void)const
    return "?getValue@MyClass@@QEBAHXZ";
#else
    // Itanium C++ ABI (GCC/Clang) Mangled Name for: int MyClass::getValue() const
    return "_ZNK7MyClass8getValueEv";
#endif
}

/** @brief Returns the compiler-specific mangled name for the destructor. */
EXPORT_API const char * get_mangled_destructor() {
#if defined(_MSC_VER)
    // MSVC Mangled Name for: public: __cdecl MyClass::~MyClass(void)
    return "??1MyClass@@QEAA@XZ";
#else
    // Itanium C++ ABI (GCC/Clang) Mangled Name for: MyClass::~MyClass()
    return "_ZN7MyClassD1Ev";
#endif
}
// This function's only purpose is to call every C++ method we want to export,
// creating a dependency that forces the linker to keep their code.
EXPORT_API void _internal_force_linker_to_keep_all_symbols() {
    // Create a temporary object. This forces the constructor to be kept.
    MyClass * temp = new MyClass(0);

    // Call getValue(). This forces getValue() to be kept.
    temp->getValue();

    // Delete the object. This forces the destructor to be kept.
    delete temp;
}
}
