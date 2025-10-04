# CMake build script for the infix FFI library
cmake_minimum_required(VERSION 3.12)
project(infix VERSION 0.1.0 LANGUAGES C CXX)

# Set the C standard to C17 and make it a requirement.
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build versioned docs from Doxygen
add_subdirectory(docs)

# Use the standard GNUInstallDirs module to define portable installation paths.
include(GNUInstallDirs)

# Add the static library target.
# Since infix uses a unity build, we only need to specify the main infix.c file.
add_library(infix STATIC src/infix.c)

# Specify include directories for the library target itself and for its consumers.
target_include_directories(infix
    # PUBLIC: Consumers linking against `infix` will automatically get these include paths.
    PUBLIC
        # When building, consumers need the path to the `include` dir in the source tree.
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        # When installed, consumers need the system's standard include directory.
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        # FIX: The public header `infix.h` includes a file from `src/common`. Therefore,
        # this directory MUST be part of the public interface for the library to be usable.
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
        src
        src/core
        src/arch/x64
        src/arch/aarch64
)

# Installation Rules:
# 1. Install the static library target (libinfix.a or infix.lib).
install(TARGETS infix
    EXPORT infix-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# 2. Install the public header directory (include/infix).
install(DIRECTORY include/infix/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# 3. Configure and install the pkg-config file.
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/infix.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/infix.pc"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/infix.pc"
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig"
)

# --- Examples ---
option(INFIX_BUILD_EXAMPLES "Build the cookbook example programs" ON)
if(INFIX_BUILD_EXAMPLES)
    # Helper library for the C++ example. Must be SHARED for dynamic loading.
    add_library(counter SHARED eg/cookbook/lib/counter.cpp)
    target_include_directories(counter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/eg/cookbook/lib)

    # Helper library for the opaque handle example. Can be STATIC.
    add_library(handle_lib STATIC eg/cookbook/lib/handle_lib.c)
    target_include_directories(handle_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/eg/cookbook/lib)

    # List all examples explicitly instead of using file(GLOB).
    set(EXAMPLE_SOURCES
        eg/cookbook/01_simple_call.c
        eg/cookbook/02_pointers.c
        eg/cookbook/03_opaque_pointers.c
        eg/cookbook/04_fixed_arrays.c
        eg/cookbook/05_dynamic_marshalling.c
        eg/cookbook/06_small_struct_by_value.c
        eg/cookbook/07_large_struct_by_reference.c
        eg/cookbook/08_return_struct.c
        eg/cookbook/09_packed_struct.c
        eg/cookbook/10_unions.c
        eg/cookbook/11_pointer_to_array.c
        eg/cookbook/12_callback_qsort.c
        eg/cookbook/13_stateful_callback.c
        eg/cookbook/14_variadic_printf.c
        eg/cookbook/15_variadic_callback.c
        eg/cookbook/16_nested_calls.c
        eg/cookbook/17_return_callback.c
        eg/cookbook/18_cpp_example.c
        eg/cookbook/19_system_libraries.c
    )

    if(WIN32)
        # If it is, append the Windows-specific examples to the list.
        list(APPEND EXAMPLE_SOURCES
            eg/win32_msgbox.c
        )
    endif()

    foreach(EXAMPLE_SOURCE ${EXAMPLE_SOURCES})
        get_filename_component(EXAMPLE_NAME ${EXAMPLE_SOURCE} NAME_WE)
        add_executable(${EXAMPLE_NAME} ${EXAMPLE_SOURCE})

        include(CheckCXXCompilerFlag)
        check_cxx_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2_GCC)
        check_cxx_compiler_flag("/arch:AVX2" COMPILER_SUPPORTS_AVX2_MSVC)
        if(COMPILER_SUPPORTS_AVX2_GCC)
            add_compile_options("-mavx2")
        elseif(COMPILER_SUPPORTS_AVX2_MSVC)
            add_compile_options("/arch:AVX2")
        else()
            message(WARNING "Compiler does not support AVX2 instruction set.")
        endif()

        # Link against the main library. This propagates the PUBLIC include directories.
        target_link_libraries(${EXAMPLE_NAME} PRIVATE infix)
        target_include_directories(${EXAMPLE_NAME}
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        )
        # For examples that use helper headers (like types.h), add the specific include path.
        if(EXAMPLE_NAME MATCHES "^(06|07|08|09|10)_")
             target_include_directories(${EXAMPLE_NAME} PRIVATE eg/cookbook/lib)
        endif()

        # Link specific examples to their helper libraries.
        if(EXAMPLE_NAME STREQUAL "03_opaque_pointers")
            target_link_libraries(${EXAMPLE_NAME} PRIVATE handle_lib)
        endif()
        if(EXAMPLE_NAME STREQUAL "18_cpp_example")
            target_link_libraries(${EXAMPLE_NAME} PRIVATE counter)
        endif()

        # Link system libraries example to platform-specific libs
        if(EXAMPLE_NAME STREQUAL "19_system_libraries")
            if(WIN32)
                target_link_libraries(${EXAMPLE_NAME} PRIVATE user32)
            elseif(UNIX)
                target_link_libraries(${EXAMPLE_NAME} PRIVATE dl)
            endif()
        endif()
    endforeach()
endif()

# --- Testing ---
enable_testing()

# Define a function to simplify adding test executables
function(add_infix_test test_name)
    add_executable("${test_name}" "t/${test_name}.c")

    # The test executable is a consumer of the `infix` library, just like an example.
    # It only needs the public include directory, which is provided by linking against `infix`.
    # We add the test-specific include directory separately.
    target_include_directories("${test_name}" PRIVATE t/include)
    target_include_directories("${test_name}"
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
    )
    # Link the test against the main library.
    target_link_libraries("${test_name}" PRIVATE infix)

    # Add specific sources for certain tests
    if (test_name STREQUAL "850_regression_cases")
        target_sources("${test_name}" PRIVATE "fuzz/fuzz_helpers.c")
        target_include_directories("${test_name}" PRIVATE fuzz)
    endif()

    target_compile_definitions("${test_name}" PRIVATE
        DBLTAP_ENABLE=1
        INFIX_DEBUG_ENABLED=1 # This can be gated behind a CMake option if desired
    )

    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-mavx2" COMPILER_SUPPORTS_AVX2_GCC)
    check_cxx_compiler_flag("/arch:AVX2" COMPILER_SUPPORTS_AVX2_MSVC)
    if(COMPILER_SUPPORTS_AVX2_GCC)
        add_compile_options("-mavx2")
    elseif(COMPILER_SUPPORTS_AVX2_MSVC)
        add_compile_options("/arch:AVX2")
    else()
        message(WARNING "Compiler does not support AVX2 instruction set.")
    endif()

    add_test(NAME "${test_name}" COMMAND "${test_name}")
endfunction()

# Add all test targets using the helper function.
# NOTE: The missing tests from the log have been added back in.
add_infix_test(001_primitives)
add_infix_test(002_simple_calls)
add_infix_test(003_type_system_api)
add_infix_test(004_signatures)
add_infix_test(005_layouts)
add_infix_test(006_end_to_end_calls)

add_infix_test(101_by_value)
add_infix_test(102_by_reference)
add_infix_test(103_unions)

add_infix_test(201_basic)
add_infix_test(202_in_structs)

add_infix_test(301_primitives)
add_infix_test(302_aggregates)
add_infix_test(303_advanced)

add_infix_test(401_large_stack)
add_infix_test(402_variadic_functions)
add_infix_test(403_special_types)

# add_infix_test(500_generated )

add_infix_test(811_fault_injection)
add_infix_test(820_threading_helgrind)
add_infix_test(830_security)
add_infix_test(840_arena_allocator)
add_infix_test(850_regression_cases)

add_infix_test(901_call_overhead)
add_infix_test(903_generation_benchmark)

# cmake -B build ; cmake --build build; ctest --test-dir build
