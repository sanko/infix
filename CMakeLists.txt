# CMake build script for the infix FFI library
cmake_minimum_required(VERSION 3.12)
project(infix VERSION 0.1.0 LANGUAGES C)

# Set the C standard to C17 and make it a requirement.
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Use the standard GNUInstallDirs module to define portable installation paths.
include(GNUInstallDirs)

# Add the static library target.
# Since infix uses a unity build, we only need to specify the main infix.c file.
add_library(infix STATIC src/infix.c)

# Specify include directories for the library target itself and for its consumers.
target_include_directories(infix
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        src
        src/common
        src/core
        src/arch/x64
        src/arch/aarch64
)

# Installation Rules:
install(TARGETS infix
    EXPORT infix-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/infix/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/infix.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/infix.pc"
    @ONLY
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/infix.pc"
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig"
)

# --- Testing ---
enable_testing()

# Define a function to simplify adding test executables
function(add_infix_test test_name)
    add_executable("${test_name}" "t/${test_name}.c")

    # Add all necessary include directories for the test targets.
    # This now includes the 'src' directory, which contains 'common/double_tap.h'.
    target_include_directories("${test_name}" PRIVATE
        "t/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
    )

    # Link the test against the main library.
    target_link_libraries("${test_name}" PRIVATE infix)

    if(UNIX)
        target_link_libraries("${test_name}" PRIVATE m)
    endif()
    # Add specific sources for certain tests
    if (test_name STREQUAL "850_regression_cases")
        target_sources("${test_name}" PRIVATE "fuzz/fuzz_helpers.c")
        target_include_directories("${test_name}" PRIVATE fuzz)
    endif()

    target_compile_definitions("${test_name}" PRIVATE
        DBLTAP_ENABLE=1
        INFIX_DEBUG_ENABLED=1
    )

    # Add architecture-specific SIMD flags
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        if(MSVC)
            target_compile_options(${test_name} PRIVATE "/arch:AVX512")
        else()
            target_compile_options(${test_name} PRIVATE "-msse2" "-mavx2" "-mavx512f")
        endif()
    elseif(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            target_compile_options(${test_name} PRIVATE "-march=armv8-a+sve")
        endif()
    endif()

    add_test(NAME "${test_name}" COMMAND "${test_name}")
endfunction()

# Add all test targets using the helper function.
add_infix_test(001_primitives)
add_infix_test(002_simple_calls)
add_infix_test(003_type_system_api)
add_infix_test(004_signatures)
add_infix_test(005_layouts)
add_infix_test(006_end_to_end_calls)
add_infix_test(007_type_registry)
add_infix_test(008_registry_introspection)
add_infix_test(101_by_value)
add_infix_test(102_by_reference)
add_infix_test(103_unions)
add_infix_test(201_basic)
add_infix_test(202_in_structs)
add_infix_test(203_complex)
add_infix_test(301_primitives)
add_infix_test(302_aggregates)
add_infix_test(303_advanced)
add_infix_test(304_reverse_call_types)
add_infix_test(401_large_stack)
add_infix_test(402_variadic_functions)
add_infix_test(403_special_types)
add_infix_test(810_memory_stress)
add_infix_test(811_fault_injection)
add_infix_test(820_threading_helgrind)
add_infix_test(821_threading_bare)
add_infix_test(830_security)
add_infix_test(840_arena_allocator)
add_infix_test(850_regression_cases)
add_infix_test(851_lifecycle_regression)
add_infix_test(860_error_handling)
add_infix_test(901_call_overhead)
add_infix_test(903_generation_benchmark)

# cmake -B build ; cmake --build build; ctest --test-dir build
