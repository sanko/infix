# CMake build script for the infix FFI library
cmake_minimum_required(VERSION 3.12)
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/infix/infix.h" INFIX_MAJOR_LINE REGEX "^#define INFIX_MAJOR")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/infix/infix.h" INFIX_MINOR_LINE REGEX "^#define INFIX_MINOR")
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/include/infix/infix.h" INFIX_PATCH_LINE REGEX "^#define INFIX_PATCH")

string(REGEX MATCH "[0-9]+" INFIX_MAJOR "${INFIX_MAJOR_LINE}")
string(REGEX MATCH "[0-9]+" INFIX_MINOR "${INFIX_MINOR_LINE}")
string(REGEX MATCH "[0-9]+" INFIX_PATCH "${INFIX_PATCH_LINE}")

project(infix VERSION ${INFIX_MAJOR}.${INFIX_MINOR}.${INFIX_PATCH} LANGUAGES C CXX)

# Set the C standard to C17 and make it a requirement.
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Use the standard GNUInstallDirs module to define portable installation paths.
include(GNUInstallDirs)

# Add the library target.
# If BUILD_SHARED_LIBS is set to ON, this will generate a shared library.
add_library(infix src/infix.c)

# Default to hidden visibility to avoid polluting the global symbol table
# with internal functions (like _infix_set_error) when linked.
set_target_properties(infix PROPERTIES C_VISIBILITY_PRESET hidden)

# If building as a shared library, define INFIX_BUILDING_DLL to export symbols on Windows.
get_target_property(INFIX_TARGET_TYPE infix TYPE)
if(INFIX_TARGET_TYPE STREQUAL "SHARED_LIBRARY")
    target_compile_definitions(infix PRIVATE INFIX_BUILDING_DLL)
endif()

if(INFIX_DEBUG_ENABLED)
    target_compile_definitions(infix PRIVATE
        INFIX_DEBUG_ENABLED=1
    )
endif()

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

# Testing
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
    
    # Special handling for 880_exports: Link against shared library if available
    if(test_name STREQUAL "880_exports")
        if(BUILD_SHARED_LIBS)
            # Force linkage against the shared library target
            target_link_libraries("${test_name}" PRIVATE infix)
            # Define INFIX_USING_DLL on Windows to ensure correct import
            if(WIN32)
                target_compile_definitions("${test_name}" PRIVATE INFIX_USING_DLL)
            endif()
        endif()
        # Enable exports from the executable so it can dlsym itself
        set_target_properties("${test_name}" PROPERTIES ENABLE_EXPORTS ON)
    endif()

    target_compile_definitions(${test_name} PRIVATE
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
# CONFIGURE_DEPENDS ensures CMake re-runs if you add/remove files in this directory.
file(GLOB TEST_SOURCES CONFIGURE_DEPENDS "t/*.c" "t/*.cpp")

foreach(test_source ${TEST_SOURCES})
    # Extract the filename without the extension ("t/001_primitives.c" => "001_primitives")
    get_filename_component(test_name "${test_source}" NAME_WE)

    # To skip specific files if they aren't meant to be run automatically, do something like this:
    if(test_name STREQUAL "903_generation_benchmark")
         continue()
    endif()

    # The function add_infix_test assumes .c, but we now have .cpp. 
    # Let's adjust the logic slightly or handle it here.
    # Since add_infix_test is a bit rigid, let's call add_executable directly for C++ 
    # or modify add_infix_test. For minimal changes, let's update add_infix_test to take source.

    if (test_source MATCHES "\\.cpp$")
         # Manual handling for C++ test
         add_executable("${test_name}" "${test_source}")
         target_include_directories("${test_name}" PRIVATE "t/include" "${CMAKE_CURRENT_SOURCE_DIR}/src")
         target_link_libraries("${test_name}" PRIVATE infix)
         if(UNIX)
            target_link_libraries("${test_name}" PRIVATE m)
         endif()
         target_compile_definitions(${test_name} PRIVATE DBLTAP_ENABLE=1 INFIX_DEBUG_ENABLED=1)
         
         # SIMD flags logic duplicated for C++... simpler to just assume standard flags or none for this compat test.
         add_test(NAME "${test_name}" COMMAND "${test_name}")
    else()
         add_infix_test("${test_name}")
    endif()
endforeach()

# cmake -DINFIX_DEBUG_ENABLED=1 -B build ; cmake --build build ; ctest --test-dir build --rerun-failed --output-on-failure
