# CMake build script for the infix FFI library
cmake_minimum_required(VERSION 3.12)
project(infix VERSION 1.0.0 LANGUAGES C CXX)

# Set the C standard to C17 and make it a requirement.
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use the standard GNUInstallDirs module to define portable installation paths
# (e.g., CMAKE_INSTALL_LIBDIR, CMAKE_INSTALL_INCLUDEDIR).
include(GNUInstallDirs)

# Add the static library target.
# Since infix uses a unity build, we only need to specify the main infix.c file.
add_library(infix STATIC src/infix.c)

# Specify the public include directory. This is necessary for consumers of the library
# to find <infix/infix.h>.
target_include_directories(infix
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/core>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/arch/x64>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/arch/aarch64>
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
#    This step creates infix.pc from the infix.pc.in template.
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/infix.pc.in"
    "${CMAKE_CURRENT_BINARY_DIR}/infix.pc"
    @ONLY
)

# Install the generated infix.pc file to the standard pkg-config location.
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/infix.pc"
    DESTINATION "${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig"
)

# Examples
option(INFIX_BUILD_EXAMPLES "Build the cookbook example programs" ON)
if(INFIX_BUILD_EXAMPLES)
    # Add a helper library for the C++ example
    add_library(counter SHARED eg/cookbook/lib/counter.cpp)
    target_include_directories(counter PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/eg/cookbook/lib)
    # Find all example source files
    file(GLOB EXAMPLE_SOURCES "eg/cookbook/*.c")
    foreach(EXAMPLE_SOURCE ${EXAMPLE_SOURCES})
        get_filename_component(EXAMPLE_NAME ${EXAMPLE_SOURCE} NAME_WE)
        add_executable(${EXAMPLE_NAME} ${EXAMPLE_SOURCE})
        target_link_libraries(${EXAMPLE_NAME} PRIVATE infix)
        target_include_directories(${EXAMPLE_NAME}
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/core>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/arch/x64>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/arch/aarch64>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/t/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/fuzz>
        )
        # Link the C++ example to the counter library
        if(EXAMPLE_NAME STREQUAL "03_opaque_pointers")
            target_sources(${EXAMPLE_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/eg/cookbook/lib/handle_lib.c")
            target_include_directories(${EXAMPLE_NAME} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/eg/cookbook/lib")
        endif()
        if(EXAMPLE_NAME STREQUAL "18_cpp_example")
            target_link_libraries(${EXAMPLE_NAME} PRIVATE counter)
        endif()
        # Link system libraries example to platform-specific libs
        if(EXAMPLE_NAME STREQUAL "19_system_libraries")
            if(WIN32)
                target_link_libraries(${EXAMPLE_NAME} PRIVATE user32)
            elseif(APPLE OR UNIX)
                target_link_libraries(${EXAMPLE_NAME} PRIVATE dl)
            endif()
        endif()
    endforeach()
endif()

# Testing (Optional)
enable_testing()

# Define a function to simplify adding test executables
function(add_infix_test category test_name)
    add_executable(
    "${category}-${test_name}"
    t/${category}/${test_name}.c)

    target_include_directories("${category}-${test_name}"
        PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/common>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/core>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/arch/x64>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/arch/aarch64>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/t/include>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/fuzz>
    )

    if (test_name STREQUAL "850_regression_cases")
        target_sources("${category}-${test_name}" PRIVATE "fuzz/fuzz_helpers.c")
    endif()

    target_compile_definitions("${category}-${test_name}" PRIVATE
        DBLTAP_ENABLE=1
        # This should be behind a --verbose gate
        INFIX_DEBUG_ENABLED=1
   )

    target_link_libraries("${category}-${test_name}" PRIVATE infix)

    add_test(
        "${category}-${test_name}"
        "${category}-${test_name}"
    )
endfunction()

add_infix_test(000_core 001_primitives)
add_infix_test(000_core 002_simple_calls)
add_infix_test(000_core 003_type_system_api)
add_infix_test(000_core 004_signatures)

add_infix_test(100_aggregates 101_by_value)
add_infix_test(100_aggregates 102_by_reference)
add_infix_test(100_aggregates 103_unions)

add_infix_test(200_pointers 201_basic)
add_infix_test(200_pointers 202_in_structs)

add_infix_test(300_callbacks 301_primitives)
add_infix_test(300_callbacks 302_aggregates)
add_infix_test(300_callbacks 303_advanced)

add_infix_test(400_advanced 401_large_stack)
add_infix_test(400_advanced 402_variadic_functions)
add_infix_test(400_advanced 403_special_types)

# add_infix_test(500_generated )

add_infix_test(800_security 811_fault_injection)
add_infix_test(800_security 820_threading_helgrind)
add_infix_test(800_security 830_security)
add_infix_test(800_security 840_arena_allocator)
add_infix_test(800_security 850_regression_cases)

add_infix_test(900_performance 901_call_overhead)
add_infix_test(900_performance 903_generation_benchmark)

# cmake -B build ; cmake --build build; ctest --test-dir build
