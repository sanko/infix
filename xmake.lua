-- XMake project file for the infix FFI Library
-- This single file supports Windows, macOS, and Linux.

set_project("infix")
set_version("0.1.0", {build = "%Y%m%d%H%M", soname = true})
set_languages("c17")

-- Add all necessary include directories for the build process.
add_includedirs("include", "src", "src/core", "src/arch/x64", "src/arch/aarch64")

-- Add compiler-specific flags globally.
after_load(function (target)
    if target:toolchain("msvc") then
        target:add("cxflags", "/experimental:c11atomics")
    end
end)

-- Define the static library target "infix"
target("infix")
    set_kind("static")
    -- Only compile the top-level core files. The unity build in trampoline.c
    -- will include the correct arch-specific .c files.
    add_files("src/infix.c")
    -- Expose only the public 'include' directory to consumers of this library
    add_includedirs("include", {public = true})
    -- Be noisy
--~     add_defines("FFI_DEBUG_ENABLED=1")

-- Define the test targets.
for _, test_file in ipairs(os.files("t/**/*.c")) do
    local target_name = path.basename(test_file)

    target(target_name)
        set_kind("binary")
        set_default(false)

        add_files(test_file)
        add_defines("FFI_DEBUG_ENABLED=1")

        -- Add dependencies for the special regression test case
        if test_file:endswith("850_regression_cases.c") then
            -- This test needs the fuzzer's helper functions to compile.
            -- We call add_files() directly; it's scoped to the current target.
            add_files("fuzz/fuzz_helpers.c")
            -- It also needs the fuzz/ directory in its include path to find fuzz_helpers.h.
            add_includedirs("fuzz")
        end

        add_deps("infix")
        set_targetdir("bin")

        add_includedirs("t/include")
        add_defines("DBLTAP_ENABLE=1")
        add_tests(target_name)

        -- Add platform-specific system libraries for tests
        on_config(function(target)
            if is_plat("linux") then
            -- Always need pthread and dl on Linux for tests
                target:add("syslinks", "pthread", "dl")
                -- Check if shm_open requires linking librt
                if target:has_cfuncs("shm_open_in_rt", {includes = "sys/mman.h", trylinks="rt"}) then
                    target:add("defines", "HAVE_LIBRT") -- For kicks
                end
            elseif is_plat("posix") then
                target:add_syslinks("dl")
            end
         end)
end

-- Define the fuzzing harness targets
-- This will automatically create targets for fuzz_types, fuzz_trampoline, and fuzz_signature
for _, fuzz_harness in ipairs(os.files("fuzz/fuzz_*.c")) do
    -- Exclude the helper file from being a main target
    if not fuzz_harness:endswith("helpers.c") then
        local target_name = path.basename(fuzz_harness):gsub("%.c", "")

        target(target_name)
            set_kind("binary")
            set_default(false)
            set_targetdir("bin") -- Place fuzzers in the same output dir as tests

            add_files(fuzz_harness)
            -- All fuzzers need the helpers and the main library
            add_files("fuzz/fuzz_helpers.c")
            add_deps("infix")
            set_policy("build.sanitizer.address", true)
            add_includedirs("fuzz", "src/core") -- Add src/core for internals.h

            -- Add fuzzer-specific flags
            -- This requires the user to configure the toolchain appropriately,
            -- e.g., 'xmake f -c clang' for sanitizers.
            on_load(function (target)
                if target:toolchain("clang") then
                    target:add("cxflags", "-g", "-fsanitize=fuzzer,address,undefined")
                    target:add("ldflags", "-fsanitize=fuzzer,address,undefined")
                elseif target:toolchain("gcc") then
                    -- For AFL++, the user should set the compiler via `xmake f --cc=afl-gcc`
                    target:add("defines", "USE_AFL=1")
                end
            end)
    end
end

--~ xmake test
--~ xmake f --toolchain=gcc -c
--~ xmake f --toolchain=clang -c
--~ xmake f --toolchain=msvc -c
