-- XMake project file for the infix FFI Library
-- This single file supports Windows, macOS, and Linux.

set_project("infix")
set_version("0.1.0", {build = "%Y%m%d%H%M", soname = true})
set_languages("c17")

-- Add all necessary include directories for the build process.
add_includedirs("include", "src", "src/arch/x64", "src/arch/aarch64")

-- Add compiler-specific flags globally.
after_load(function (target)
    if target:toolchain("msvc") then
        target:add("cxflags", "/experimental:c11atomics")
    end
    target:add("defines", "FFI_DEBUG_ENABLED=1")
end)

-- Define the static library target "infix"
target("infix")
    set_kind("static")
    -- Only compile the top-level core files. The unity build in trampoline.c
    -- will include the correct arch-specific .c files.
    add_files("src/core/*.c")
    -- Expose only the public 'include' directory to consumers of this library
    add_includedirs("include", {public = true})

    -- Define the test targets.
    for _, test_file in ipairs(os.files("t/**/*.c")) do
        local target_name = path.basename(test_file)

        target(target_name)
            set_kind("binary")
            set_default(false)

            add_files(test_file)
            add_deps("infix")
            set_targetdir("bin")

            add_includedirs("t/include", "third_party/double_tap")
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

--~ xmake test
--~ xmake f --toolchain=gcc -c
--~ xmake f --toolchain=clang -c
--~ xmake f --toolchain=msvc -c
