#!/usr/bin/perl
use v5.36;
use Config qw[%Config];
use Cwd    qw[abs_path cwd];
use Data::Dumper;
use File::Basename qw[basename dirname];
use File::Copy     qw[copy move];
use File::Find     qw[find];
use File::Path     qw[make_path rmtree];
use File::Spec;
use File::Temp   qw[tempfile];
use Getopt::Long qw[GetOptions];
use List::Util   qw[uniq];
use FindBin;
$|++;

# Argument Parsing
my %opts;
GetOptions( \%opts, 'cc|compiler=s', 'cflags=s', 'h|help', 'codecov=s', 'abi=s', 'verbose|v' );
show_help() if $opts{help};
my $command    = lc( shift @ARGV || 'build' );
my @test_names = @ARGV;

# Global Cache for Git Info
my %git_info;

# Build Configuration
my $is_fuzz_build     = ( $command =~ /^fuzz/ );
my $is_coverage_build = ( $command eq 'coverage' );
my %config            = (
    sources => [
        $FindBin::Bin . '/src/core/executor.c',
        $FindBin::Bin . '/src/core/trampoline.c',
        $FindBin::Bin . '/src/core/types.c',
        $FindBin::Bin . '/src/core/arena.c',
        $FindBin::Bin . '/src/core/utility.c',
        $FindBin::Bin . '/src/core/signature.c'
    ],
    include_dirs => [
        File::Spec->catdir( $FindBin::Bin, 'include' ),
        File::Spec->catdir( $FindBin::Bin, 'src' ),
        File::Spec->catdir( $FindBin::Bin, 'src/core' ),
        File::Spec->catdir( $FindBin::Bin, 'src/arch/x64/' ),
        File::Spec->catdir( $FindBin::Bin, 'src/arch/aarch64' ),
        File::Spec->catdir( $FindBin::Bin, 'third_party/double_tap' ),
        File::Spec->catdir( $FindBin::Bin, 't/include' ),
    ],
    lib_dir      => 'build_lib',
    lib_name     => 'infix',
    coverage_dir => 'coverage'
);
$config{is_windows} = ( $^O =~ /MSWin32|msys|cygwin/i );

# Base CFLAGS that will be modified by ABI forcing or other options
my @base_cflags;

# Enable verbose/debug mode if requested
#~ if ( $opts{verbose} ) {
#~ print "# Verbose mode enabled. Compiling with FFI_DEBUG_ENABLED.\n";
#~ push @base_cflags, '-DFFI_DEBUG_ENABLED=1';
#~ }
# Environment Detection
$config{arch} = 'x64';
my $host_arch_raw = '';
if ( $config{is_windows} ) {
    if ( $ENV{PROCESSOR_IDENTIFIER} =~ m[ARM]i ) {
        $config{arch} = 'arm64';
        $host_arch_raw = 'arm64';
    }
    else {
        $config{arch} = 'x64';
        $host_arch_raw = 'x86_64';
    }
}
else {
    $host_arch_raw = `uname -m`;
    chomp $host_arch_raw;
    $config{arch} = $host_arch_raw;
    $config{arch} = 'arm64' if $config{arch} eq 'arm64'  || $config{arch} eq 'aarch64' || $config{arch} eq 'evbarm';
    $config{arch} = 'x64'   if $config{arch} eq 'x86_64' || $config{arch} eq 'amd64';
}
die "Could not determine architecture for $^O" unless $config{arch};

# --- ABI Forcing ---
if ( $opts{abi} ) {
    my $forced_abi = lc( $opts{abi} );
    print "User is forcing ABI to: $forced_abi (for code generation logic only)\n";
    if ( $forced_abi eq 'windows_x64' ) {
        push @base_cflags, '-DFFI_FORCE_ABI_WINDOWS_X64';
    }
    elsif ( $forced_abi eq 'sysv_x64' ) {
        push @base_cflags, '-DFFI_FORCE_ABI_SYSV_X64';
    }
    elsif ( $forced_abi eq 'aapcs64' ) {
        push @base_cflags, '-DFFI_FORCE_ABI_AAPCS64';
    }
    else {
        die "Error: Unknown ABI '$forced_abi'. Supported values are: windows_x64, sysv_x64, aapcs64.";
    }
}

# Compiler Selection
my %valid_compilers = map { $_ => 1 } qw[msvc gcc egcc clang];
my $compiler_arg    = $opts{cc} || '';
die "Error: Unknown compiler '$compiler_arg'. Please use one of: msvc, gcc, clang." if $compiler_arg && !$valid_compilers{$compiler_arg};
$config{compiler}
    = $compiler_arg ? $compiler_arg :
    ( $^O eq 'darwin' ? 'clang' :
        $config{is_windows}    ? ( command_exists('cl') ? 'msvc' : command_exists('gcc') ? 'gcc' : 'clang' ) :
        command_exists('egcc') ? 'egcc' :
        'gcc' );
if ( $is_fuzz_build && ( $config{compiler} ne 'clang' && $config{compiler} ne 'gcc' ) ) {
    die "Error: Fuzzing requires the 'clang' compiler for libFuzzer support or 'gcc' for AFL++ support.";
}

# Configure Build
my $obj_suffix = ( $config{compiler} eq 'msvc' ) ? '.obj' : '.o';
if ( $config{compiler} eq 'msvc' ) {
    die 'Warning: MSVC environment not detected. Build may fail. Please run from a VS dev prompt.' unless $ENV{VCINSTALLDIR};
    $config{cc} = 'cl';
    my @include_flags = map { '-I' . File::Spec->catfile($_) } @{ $config{include_dirs} };
    $config{cflags}  = [ @base_cflags, '-std:c17', '-experimental:c11atomics', '-W3', '-GS', '-MD', @include_flags ];
    $config{ldflags} = ['-link'];
    if ( $is_coverage_build || $command eq 'test' ) {
        push @{ $config{cflags} },  '-Zi';
        push @{ $config{ldflags} }, '-DEBUG';
    }
    if ( $command ne 'build' ) {
        push @{ $config{cflags} }, '-O2';
    }
}
else {    # GCC or Clang
    $config{cc} = $config{compiler};
    my @include_flags = map { "-I" . File::Spec->catfile($_) } @{ $config{include_dirs} };
    $config{cflags}  = [ @base_cflags, '-std=c17', '-Wall', '-Wextra', '-g', '-O2', '-pthread', @include_flags ];
    $config{ldflags} = [];
    if ( $config{compiler} eq 'clang' && $config{arch} eq 'arm64' && $host_arch_raw !~ /arm64|aarch64|evbarm/ && !$opts{abi} ) {
        print "ARM64 cross-compilation detected for clang. Adding --target flag.\n";
        my $target_triple = $config{is_windows} ? 'aarch64-pc-windows-msvc' : 'aarch64-linux-gnu';
        push @{ $config{cflags} },  "--target=$target_triple";
        push @{ $config{ldflags} }, "--target=$target_triple";
    }
    if ($is_coverage_build) {
        if ( $config{compiler} eq 'clang' ) {
            push @{ $config{cflags} },  '-fprofile-instr-generate', '-fcoverage-mapping';
            push @{ $config{ldflags} }, '-fprofile-instr-generate', '-fcoverage-mapping';
        }
        else {    # gcc
            push @{ $config{cflags} },  '--coverage';
            push @{ $config{ldflags} }, '--coverage';
        }
    }
    if ( !( $config{is_windows} && $config{compiler} eq 'clang' ) ) {
        push @{ $config{ldflags} }, '-lm';
    }
    if ( !$config{is_windows} ) {
        push @{ $config{ldflags} }, '-pthread';
        my $lrt_flag = check_for_lrt( \%config );
        push @{ $config{ldflags} }, $lrt_flag if $lrt_flag;
    }
    if ( $^O eq 'openbsd' ) {
        push @{ $config{ldflags} }, '-Wl,-w';
    }
}
push @{ $config{cflags} }, $opts{cflags} if $opts{cflags};

# Command Dispatch
print "Detected: OS=$^O, Arch=$config{arch}, Using Compiler=$config{compiler}\n";
my $final_status = 0;
if ( $command eq 'clean' ) {
    print "Cleaning build artifacts...\n";
    clean(%config);
}
elsif ( $command eq 'build' ) {
    my $lib_path = create_static_library( \%config, $obj_suffix );
    print "\nStatic library '$lib_path' built successfully.\n";
}
elsif ( $command eq 'test' || $command eq 'coverage' ) {
    push @{ $config{cflags} }, '-DDBLTAP_ENABLE=1';
    push @{ $config{cflags} }, '-DFFI_DEBUG_ENABLED=1' if $opts{verbose};
    $final_status = compile_and_run_tests( \%config, $obj_suffix, \@test_names, $is_coverage_build );
}
elsif ( $command eq 'memtest' ) {
    my %memtest_config = %config;
    @{ $memtest_config{cflags} } = @{ $config{cflags} };
    push @{ $memtest_config{cflags} }, '-DDBLTAP_ENABLE=1';
    push @{ $memtest_config{cflags} }, '-DFFI_DEBUG_ENABLED=1' if $opts{verbose};
    $final_status = run_valgrind_test( \%memtest_config, $obj_suffix, '800_security/810_memory_stress', 'memcheck' );
}
elsif ( $command eq 'memtest:fault' ) {
    my %memtest_config = %config;
    @{ $memtest_config{cflags} } = @{ $config{cflags} };
    push @{ $memtest_config{cflags} }, '-DDBLTAP_ENABLE=1';
    push @{ $memtest_config{cflags} }, '-DFFI_DEBUG_ENABLED=1' if $opts{verbose};
    $final_status = run_valgrind_test( \%memtest_config, $obj_suffix, '800_security/811_fault_injection', 'memcheck' );
}
elsif ( $command eq 'memtest:arena' ) {
    my %memtest_config = %config;
    @{ $memtest_config{cflags} } = @{ $config{cflags} };
    push @{ $memtest_config{cflags} }, '-DDBLTAP_ENABLE=1';
    push @{ $memtest_config{cflags} }, '-DFFI_DEBUG_ENABLED=1' if $opts{verbose};
    $final_status = run_valgrind_test( \%memtest_config, $obj_suffix, '800_security/840_arena_allocator', 'memcheck' );
}
elsif ( $command eq 'helgrindtest' ) {
    my %helgrind_config = %config;
    @{ $helgrind_config{cflags} } = @{ $config{cflags} };
    push @{ $helgrind_config{cflags} }, '-DDBLTAP_ENABLE=1';
    $final_status = run_valgrind_test( \%helgrind_config, $obj_suffix, '800_security/820_threading_helgrind', 'helgrind' );
}
elsif ( $command eq 'helgrindtest:bare' ) {
    my %bare_config = %config;
    @{ $bare_config{cflags} } = @{ $config{cflags} };
    $final_status = run_valgrind_test( \%bare_config, $obj_suffix, '800_security/821_threading_bare', 'helgrind' );
}
elsif ( $command =~ /^fuzz(?::(\w+))?$/ ) {
    my $harness_name = $1;
    die "Error: The 'fuzz' command requires a target harness name.\nUsage: perl build.pl fuzz:<name>" unless $harness_name;
    $final_status = run_fuzz_test( \%config, $obj_suffix, $harness_name );
}
else {
    warn "Unknown command '$command'.\n";
    show_help();
    exit 1;
}
if ( $final_status == 0 ) {
    print "\nBuild successful.\n";
}
else {
    print "\nBuild FAILED.\n";
}
exit $final_status;

sub clean {
    rmtree( $config{lib_dir},      { verbose => 0 } );
    rmtree( $config{coverage_dir}, { verbose => 0 } );
    rmtree( 'build_tools',         { verbose => 0 } );
    my @artifacts;
    find(
        sub {
            if ( -d $_ && $File::Find::dir =~ m{[/\\]old$} ) { $File::Find::prune = 1; return; }
            push @artifacts, $File::Find::name
                if ( -f $_ && ( $^O eq 'MSWin32' ? /\.(exe|obj|lib|ilk|pdb|cov)$/i : ( /\.(o|a|gcda|gcno|gcov)$/i || ( -x _ && !/\.p[lm]$/ ) ) ) );
        },
        't',
        'src',
        'fuzz'
    );
    unlink @artifacts if @artifacts;
    find( sub { /\.gc(da|no|ov)$/i && -f $_ && unlink $_ }, '.' );
    find( sub { /\.profraw$/i      && -f $_ && unlink $_ }, '.' );
    print "Clean finished.\n";
}

sub show_help {
    print <<~'END_HELP';
    Usage: ./build.pl [command] [options] [test_names...]

    Commands:
      build              Builds the core static library.
      test               Builds and runs specified tests (or all) individually.
                         Test names are partial paths, e.g., '001_primitives'.
      coverage           Generates a unified code coverage report by running all tests.
      memtest            Runs the memory stress test under Valgrind/memcheck.
      memtest:fault      Runs the fault-injection memory leak test under Valgrind/memcheck.
      memtest:arena      Runs the arena allocator test under Valgrind/memcheck.
      helgrindtest       Runs the threading stress test under Valgrind/Helgrind.
      helgrindtest:bare  Runs a "barebones" Helgrind test with no testing framework.
      clean              Removes all build and coverage artifacts.
      fuzz:<name>        Builds a specific fuzzer (e.g., fuzz:types, fuzz:trampoline, fuzz:signature, fuzz:abi).

    Options:
      --cc, --compiler=<s>  Force a specific compiler (e.g., 'msvc', 'gcc', 'clang').
      --cflags=<s>          Append custom flags to the compiler command line.
      --abi=<s>             Force a specific ABI for code generation. Overrides auto-detection.
                            Supported: windows_x64, sysv_x64, aapcs64
      --codecov=<s>         Specify a Codecov token to upload coverage results (or use CODECOV_TOKEN env var).
      -v, --verbose         Enable verbose debug output from the library by compiling with -DFFI_DEBUG_ENABLED=1.
      -h, --help            Show this help message.
    END_HELP
    exit 0;
}

sub get_test_files {
    my ($test_names_ref) = @_;
    my @all_c_files;
    find(
        sub {
            if ( -d $_ && $File::Find::dir =~ m{[/\\]old$} ) { $File::Find::prune = 1; return; }
            push @all_c_files, $File::Find::name if /\.c$/ && -f $_;
        },
        't'
    );
    my @tests;
    if ( @{$test_names_ref} ) {
        for my $name (@$test_names_ref) {
            my @found = grep { $_ =~ qr{[/\\]$name(?:\.c)?$}i or $_ =~ qr{[/\\]\d+_$name(?:\.c)?$}i } @all_c_files;
            die "Error: Test '$name' not found or is ambiguous (found " . scalar(@found) . " matches)." if @found != 1;
            push @tests, $found[0];
        }
    }
    else { @tests = @all_c_files; }
    die "No test C files were found in 't/'." unless @tests;
    return sort @tests;
}

sub compile_objects {
    my ( $config, $obj_suffix, $custom_lib_dir ) = @_;
    my $output_dir = $custom_lib_dir || '';
    print "Compiling library object files";
    print " into '$output_dir'" if $output_dir;
    print "...\n";
    my @all_sources = ( @{ $config->{sources} } );
    my @obj_files;
    for my $src (@all_sources) {
        my $obj_basename = basename($src);
        $obj_basename =~ s/\.c$/$obj_suffix/i;
        my $obj_path = $output_dir ? File::Spec->catfile( $output_dir, $obj_basename ) : $obj_basename;
        make_path( dirname($obj_path) ) if $output_dir;
        push @obj_files, $obj_path;
        my @cmd;
        if ( $config->{compiler} eq 'msvc' ) {
            @cmd = ( $config->{cc}, @{ $config->{cflags} }, '-c', '-Fo' . $obj_path, $src );
        }
        else {
            @cmd = ( $config->{cc}, @{ $config->{cflags} }, '-c', '-o', $obj_path, $src );
        }
        run_command(@cmd);
    }
    return @obj_files;
}

sub create_static_library_from_objects {
    my ( $config, $obj_files_ref, $output_lib_path ) = @_;
    my $use_msvc_style_linker = ( $config->{compiler} eq 'msvc' ) || ( $config->{compiler} eq 'clang' && $config->{is_windows} );
    my $lib_path              = $output_lib_path;
    unless ($lib_path) {
        my $lib_filename = $use_msvc_style_linker ? "$config->{lib_name}.lib" : "lib$config->{lib_name}.a";
        $lib_path = File::Spec->catfile( $config->{lib_dir}, $lib_filename );
    }
    my @cmd;
    if ($use_msvc_style_linker) {
        my $archiver = ( $config->{compiler} eq 'msvc' ) ? 'lib'   : 'llvm-lib';
        my $out_flag = ( $archiver eq 'lib' )            ? '-OUT:' : '/OUT:';
        @cmd = ( $archiver, $out_flag . $lib_path, @$obj_files_ref );
    }
    else {
        @cmd = ( 'ar', 'rcs', $lib_path, @$obj_files_ref );
    }
    run_command(@cmd);
    return $lib_path;
}

sub create_static_library {
    my ( $config, $obj_suffix, $output_lib_path ) = @_;
    my $obj_dir = File::Spec->catdir( $config->{lib_dir}, 'objects_' . time() . int( rand(1000) ) );
    make_path($obj_dir);
    my @obj_files = compile_objects( $config, $obj_suffix, $obj_dir );
    return unless @obj_files;
    my $lib_path = create_static_library_from_objects( $config, \@obj_files, $output_lib_path );
    rmtree($obj_dir);
    return $lib_path;
}

sub compile_and_run_tests {
    my ( $config, $obj_suffix, $test_names_ref, $is_coverage ) = @_;
    if ($is_coverage) {
        return run_coverage_individually( $config, $obj_suffix, $test_names_ref );
    }
    my @test_c_files = get_test_files($test_names_ref);
    print "\nPreparing to build static library for tests...\n";
    my $static_lib_path = create_static_library( $config, $obj_suffix );
    die "Failed to create static library, cannot proceed." unless $static_lib_path && -e $static_lib_path;
    print "\nCompiling all test executables...\n";
    my @test_executables;
    for my $test_c (@test_c_files) {
        if ( $test_c =~ m{800_security[/\\]821_threading_bare\.c$} ) {
            print "# INFO: Skipping '821_threading_bare.c' in regular test run. Use 'helgrindtest:bare' to run it.\n";
            next;
        }
        my @source_files = ($test_c);
        my @local_cflags = @{ $config->{cflags} };
        if ( $test_c =~ /850_regression_cases\.c$/ ) {
            print "# INFO: Adding fuzz_helpers.c to build for regression test.\n";
            push @source_files, File::Spec->catfile( 'fuzz', 'fuzz_helpers.c' );
            push @local_cflags, '-Ifuzz';
        }
        my $exe_path = $test_c;
        $exe_path =~ s/\.c$/$Config{_exe}/;
        push @test_executables, $exe_path;
        my @ldflags = @{ $config->{ldflags} };
        if ( $config->{compiler} eq 'msvc' ) {
            my @obj_paths;
            for my $src (@source_files) {
                my $obj_path = $src;
                $obj_path =~ s/\.c$/.obj/i;
                run_command( $config->{cc}, @local_cflags, '-c', '-Fo' . $obj_path, $src );
                push @obj_paths, $obj_path;
            }
            run_command( $config->{cc}, '-Fe' . $exe_path, @obj_paths, $static_lib_path, @ldflags );
        }
        else {
            my @compile_cmd = ( $config->{cc}, @local_cflags, '-o', $exe_path, @source_files, $static_lib_path, @ldflags );
            run_command(@compile_cmd);
        }
    }
    my $use_prove = command_exists('prove') && !$opts{abi} && !( $config->{is_windows} && $config->{arch} eq 'arm64' );
    if ($use_prove) {
        print "\nRunning all tests with 'prove'\n";
        return run_command( 'prove', '-v', @test_executables );
    }
    else {
        if ( $opts{abi} ) {
            warn "\n# WARNING: Cross-ABI testing detected. Tests were compiled but will not be run.\n";
            return 0;
        }
        elsif ( $config->{is_windows} && $config->{arch} eq 'arm64' ) {
            warn "\n# INFO: Windows on ARM detected. Bypassing 'prove' and running tests individually.\n";
        }
        else {
            warn "\n# WARNING: 'prove' command not found. Falling back to running tests individually.\n";
        }
        my $failures = 0;
        print "\nRunning all tests individually\n";
        for my $exe (@test_executables) {
            if ( run_command($exe) != 0 ) {
                $failures++;
            }
        }
        if ( $failures > 0 ) {
            warn "# SUMMARY: $failures test(s) failed.\n";
            return 1;
        }
        return 0;
    }
}

sub run_coverage_individually {
    my ( $config, $obj_suffix, $test_names_ref ) = @_;
    print "\nPreparing for Coverage Run\n";
    clean(%config);
    make_path( $config->{coverage_dir} );
    my $status = 0;
    if ( $config->{compiler} eq 'msvc' ) {
        $status = run_coverage_msvc( $config, $obj_suffix, $test_names_ref );
    }
    else {
        $status = run_coverage_gcov( $config, $obj_suffix, $test_names_ref );
    }
    upload_to_codecov($config) if $status == 0;
    return $status;
}

sub run_coverage_gcov {
    my ( $config, $obj_suffix, $test_names_ref ) = @_;
    my $failed_tests = 0;
    my $cov_obj_dir  = File::Spec->catdir( $config->{lib_dir}, 'coverage_objects' );
    make_path($cov_obj_dir);
    my @obj_files    = compile_objects( $config, $obj_suffix, $cov_obj_dir );
    my $lib_path     = create_static_library_from_objects( $config, \@obj_files );
    my @test_c_files = get_test_files($test_names_ref);
    for my $test_c (@test_c_files) {
        if ( $test_c =~ m{800_security[/\\]82\d_} ) { next; }
        my @source_files = ($test_c);
        my @local_cflags = @{ $config->{cflags} };
        if ( $test_c =~ /850_regression_cases\.c$/ ) {
            print "# INFO: Adding fuzz_helpers.c to coverage build for regression test.\n";
            push @source_files, File::Spec->catfile( 'fuzz', 'fuzz_helpers.c' );
            push @local_cflags, '-Ifuzz';
        }
        my $exe_path = $test_c;
        $exe_path =~ s/\.c$/$Config{_exe}/;
        run_command( $config->{cc}, @local_cflags, '-o', $exe_path, @source_files, $lib_path, @{ $config->{ldflags} } );
        if ( run_command($exe_path) != 0 ) { $failed_tests++; }
    }
    print "\nGenerating .gcov reports...\n";
    if ( command_exists('gcov') ) {

        # Consolidate all .gcda files into the object directory before running gcov.
        my @gcda_files;
        find( sub { push @gcda_files, $File::Find::name if /\.gcda$/ }, '.' );
        for my $gcda_file (@gcda_files) {
            my $basename = basename($gcda_file);
            move( $gcda_file, File::Spec->catfile( $cov_obj_dir, $basename ) ) or warn "Could not move $gcda_file to $cov_obj_dir: $!";
        }
        my $original_dir = cwd();
        chdir($cov_obj_dir) or die "Cannot chdir to $cov_obj_dir: $!";
        for my $src ( @{ $config->{sources} } ) {

            # Run gcov from inside the object directory. It will find .gcno and .gcda files
            # in the CWD and generate the .c.gcov file here.
            run_command( 'gcov', abs_path($src) );
        }

        # Move the generated reports back to the project root for Codecov.
        my @gcov_files;
        find( sub { push @gcov_files, $File::Find::name if /\.gcov$/ }, '.' );
        for my $gcov_file (@gcov_files) {
            move( $gcov_file, $original_dir ) or warn "Could not move $gcov_file to $original_dir: $!";
        }
        chdir($original_dir) or die "Cannot chdir back to $original_dir: $!";
    }
    else { warn "gcov not found" }
    return $failed_tests;
}

sub run_coverage_msvc {
    my ( $config, $obj_suffix, $test_names_ref ) = @_;
    if ( $config->{arch} eq 'arm64' ) {
        warn "\n# Warning: Skipping OpenCppCoverage on Windows ARM64 as it is unsupported.\n";
        return 0;
    }
    my $tool_path = File::Spec->catfile( $ENV{PROGRAMFILES}, 'OpenCppCoverage', 'OpenCppCoverage.exe' );
    warn "Error: OpenCppCoverage not found at '$tool_path'." unless -f $tool_path;
    print "\nBuilding libraries with debug info for coverage (MSVC)\n";
    my $normal_lib_path = create_static_library( $config, $obj_suffix );
    die "Failed to build standard library." unless $normal_lib_path && -e $normal_lib_path;
    my @test_c_files = get_test_files($test_names_ref);
    my @cov_files;
    my $failed_tests = 0;
    print "\nCompiling and running tests under OpenCppCoverage\n";

    for my $test_c (@test_c_files) {
        if ( $test_c =~ m{800_security[/\\]821_threading_bare\.c$} ) { next; }
        my @source_files = ($test_c);
        my @local_cflags = @{ $config->{cflags} };
        if ( $test_c =~ /850_regression_cases\.c$/ ) {
            print "# INFO: Adding fuzz_helpers.c to MSVC coverage build for regression test.\n";
            push @source_files, File::Spec->catfile( 'fuzz', 'fuzz_helpers.c' );
            push @local_cflags, '-Ifuzz';
        }
        my @link_objects;
        for my $src (@source_files) {
            my $obj_path = $src;
            $obj_path =~ s/\.c$/.obj/i;
            run_command( $config->{cc}, @local_cflags, '-c', '-Fo' . $obj_path, $src );
            push @link_objects, $obj_path;
        }
        my $exe_path = $test_c;
        $exe_path =~ s/\.c$/$Config{_exe}/;
        run_command( $config->{cc}, '-Fe' . $exe_path, @link_objects, $normal_lib_path, @{ $config->{ldflags} } );
        my $cov_file = $exe_path;
        $cov_file =~ s/\.exe$/.cov/;
        push @cov_files, $cov_file;
        my @occ_cmd = ( $tool_path, '--export_type=binary:' . $cov_file, '--cover_children', '--', $exe_path );

        if ( run_command(@occ_cmd) != 0 ) {
            $failed_tests++;
            print "# WARNING: Test '$exe_path' failed during coverage run.\n";
        }
    }
    print "\nMerging coverage data and generating final report\n";
    my $report_path = File::Spec->catfile( $config->{coverage_dir}, 'coverage.xml' );
    my @input_args  = map { '--input_coverage=' . $_ } @cov_files;
    my @merge_cmd   = ( $tool_path, @input_args, '--export_type=cobertura:' . $report_path, '--sources=src/core' );
    run_command(@merge_cmd);
    print "\nCoverage report generated successfully: $report_path\n";
    if ( $failed_tests > 0 ) {
        warn "\n# WARNING: $failed_tests test(s) failed during coverage run. See output above.\n";
        return 1;
    }
    return 0;
}

sub upload_to_codecov {
    my ($config) = @_;
    my $token = $opts{codecov} || $ENV{CODECOV_TOKEN};
    unless ($token) {
        print "\n# INFO: No Codecov token provided. Skipping upload.\n";
        return;
    }
    get_git_info();
    print "\nUploading coverage report to Codecov.io\n";
    my $uploader    = get_codecov_uploader($config);
    my @cmd         = ( $uploader, 'upload-process', '--verbose', '-t', $token, '-Z' );
    my $upload_name = join( '-', $config->{compiler}, $config->{arch}, $^O );
    push @cmd, '-n',            $upload_name;
    push @cmd, '-F',            $_ for ( $config->{compiler}, $config->{arch}, $^O );
    push @cmd, '--sha',         $git_info{commit_sha}  if $git_info{commit_sha};
    push @cmd, '--slug',        $git_info{slug}        if $git_info{slug};
    push @cmd, '--git-service', $git_info{git_service} if $git_info{git_service};
    my $report_file;

    if ( $config->{compiler} eq 'msvc' ) {
        $report_file = File::Spec->catfile( $config->{coverage_dir}, 'coverage.xml' );
    }
    elsif ( $config->{compiler} eq 'clang' ) {
        $report_file = File::Spec->catfile( $config->{coverage_dir}, 'coverage.lcov' );
    }
    if ( defined $report_file && -f $report_file ) {
        push @cmd, '-f', $report_file;
    }
    elsif ( $config->{compiler} eq 'gcc' ) {
        print "# INFO: No single report file for GCC, letting uploader find .gcov files.\n";
    }
    else {
        warn "# WARNING: Coverage report not found. Skipping Codecov upload.\n";
        return;
    }
    if ( run_command(@cmd) == 0 ) {
        print "\nCoverage upload completed successfully.\n";
    }
    else {
        warn "\n# WARNING: Codecov upload failed. This will not fail the build.\n";
    }
}

sub run_command {
    my @cmd = @_;
    print "Executing: " . join( ' ', @_ ) . "\n";
    my $exit_code = system(@cmd);
    my $status    = $exit_code >> 8;
    if ( $status != 0 ) {
        my $is_allowed_to_fail = 0;
        $is_allowed_to_fail = 1 if $cmd[0] eq 'prove';
        $is_allowed_to_fail = 1 if $cmd[0] =~ /codecov/;
        $is_allowed_to_fail = 1 if $cmd[0] =~ /gcov/ || $cmd[0] =~ /llvm-/;
        $is_allowed_to_fail = 1
            if $ENV{PROGRAMFILES} && $cmd[0] eq File::Spec->catfile( $ENV{PROGRAMFILES}, 'OpenCppCoverage', 'OpenCppCoverage.exe' );
        if ( $is_coverage_build && $cmd[0] =~ m{[\\/]?t[\\/]} && -x $cmd[0] ) {
            $is_allowed_to_fail = 1;
        }
        unless ($is_allowed_to_fail) {
            die "FATAL: Command failed with exit code: $status\n";
        }
    }
    return $status;
}

sub command_exists {
    my ($cmd)       = @_;
    my $null_device = $config{is_windows} ? 'NUL'                            : '/dev/null';
    my $search_cmd  = $config{is_windows} ? "where $cmd > $null_device 2>&1" : "command -v $cmd > $null_device 2>&1";
    return system($search_cmd) == 0;
}

sub check_for_lrt {
    my ($config) = @_;
    print "Checking if -lrt is required...\n";
    my $test_code = <<'END_C_CODE';
#include <sys/mman.h>
#include <fcntl.h>
int main(void) { shm_open("/test", O_RDONLY, 0); return 0; }
END_C_CODE
    my @base_cmd = ( $config->{cc} );
    push @base_cmd, @{ $config->{cflags} } if exists $config->{cflags};
    return ''     if try_link( \@base_cmd, $test_code, '' );
    return '-lrt' if try_link( \@base_cmd, $test_code, '-lrt' );
    return '';
}

sub try_link {
    my ( $base_cmd_ref, $code, $flags ) = @_;
    my @cmd = @{$base_cmd_ref};
    my ( $fh, $source_file )  = tempfile( SUFFIX => '.c', UNLINK => 1 );
    my ( $ofh, $output_file ) = tempfile( UNLINK => 1 );
    close($ofh);
    print $fh $code;
    close $fh;
    my $null_device = $config{is_windows} ? 'NUL' : '/dev/null';
    push @cmd, ( '-o', $output_file, $source_file );
    push @cmd, $flags if $flags;
    my $command_str = join( ' ', @cmd ) . " >$null_device 2>&1";
    system($command_str);
    return ( $? >> 8 ) == 0;
}

sub get_git_info {
    return if $git_info{_cached};
    print "\nGathering Git information for Codecov\n";
    if ( command_exists('git') ) {
        my $commit_sha = `git rev-parse HEAD`;
        chomp $commit_sha;
        $git_info{commit_sha} = $commit_sha if $commit_sha;
        my $remote_url = `git config --get remote.origin.url`;
        chomp $remote_url;
        if ( $remote_url =~ m{[/:]([^/]+/[^/]+?)(?:\.git)?$} ) {
            $git_info{slug}        = $1;
            $git_info{git_service} = 'github';
        }
        else { warn "# WARNING: Could not parse git repository slug from remote URL: $remote_url\n"; }
    }
    else { warn "# WARNING: 'git' command not found. Cannot determine commit SHA or repo slug.\n"; }
    $git_info{_cached} = 1;
}

sub get_codecov_uploader {
    my ($config) = @_;
    my $tools_dir = 'build_tools';
    make_path($tools_dir) unless -d $tools_dir;
    my $exe_name      = $config->{is_windows} ? 'codecov.exe' : 'codecov';
    my $uploader_path = File::Spec->catfile( $tools_dir, $exe_name );
    return $uploader_path if -e $uploader_path;
    print "\nDownloading Codecov Uploader\n";
    my $os  = $config->{is_windows} ? 'windows' : ( $^O eq 'darwin' ? 'macos' : 'linux' );
    my $url = "https://uploader.codecov.io/latest/$os/$exe_name";
    my $downloader;
    if    ( command_exists('curl') ) { $downloader = [ 'curl', '-L', '-o', $uploader_path, $url ]; }
    elsif ( command_exists('wget') ) { $downloader = [ 'wget', '-O', $uploader_path, $url ]; }
    else                             { die "Error: Cannot download Codecov uploader. Please install 'curl' or 'wget'."; }
    run_command(@$downloader);
    chmod 0755, $uploader_path unless $config->{is_windows};
    die "Failed to download Codecov uploader from $url" unless -e $uploader_path;
    return $uploader_path;
}

sub run_valgrind_test {
    my ( $config, $obj_suffix, $test_name, $tool ) = @_;
    my $title = { memcheck => 'Memory Stress', helgrind => 'Thread Safety' }->{$tool} || ucfirst($tool);
    print "\nPreparing for Valgrind Test ($title: $test_name)\n";
    my @test_files = get_test_files( [$test_name] );
    die "Error: Could not find the test file for '$test_name'" unless @test_files;
    my $test_c          = $test_files[0];
    my $static_lib_path = create_static_library( $config, $obj_suffix );
    die "Failed to create static library, cannot proceed." unless $static_lib_path && -e $static_lib_path;
    my $exe_path = $test_c;
    $exe_path =~ s/\.c$/$Config{_exe}/;
    print "\nCompiling test executable for Valgrind...\n";
    my @cflags       = @{ $config->{cflags} };
    my @ldflags      = @{ $config->{ldflags} };
    my @source_files = ($test_c);

    if ( $test_c =~ /850_regression_cases\.c$/ ) {
        print "# INFO: Adding fuzz_helpers.c to Valgrind build for regression test.\n";
        push @source_files, File::Spec->catfile( 'fuzz', 'fuzz_helpers.c' );
        push @cflags,       '-Ifuzz';
    }
    if ( $test_c =~ /fault_injection\.c$/ && $config->{compiler} ne 'msvc' ) { push @cflags, '-Wno-macro-redefined'; }
    if ( $tool eq 'helgrind' && !$config->{is_windows} ) { push @cflags, '-pthread'; push @ldflags, '-pthread'; }
    my @compile_cmd = ( $config->{cc}, @cflags, '-o', $exe_path, @source_files, $static_lib_path, @ldflags );
    run_command(@compile_cmd);
    print "\nRunning Test with Valgrind ($tool)\n";
    die "Error: 'valgrind' command not found." unless command_exists('valgrind');
    my @valgrind_cmd = ( 'valgrind', '--tool=' . $tool, '--error-exitcode=1' );
    if ( $tool eq 'memcheck' ) { push @valgrind_cmd, '--leak-check=full', '--show-leak-kinds=all', '--track-origins=yes'; }
    push @valgrind_cmd, $exe_path;
    return run_command(@valgrind_cmd);
}

sub run_fuzz_test {
    my ( $config, $obj_suffix, $harness_name ) = @_;
    die "Error: Must provide a fuzz harness name (e.g., 'types', 'trampoline')." unless $harness_name;
    my $is_gcc_fuzz = ( $config->{compiler} eq 'gcc' );
    if ($is_gcc_fuzz) {
        die "Error: Fuzzing with GCC requires AFL++ to be installed." unless command_exists('afl-gcc');
        print "\nGCC compiler detected. Will build for AFL++ fuzzing.\n";
    }
    else {
        die "Error: Fuzzing currently requires 'clang' or 'gcc'." unless $config->{compiler} eq 'clang';
        print "\nClang compiler detected. Will build for libFuzzer fuzzing.\n";
    }
    my $fuzz_harness_c = File::Spec->catfile( 'fuzz', "fuzz_$harness_name.c" );
    my $fuzz_helpers_c = File::Spec->catfile( 'fuzz', "fuzz_helpers.c" );
    die "Error: Fuzzing harness not found at '$fuzz_harness_c'" unless -f $fuzz_harness_c;
    die "Error: Fuzzing helpers not found at '$fuzz_helpers_c'" unless -f $fuzz_helpers_c;
    print "\nPreparing Fuzzing Build for Harness: $harness_name\n";
    my @fuzz_cflags = @{ $config->{cflags} };
    push @fuzz_cflags, '-Ifuzz', '-I' . File::Spec->catdir( $FindBin::Bin, 'src/core' );
    @fuzz_cflags = grep { $_ !~ /^-O\d/ } @fuzz_cflags;
    my %fuzz_config = %$config;
    my $fuzz_cc     = $config->{cc};

    if ($is_gcc_fuzz) {
        $fuzz_cc = 'afl-gcc';
        push @fuzz_cflags, '-DUSE_AFL=1', '-I/usr/local/include';
    }
    else { push @fuzz_cflags, '-g', '-fsanitize=fuzzer,address,undefined'; }
    $fuzz_config{cflags} = \@fuzz_cflags;
    $fuzz_config{cc}     = $fuzz_cc;
    my @obj_files  = compile_objects( \%fuzz_config, $obj_suffix );
    my $helper_obj = $fuzz_helpers_c;
    $helper_obj =~ s{\.c$}{$obj_suffix}ix;
    run_command( $fuzz_cc, @fuzz_cflags, "-c", "-o", $helper_obj, $fuzz_helpers_c );
    push @obj_files, $helper_obj;
    print "\nCompiling fuzzing harness...\n";
    my $fuzz_exe = "fuzz_${harness_name}_harness" . $Config{_exe};
    my @ldflags  = @{ $config->{ldflags} };
    if ( $config->{compiler} eq 'clang' ) { push @ldflags, '-fsanitize=fuzzer,address,undefined'; }
    my @cmd = ( $fuzz_cc, @fuzz_cflags, '-o', $fuzz_exe, $fuzz_harness_c, @obj_files, @ldflags );
    run_command(@cmd);
    print "\nFuzz Harness Built Successfully: $fuzz_exe\n";

    if ($is_gcc_fuzz) {
        print "To run the AFL++ fuzzer, first create a directory for sample inputs (corpus):\n";
        print "  mkdir -p corpus && echo 'seed' > corpus/seed.txt\n\n";
        print "Then, run afl-fuzz:\n  afl-fuzz -i corpus -o findings -- ./$fuzz_exe\n\n";
    }
    else {
        print "To run the libFuzzer harness, first create a directory for sample inputs (corpus):\n";
        print "  mkdir -p corpus\n\nThen run the harness:\n  ./$fuzz_exe -max_total_time=300 corpus\n\n";
    }
    return 0;
}
