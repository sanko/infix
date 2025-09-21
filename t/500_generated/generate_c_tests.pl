#!/usr/bin/perl
use v5.40;
use File::Spec;
use File::Basename;

# Define the complete set of primitive type characters based on the Itanium ABI.
my $primitive_chars = 'vabchstijlmxynofde';

sub tokenize {
    my ( $string, $line_num ) = @_;
    my @tokens;
    my $pos = 0;
    while ( $pos < length($string) ) {

        # 1. Skip leading whitespace and semicolons
        if ( substr( $string, $pos, 1 ) =~ /[\s;]/ ) {
            $pos++;
            next;
        }

        # 2. Handle simple, standalone tokens (=> and .)
        if ( substr( $string, $pos, 2 ) eq '=>' ) {
            push @tokens, '=>';
            $pos += 2;
            next;
        }
        if ( substr( $string, $pos, 1 ) eq '.' ) {
            push @tokens, '.';
            $pos += 1;
            next;
        }

        # 3. Handle a complex type token (base + postfixes)
        my $start_pos    = $pos;
        my $base_end_pos = -1;
        my $first_char   = substr( $string, $pos, 1 );

        # Check for the p{...} prefix for packed structs
        if ( $first_char eq 'p' && substr( $string, $pos + 1, 1 ) eq '{' ) {
            my $depth = 1;
            for ( my $i = $pos + 2; $i < length($string); $i++ ) {
                my $char = substr( $string, $i, 1 );
                if ( $char eq '{' ) {
                    $depth++;
                }
                elsif ( $char eq '}' ) {
                    $depth--;
                    if ( $depth == 0 ) {
                        $base_end_pos = $i + 1;
                        last;
                    }
                }
            }
        }

        # Standard logic for other types
        elsif ( index( $primitive_chars, $first_char ) != -1 ) {
            $base_end_pos = $pos + 1;
        }
        elsif ( $first_char eq '{' || $first_char eq '<' || $first_char eq '(' ) {
            my $close_delim = { '{' => '}', '<' => '>', '(' => ')' }->{$first_char};
            my $depth       = 1;
            for ( my $i = $pos + 1; $i < length($string); $i++ ) {
                if ( substr( $string, $i, 2 ) eq '=>' ) {
                    $i++;
                    next;
                }
                my $char = substr( $string, $i, 1 );
                if ( $char eq $first_char ) {
                    $depth++;
                }
                elsif ( $char eq $close_delim ) {
                    $depth--;
                    if ( $depth == 0 ) {
                        $base_end_pos = $i + 1;
                        last;
                    }
                }
            }
        }
        unless ( $base_end_pos != -1 ) {
            warn "Tokenizer error on line $line_num: Could not find a valid token base at position $pos in string: '$string'";
            return ();
        }

        # 4. Greedily consume any postfix operators (* or [])
        my $current_token_end = $base_end_pos;
        while ( $current_token_end < length($string) ) {
            my $next_char_pos = $current_token_end;
            while ( $next_char_pos < length($string) && substr( $string, $next_char_pos, 1 ) =~ /\s/ ) {
                $next_char_pos++;
            }
            if ( $next_char_pos >= length($string) ) { last; }
            my $next_char = substr( $string, $next_char_pos, 1 );
            if ( $next_char eq '*' ) {
                $current_token_end = $next_char_pos + 1;
            }
            elsif ( $next_char eq '[' ) {
                my $close_bracket = index( $string, ']', $next_char_pos );
                if ( $close_bracket != -1 ) {
                    $current_token_end = $close_bracket + 1;
                }
                else { last; }
            }
            else {
                last;
            }
        }
        my $token = substr( $string, $start_pos, $current_token_end - $start_pos );
        $token =~ s/\s//g;
        push @tokens, $token;
        $pos = $current_token_end;
    }
    return @tokens;
}

sub _walk {
    my ( $string, $line_num ) = @_;
    return { base_type => 'error', value => 'undefined input' } unless defined $string;
    $string =~ s/^\s+|\s+$//g;
    if ( $string =~ /^(.*)\*$/s ) {
        return { base_type => 'pointer', pointee_type => _walk( $1, $line_num ) };
    }
    if ( $string =~ /^(.*?)(\[\d*\])$/s ) {
        my ( $base_str, $array_part ) = ( $1, $2 );
        my @dims         = $array_part =~ /(\d+)/g;
        my $element_type = _walk( $base_str, $line_num );
        return { base_type => 'array', array_info => { dims => \@dims, element_type => $element_type } };
    }
    my %type_info;
    if ( $string =~ /^p\{(.*)\}$/s ) {
        $type_info{base_type} = 'packed_struct';
        my $content = $1;
        $type_info{members} = ( $content =~ /^\s*$/ ) ? [] : [ map { _walk( $_, $line_num ) } tokenize( $content, $line_num ) ];
    }
    elsif ( $string =~ /^\{(.*)\}$/s ) {
        $type_info{base_type} = 'struct';
        my $content = $1;
        $type_info{members} = ( $content =~ /^\s*$/ ) ? [] : [ map { _walk( $_, $line_num ) } tokenize( $content, $line_num ) ];
    }
    elsif ( $string =~ /^\<(.*)\>$/s ) {
        $type_info{base_type} = 'union';
        my @members = tokenize( $1, $line_num );
        $type_info{members} = [ map { _walk( $_, $line_num ) } @members ];
    }
    elsif ( $string =~ /^\((.*)\)$/s ) {
        my $content   = $1;
        my @tokens    = tokenize( $content, $line_num );
        my $arrow_idx = -1;
        for my $i ( 0 .. $#tokens ) {
            if ( $tokens[$i] eq '=>' ) { $arrow_idx = $i; last; }
        }
        if ( $arrow_idx != -1 ) {
            $type_info{base_type} = 'func_ptr';
            $type_info{args}      = [];
            $type_info{ret}       = { base_type => 'primitive', value => 'v' };
            my @arg_tokens = @tokens[ 0 .. $arrow_idx - 1 ];
            my @ret_tokens = @tokens[ $arrow_idx + 1 .. $#tokens ];
            my $dot_idx    = -1;
            for my $i ( 0 .. $#arg_tokens ) {
                if ( $arg_tokens[$i] eq '.' ) { $dot_idx = $i; last; }
            }
            if ( $dot_idx != -1 ) {
                my @fixed = @arg_tokens[ 0 .. $dot_idx - 1 ];
                $type_info{variadic_after_arg} = scalar(@fixed);
                splice( @arg_tokens, $dot_idx, 1 );
            }
            $type_info{args} = [ map { _walk( $_, $line_num ) } @arg_tokens ];
            $type_info{ret}  = _walk( $ret_tokens[0], $line_num ) if @ret_tokens;
        }
        else {
            return _walk( $content, $line_num );
        }
    }
    elsif ( $string =~ /^([$primitive_chars])$/ ) {
        $type_info{base_type} = 'primitive';
        $type_info{value}     = $1;
    }
    else {
        return { base_type => 'unknown', value => $string };
    }
    return \%type_info;
}

sub parse_signature {
    my ( $signature, $line_num ) = @_;
    my @tokens = tokenize( $signature, $line_num );
    return unless @tokens;
    my $arrow_idx = -1;
    for my $i ( 0 .. $#tokens ) {
        if ( $tokens[$i] eq '=>' ) { $arrow_idx = $i; last; }
    }
    unless ( $arrow_idx != -1 ) { warn "Invalid signature format on line $line_num (missing top-level =>): $signature"; return; }
    my @arg_tokens = @tokens[ 0 .. $arrow_idx - 1 ];
    my @ret_tokens = @tokens[ $arrow_idx + 1 .. $#tokens ];
    return { base_type => 'error', value => 'missing return type' } unless @ret_tokens;
    my %parsed_structure;
    my $dot_idx = -1;
    my @all_arg_tokens;

    for my $i ( 0 .. $#arg_tokens ) {
        if ( $arg_tokens[$i] eq '.' ) {
            $dot_idx = $i unless $dot_idx != -1;    # Only capture the first dot
        }
        else {
            push @all_arg_tokens, $arg_tokens[$i];
        }
    }
    if ( $dot_idx != -1 ) {
        $parsed_structure{variadic_after_arg} = $dot_idx;
        my @fixed_args    = @all_arg_tokens[ 0 .. $dot_idx - 1 ];
        my @variadic_args = @all_arg_tokens[ $dot_idx .. $#all_arg_tokens ];
        $parsed_structure{args}               = [ map { _walk( $_, $line_num ) } @fixed_args ];
        $parsed_structure{variadic_arguments} = [ map { _walk( $_, $line_num ) } @variadic_args ];
    }
    else {
        $parsed_structure{args} = [ map { _walk( $_, $line_num ) } @all_arg_tokens ];
    }
    $parsed_structure{return} = _walk( $ret_tokens[0], $line_num );
    return \%parsed_structure;
}

# Part 2: C Code Generation Logic
my %primitive_map_infix = (
    a => 'FFI_PRIMITIVE_TYPE_SINT8',
    b => 'FFI_PRIMITIVE_TYPE_BOOL',
    c => 'FFI_PRIMITIVE_TYPE_SINT8',
    h => 'FFI_PRIMITIVE_TYPE_UINT8',
    s => 'FFI_PRIMITIVE_TYPE_SINT16',
    t => 'FFI_PRIMITIVE_TYPE_UINT16',
    i => 'FFI_PRIMITIVE_TYPE_SINT32',
    j => 'FFI_PRIMITIVE_TYPE_UINT32',
    l => 'FFI_PRIMITIVE_TYPE_SINT64',
    m => 'FFI_PRIMITIVE_TYPE_UINT64',
    x => 'FFI_PRIMITIVE_TYPE_SINT64',
    y => 'FFI_PRIMITIVE_TYPE_UINT64',
    n => 'FFI_PRIMITIVE_TYPE_SINT128',
    o => 'FFI_PRIMITIVE_TYPE_UINT128',
    f => 'FFI_PRIMITIVE_TYPE_FLOAT',
    d => 'FFI_PRIMITIVE_TYPE_DOUBLE',
    e => 'FFI_PRIMITIVE_TYPE_LONG_DOUBLE',
);
my %primitive_map_c = (
    v => 'void',
    a => 'signed char',
    b => 'bool',
    c => 'char',
    h => 'unsigned char',
    s => 'short',
    t => 'unsigned short',
    i => 'int',
    j => 'unsigned int',
    l => 'long',
    m => 'unsigned long',
    x => 'long long',
    y => 'unsigned long long',
    n => '__int128_t',
    o => '__uint128_t',
    f => 'float',
    d => 'double',
    e => 'long double',
);
my %primitive_vals = (
    a => "-120",
    b => 'true',
    c => "'z'",
    h => "250",
    s => "-32000",
    t => "65000",
    i => "-2000000000",
    j => "4000000000U",
    l => "-2000000000L",
    m => "4000000000UL",
    x => "-9000000000000000000LL",
    y => "18000000000000000000ULL",
    n => '((__int128_t)-0x1234567890ABCDEFLL)',
    o => '((__uint128_t)0xFEDCBA0987654321ULL)',
    f => "9.87f",
    d => "6.54",
    e => "1.234567890123456789L",
);

# ############################################################################
# Functions for Pretty-Printing Signatures
# ############################################################################
# Human-readable names for primitive types
my %c_like_map = ( %primitive_map_c, n => '__int128', o => 'unsigned __int128' );

# Recursively converts a single parsed type hash into a C-like string.
sub type_hash_to_c_like_string {
    my ( $type_hash, $declarator ) = @_;
    $declarator //= '';
    return "/* invalid_type */" unless $type_hash && exists $type_hash->{base_type};
    my $base = $type_hash->{base_type};
    if ( $base eq 'primitive' ) {
        return $c_like_map{ $type_hash->{value} } . ( $declarator ? " $declarator" : '' );
    }
    if ( $base eq 'pointer' ) {
        return type_hash_to_c_like_string( $type_hash->{pointee_type}, "*$declarator" );
    }
    if ( $base eq 'array' ) {
        my $dims = join '', map {"[$_]"} @{ $type_hash->{array_info}{dims} };
        return type_hash_to_c_like_string( $type_hash->{array_info}{element_type}, "$declarator$dims" );
    }
    if ( $base eq 'struct' || $base eq 'packed_struct' || $base eq 'union' ) {
        my $keyword = $base =~ s/_/ /r;                                                          # packed_struct -> "packed struct"
        my @members = map { type_hash_to_c_like_string($_) . ';' } @{ $type_hash->{members} };
        my $body    = @members ? ' ' . join( ' ', @members ) . ' ' : ' ';
        return "$keyword {$body}" . ( $declarator ? " $declarator" : '' );
    }
    if ( $base eq 'func_ptr' ) {
        my @arg_types;
        my $args_ref = $type_hash->{args} || [];
        if ( !@$args_ref || ( @$args_ref == 1 && $args_ref->[0]{base_type} eq 'primitive' && $args_ref->[0]{value} eq 'v' ) ) {
            push @arg_types, 'void';
        }
        else {
            @arg_types = map { type_hash_to_c_like_string($_) } @$args_ref;
            push @arg_types, '...' if exists $type_hash->{variadic_after_arg};
        }
        my $return_type = type_hash_to_c_like_string( $type_hash->{ret} );
        return "$return_type (*$declarator)(" . join( ', ', @arg_types ) . ')';
    }
    return "/* unknown_type */";
}

# Converts a full parsed signature into a C-like string.
sub signature_to_c_like_string {
    my ($parsed_hash) = @_;
    my @arg_strings;
    my $args_ref = $parsed_hash->{args} // [];
    if ( !@$args_ref ) {
        push @arg_strings, 'void' if !exists $parsed_hash->{variadic_after_arg};
    }
    else {
        push @arg_strings, map { type_hash_to_c_like_string($_) } @$args_ref;
    }
    if ( exists $parsed_hash->{variadic_after_arg} ) {
        push @arg_strings, '...';
    }
    my $return_string = type_hash_to_c_like_string( $parsed_hash->{return} );
    return "FN(" . join( ', ', @arg_strings ) . ") -> " . $return_string;
}

# ############################################################################
my %is_msvc_incompatible_memo;

sub is_msvc_incompatible {
    my ($type_hash) = @_;
    return 0 unless $type_hash && exists $type_hash->{base_type};
    my $key = _get_canonical_key($type_hash);
    return $is_msvc_incompatible_memo{$key} if defined $key && exists $is_msvc_incompatible_memo{$key};
    my $result = 0;
    my $base   = $type_hash->{base_type};
    if ( $base eq 'primitive' ) {
        $result = 1 if $type_hash->{value} eq 'n' || $type_hash->{value} eq 'o';
    }
    elsif ( $base eq 'pointer' ) {
        $result = is_msvc_incompatible( $type_hash->{pointee_type} );
    }
    elsif ( $base eq 'array' ) {
        $result = is_msvc_incompatible( $type_hash->{array_info}{element_type} );
    }
    elsif ( $base eq 'struct' || $base eq 'union' || $base eq 'packed_struct' ) {
        for my $member ( @{ $type_hash->{members} } ) {
            if ( is_msvc_incompatible($member) ) {
                $result = 1;
                last;
            }
        }
    }
    elsif ( $base eq 'func_ptr' ) {
        if ( is_msvc_incompatible( $type_hash->{ret} ) ) {
            $result = 1;
        }
        else {
            for my $arg ( @{ $type_hash->{args} } ) {
                if ( is_msvc_incompatible($arg) ) {
                    $result = 1;
                    last;
                }
            }
        }
    }
    $is_msvc_incompatible_memo{$key} = $result if defined $key;
    return $result;
}

sub _get_canonical_key {
    my ($type_hash) = @_;
    return undef unless $type_hash && exists $type_hash->{base_type};
    my $base = $type_hash->{base_type};
    return undef if $base eq 'unknown' || $base eq 'error';
    my $key = '';
    if    ( $base eq 'primitive' ) { $key = $type_hash->{value} }
    elsif ( $base eq 'pointer' )   { $key = _get_canonical_key( $type_hash->{pointee_type} ) . '*'; }
    elsif ( $base eq 'packed_struct' ) {
        my @members = map { _get_canonical_key($_) } @{ $type_hash->{members} };
        $key = 'p{' . join( ';', @members ) . '}';
    }
    elsif ( $base eq 'struct' ) {
        my @members = map { _get_canonical_key($_) } @{ $type_hash->{members} };
        $key = '{' . join( ';', @members ) . '}';
    }
    elsif ( $base eq 'union' ) {
        my @members = map { _get_canonical_key($_) } @{ $type_hash->{members} };
        $key = '<' . join( ';', @members ) . '>';
    }
    elsif ( $base eq 'array' ) {
        $key = _get_canonical_key( $type_hash->{array_info}{element_type} ) . join( '', map { "[" . $_ . "]" } @{ $type_hash->{array_info}{dims} } );
    }
    elsif ( $base eq 'func_ptr' ) {
        my @args    = defined $type_hash->{args} ? map { _get_canonical_key($_) } @{ $type_hash->{args} } : [];
        my $ret     = defined $type_hash->{ret}  ? _get_canonical_key( $type_hash->{ret} )                : 'v';
        my $arg_str = join( '', @args );
        $key = '(' . $arg_str . ( exists( $type_hash->{variadic_after_arg} ) ? '.' : '' ) . '=>' . $ret . ')';
    }
    return $key;
}

sub _get_safe_c_name {
    my $key = shift;
    $key //= '';

    # Prepend type for structs/unions to avoid name collision.
    $key =~ s/^{/struct_/;
    $key =~ s/^</union_/;
    $key =~ s/^p\{/packed_struct_/;
    $key =~ s/[^a-zA-Z0-9_]/_/g;
    return $key;
}

# Generates a C99 compound literal for local variables or return values.
sub get_c_value_string {
    my ( $type_hash, $context ) = @_;
    return '/* void */' if ( $type_hash->{base_type} eq 'primitive' && $type_hash->{value} eq 'v' );
    if ( $type_hash->{base_type} eq 'primitive' ) { return $primitive_vals{ $type_hash->{value} }; }
    if ( $type_hash->{base_type} eq 'pointer' ) {
        my $pointee_type = $type_hash->{pointee_type};
        my $pointee_key  = _get_canonical_key($pointee_type);
        if ( $pointee_key eq 'c' && exists $context->{global_vars}->{$pointee_key} ) {
            return $context->{global_vars}->{$pointee_key};
        }
        if ( exists $context->{global_vars}->{$pointee_key} ) { return '&' . $context->{global_vars}->{$pointee_key}; }
        if ( $pointee_type->{base_type} eq 'pointer' && exists $context->{global_vars}->{$pointee_key} ) {
            return '&' . $context->{global_vars}->{$pointee_key};
        }
        return 'NULL';
    }
    if ( $type_hash->{base_type} eq 'packed_struct' || $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' ) {
        my $type_name   = $context->{typedef_names}->{ _get_canonical_key($type_hash) };
        my @members     = map { get_c_value_string( $_, $context ) } @{ $type_hash->{members} };
        my $initializer = $type_hash->{base_type} eq 'union' ? $members[0] : join( ', ', @members );
        return '(' . $type_name . '){ ' . $initializer . ' }';
    }
    if ( $type_hash->{base_type} eq 'array' ) {
        my $val          = get_c_value_string( $type_hash->{array_info}{element_type}, $context );
        my $wrapper_name = $context->{typedef_names}->{ _get_canonical_key($type_hash) };
        return '(' . $wrapper_name . '){ { ' . join( ', ', ($val) x $type_hash->{array_info}{dims}[0] ) . ' } }';
    }
    if ( $type_hash->{base_type} eq 'func_ptr' ) { return 'NULL'; }
    return "/* UNSUPPORTED VALUE */";
}

# Generates a C89-compatible static initializer for global variables.
sub get_c_static_initializer {
    my ( $type_hash, $context ) = @_;
    if ( $type_hash->{base_type} eq 'primitive' ) { return $primitive_vals{ $type_hash->{value} }; }
    if ( $type_hash->{base_type} eq 'pointer' ) {
        my $pointee_type = $type_hash->{pointee_type};
        my $pointee_key  = _get_canonical_key($pointee_type);
        if ( $pointee_key eq 'c' && exists $context->{global_vars}->{'c'} ) {
            return $context->{global_vars}->{'c'};
        }
        if ( exists $context->{global_vars}->{$pointee_key} ) {
            return '&' . $context->{global_vars}->{$pointee_key};
        }
        return 'NULL';
    }
    if ( $type_hash->{base_type} eq 'packed_struct' || $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' ) {
        my @members     = map { get_c_static_initializer( $_, $context ) } @{ $type_hash->{members} };
        my $initializer = $type_hash->{base_type} eq 'union' ? $members[0] : join( ', ', @members );
        return '{ ' . $initializer . ' }';
    }
    if ( $type_hash->{base_type} eq 'array' ) {
        my $val = get_c_static_initializer( $type_hash->{array_info}{element_type}, $context );
        return '{ { ' . join( ', ', ($val) x $type_hash->{array_info}{dims}[0] ) . ' } }';
    }
    if ( $type_hash->{base_type} eq 'func_ptr' ) { return 'NULL'; }
    return "/* UNSUPPORTED INITIALIZER */";
}

sub get_c_verify_expr {
    my ( $type_hash, $var_name, $context ) = @_;
    my $key = _get_canonical_key($type_hash);
    if ( $type_hash->{base_type} eq 'primitive' ) {
        if ( $type_hash->{value} eq 'f' || $type_hash->{value} eq 'd' || $type_hash->{value} eq 'e' ) {
            return '(fabsl(' . $var_name . ' - ' . $primitive_vals{ $type_hash->{value} } . ') < 0.0001L)';
        }
        return '(' . $var_name . ' == ' . $primitive_vals{ $type_hash->{value} } . ')';
    }
    if ( $type_hash->{base_type} eq 'pointer' ) {
        my $pointee_type = $type_hash->{pointee_type};
        my $pointee_key  = _get_canonical_key($pointee_type);
        if ( $pointee_key eq 'c' ) {
            return '(strcmp(' . $var_name . ', "Hello, c*!") == 0)';
        }
        my $expected_value_str;
        if ( exists $context->{global_vars}->{$pointee_key} ) {
            my $addr_op = ( $pointee_key eq 'c' ) ? '' : '&';
            $expected_value_str = $addr_op . $context->{global_vars}->{$pointee_key};
        }
        else {
            $expected_value_str = 'NULL';
        }
        return '(' . $var_name . ' == ' . $expected_value_str . ')';
    }
    if ( $type_hash->{base_type} eq 'func_ptr' ) {
        return '(' . $var_name . ' == NULL)';
    }

    # This function should only be called for types that don't have a void verifier.
    # The calling logic must handle void verifiers directly.
    # If we get here with a composite type, it's a logic error in the script.
    if ( $type_hash->{base_type} ne 'primitive' && $type_hash->{base_type} ne 'pointer' && $type_hash->{base_type} ne 'func_ptr' ) {
        die "FATAL: get_c_verify_expr called with a composite type '$key' that should have a void verifier.";
    }
    return "/* Should not be reached */";
}

sub get_c_type_string {
    my ( $type_hash, $declarator, $context ) = @_;
    $declarator //= '';
    my $current = $type_hash;
    if ( !$current || !exists $current->{base_type} ) { return "/* invalid_type */ " . $declarator; }
    if ( $current->{base_type} eq 'pointer' ) {
        return get_c_type_string( $current->{pointee_type}, '*' . $declarator, $context );
    }
    if ( $current->{base_type} eq 'func_ptr' ) {
        my @arg_types;
        my $args_ref    = $current->{args} || [];
        my $is_void_arg = !@{$args_ref}    || ( @{$args_ref} == 1 && $args_ref->[0]{base_type} eq 'primitive' && $args_ref->[0]{value} eq 'v' );
        if ($is_void_arg) {
            push @arg_types, 'void';
        }
        else {
            @arg_types = map { get_c_type_string( $_, '', $context ) } @{$args_ref};
            if ( exists $current->{variadic_after_arg} ) {
                push @arg_types, '...';
            }
        }
        my $new_declarator = '(*' . $declarator . ')(' . join( ', ', @arg_types ) . ')';
        return get_c_type_string( $current->{ret}, $new_declarator, $context );
    }
    my $type_name;
    if ( $current->{base_type} eq 'array' ||
        $current->{base_type} eq 'struct' ||
        $current->{base_type} eq 'union'  ||
        $current->{base_type} eq 'packed_struct' ) {
        $type_name = $context->{typedef_names}->{ _get_canonical_key($current) };
    }
    else { $type_name = exists( $current->{value} ) ? ( $primitive_map_c{ $current->{value} } // "/* unknown_type */" ) : "/* missing_value */"; }
    return $type_name . ( $declarator ? ' ' . $declarator : '' );
}

sub get_c_func_ptr_type_from_sig {
    my ( $sig_hash, $name, $context ) = @_;
    my $declarator  = $name // '';
    my @arguments   = @{ $sig_hash->{args} // [] };
    my $is_void_arg = @arguments == 0 || ( @arguments == 1 && $arguments[0]{base_type} eq 'primitive' && $arguments[0]{value} eq 'v' );
    my @arg_list_with_names;
    if ($is_void_arg) {
        push @arg_list_with_names, 'void';
    }
    else {
        @arg_list_with_names = map { get_c_type_string( $arguments[$_], "arg" . $_, $context ) } 0 .. $#arguments;
        if ( exists $sig_hash->{variadic_after_arg} ) {
            if ( exists $sig_hash->{variadic_arguments} ) {
                push @arg_list_with_names, '...';
            }
        }
    }
    my $full_declarator = $declarator . '(' . join( ', ', @arg_list_with_names ) . ')';
    return get_c_type_string( $sig_hash->{return}, $full_declarator, $context );
}

sub get_c_func_ptr_type_for_cast {
    my ( $sig_hash, $name, $context ) = @_;
    my $declarator  = $name // '';
    my @arguments   = @{ $sig_hash->{args} // [] };
    my $is_void_arg = @arguments == 0 || ( @arguments == 1 && $arguments[0]{base_type} eq 'primitive' && $arguments[0]{value} eq 'v' );
    my @arg_types;
    if ($is_void_arg) {
        push @arg_types, 'void';
    }
    else {
        @arg_types = map { get_c_type_string( $_, '', $context ) } @arguments;
        if ( exists $sig_hash->{variadic_after_arg} ) {
            push @arg_types, '...';
        }
    }
    my $full_declarator = '(*' . $declarator . ')(' . join( ', ', @arg_types ) . ')';
    return get_c_type_string( $sig_hash->{return}, $full_declarator, $context );
}

sub register_all_types {
    my ( $type_hash, $context ) = @_;
    return unless $type_hash && exists $type_hash->{base_type};
    my $key = _get_canonical_key($type_hash);
    return if !$key || exists $context->{registered}->{$key};
    $context->{registered}->{$key} = 1;
    if ( $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' || $type_hash->{base_type} eq 'packed_struct' ) {
        my $keyword   = $type_hash->{base_type};
        my $type_name = '_' . $keyword . '_t_' . _get_safe_c_name($key);
        $context->{typedef_names}->{$key} = $type_name;
        register_all_types( $_, $context ) for @{ $type_hash->{members} };
        my @c_members   = map { get_c_type_string( $type_hash->{members}->[$_], "member" . $_, $context ) } 0 .. $#{ $type_hash->{members} };
        my $members_str = @c_members ? "\n    " . join( ";\n    ", @c_members ) . ";\n" : " ";
        my $typedef_str;
        if ( $keyword eq 'packed_struct' ) {
            my $struct_body = "struct {\n" . $members_str . "}";
            $typedef_str
                = "#if defined(_MSC_VER)\n" .
                "#pragma pack(push, 1)\n" .
                "typedef " .
                $struct_body . " " .
                $type_name . ";\n" .
                "#pragma pack(pop)\n" .
                "#else\n" .
                "typedef " .
                $struct_body .
                " __attribute__((packed)) " .
                $type_name . ";\n" .
                "#endif";
        }
        else {
            $typedef_str = 'typedef ' . ( $keyword eq 'struct' ? 'struct' : 'union' ) . ' {' . $members_str . '} ' . $type_name . ';';
        }
        if ( is_msvc_incompatible($type_hash) ) {
            $typedef_str = "#if !defined(FFI_COMPILER_MSVC)\n" . $typedef_str . "\n#endif  // !FFI_COMPILER_MSVC";
        }
        push @{ $context->{typedefs} }, $typedef_str;
    }
    elsif ( $type_hash->{base_type} eq 'array' ) {
        my $array_wrapper_name = '_arr_wrap_t_' . _get_safe_c_name($key);
        $context->{typedef_names}->{$key} = $array_wrapper_name;
        register_all_types( $type_hash->{array_info}{element_type}, $context );
        my $dims             = join( '', map { "[" . $_ . "]" } @{ $type_hash->{array_info}{dims} } );
        my $full_member_decl = get_c_type_string( $type_hash->{array_info}{element_type}, 'data' . $dims, $context );
        my $typedef_str      = "typedef struct {\n    " . $full_member_decl . ";\n} " . $array_wrapper_name . ';';
        if ( is_msvc_incompatible($type_hash) ) {
            $typedef_str = "#if !defined(FFI_COMPILER_MSVC)\n" . $typedef_str . "\n#endif  // !FFI_COMPILER_MSVC";
        }
        push @{ $context->{typedefs} }, $typedef_str;
    }
    elsif ( $type_hash->{base_type} eq 'pointer' ) {
        register_all_types( $type_hash->{pointee_type}, $context );
    }
    elsif ( $type_hash->{base_type} eq 'func_ptr' ) {
        register_all_types( $type_hash->{ret}, $context );
        register_all_types( $_,                $context ) for @{ $type_hash->{args} };
    }
}

sub generate_tap_verifiers {
    my ( $type_hash, $context ) = @_;
    return unless $type_hash && exists $type_hash->{base_type};
    my $key = _get_canonical_key($type_hash);
    return if !defined $key || exists $context->{helpers_generated}->{$key};
    $context->{helpers_generated}->{$key} = 1;
    if ( $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' || $type_hash->{base_type} eq 'packed_struct' ) {
        generate_tap_verifiers( $_, $context ) for @{ $type_hash->{members} };
    }
    elsif ( $type_hash->{base_type} eq 'array' ) {
        generate_tap_verifiers( $type_hash->{array_info}{element_type}, $context );
    }
    elsif ( $type_hash->{base_type} eq 'pointer' ) {
        generate_tap_verifiers( $type_hash->{pointee_type}, $context );
    }
    my $helper_str;
    my $decl_str;
    if ( $type_hash->{base_type} eq 'struct' ||
        $type_hash->{base_type} eq 'union' ||
        $type_hash->{base_type} eq 'array' ||
        $type_hash->{base_type} eq 'packed_struct' ) {
        my $safe_key  = $type_hash->{base_type} . "_" . _get_safe_c_name($key);
        my $type_name = $context->{typedef_names}->{$key};
        $decl_str = 'void _run_tap_verify_' . $safe_key . '(const char * name, ' . $type_name . " val);";
        if ( $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' || $type_hash->{base_type} eq 'packed_struct' ) {
            my @verifies;
            my $plan_count           = 0;
            my $num_members_to_check = $type_hash->{base_type} eq 'union' ? 1 : scalar( @{ $type_hash->{members} } );
            for my $i ( 0 .. $num_members_to_check - 1 ) {
                my $member      = $type_hash->{members}[$i];
                my $m_base_type = $member->{base_type};
                my $check;
                if ( $m_base_type eq 'struct' || $m_base_type eq 'array' || $m_base_type eq 'union' || $m_base_type eq 'packed_struct' ) {
                    my $m_key      = _get_canonical_key($member);
                    my $m_safe_key = $m_base_type . "_" . _get_safe_c_name($m_key);
                    $check = '        _run_tap_verify_' . $m_safe_key . '("Verifying member \'member' . $i . '\'", val.member' . $i . ');';
                }
                else {
                    my $expr = get_c_verify_expr( $member, "val.member" . $i, $context );
                    $check = '        ok(' . $expr . ', "Member \'member' . $i . '\' has correct value");';
                }
                push @verifies, $check;
                $plan_count++;
            }
            my $body = "    subtest(name) {\n";
            $body .= "        plan(" . $plan_count . ");\n";
            $body .= join( "\n", @verifies ) . "\n";
            $body .= "    }\n";
            $helper_str = 'void _run_tap_verify_' . $safe_key . '(const char * name, ' . $type_name . " val) {\n" . $body . "}";
        }
        elsif ( $type_hash->{base_type} eq 'array' ) {
            my $dim       = $type_hash->{array_info}{dims}[0];
            my $elem_type = $type_hash->{array_info}{element_type};
            my $body      = "    subtest(name) {\n";
            $body .= "        plan(" . $dim . ");\n";
            $body .= "        for (int i = 0; i < " . $dim . "; i++) {\n";
            my $elem_base_type = $elem_type->{base_type};
            if ( $elem_base_type eq 'struct' || $elem_base_type eq 'array' || $elem_base_type eq 'union' || $elem_base_type eq 'packed_struct' ) {
                my $elem_key      = _get_canonical_key($elem_type);
                my $elem_safe_key = $elem_base_type . "_" . _get_safe_c_name($elem_key);
                $body .= "            char elem_name[256];\n";
                $body .= "            snprintf(elem_name, sizeof(elem_name), \"Verifying element [%d]\", i);\n";
                $body .= "            _run_tap_verify_" . $elem_safe_key . "(elem_name, val.data[i]);\n";
            }
            else {
                my $expr = get_c_verify_expr( $elem_type, "val.data[i]", $context );
                $body .= "            ok(" . $expr . ", \"Element [%d] has correct value\", i);\n";
            }
            $body .= "        }\n    }\n";
            $helper_str = 'void _run_tap_verify_' . $safe_key . '(const char * name, ' . $type_name . " val) {\n" . $body . "}";
        }
    }
    if ( defined $helper_str ) {
        if ( is_msvc_incompatible($type_hash) ) {
            $helper_str = "#if !defined(FFI_COMPILER_MSVC)\n" . $helper_str . "\n#endif // !FFI_COMPILER_MSVC";
            $decl_str   = "#if !defined(FFI_COMPILER_MSVC)\n" . $decl_str . "\n#endif // !FFI_COMPILER_MSVC" if defined $decl_str;
        }
        push @{ $context->{helpers} },      $helper_str;
        push @{ $context->{helper_decls} }, $decl_str if defined $decl_str;
    }
}

sub generate_ffi_type_constructor {
    my ( $type_hash, $context ) = @_;
    return unless $type_hash && exists $type_hash->{base_type};
    my $key = _get_canonical_key($type_hash);
    return if !$key || exists $context->{ffi_types}->{$key};
    my ( $code_ref, $pcount_ref ) = ( $context->{creation_code}, $context->{plan_count} );
    $context->{ffi_types}->{$key} = 1;    # Memoize to prevent re-entry
    if ( $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' || $type_hash->{base_type} eq 'packed_struct' ) {
        generate_ffi_type_constructor( $_, $context ) for @{ $type_hash->{members} };
    }
    elsif ( $type_hash->{base_type} eq 'array' )   { generate_ffi_type_constructor( $type_hash->{array_info}{element_type}, $context ); }
    elsif ( $type_hash->{base_type} eq 'pointer' ) { generate_ffi_type_constructor( $type_hash->{pointee_type},             $context ); }
    elsif ( $type_hash->{base_type} eq 'func_ptr' ) {
        generate_ffi_type_constructor( $type_hash->{ret}, $context );
        generate_ffi_type_constructor( $_,                $context ) for @{ $type_hash->{args} };
    }
    my $var_name = "_ffi_type_" . $context->{counter}++;
    $context->{ffi_types}->{$key} = $var_name;    # Store final C variable name
    my $code = "";
    if ( $type_hash->{base_type} eq 'primitive' ) {
        if ( $type_hash->{value} eq 'v' ) { $code = '        ' . $var_name . ' = ffi_type_create_void();'; }
        else { my $id = $primitive_map_infix{ $type_hash->{value} }; $code = '        ' . $var_name . ' = ffi_type_create_primitive(' . $id . ');'; }
    }
    elsif ( $type_hash->{base_type} eq 'pointer' || $type_hash->{base_type} eq 'func_ptr' ) {
        $code = '        ' . $var_name . ' = ffi_type_create_pointer();';
    }
    elsif ( $type_hash->{base_type} eq 'struct' || $type_hash->{base_type} eq 'union' || $type_hash->{base_type} eq 'packed_struct' ) {
        $$pcount_ref++;
        my $keyword   = $type_hash->{base_type};
        my $type_name = $context->{typedef_names}->{$key};
        my @members_code;
        for my $i ( 0 .. $#{ $type_hash->{members} } ) {
            my $member_type = $type_hash->{members}->[$i];
            my $m_key       = _get_canonical_key($member_type);
            my $m_var       = $context->{ffi_types}->{$m_key};
            die "FATAL: FFI type constructor for member type '$m_key' was not generated." unless defined $m_var;
            push @members_code, "ffi_struct_member_create(NULL, " . $m_var . ", offsetof(" . $type_name . ", member" . $i . "))";
        }
        $code = '        ffi_struct_member _members_' . $var_name . '[] = {' . "\n            " . join( ",\n            ", @members_code ) . "};";
        my $creator_func;
        my $creator_args;
        if ( $keyword eq 'packed_struct' ) {
            $creator_func = 'ffi_type_create_packed_struct';
            $creator_args
                = '&' .
                $var_name .
                ', sizeof(' .
                $type_name .
                '), _Alignof(' .
                $type_name .
                '), _members_' .
                $var_name . ', ' .
                scalar(@members_code);
        }
        elsif ( $keyword eq 'union' ) {
            $creator_func = 'ffi_type_create_union';
            $creator_args = '&' . $var_name . ', _members_' . $var_name . ', ' . scalar(@members_code);
        }
        else {    # struct
            $creator_func = 'ffi_type_create_struct';
            $creator_args = '&' . $var_name . ', _members_' . $var_name . ', ' . scalar(@members_code);
        }
        $code .= "\n" . '        status = ' . $creator_func . '(' . $creator_args . ");\n";
        $code .= '        ok(status == FFI_SUCCESS, "' . ucfirst($keyword) . ' type \'' . $key . '\' created");';
    }
    elsif ( $type_hash->{base_type} eq 'array' ) {
        $$pcount_ref++;
        my $elem_key = _get_canonical_key( $type_hash->{array_info}{element_type} );
        my $elem_var = $context->{ffi_types}->{$elem_key};
        die "FATAL: FFI type constructor for array element type '$elem_key' was not generated." unless defined $elem_var;
        $code = '        status = ffi_type_create_array(&' . $var_name . ', ' . $elem_var . ', ' . $type_hash->{array_info}{dims}[0] . ");\n";
        $code .= '        ok(status == FFI_SUCCESS, "Array type \'' . $key . '\' created");';
    }
    push @$code_ref, $code if $code;
}

# Part 3: C Test Case Generation
sub get_promoted_c_type_string {
    my ( $type_hash, $context ) = @_;
    if ( $type_hash->{base_type} eq 'primitive' ) {
        my $val = $type_hash->{value};
        if ( $val =~ /^[abchsti]$/ && $primitive_map_c{$val} ne 'int' && $primitive_map_c{$val} ne 'unsigned int' ) {
            return 'int';
        }
        if ( $val eq 'f' ) {
            return 'double';
        }
    }
    return get_c_type_string( $type_hash, '', $context );
}

sub generate_target_function {
    my ( $parsed_hash, $index, $context, $mode ) = @_;
    my $target_func_name = $mode . "_target_func_" . $index;
    my $is_void_return   = ( $parsed_hash->{return}{base_type} eq 'primitive' && $parsed_hash->{return}{value} eq 'v' );
    my $target_func_decl = get_c_func_ptr_type_from_sig( $parsed_hash, $target_func_name, $context );
    my @arguments        = @{ $parsed_hash->{args} // [] };
    my $is_void_arg      = @arguments == 0 || ( @arguments == 1 && $arguments[0]{base_type} eq 'primitive' && $arguments[0]{value} eq 'v' );
    my @verifies;
    my $num_args_to_plan = 0;

    if ( !$is_void_arg ) {
        for my $i ( 0 .. $#arguments ) {
            my $arg       = $arguments[$i];
            my $base_type = $arg->{base_type};
            if ( $base_type eq 'struct' || $base_type eq 'array' || $base_type eq 'union' || $base_type eq 'packed_struct' ) {
                my $key      = _get_canonical_key($arg);
                my $safe_key = $base_type . "_" . _get_safe_c_name($key);
                push @verifies, '        _run_tap_verify_' . $safe_key . '("Verifying argument \'arg' . $i . '\'", arg' . $i . ');';
            }
            else {
                my $expr = get_c_verify_expr( $arg, "arg" . $i, $context );
                push @verifies, '        ok(' . $expr . ', "Argument \'arg' . $i . '\' has correct value");';
            }
            $num_args_to_plan++;
        }
    }
    if ( exists $parsed_hash->{variadic_after_arg} ) {
        my $last_fixed_arg_name = @arguments > 0 ? "arg" . ($#arguments) : "arg" . ( $parsed_hash->{variadic_after_arg} - 1 );
        push @verifies, "        va_list varargs;";
        push @verifies, "        va_start(varargs, " . $last_fixed_arg_name . ");";
        my $va_arg_idx = 0;
        for my $va_type ( @{ $parsed_hash->{variadic_arguments} } ) {
            my $promoted_type_str = get_promoted_c_type_string( $va_type, $context );
            my $type_key          = _get_canonical_key($va_type);
            my $base_type         = $va_type->{base_type};
            if ( $base_type eq 'struct' || $base_type eq 'array' || $base_type eq 'union' || $base_type eq 'packed_struct' ) {
                my $safe_key    = $base_type . "_" . _get_safe_c_name($type_key);
                my $c_type_name = $context->{typedef_names}->{$type_key};
                push @verifies,
                    '        _run_tap_verify_' .
                    $safe_key .
                    '("Verifying variadic arg ' .
                    $va_arg_idx . ' (' .
                    $type_key .
                    ')", va_arg(varargs, ' .
                    $c_type_name . '));';
            }
            else {
                my $expr = get_c_verify_expr( $va_type, "va_arg(varargs, " . $promoted_type_str . ")", $context );
                push @verifies, '        ok(' . $expr . ', "Variadic argument ' . $va_arg_idx . ' (' . $type_key . ') correct");';
            }
            $va_arg_idx++;
        }
        push @verifies, "        va_end(varargs);";
        $num_args_to_plan += scalar( @{ $parsed_hash->{variadic_arguments} } );
    }
    my $verification_block = "";
    if ( $num_args_to_plan > 0 ) {
        $verification_block = "    subtest(\"Target function '$target_func_name' argument verification\") {\n";
        $verification_block .= '        plan(' . $num_args_to_plan . ');' . "\n";
        $verification_block .= join( "\n", @verifies ) . "\n";
        $verification_block .= "    }\n";
    }
    my $return_stmt = $is_void_return ? "    return;\n" : "    return " . get_c_value_string( $parsed_hash->{return}, $context ) . ";\n";
    my $body        = "{\n" . $verification_block . $return_stmt . "}";
    my $output      = $target_func_decl . " " . $body;
    if ( $parsed_hash->{is_msvc_incompatible} ) {
        $output = "#if !defined(FFI_COMPILER_MSVC)\n" . $output . "\n#endif  // !FFI_COMPILER_MSVC";
    }
    return $output;
}

sub generate_caller_function {
    my ( $parsed_hash, $index, $context ) = @_;
    my $caller_func_name  = "caller_func_" . $index;
    my $is_void_return    = ( $parsed_hash->{return}{base_type} eq 'primitive' && $parsed_hash->{return}{value} eq 'v' );
    my $func_ptr_type_str = get_c_func_ptr_type_from_sig( $parsed_hash, 'func_ptr', $context );
    my @arguments         = @{ $parsed_hash->{args} // [] };
    my $is_void_arg       = @arguments == 0 || ( @arguments == 1 && $arguments[0]{base_type} eq 'primitive' && $arguments[0]{value} eq 'v' );
    my @all_passed_args;
    unless ($is_void_arg) {
        push @all_passed_args, @arguments;
    }
    if ( exists $parsed_hash->{variadic_arguments} ) {
        push @all_passed_args, @{ $parsed_hash->{variadic_arguments} };
    }
    my @main_inits;
    my @call_args;
    my $arg_idx = 0;
    for my $arg_type (@all_passed_args) {
        my $var_name = "arg" . $arg_idx;
        my $type_str = get_c_type_string( $arg_type, $var_name, $context );
        my $val_str;
        if ( $arg_type->{base_type} eq 'pointer' && $arg_type->{pointee_type}{base_type} eq 'primitive' && $arg_type->{pointee_type}{value} eq 'c' ) {
            $val_str = '"Hello, c*!"';
        }
        else {
            $val_str = get_c_value_string( $arg_type, $context );
        }
        push @main_inits, "        " . $type_str . " = " . $val_str . ";";
        push @call_args,  $var_name;
        $arg_idx++;
    }
    my $plan_count = 0;
    $plan_count++ if ( scalar @all_passed_args > 0 || ( exists $parsed_hash->{variadic_arguments} && @{ $parsed_hash->{variadic_arguments} } > 0 ) );
    $plan_count++ unless $is_void_return;
    my $ret_handling;
    if ($is_void_return) {
        $ret_handling = '        func_ptr(' . join( ', ', @call_args ) . ");";
    }
    else {
        my $ret_val_decl = get_c_type_string( $parsed_hash->{return}, "ret_val", $context );
        $ret_handling = "        " . $ret_val_decl . " = func_ptr(" . join( ', ', @call_args ) . ");";
        my $ret_type  = $parsed_hash->{return};
        my $base_type = $ret_type->{base_type};
        if ( $base_type eq 'struct' || $base_type eq 'array' || $base_type eq 'union' || $base_type eq 'packed_struct' ) {
            my $key      = _get_canonical_key($ret_type);
            my $safe_key = $base_type . "_" . _get_safe_c_name($key);
            $ret_handling .= "\n" . '        _run_tap_verify_' . $safe_key . '("Verifying return value from caller", ret_val);';
        }
        else {
            my $verify_expr = get_c_verify_expr( $ret_type, "ret_val", $context );
            $ret_handling .= "\n" . '        ok(' . $verify_expr . ', "Caller received correct return value");';
        }
    }
    my $subtest_body = join( "\n", @main_inits ) . "\n" . $ret_handling;
    my $body         = "{\n    subtest(\"Calling function pointer from native C\") {\n";
    if ( $plan_count > 0 ) {
        $body .= '        plan(' . $plan_count . ');' . "\n";
    }
    $body .= $subtest_body;
    $body .= "\n    }\n}";
    my $output = "void " . $caller_func_name . '(' . $func_ptr_type_str . ") " . $body;
    if ( $parsed_hash->{is_msvc_incompatible} ) {
        $output = "#if !defined(FFI_COMPILER_MSVC)\n" . $output . "\n#endif // !FFI_COMPILER_MSVC";
    }
    return $output;
}

sub generate_tap_test_case {
    my ( $parsed_hash, $index, $context, $mode ) = @_;
    if ( $parsed_hash->{is_msvc_incompatible} ) {
        return '    subtest("' .
            $mode .
            '") {' . "\n" .
            '        plan(1);' . "\n" .
            '        skip(1, "Test skipped on MSVC: uses __int128_t");' . "\n" . '    }';
    }
    my $target_func_name = $mode . "_target_func_" . $index;
    my @arguments        = @{ $parsed_hash->{args} // [] };
    my $is_void_arg      = @arguments == 0 || ( @arguments == 1 && $arguments[0]{base_type} eq 'primitive' && $arguments[0]{value} eq 'v' );
    my $is_void_return   = ( $parsed_hash->{return}{base_type} eq 'primitive' && $parsed_hash->{return}{value} eq 'v' );
    my $plan_count       = 0;
    if ( $mode eq 'forward' ) {
        $plan_count = 1;    # For the trampoline creation ok()
        $plan_count++ unless $is_void_return;
        $plan_count++ if ( scalar @arguments > 0 && !($is_void_arg) );
    }
    else {                  # reverse mode
        $plan_count = 2;    # For the reverse trampoline ok() and the caller_func() subtest
    }
    my $local_context = {
        ffi_types     => {},
        creation_code => [],
        counter       => 0,
        typedef_names => $context->{typedef_names},
        plan_count    => \$plan_count,
        global_vars   => $context->{global_vars}
    };
    my @all_passed_args;
    unless ($is_void_arg) {
        push @all_passed_args, @arguments;
    }
    if ( exists $parsed_hash->{variadic_arguments} ) {
        push @all_passed_args, @{ $parsed_hash->{variadic_arguments} };
    }
    generate_ffi_type_constructor( $parsed_hash->{return}, $local_context );
    generate_ffi_type_constructor( $_,                     $local_context ) for @all_passed_args;
    my $ret_type_key = _get_canonical_key( $parsed_hash->{return} );
    my $ret_type_var = $local_context->{ffi_types}->{$ret_type_key};
    die "FATAL: FFI type constructor for return type '$ret_type_key' was not generated." unless defined $ret_type_var;
    my @arg_type_vars = map {
        my $type  = $_;
        my $key   = _get_canonical_key($type);
        my $c_var = $local_context->{ffi_types}->{$key};
        die "FATAL: FFI type constructor for argument type '$key' was not generated in signature '$parsed_hash->{original_sig}'."
            unless defined $c_var;
        $c_var;
    } @all_passed_args;
    my $num_fixed_args = exists( $parsed_hash->{variadic_after_arg} ) ? $parsed_hash->{variadic_after_arg} : scalar(@arg_type_vars);
    my $total_args     = scalar(@all_passed_args);
    my @ffi_type_decls = map { "ffi_type * " . $_ . ";" } sort ( values %{ $local_context->{ffi_types} } );
    my $harness_c      = '    subtest("' . $mode . '") {' . "\n";
    $harness_c .= '        plan(' . $plan_count . ');' . "\n";
    $harness_c .= "        ffi_status status;\n";
    $harness_c .= "#if defined(__GNUC__) || defined(__clang__)\n";
    $harness_c .= "        #pragma GCC diagnostic push\n";
    $harness_c .= "        #pragma GCC diagnostic ignored \"-Wunused-variable\"\n";
    $harness_c .= "        #pragma GCC diagnostic ignored \"-Wunused-but-set-variable\"\n";
    $harness_c .= "#endif\n";
    $harness_c .= join( "\n", map { "        " . $_ } @ffi_type_decls ) . "\n";
    $harness_c .= "#if defined(__GNUC__) || defined(__clang__)\n";
    $harness_c .= "        #pragma GCC diagnostic pop\n";
    $harness_c .= "#endif\n\n";
    $harness_c .= join( "\n", @{ $local_context->{creation_code} } ) . "\n";

    if (@arg_type_vars) {
        $harness_c .= '        ffi_type * arg_types[] = {' . join( ', ', @arg_type_vars ) . "};\n";
    }
    if ( $mode eq 'forward' ) {
        my @main_inits;
        my @main_arg_pointers;
        my $arg_idx = 0;
        for my $arg_type (@all_passed_args) {
            my $var_name = "arg" . $arg_idx;
            my $type_str = get_c_type_string( $arg_type, $var_name, $context );
            my $val_str;
            if ( $arg_type->{base_type} eq 'pointer' &&
                $arg_type->{pointee_type}{base_type} eq 'primitive' &&
                $arg_type->{pointee_type}{value} eq 'c' ) {
                $val_str = '"Hello, c*!"';
            }
            else {
                $val_str = get_c_value_string( $arg_type, $context );
            }
            push @main_inits,        "        " . $type_str . " = " . $val_str . ";";
            push @main_arg_pointers, "&" . $var_name;
            $arg_idx++;
        }
        my $ret_handling;
        if ($is_void_return) {
            $ret_handling = "        cif_func((void *)" . $target_func_name . ", NULL, " . ( @main_arg_pointers ? "args" : "NULL" ) . ");";
        }
        else {
            my $ret_val_decl = get_c_type_string( $parsed_hash->{return}, "ret_val", $context );
            my $ret_val_type = $parsed_hash->{return};
            my $base_type    = $ret_val_type->{base_type};
            $ret_handling
                = "        " .
                $ret_val_decl .
                ";\n        cif_func((void *)" .
                $target_func_name .
                ", &ret_val, " .
                ( @main_arg_pointers ? "args" : "NULL" ) . ");\n";
            if ( $base_type eq 'struct' || $base_type eq 'array' || $base_type eq 'union' || $base_type eq 'packed_struct' ) {
                my $key      = _get_canonical_key($ret_val_type);
                my $safe_key = $base_type . "_" . _get_safe_c_name($key);
                $ret_handling .= '        _run_tap_verify_' . $safe_key . '("Verifying return value", ret_val);';
            }
            else {
                my $verify_expr = get_c_verify_expr( $ret_val_type, "ret_val", $context );
                $ret_handling .= '        ok(' . $verify_expr . ', "Correct return value received");';
            }
        }
        $harness_c .= "        ffi_trampoline_t * trampoline = NULL;\n";
        $harness_c
            .= '        status = generate_forward_trampoline(&trampoline, ' .
            $ret_type_var . ', ' .
            ( @arg_type_vars ? 'arg_types' : 'NULL' ) . ', ' .
            $total_args . ', ' .
            $num_fixed_args . ");\n";
        $harness_c .= "        ok(status == FFI_SUCCESS, \"Trampoline created successfully\");\n\n";
        $harness_c .= "        ffi_cif_func cif_func = (ffi_cif_func)ffi_trampoline_get_code(trampoline);\n";
        $harness_c .= join( "\n", @main_inits ) . "\n";
        if (@main_arg_pointers) {
            $harness_c .= '        void * args[] = {' . join( ', ', @main_arg_pointers ) . "};\n";
        }
        $harness_c .= $ret_handling . "\n";
        $harness_c .= "        ffi_trampoline_free(trampoline);\n";
    }
    else {    # reverse
        my $func_ptr_decl_str = get_c_func_ptr_type_for_cast( $parsed_hash, 'func_ptr', $context );
        my $func_ptr_cast_str = get_c_func_ptr_type_for_cast( $parsed_hash, '',         $context );
        $harness_c .= "        ffi_reverse_trampoline_t * rt = NULL;\n";
        $harness_c
            .= '        status = generate_reverse_trampoline(&rt, ' .
            $ret_type_var . ', ' .
            ( @arg_type_vars ? 'arg_types' : 'NULL' ) . ', ' .
            $total_args . ', ' .
            $num_fixed_args .
            ", (void *)" .
            $target_func_name .
            ", NULL);\n";
        $harness_c .= "        ok(status == FFI_SUCCESS && rt, \"Reverse trampoline created\");\n\n";
        $harness_c .= "        if (rt) {\n";
        $harness_c .= "            " . $func_ptr_decl_str . " = (" . $func_ptr_cast_str . ")ffi_reverse_trampoline_get_code(rt);\n";
        $harness_c .= "            caller_func_" . $index . "(func_ptr);\n";
        $harness_c .= "        }\n";
        $harness_c .= "        else {\n";
        $harness_c .= "            skip(1, \"Test skipped due to creation failure\");\n";
        $harness_c .= "        }\n";
        $harness_c .= "        ffi_reverse_trampoline_free(rt);\n";
    }
    $harness_c .= "    }";
    return $harness_c;
}

# Part 4: Main Script Execution
sub read_signatures_from_file {
    my ($filename) = @_;
    my @signatures;
    open my $fh, '<', $filename or die "Could not open signature file '$filename': $!";
    my $line_num = 0;
    while ( my $line = <$fh> ) {
        $line_num++;
        chomp $line;
        $line =~ s/\s*#.*//;
        $line =~ s/^\s+|\s+$//g;
        push @signatures, { line => $line_num, text => $line } if $line;
    }
    close $fh;
    return @signatures;
}

sub register_global_var_for_type {
    my ( $type_hash, $context ) = @_;
    return unless $type_hash && exists $type_hash->{base_type};
    if ( ( $type_hash->{base_type} eq 'primitive' && $type_hash->{value} eq 'v' ) || $type_hash->{base_type} eq 'func_ptr' ) {
        return;
    }
    my $key = _get_canonical_key($type_hash);
    return if !$key || exists $context->{global_vars}->{$key};
    if ( $key eq 'c' ) {
        my $safe_name = "g_c_str";
        $context->{global_vars}->{$key} = $safe_name;
        my $decl = 'char ' . $safe_name . '[] = "Hello, c*!";';
        push @{ $context->{global_var_defs} }, $decl unless grep { $_ eq $decl } @{ $context->{global_var_defs} };
        return;
    }
    my $safe_name = "g_" . _get_safe_c_name($key);
    $context->{global_vars}->{$key} = $safe_name;
    my $decl;
    if ( $type_hash->{base_type} eq 'pointer' ) {
        my $pointee_key = _get_canonical_key( $type_hash->{pointee_type} );
        if ( $pointee_key eq 'v' ) {
            $decl = get_c_type_string( $type_hash, $safe_name, $context ) . " = NULL;";
        }
        else {
            return unless $pointee_key && exists $context->{global_vars}->{$pointee_key};
            my $global_to_point_to = $context->{global_vars}->{$pointee_key};
            my $addr_op            = ( $pointee_key eq 'c' ) ? '' : '&';
            $decl = get_c_type_string( $type_hash, $safe_name, $context ) . " = " . $addr_op . $global_to_point_to . ";";
        }
    }
    else {
        my $val_str = get_c_static_initializer( $type_hash, $context );
        $decl = get_c_type_string( $type_hash, $safe_name, $context ) . " = " . $val_str . ";";
    }
    if ( is_msvc_incompatible($type_hash) ) {
        $decl = "#if !defined(FFI_COMPILER_MSVC)\n" . $decl . "\n#endif // !FFI_COMPILER_MSVC";
    }
    push @{ $context->{global_var_defs} }, $decl;
}

# Recursively register global vars needed for pointer tests
sub _recursively_register_pointer_globals {
    my ( $type_hash, $context ) = @_;
    return unless $type_hash && $type_hash->{base_type} eq 'pointer';
    _recursively_register_pointer_globals( $type_hash->{pointee_type}, $context );
    register_global_var_for_type( $type_hash->{pointee_type}, $context );
    register_global_var_for_type( $type_hash,                 $context );
}
my %globals_registered_memo;    # Memoization to prevent redundant work

sub recursively_register_globals_for_all_types {
    my ( $type_hash, $context ) = @_;
    return unless $type_hash && exists $type_hash->{base_type};
    my $key = _get_canonical_key($type_hash);
    return if defined $key && exists $globals_registered_memo{$key};
    $globals_registered_memo{$key} = 1 if defined $key;
    my $base = $type_hash->{base_type};
    if ( $base eq 'pointer' ) {
        _recursively_register_pointer_globals( $type_hash, $context );
    }
    elsif ( $base eq 'struct' || $base eq 'union' || $base eq 'packed_struct' ) {
        recursively_register_globals_for_all_types( $_, $context ) for @{ $type_hash->{members} };
    }
    elsif ( $base eq 'array' ) {
        recursively_register_globals_for_all_types( $type_hash->{array_info}{element_type}, $context );
    }
    elsif ( $base eq 'func_ptr' ) {
        recursively_register_globals_for_all_types( $type_hash->{ret}, $context );
        recursively_register_globals_for_all_types( $_,                $context ) for @{ $type_hash->{args} };
    }
}

sub signature_is_msvc_incompatible {
    my ($parsed_hash) = @_;
    return 0 unless $parsed_hash;
    if ( is_msvc_incompatible( $parsed_hash->{return} ) ) {
        return 1;
    }
    for my $arg ( @{ $parsed_hash->{args} // [] } ) {
        if ( is_msvc_incompatible($arg) ) {
            return 1;
        }
    }
    if ( exists $parsed_hash->{variadic_arguments} ) {
        for my $arg ( @{ $parsed_hash->{variadic_arguments} } ) {
            if ( is_msvc_incompatible($arg) ) {
                return 1;
            }
        }
    }
    return 0;
}
my $script_dir  = dirname(__FILE__);
my $output_file = "501_generated.c";
my $sig_file    = File::Spec->catfile( $script_dir, 'signatures.def' );
my @signatures  = read_signatures_from_file($sig_file);
unless (@signatures) {
    die "No signatures were loaded from '$sig_file'. Aborting.";
}
my $master_context = {
    registered        => {},
    typedefs          => [],
    typedef_names     => {},
    helpers           => [],
    helper_decls      => [],
    helpers_generated => {},
    global_vars       => {},
    global_var_defs   => [],
    test_counts       => {},
};
for my $sig_info (@signatures) {
    my $parsed = parse_signature( $sig_info->{text}, $sig_info->{line} );
    next unless $parsed;
    register_all_types( $parsed->{return}, $master_context );
    register_all_types( $_,                $master_context ) for @{ $parsed->{args} // [] };
    if ( exists $parsed->{variadic_arguments} ) {
        register_all_types( $_, $master_context ) for @{ $parsed->{variadic_arguments} };
    }
}
for my $sig_info (@signatures) {
    my $parsed = parse_signature( $sig_info->{text}, $sig_info->{line} );
    next unless $parsed;
    for my $arg ( @{ $parsed->{args} // [] } ) {
        recursively_register_globals_for_all_types( $arg, $master_context );
    }
    if ( exists $parsed->{variadic_arguments} ) {
        recursively_register_globals_for_all_types( $_, $master_context ) for @{ $parsed->{variadic_arguments} };
    }
    recursively_register_globals_for_all_types( $parsed->{return}, $master_context );
}
for my $sig_info (@signatures) {
    my $parsed = parse_signature( $sig_info->{text}, $sig_info->{line} );
    next unless $parsed;
    generate_tap_verifiers( $parsed->{return}, $master_context );
    generate_tap_verifiers( $_,                $master_context ) for @{ $parsed->{args} // [] };
    if ( exists $parsed->{variadic_arguments} ) {
        generate_tap_verifiers( $_, $master_context ) for @{ $parsed->{variadic_arguments} };
    }
}
my @target_funcs;
my @caller_funcs;
my @harness_blocks;
my $i = 0;
my @forward_declarations;
for my $sig_info (@signatures) {
    my $parsed = parse_signature( $sig_info->{text}, $sig_info->{line} );
    unless ($parsed) { warn "Skipping signature on line " . $sig_info->{line} . "\n"; next; }
    my $is_incompatible = signature_is_msvc_incompatible($parsed);
    if ($is_incompatible) { push @forward_declarations, "#if !defined(FFI_COMPILER_MSVC)"; }
    push @forward_declarations, get_c_func_ptr_type_from_sig( $parsed, "forward_target_func_" . $i, $master_context ) . ";";
    push @forward_declarations, get_c_func_ptr_type_from_sig( $parsed, "reverse_target_func_" . $i, $master_context ) . ";";
    my $caller_ptr_type = get_c_func_ptr_type_from_sig( $parsed, 'func_ptr', $master_context );
    push @forward_declarations, "void caller_func_" . $i . "(" . $caller_ptr_type . ");";
    if ($is_incompatible) { push @forward_declarations, "#endif // !FFI_COMPILER_MSVC"; }
    $i++;
}
$i = 0;
for my $sig_info (@signatures) {
    my $parsed = parse_signature( $sig_info->{text}, $sig_info->{line} );
    unless ($parsed) {
        warn "Skipping code generation for signature on line " . $sig_info->{line} . "\n";
        next;
    }
    $parsed->{original_sig}         = $sig_info->{text};
    $parsed->{is_msvc_incompatible} = signature_is_msvc_incompatible($parsed);
    push @target_funcs, generate_target_function( $parsed, $i, $master_context, 'forward' );
    push @target_funcs, generate_target_function( $parsed, $i, $master_context, 'reverse' );
    push @caller_funcs, generate_caller_function( $parsed, $i, $master_context );
    my $forward_harness = generate_tap_test_case( $parsed, $i, $master_context, 'forward' );
    my $reverse_harness = generate_tap_test_case( $parsed, $i, $master_context, 'reverse' );
    $forward_harness =~ s/^/    /gm;
    $reverse_harness =~ s/^/    /gm;

    # Add the C-like signature as a comment
    my $c_like_sig   = signature_to_c_like_string($parsed);
    my $parent_block = '    // C-like signature: ' . $c_like_sig . "\n";
    $parent_block .= '    subtest("Signature: ' . $parsed->{original_sig} . '") {' . "\n";
    $parent_block .= '        diag("' . $c_like_sig . '");' . "\n";
    $parent_block .= '        plan(2);' . "\n";
    $parent_block .= $forward_harness . "\n";
    $parent_block .= $reverse_harness . "\n";
    $parent_block .= '    }';
    push @harness_blocks, $parent_block;
    $i++;
}

# Part 5: File Output
open my $out_fh, '>', $output_file or die "Could not open '$output_file' for writing: $!";
print {$out_fh} <<'END_HEADER';
/**
 * Copyright (c) 2025 Sanko Robinson
 *
 * This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
 * You may choose to use this code under the terms of either license.
 *
 * SPDX-License-Identifier: (Artistic-2.0 OR MIT)
 *
 * The documentation blocks within this file are licensed under the
 * Creative Commons Attribution 4.0 International License (CC BY 4.0).
 *
 * SPDX-License-Identifier: CC-BY-4.0
 */
/**
 * @file 501_generated.c
 * @brief Auto-generated FFI test suite.
 *
 * @details This file was generated by a Perl script to test a variety of
 * function signatures, including primitives, structs, arrays, and function
 * pointers, using the `double_tap.h` testing framework.
 */

#define DBLTAP_IMPLEMENTATION
#include <double_tap.h>
#include <infix.h>
#include <math.h>    // For fabs() and fabsl()
#include <stdarg.h>  // For va_list and friends
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>   // For snprintf()
#include <string.h>  // For strcmp()

// ============================================================================
// Type Definitions and Verifiers (Global Scope)
// ============================================================================
END_HEADER

# Do NOT sort typedefs or global vars, as their order is important.
print {$out_fh} join( "\n", @{ $master_context->{typedefs} } ), "\n\n";
print {$out_fh} "// ============================================================================\n";
print {$out_fh} "// Global Variables for Pointer Tests\n";
print {$out_fh} "// ============================================================================\n";
print {$out_fh} join( "\n", @{ $master_context->{global_var_defs} } ), "\n\n";
print {$out_fh} "// ============================================================================\n";
print {$out_fh} "// TAP Verifier Forward Declarations\n";
print {$out_fh} "// ============================================================================\n";

# Sort declarations for deterministic output. This is safe because they are just declarations.
print {$out_fh} join( "\n", sort @{ $master_context->{helper_decls} } ), "\n\n";

# Do NOT sort the helper function bodies themselves, to respect declaration-before-use order.
print {$out_fh} join( "\n\n", @{ $master_context->{helpers} } ), "\n\n";
print {$out_fh} "// ============================================================================\n";
print {$out_fh} "// Forward Declarations\n";
print {$out_fh} "// ============================================================================\n";

# Do NOT sort forward declarations, to preserve #if/#endif blocks.
print {$out_fh} join( "\n", @forward_declarations ), "\n\n";
print {$out_fh} <<'END_TARGET_HEADER';
// ============================================================================
// Target and Caller Functions
// ============================================================================
END_TARGET_HEADER
print {$out_fh} join( "\n\n", @target_funcs ), "\n\n";
print {$out_fh} join( "\n\n", @caller_funcs ), "\n\n";
print {$out_fh} <<'END_HARNESS_HEADER';
// ============================================================================
// Test Harnesses
// ============================================================================
TEST {
END_HARNESS_HEADER
print {$out_fh} '    plan(' . scalar(@harness_blocks) . ");\n\n";
print {$out_fh} join( "\n", @harness_blocks ), "\n";
print {$out_fh} "}\n";
close $out_fh;
say "Successfully generated '$output_file' with " . scalar(@signatures) . " test blocks.";

=pod

=head1 License and Legal

Copyright (c) 2025 Sanko Robinson

This source code is dual-licensed under the Artistic License 2.0 or the MIT License.
You may choose to use this code under the terms of either license.

SPDX-License-Identifier: (Artistic-2.0 OR MIT)

The documentation blocks within this file are licensed under the
Creative Commons Attribution 4.0 International License (CC BY 4.0).

SPDX-License-Identifier: CC-BY-4.0

=cut
