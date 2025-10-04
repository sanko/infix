use v5.36;
use Data::Dump;
use Path::Tiny;
$|++;
my $sig_file = path($0)->sibling('signatures.def');
#
my @lines = grep {length} map {s[#.*$][]rg} path($sig_file)->lines( { chomp => 1 } );
ddx @lines;

# This regex finds optional leading whitespace followed by the next valid token.
# This structure prevents zero-width matches and the infinite loop.
my $token_prefix_finder_regex = qr{
    ^ \s* # Consume leading whitespace
    ( # Start capturing the clean token ($1)
        (?:
            [vbcCsSiIlLfdp] # A primitive character
            |
            \.              # A literal dot for variadic args
            |
            =>              # The arrow separator
            |
            (?&struct_block)   # A balanced {} block
            |
            (?&func_block)     # A balanced () block
        )
        (?: \[\d*\] )* # Any array specifiers are part of the token
    )

    (?(DEFINE)
        # These definitions are LOCAL to this regex.
        (?<struct_block> \{ (?: [^{}]++ | (?&struct_block) )* \} )
        (?<func_block>   \( (?: [^()]++ | (?&func_block) )* \) )
    )
}x;

# This regex validates and parses a single token's internal structure
my $type_parser_regex = qr{
    ^ \s*
    (?:
        (?<primitive> [vbcCsSiIlLfdp] )
        |
        (?<struct>    \{ (?<struct_content>.*) \} )
        |
        (?<func_ptr>  \( (?<func_content>.*) \) )
    )
    (?<array> (?: \[\d*\] )* )
    \s* $
}x;

sub tokenize ($string) {
    return () unless defined $string and length $string;
    my @tokens;

    # This loop is now safe from infinite recursion
    while ( length $string ) {
        if ( $string =~ /$token_prefix_finder_regex/ ) {

            # $1 contains the clean token (e.g., 'i', '{dd}')
            push @tokens, $1;

            # $& contains the entire match (e.g., '  i ')
            # Advancing by its length correctly consumes the processed part
            $string = substr( $string, length($&) );
        }
        else {
            # If the string isn't empty but no token can be found, it's a syntax error
            warn "Tokenizer error: Cannot find valid type at start of '$string'";
            last;
        }
    }
    return @tokens;
}

# Takes a single token and determines its structure
sub _walk ($string) {
    return { base_type => 'error', value => 'undefined input' } unless defined $string;
    unless ( $string =~ $type_parser_regex ) {
        warn "Parser error: Invalid syntax for type '$string'";
        return { base_type => 'unknown', value => $string };
    }
    my %captures = %+;
    my %type_info;
    if ( defined $captures{primitive} ) {
        $type_info{base_type} = 'primitive';
        $type_info{value}     = $captures{primitive};
    }
    elsif ( defined $captures{struct} ) {
        $type_info{base_type} = 'struct';
        my @members = tokenize( $captures{struct_content} );
        $type_info{members} = [ map { _walk($_) } @members ];
    }
    elsif ( defined $captures{func_ptr} ) {
        $type_info{base_type} = 'func_ptr';
        my @tokens = tokenize( $captures{func_content} );
        my ( $arrow_idx, $dot_idx ) = ( -1, -1 );
        for my $i ( 0 .. $#tokens ) {
            if ( $tokens[$i] eq '=>' ) { $arrow_idx = $i }
            if ( $tokens[$i] eq '.' )  { $dot_idx   = $i }
        }
        if ( $arrow_idx != -1 ) {
            my @arg_tokens = @tokens[ 0 .. $arrow_idx - 1 ];
            my @ret_tokens = @tokens[ $arrow_idx + 1 .. $#tokens ];
            if ( $dot_idx != -1 && $dot_idx < $arrow_idx ) {
                my @fixed = @arg_tokens[ 0 .. $dot_idx - 1 ];
                $type_info{variadic_after_arg} = scalar(@fixed) - 1;
                splice( @arg_tokens, $dot_idx, 1 );    # Remove the dot
            }
            $type_info{args} = [ map { _walk($_) } @arg_tokens ];
            $type_info{ret}  = _walk( $ret_tokens[0] ) if @ret_tokens;
        }
        else {
            warn "Parser error: Invalid function pointer content '$captures{func_content}'";
        }
    }
    if ( defined $captures{array} and length $captures{array} ) {
        $type_info{array_specifiers} = [ $captures{array} =~ /(\[\d*\])/g ];
    }
    return \%type_info;
}

sub parse_signature ($signature) {
    my @tokens = tokenize($signature);
    return unless @tokens;
    my $arrow_idx = -1;
    for my $i ( 0 .. $#tokens ) {
        if ( $tokens[$i] eq '=>' ) {
            $arrow_idx = $i;
            last;
        }
    }
    unless ( $arrow_idx != -1 ) {
        warn "Invalid signature format (missing top-level =>): $signature";
        return;
    }
    my @arg_tokens = @tokens[ 0 .. $arrow_idx - 1 ];
    my @ret_tokens = @tokens[ $arrow_idx + 1 .. $#tokens ];
    return { base_type => 'error', value => 'missing return type' } unless @ret_tokens;
    my %parsed_structure;
    my $dot_idx = -1;
    for my $i ( 0 .. $#arg_tokens ) {
        if ( $arg_tokens[$i] eq '.' ) {
            $dot_idx = $i;
            last;
        }
    }
    if ( $dot_idx != -1 ) {
        my @fixed = @arg_tokens[ 0 .. $dot_idx - 1 ];
        $parsed_structure{variadic_after_arg} = scalar(@fixed) - 1;
        splice( @arg_tokens, $dot_idx, 1 );    # Remove the dot
    }
    $parsed_structure{arguments} = [ map { _walk($_) } @arg_tokens ];
    $parsed_structure{return}    = _walk( $ret_tokens[0] );
    return \%parsed_structure;
}
for my $sig (@lines) {
    print "Parsing: $sig\n";
    my $structure = parse_signature($sig);
    ddx($structure);
}

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
