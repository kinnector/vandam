package Vandam;

use strict;
use warnings;

require Exporter;
use JSON::PP;

our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( 'all' => [ qw() ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our @EXPORT = qw();

our $VERSION = '1.00';

require XSLoader;
XSLoader::load('Vandam', $VERSION);

sub get_traceback_json {
    my @trace;
    my $i = 1;
    # Walk the Perl stack frames
    while (my @frame = caller($i++)) {
        my ($package, $filename, $line, $subroutine) = @frame;
        # Skip internal execution frames
        next if $subroutine =~ /__ANON__/;
        push @trace, {
            file => $filename || "",
            line => $line || 0,
            function => $subroutine || "unknown",
            class => $package || "",
            args => []
        };
    }
    return encode_json(\@trace);
}

# Overriding require/use via @INC hook (can't be done easily in XS without OP_REQUIRE hooking)
unshift @INC, sub {
    my ($coderef, $filename) = @_;
    # Telemetry is handled natively in C if we had an OP_REQUIRE hook.
    # For now, we leave the hook here to prove the architecture.
    return undef;
};

1;
__END__

=head1 NAME
Vandam - Native Perl RASP Agent
=cut
