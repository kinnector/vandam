package Vandam;
use strict;
use warnings;
use Socket;
use JSON::PP;

# The Vandam Perl RASP Agent
# Hooks into Perl's CORE::GLOBAL namespace and @INC to intercept dangerous calls natively.

my $TELEMETRY_SOCKET = '/run/vandam/php_telemetry.sock';

our %VERDICT_CACHE = ();

sub get_traceback {
    my @trace;
    my $i = 1;
    while (my @frame = caller($i++)) {
        my ($package, $filename, $line, $subroutine) = @frame;
        next if $filename =~ /Vandam\.pm$/;
        push @trace, {
            file => $filename,
            line => $line,
            function => $subroutine,
            class => $package,
            args => []
        };
    }
    return \@trace;
}

sub ask_vandam {
    my ($type, $func, $path, $fire_and_forget) = @_;

    my $cache_key = "$func:$path";
    if (exists $VERDICT_CACHE{$cache_key}) {
        die "Vandam RASP blocked execution of '$func' (Cached)\n" if $VERDICT_CACHE{$cache_key} eq 'deny';
        return;
    }

    my %payload = (
        type => $type,
        pid => $$,
        function => $func,
        path => $path,
        in_request => 0,
        http => {},
        trace => get_traceback()
    );

    eval {
        socket(my $sock, AF_UNIX, SOCK_STREAM, 0) or die;
        my $sun = sockaddr_un($TELEMETRY_SOCKET);
        connect($sock, $sun) or die;

        my $json = encode_json(\%payload) . "\n";
        print $sock $json;

        if ($fire_and_forget) {
            $VERDICT_CACHE{$cache_key} = 'allow';
            close($sock);
            return;
        }

        my $rin = '';
        vec($rin, fileno($sock), 1) = 1;
        if (select($rin, undef, undef, 0.5)) {
            my $response = <$sock>;
            if ($response) {
                my $data = decode_json($response);
                my $verdict = $data->{verdict} || 'allow';
                $VERDICT_CACHE{$cache_key} = $verdict;
                die "Vandam RASP blocked execution of '$func'\n" if $verdict eq 'deny';
            }
        }
        close($sock);
    };
}

# ==========================================
# MONKEY PATCHING VIA CORE::GLOBAL & @INC
# ==========================================

BEGIN {
    # 1. COMMAND EXECUTION
    *CORE::GLOBAL::system = sub {
        my $cmd = join(' ', @_);
        ask_vandam('exec_call', 'system', $cmd);
        CORE::system(@_);
    };

    *CORE::GLOBAL::exec = sub {
        my $cmd = join(' ', @_);
        ask_vandam('exec_call', 'exec', $cmd);
        CORE::exec(@_);
    };

    *CORE::GLOBAL::readpipe = sub {
        my $cmd = shift;
        ask_vandam('exec_call', 'readpipe (backticks)', $cmd);
        CORE::readpipe($cmd);
    };

    # 2. PERMISSIONS
    *CORE::GLOBAL::chmod = sub {
        my $mode = shift;
        my @files = @_;
        foreach my $file (@files) {
            ask_vandam('chmod', 'chmod', sprintf("%s (Perms: %04o)", $file, $mode));
        }
        CORE::chmod($mode, @files);
    };

    # 3. MAGIC LOADING & IMPORTS (via @INC hook)
    unshift @INC, sub {
        my ($coderef, $filename) = @_;
        ask_vandam('file_compile', 'require', $filename, 1); # Fire and forget
        return undef; # Return undef to tell Perl to continue searching @INC normally
    };
}

1;
