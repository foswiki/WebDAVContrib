#!/usr/bin/env perl
# Ultra-lightweight WebDAV server daemon
# See System.ConfiguringWebDAVContribWithHTTPDaemon
#
# Copyright (C) 2013-2015 C-Dot Consultants http://c-dot.co.uk
# Copyright (C) 2015-2020 Foswiki Contributors
#
# This program is licensed to you under the terms of the GNU General
# Public License, version 2. It is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.
#

use strict;
use File::Spec ();

sub usage {
    print STDERR '** ' . shift . ' **\n';
    print STDERR "$0 [options] url\n";
    print STDERR <DATA>;
    exit 1;
}

BEGIN {
    my ( $volume, $binDir, $action ) = File::Spec->splitpath(__FILE__);
    $binDir .= '/' if $binDir;
    my $setlib = File::Spec->catpath( $volume, "$binDir../bin", 'setlib.cfg' );
    @INC = ( '.', grep { $_ ne '.' } @INC ) unless $binDir;
    require $setlib;
}

my $host      = '';
my $port      = 80;
my $location  = '/';
my $root_path = '/tmp';
my $trace     = 0;
my $fs        = 'Foswiki';
my $realm     = 'Foswiki';

while ( scalar(@ARGV) ) {
    my $arg = shift(@ARGV);
    if ( $arg eq '-t' || $arg eq '--trace' ) {
        $trace = shift(@ARGV);
    }
    elsif ( $arg eq '-fs' || $arg eq '--filesystem' ) {
        $fs = shift(@ARGV);
    }
    elsif ( $arg eq '-ar' || $arg eq '--authrealm' ) {
        $realm = shift(@ARGV);
    }
    elsif ( $arg eq '-r' || $arg eq '--root' ) {

        # Only used with PlainPlusAttrs
        $root_path = shift(@ARGV);
    }
    else {

        # http://host[:port][location] e.g.
        # http://server:8080/ -> server 8080 /
        if ( $arg =~ m#^(?:[a-z]+://)?([^/:]+)(?::(\d+))?(/.*)?$# ) {
            $host     = $1;
            $port     = $2 if defined $2;
            $location = $3 if defined $3;
        }
    }
}
$location ||= '/';

unless ($host) {
    usage "Host must be given";
}

if ( $fs eq 'PlainPlusAttrs' && !-d $root_path ) {
    usage "root path must exist and be a directory";
}

use HTTP::Daemon::FoswikiWebDAV ();
while (1) {
    my $daemon = HTTP::Daemon::FoswikiWebDAV->new(
        host      => $host,
        port      => $port,
        filesys   => 'Filesys::Virtual::' . $fs,
        trace     => $trace,
        realm     => $realm,
        location  => $location,
        root_path => $root_path
    );
    if ($daemon) {
        $daemon->run();
    }
    else {
        print STDERR "Waiting for socket\n";
        sleep 1;
    }
}
1;
__DATA__
Where url specifies the url we are serving, like this: http://server:8080/

Options:
   -fs FS or --filesystem FS
      set filesystem to Filesys::Virtual::FS (e.g. PlainPlusAttrs)
      default is Foswiki
   -r R or --root R
      set root filesystem path to R (required, for PlainPlusAttrs only)
   -t N or --trace N
      set tracing to N
   -ar R or --authrealm R
      set authrealm to R (default is Foswiki)
