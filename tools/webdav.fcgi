#!/usr/bin/env perl
# Lightweight WebDAV server using FCGI
#
# Copyright (C) 2014-2015 C-Dot Consultants http://c-dot.co.uk
# Copyright (C) 2015-2025 Foswiki Contributors
# 
# This program is licensed to you under the terms of the GNU General
# Public License, version 2. It is distributed in the hope that it will
# be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# 
# As per the GPL, removal of this notice is prohibited.
# 

use strict;
use warnings;

use File::Spec;

BEGIN {
    my ( $volume, $binDir, $action ) = File::Spec->splitpath(__FILE__);
    $binDir .= '/' if $binDir;
    my $setlib = File::Spec->catpath( $volume, "$binDir../bin", 'setlib.cfg' );
    @INC = ( '.', grep { $_ ne '.' } @INC ) unless $binDir;
    require $setlib;
    $Foswiki::cfg{Engine} = 'Foswiki::Engine::CGI';
}

use FCGI ();
use HTTP::Request ();
use HTTP::Response ();
use MIME::Base64 ();
use Getopt::Long ();
use Pod::Usage ();
use FCGI::FoswikiWebDAV ();

my $detach = 0;
my $fs = 'Foswiki';
my $help = 0;
my $host = '';
my $listen = 0;
my $location = '/dav';
my $manager = 'FCGI::FoswikiWebDAVProcManager';
my $nproc = 0;
my $pidfile = '';
my $port = 80;
my $quiet = 0;
my $realm = 'Foswiki';
my $trace = 0;
my $removeStatusLine = 0;

my $isOkay;
my $max;
my $size;
my $check;

my %options = (
    'listen|l=s'  => \$listen,
    'nproc|n=i'   => \$nproc,
    'max|x=i'     => \$max,
    'check|c=i'   => \$check,
    'size|s=i'    => \$size,
    'pidfile|p=s' => \$pidfile,
    'manager|M=s' => \$manager,
    'daemon|d'    => \$detach,
    'apache|ap'   => \$removeStatusLine,

    'host|h=s'        => \$host,
    'port=s'          => \$port,
    'location=s'      => \$location,
    'trace|t=i'       => \$trace,
    'filesystem|fs=s' => \$fs,
    'authrealm|ar=s'  => \$realm,

    'help|?'   => \$help,
    'quiet|q'  => \$quiet,

    '<>' => \&parseURL
    );

if (!scalar(@ARGV) && defined $ENV{WEBDAV_FCGI_OPTIONS}) {
    # No @ARGV but we've got an ENV
    $isOkay = Getopt::Long::GetOptionsFromString(
        $ENV{WEBDAV_FCGI_OPTIONS}, %options);
} else {
    # parse @ARGV
    my @argv = @ARGV;
    $isOkay = Getopt::Long::GetOptions(%options);
    @ARGV = @argv;
    undef @argv;
}

Pod::Usage::pod2usage(1) if $help || !$isOkay;

sub parseURL {
  my $arg = shift;
  if ($arg =~ m#^(?:[a-z]+://)?([^/:]+)(?::(\d+))?(/.*)?$#) {
      $host = $1;
      $port = $2 if defined $2;
      $location = $3 if defined $3;
  }
}

# Get a daemon, and dispatch the request
my $daemon = FCGI::FoswikiWebDAV->new(
    listen  => $listen,
    nproc   => $nproc,
    pidfile => $pidfile,
    manager => $manager,
    detach  => $detach,
    quiet   => $quiet,
    removeStatusLine => $removeStatusLine,
    max     => $max,
    size    => $size,
    check   => $check,

    filesys => 'Filesys::Virtual::' . $fs,
    trace => $trace,
    realm => $realm,
    location => $location
);

$daemon->run();

1;
__DATA__

=head1 SYNOPSIS

  webdav.fcgi [options] [url]

  This script is designed to be called from a web server using a FastCGI
  module, where you can pass parameters (for example, Lighttpd, Nginx).

  If you can't pass parameters from the web server configuration, you
  can 

  Options:
    -fs FS or --filesystem FS   set filesystem to Filesys::Virtual::FS (e.g. PlainPlusAttrs) default is Foswiki
    -t N or --trace N           set tracing to N
    -ar R or --authrealm R      set authrealm to R (default is Foswiki)
    -h HOST or --host HOST      set the server name (parsed off the URL if not set)
    -p PORT or --port PORT      set the server port (parsed off the URL if not set)
    --location LOCATION         set the url prefix on the server where the webdav directory is available

    -l --listen     Socket to listen on
    -n --nproc      Number of backends to use, defaults to 1
    -p --pidfile    File used to write pid to
    -M --manager    FCGI manager class
    -ap --apache    Enable special options for Apache
    -d --daemon     Detach from terminal and keeps running as a daemon
    -q --quiet      Disable notification messages
    -? --help       Display this help and exits

  url specifies the url we are serving, like this: http://server:8080/

  Note:
    FCGI manager class defaults to FCGI::FoswikiWebDAVProcManager, a
    wrapper around FCGI::ProcManager to enable automatic reload of 
    configurations if changed. If you provide another class, probably you'll 
    need to restart FastCGI processes manually.

  Options may also be passed in the environment variable WEBDAV_FCGI_OPTIONS
  (this will only be read if there are no arguments to the script)

=cut
