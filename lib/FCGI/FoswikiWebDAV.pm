# See bottom of file for license and copyright information
package FCGI::FoswikiWebDAV;

use strict;
use warnings;

our @ISA = ('HTTP::WebDAV');

=begin TML

WebDAV server using FCGI. Subclasses HTTP::WebDAV.
This is called from tools/webdav.fcgi

=cut

use FCGI;
use POSIX qw(:signal_h);
use HTTP::WebDAV    ();
use HTTP::BasicAuth ();
use Foswiki         ();
use Cwd ();

our $VERSION = '1.0.0';

sub new {
    my ( $class, %args ) = @_;
    my $this = $class->SUPER::new(%args);

    $this->{manager}     ||= 'FCGI::FoswikiWebDAVProcManager';
    $this->{nproc}       ||= 1;
    $this->{maxRequests} ||= 100;
    $this->{sock}        = 0;
    $this->{hupRecieved} = 0;
    $this->{removeStatusLine} = $args{removeStatusLine};

    if ( defined $this->{pidfile} ) {
        $this->{pidfile} =~ /^(.*)$/ and $this->{pidfile} = $1;
    }

    ($this->{script}) = $0         =~ /^(.*)$/;
    ($this->{dir})  = Cwd::cwd() =~ /^(.*)$/;

    return $this;
}

sub run {
    my $this = shift;

    if ( $this->{listen} ) {
        $this->{sock} = FCGI::OpenSocket( $this->{listen}, 100 )
          or die "Failed to create FastCGI socket: $!";
    }

    my $r = FCGI::Request( \*STDIN, \*STDOUT, \*STDERR, \%ENV, $this->{sock},
        &FCGI::FAIL_ACCEPT_ON_INTR );
    my $manager;

    if ($this->{listen}) {

        $this->fork() if $this->{detach};
        eval "use " . $this->{manager} . "; 1";
        unless ($@) {
            $manager = $this->{manager}->new(
                {
                    client => $this, 
                    n_processes => $this->{nproc},
                    pid_fname   => $this->{pidfile},
                    quiet       => $this->{quiet}
                }
            );
            $manager->pm_manage();
        }
        else {    # No ProcManager

            # ProcManager is in charge SIGHUP handling. If there is no manager,
            # we handle SIGHUP ourslves.
            eval {
                sigaction( SIGHUP,
                    POSIX::SigAction->new( sub { $this->{hupRecieved}++ } ) );
            };
            warn "Could not install SIGHUP handler: $@$!" if $@ || $@;
        }
        $this->daemonize() if $this->{detach};
    }

    my $localSiteCfg = $INC{'LocalSite.cfg'};
    die "LocalSite.cfg is not loaded - Check permissions or run configure\n"
      unless defined $localSiteCfg;

    my $lastMTime = ( stat $localSiteCfg )[9];

    while ( $r->Accept() >= 0 ) {
        $manager && $manager->pm_pre_dispatch();

        # Need handlers, or FCGI pumps these into the void
        $SIG{__WARN__} = sub { print STDERR "WARN ", @_ };
        $SIG{__DIE__}  = sub { print STDERR "DIE ",  @_ };

        # Pull in FCGI environment
        my $r = new HTTP::Request( $ENV{REQUEST_METHOD}, $ENV{REQUEST_URI} );

        foreach my $header ( keys %ENV ) {
            next unless $header =~ /^(?:HTTP|CONTENT|COOKIE)/i;
            ( my $field = $header ) =~ s/^HTTPS?_//;
            $r->header( $field => $ENV{$header} );
        }

        # Pull in content
        if ( my $bytes = $r->header('Content-Length') ) {
            my $content;
            my $read = read( STDIN, $content, $bytes );
            $r->content($content);
        }

        # Compose response
        my $response = new HTTP::Response();
        $response->protocol('HTTP/1.1');
        my $status =
          $this->handleRequest( $r, $response,
            new HTTP::BasicAuth( $r, $this->{realm} ) );

        # FCGI isn't happy with just the status line; it needs the
        # header field as well.
        $response->header( 'Status' => $status );
        $response->code($status);

        # Send response
        my $rs = $response->as_string();
        # Apache FCGID doesn't support NPH and can't parse off the header
        $rs =~ s/^HTTP.*?\n//s if $this->{removeStatusLine};
        print $rs;

        # check lifetime conditions
        my $mtime = ( stat $localSiteCfg )[9];
        $this->{maxRequests}--;
        if (   $mtime > $lastMTime
            || $this->{hupRecieved}
            || $this->{maxRequests} == 0 )
        {
            $r->LastCall();
            if ($manager) {
                kill SIGHUP, $manager->pm_parameter('MANAGER_PID');
            }
            else {
                $this->{hupRecieved}++;
            }
        }
        $manager && $manager->pm_post_dispatch();
    }

    $this->reExec if $this->{hupRecieved} || $this->{maxRequests} == 0;
    $this->closeSocket;
}

# Look up mime types DB to map a file extension to a mime type
# Overrides HTTP::WebDAV
sub getMimeTypesFile {
    return $Foswiki::cfg{MimeTypesFileName};
}

sub closeSocket {
    my $this = shift;
    return unless $this->{sock};
    FCGI::CloseSocket( $this->{sock} );
    $this->{sock} = 0;
}

sub reExec {
    my $this = shift;

    $this->closeSocket;

    require Config;
    $ENV{PERL5LIB} .= join $Config::Config{path_sep}, @INC;
    $ENV{PATH} = $Foswiki::cfg{SafeEnvPath};
    my $perl = $Config::Config{perlpath};

    chdir $this->{dir}
      or die
      "FCGI::FoswikiWebDAV::reExec(): Could not restore directory: $!";

    exec $perl, '-wT', $this->{script}, map { /^(.*)$/; $1 } @ARGV
      or die "FCGI::FoswikiWebDAV::reExec(): Could not exec(): $!";
}

sub fork () {

    ### block signal for fork
    my $sigset = POSIX::SigSet->new(SIGINT);
    POSIX::sigprocmask( SIG_BLOCK, $sigset )
      or die "Can't block SIGINT for fork: [$!]\n";

    ### fork off a child
    my $pid = fork;
    unless ( defined $pid ) {
        die "Couldn't fork: [$!]\n";
    }

    ### make SIGINT kill us as it did before
    $SIG{INT} = 'DEFAULT';

    ### put back to normal
    POSIX::sigprocmask( SIG_UNBLOCK, $sigset )
      or die "Can't unblock SIGINT for fork: [$!]\n";

    $pid && exit;

    return $pid;
}

sub daemonize {
    umask(0);
    chdir File::Spec->rootdir;
    open STDIN,  File::Spec->devnull or die $!;
    open STDOUT, ">&STDIN"           or die $!;
    open STDERR, ">&STDIN"           or die $!;
    POSIX::setsid();
}

1;
__END__

Copyright (C) 2013-2015 WikiRing http://wikiring.com

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

Author: Crawford Currie http://c-dot.co.uk