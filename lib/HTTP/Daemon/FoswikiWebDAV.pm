# See bottom of file for license, copyright, and documentation
package HTTP::Daemon::FoswikiWebDAV;
our @ISA = ('HTTP::WebDAV');

=begin TML

package HTTP::Daemon::FoswikiWebDAV

Tiny WebDAV server using HTTP::Daemon that is specific to serving
WebDAV requests. It requires no other web server support, and as such
has a very small footprint.
This is called from tools/http_daemon.pl

=cut

use strict;
use warnings;

our $VERSION = '3.0.0';

use HTTP::WebDAV ();    # base class

use HTTP::Daemon    ();
use Foswiki         ();
use HTTP::BasicAuth ();
use MIME::Base64;

our %mimeTypes;

# Constructor
sub new {
    my ( $class, %args ) = @_;
    my $this = $class->SUPER::new(%args);
    return $this;
}

sub run {
    my $this = shift;

    #$HTTP::Daemon::DEBUG = 1;
    my $daemon;

    do {
        local $| = 1;
        $daemon = HTTP::Daemon->new(
            LocalAddr => $this->{host},
            LocalPort => $this->{port},
            ReuseAddr => 1
        );
        unless ($daemon) {
            print STDERR '.';
            sleep 2;
        }
    } while ( !$daemon );

    $this->_trace(
        1,                 'HTTP::Daemon STARTED ON',
        $this->{host},     'port',
        $this->{port},     'at',
        $this->{location}, 'with filesystem',
        $this->{filesys}
    ) if $this->{trace};

    while ( my $client = $daemon->accept ) {
        my $pid = fork();

        # We are going to close the new connection on one of two conditions
        #  1. The fork failed ($pid is undefined)
        #  2. We are the parent ($pid != 0)
        if ( !defined $pid || $pid != 0 ) {
            $client->close();

            #print STDERR "Needs close: $pid\n";
            next;
        }

        # From this point on, we are the child.
        while ( my $request = $client->get_request ) {
            my $response = new HTTP::Response();
            my $status =
              $this->handleRequest( $request, $response,
                new HTTP::BasicAuth( $request, 'Foswiki' ) );
            $response->code($status);
            $client->send_response($response);
        }
        $client->close;
        undef($client);
    }
}

# Look up mime types DB to map a file extension to a mime type
# Overrides HTTP::WebDAV
sub getMimeTypesFile {
    return $Foswiki::cfg{MimeTypesFileName};
}

1;
__END__

Copyright (C) 2008-2015 WikiRing http://wikiring.com

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

Author: Crawford Currie http://c-dot.co.uk
