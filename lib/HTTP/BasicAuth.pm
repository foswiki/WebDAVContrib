# See bottom of file for license and copyright information
package HTTP::BasicAuth;

=begin TML

package HTTP::BasicAuth

Simple auth provider that uses Basic Auth to provide authentication support
for non-Apache webdav servers. Used by HTTP::Daemon::FoswikiWebDAV and
FCGI::FoswikiWebDAV

=cut

use strict;

use HTTP::Status qw(:constants);
use MIME::Base64 ();

our $VERSION = '1.0.0';

sub new {
    my ( $class, $req, $realm ) = @_;
    my $auth = $req->header('Authorization');
    my $this = bless( { realm => $realm }, $class );
    if ( $auth && $auth =~ /^Basic (.+)$/ ) {

        # Decode Basic Auth header
        ( $this->{user}, $this->{pass} ) =
          split( ':', MIME::Base64::decode_base64($1), 2 );
    }
    return $this;
}

=begin TML

ObjectMethod user() -> ( $user, $pass )

Determine user and password from basic auth header

=cut

sub user {
    my $this = shift;
    return ( $this->{user}, $this->{pass} );
}

=begin TML

ObjectMethod auth_failed($response)

Called when authentication information hasn't been verified, thus rejecting
the request.

=cut

sub auth_failed {
    my ( $this, $response ) = @_;

    $response->header( 'WWW-Authenticate' => "Basic realm=\"$this->{realm}\"" );
}

1;
__END__

Copyright (C) 2013-2015 WikiRing http://wikiring.com
Copyright (C) 2015-2025 Foswiki Contributors

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

Author: Crawford Currie http://c-dot.co.uk
