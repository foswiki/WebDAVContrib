# HTTP::WebDAVAuth is Copyright (C) 2015-2025 Foswiki Contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details, published at
# http://www.gnu.org/copyleft/gpl.html

package HTTP::WebDAVAuth;

=begin TML

package HTTP::WebDAVAuth

Auth provider that combines different authentication schemes in one

=cut

use strict;
use warnings;

use HTTP::Status qw(:constants);
use MIME::Base64 ();
use Encode       ();

use constant TRACE => 0;
our $GSSAPI_ENABLED = 0;

BEGIN {
    eval 'use GSSAPI ()';
    $GSSAPI_ENABLED = 1 unless $@;
}

sub new {
    my ( $class, $req, $realm ) = @_;

    my $auth = $req->header('Authorization');
    my $this = bless( { realm => $realm }, $class );

    writeDebug("new WebDAVAuth for realm $realm");
    writeDebug( "req=" . $req->as_string );
    $this->{type} = 'unknown';

    if ( defined $ENV{REMOTE_USER} && $ENV{REMOTE_USER} ne '' ) {
        $this->{type} = 'remote_user';

        $this->{user} = Encode::decode_utf8( $ENV{REMOTE_USER} );
        $this->{pass} = "";
        writeDebug("...found remote user '$this->{user}'");
    }
    elsif ($auth) {

        if ( $auth =~ /^Basic (.+)$/ ) {
            my $token = $1;
            writeDebug("...found basic auth header");

            # Decode Basic Auth header

            $this->{type} = "basic";

            ( $this->{user}, $this->{pass} ) =
              split( ':', MIME::Base64::decode_base64($token), 2 );

            $this->{user} = $this->{user};
            $this->{pass} = $this->{pass};
            writeDebug("...found basic auth user $this->{user}");
        }
        elsif ( $GSSAPI_ENABLED && $auth =~ /^Negotiate (.*)$/ ) {
            my $token = $1;
            writeDebug("...found token in header");
            if ( $token =~ /^TlRMT/ ) {
                writeDebug("...but it is an NTLM token, setting failure state");
            }
            else {

                my $keytabFile = $Foswiki::cfg{Ldap}{KerberosKeyTab};
                if (  !$keytabFile
                    && $Foswiki::cfg{PluggableAuth}{Providers}{Kerberos}
                    {Enabled} )
                {
                    $keytabFile =
                      $Foswiki::cfg{PluggableAuth}{Providers}{Kerberos}{KeyTab};
                }

                if ( $keytabFile && -r $keytabFile ) {
                    $ENV{KRB5_KTNAME} = "FILE:$keytabFile";

                    # Decode Kerberos Auth header
                    $this->{krbToken} = MIME::Base64::decode_base64($token);
                    $this->{type}     = "kerberos";
                }
                else {
                    writeDebug("keytab not defined or not readable");
                }
            }
        }
    }
    else {
        writeDebug("... no auth header");
    }

    return $this;
}

=begin TML

ObjectMethod user() -> ( $user, $pass )

Determine user and password from basic auth header

=cut

sub user {
    my $this = shift;

    writeDebug( "called user() - user=" . ( $this->{user} // 'undef' ) );
    return ( $this->{user}, $this->{pass} ) if defined $this->{user};

    $this->{user} = $this->getUserFromKerberos() if $GSSAPI_ENABLED;

    return ( $this->{user} );
}

sub getUserFromKerberos {
    my $this = shift;

    unless ( defined $this->{krbToken} ) {
        writeDebug("no krbToken");
        return;
    }

    my $status;
    my $context;
    my $error;
    my $user;

    no strict;
  TRY: {

        writeDebug("calling accept context");
        $status = GSSAPI::Context::accept(
            $context,             GSS_C_NO_CREDENTIAL,
            $this->{krbToken},    GSS_C_NO_CHANNEL_BINDINGS,
            my $src_name,         undef,
            my $gss_output_token, undef,
            undef,                undef
        );

        # bail out on error
        if ( GSSAPI::Status::GSS_ERROR( $status->major ) ) {
            $error = "Unable to accept security context";
            last;
        }

        writeDebug("getting client name");
        $status = $src_name->display($user);

        # bail out on error
        if ( GSSAPI::Status::GSS_ERROR( $status->major ) ) {
            $error = "Unable to display client name";
            last;
        }

        if ($user) {
            $user =~ s/@.*//;    # strip off domain

            writeDebug( "user=" . ( $user || '' ) );
        }
    }
    use strict;

    writeDebug( "ERROR: $error" . _getStatusMessage($status) ) if $error;

    return $user;
}

=begin TML

ObjectMethod auth_failed($response)

Called when authentication information hasn't been verified, thus rejecting
the request.

=cut

sub auth_failed {
    my ( $this, $response ) = @_;

    writeDebug("called auth_failed");

    if ( $this->{type} eq 'kerberos' ) {
        writeDebug("... kerberos");
        $response->header(
            -status            => 401,
            'WWW-Authenticate' => 'Negotiate'
        );
    }
    else {
        writeDebug("... basic auth");
        $response->header(
            -status            => 401,
            'WWW-Authenticate' => "Basic realm=\"$this->{realm}\""
        );
    }
}

sub _getStatusMessage {
    my $status = shift;

    my $text = " - MAJOR: " . join( ", ", $status->generic_message() );
    $text .= " - MINOR: " . join( ", ", $status->specific_message() );

    return $text;
}

sub writeDebug {
    return unless TRACE;
    print STDERR "- WebDAVAuth - $_[0]\n";
}

1;
