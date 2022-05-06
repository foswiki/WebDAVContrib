# See bottom of file for license, copyright, and documentation
package Apache::FoswikiWebDAV;

use strict;
use warnings;

our @ISA = ('HTTP::WebDAV');

# WebDAV server using mod_perl

# Pull in base class
use HTTP::WebDAV ();

our $VERSION = '3.0.0';

use Apache2::Directive ();
use Apache2::Const     ();
use APR::UUID          ();

# Constructor
sub new {
    my $class = shift;
    my $this  = $class->SUPER::new(@_);
    return $this;
}

#
# Process the request. $requestRec is the Apache request object.
#
sub process {
    my ( $this, $requestRec ) = @_;

    # $requestRec is an Apache2::RequestRec, but HTTP::WebDAV uses the
    # HTTP::Request and HTTP::Response APIs, so we need to shim it.
    my $req    = Apache::FoswikiWebDAV::RequestShim->new($requestRec);
    my $rsp    = Apache::FoswikiWebDAV::ResponseShim->new($requestRec);
    my $status = $this->handleRequest( $req, $rsp, $req );
    $requestRec->status($status);

    return Apache2::Const::OK;
}

# get filesystem - overrides HTTP::WebDAV
sub getFilesys {
    my ( $this, $uri, $request ) = @_;

    my $module = $this->{module};
    my $path   = $module . '.pm';
    $path =~ s/::/\//g;
    eval { require $path } || die $@;
    my $webServerHandledAuth = $request->{rr}->some_auth_required();

    #print STDERR "Construct filesys ".($webServerHandledAuth||0)."\n";
    return $module->new(
        {
            location  => $this->{location},
            root_path => $this->{root_path},
            cwd       => '/',

            # If Apache required auth, then we don't
            # have to further validate the Foswiki login.
            validateLogin => !$webServerHandledAuth,

            # Pass trace bits to filesys
            trace => $HTTP::WebDAV::trace >> 4
        }
    );
}

# Look up mime types DB to map a file extension to a mime type
# - overrides HTTP::WebDAV
sub getMimeTypesFile {
    my $tree = Apache2::Directive::conftree();
    return $tree->lookup('TypesConfig');
}

# Create a UUID - overrides HTTP::WebDAV
sub createUUID {
    return APR::UUID->new->format;
}

# Wrap Apache2::RequestRec in a HTTP::Request/HTTP::Response-compatible shim
package Apache::FoswikiWebDAV::RequestShim;

sub new {
    my ( $class, $request ) = @_;

    # Get the content now to protect it from the Foswiki startup
    # process, which will attempt to suck it dry.
    # Note from Apache docs:
    #
    # "The $r->content method will return the entity body read
    #  from the client, but only if the request content type is
    #  application/x-www-form-urlencoded."
    #
    # Can't use $r->content() because the content type is text/xml, not
    # application/x-www-form-urlencoded
    my $content = '';
    my $length  = $request->headers_in->get('Content-Length');
    if ($length) {
        my $read = $request->read( $content, $length );

        # Die so we don't upload zero-sized content
        die "Failed to read request body" if !$read;
    }

    return bless( { rr => $request, content => $content }, $class );
}

sub as_string {
    my $this = shift;
    return $this->{rr}->as_string(@_);
}

sub user {
    my $this = shift;
    my $rr   = $this->{rr};

    if ( $rr->some_auth_required ) {

        # the request was authorised by the Apache server, so we don't
        # have to do any more.
        #print STDERR "User was authed by Apache\n";
        return ( $rr->user(@_) );
    }

    # Foswiki must validate the PW

    # The webserver didn't require a login, so see if we have a
    # BasicAuth header
    my ( $rc, $pw ) = $rr->get_basic_auth_pw;
    if ( $rc == Apache2::Const::OK ) {

        #print STDERR "We have Basic\n";
        return ( $rr->user(@_), $pw );
    }

    # Last ditch; try the remote logname (RFC1413)

    #print STDERR "Remote logname is ".($rr->get_remote_logname||'')."\n";
    return $rr->get_remote_logname;
}

sub method {
    shift->{rr}->method(@_);
}

sub header {
    my ( $this, $header ) = @_;
    return $this->{rr}->headers_in->get($header);
}

sub header_only {
    my $this = shift;
    return $this->{rr}->header_only(@_);
}

sub uri {
    return shift->{rr}->uri;
}

sub content {
    my $this = shift;
    return $this->{content};
}

sub auth_failed {
    my ( $this, $response ) = @_;

#    $response->header( 'WWW-Authenticate' => "Basic realm=\"$this->{realm}\"" );
}

package Apache::FoswikiWebDAV::ResponseShim;

sub new {
    my ( $class, $request ) = @_;
    return bless( { rr => $request }, $class );
}

sub as_string {
    my $this = shift;
    return $this->{rr}->as_string(@_);
}

sub header {
    my ( $this, $header, $set ) = @_;
    return $this->{rr}->headers_out->set( $header => $set );
}

sub content {
    my ( $this, $string ) = @_;
    $this->{rr}->print($string);
}

1;
__END__

Copyright (C) 2008-2015 WikiRing http://wikiring.com
Copyright (C) 2015-2022 Foswiki Contributors

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

Author: Crawford Currie http://c-dot.co.uk
