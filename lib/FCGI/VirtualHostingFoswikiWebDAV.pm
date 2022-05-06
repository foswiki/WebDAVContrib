# See bottom of file for license and copyright info
package FCGI::VirtualHostingFoswikiWebDAV;

use strict;
use warnings;

use Foswiki                                              ();
use Foswiki::Contrib::VirtualHostingContrib::VirtualHost ();
use FCGI::FoswikiWebDAV                                  ();

our @ISA = ('FCGI::FoswikiWebDAV');

sub handleRequest {
    my ( $this, $request, $response, $auth_provider ) = @_;

    my $host = $request->header("host");
    $host =~ s/:.*$//;    # strip off port

    my $status;
    Foswiki::Contrib::VirtualHostingContrib::VirtualHost->run_on(
        $host,
        sub {
            # change the process name during the request
            local $0 = sprintf( "foswiki-virtualhost-webdav[%s%s]",
                $host, $request->uri() );

            $status =
              $this->SUPER::handleRequest( $request, $response,
                $auth_provider );
        }
    );

    return $status;
}

1;

__END__

Copyright (C) 2013-2022 Foswiki Contributors

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

