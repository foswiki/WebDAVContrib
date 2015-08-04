# See bottom of file for license and copyright info
package FCGI::FoswikiWebDAVProcManager;

use strict;
use warnings;

use FCGI::ProcManager::Constrained;
our @ISA = qw( FCGI::ProcManager::Constrained );

sub sig_manager {
    my $this = shift;

    $this->SUPER::sig_manager(@_);
    $this->{client}{hupRecieved}++;
    $this->n_processes(0);
}

sub pm_die {
    my ( $this, $msg, $n ) = @_;

    $msg ||= '';    # protect against error in FCGI.pm

    if ( $this->{client}{hupRecieved} ) {
        $this->{client}->reExec;
    }
    else {
        $this->SUPER::pm_die( $msg, $n );
    }
}

sub pm_notify {
    my ( $this, $msg ) = @_;

    return if $this->{quiet};
    $this->SUPER::pm_notify($msg);
}

sub pm_change_process_name {
    my ( $this, $name ) = @_;

    $name =~ s/perl/foswiki-dav/g;
    $0 = $name;
}

1;

__END__

Copyright (C) 2013-2015 Foswiki Contributors

This program is licensed to you under the terms of the GNU General
Public License, version 2. It is distributed in the hope that it will
be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.

