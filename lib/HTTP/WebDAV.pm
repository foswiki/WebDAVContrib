# See bottom of file for license, copyright, and documentation
package HTTP::WebDAV;

# Common WebDAV handling, written so that different web server
# implementations can make use of it. To use it, subclass it and
# call handleRequest to deal with incoming requests. handleRequest
# will fill in the response and return a status; it is up to the
# subclass to deliver that back to the client.
#
# Unless otherwise indicated, section references in comments e.g. (8.1.3)
# relate to http://www.webdav.org/specs/rfc2518.html

use strict;
use warnings;

our $VERSION = '1.0.1';
our $RELEASE = '10 May 2015';

use HTTP::Status qw(:constants status_message);
use Encode ();
use POSIX qw(:errno_h);
use XML::LibXML                        ();
use File::Find::Rule::Filesys::Virtual ();
use URI::Escape                        ();
use URI                                ();

our $XMLParser;
our $filesys;
our $outdoc;
our $typesConfig;
our %mimeTypes;

our @ISOMONTH = (
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
);

our @WEEKDAY = ( 'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun' );

# The list of properties in the order a stat() call returns.
my @STAT_PROPERTIES = qw(dev ino mode nlink uid gid rdev
  getcontentlength atime getlastmodified
  creationdate);

# methods defined by WebDAV. Not all of these are implemented.
my @METHODS = qw( COPY DELETE GET HEAD MKCOL MOVE OPTIONS POST PROPFIND
  PUT PROPPATCH LOCK UNLOCK );

# The list of live properties specified by RFC4918
my %default_props = map { ( '{DAV:}' . $_ => 1 ) } (
    'creationdate',       'displayname',
    'getcontentlanguage', 'getcontentlength',
    'getcontenttype',     'getetag',
    'getlastmodified',    'lockdiscovery',
    'resourcetype',       'supportedlock'
);

our $trace = 0;

sub T_ERROR    { $trace & 0x01 } # log errors
sub T_REQUEST  { $trace & 0x02 } # log XML in requests
sub T_ACTION   { $trace & 0x04 } # log action processing
sub T_RESPONSE { $trace & 0x08 } # log XML responses
sub T_MEMORY   { $trace & 0x10 } # memory usage
sub T_AUTH     { $trace & 0x20 } # Authentication

sub new {
    my ( $class, %args ) = @_;

    $trace = $args{trace} || 0;
    require Devel::Leak if T_MEMORY;

    return bless( {%args}, $class );
}

# Reusable (static) XML parser
sub _XMLParser {
    $XMLParser ||= XML::LibXML->new();
    return $XMLParser;
}

# Handle an HTTP request
#    * =$request= - an HTTP::Request. The following methods are used:
#       method(get), header (get), uri(get), content(get)
#    * =$response= - an HTTP::Response. The following methods are used:
#       header(set), content(set)
sub handleRequest {
    my ( $this, $request, $response, $auth_provider ) = @_;

    my $uri    = Encode::decode_utf8(
	URI::Escape::uri_unescape( $request->uri() ) );
    my $method = uc( $request->method() );

    my $memHandle;
    _trace('------------------------') if $trace;
    _trace( 'START MEM', $method, Devel::Leak::NoteSV($memHandle) ) if T_MEMORY;

    # Local for thread safety
    local $outdoc    = undef;
    local $XMLParser = undef;

    my $status = HTTP_BAD_REQUEST;

    $typesConfig ||= $this->getMimeTypesFile();

    if ( $this->can($method) ) {

        # Protect the request body from Foswiki, which wipes it when it is
        # initialised during login (I think it's actually a CGI problem,
        # but in our tests it only manifests with TWiki)
        my $content;
        my $length = $request->header('Content-Length');
        if ( defined $length && $length =~ /(\d+)/ ) {
            if ( $1 > 0 ) {
                $content = $request->content();
            }
            else {
                $content = '';
            }
        }

        _trace( $method, $uri ) if $trace;
        _trace( $request ) if T_REQUEST;

        local $filesys = $this->getFilesys( $uri, $request );

        # Don't auth OPTIONS or M$ Office won't be able to talk to us (it
        # doesn't send auth headers with OPTIONS)
        if (   $method eq 'OPTIONS'
            || $this->_processAuth( $request, $response, $auth_provider ) )
        {

            eval { $status = $this->$method( $uri, $request, $response, $content ); };
            if ($@) {
                _trace("Error: $@") if T_ERROR;
                $status = HTTP_BAD_REQUEST;
            }

            _trace( 'DAV:', '<-', $status, '-', $method, $uri ) if $trace;
        }
        else {
            $status = HTTP_UNAUTHORIZED;
        }
    }

    _trace( 'END MEM', $method, Devel::Leak::NoteSV($memHandle) ) if T_MEMORY;

    return $status;
}

sub PROPPATCH {
    my ( $this, $path, $request, $response, $content ) = @_;

    # Don't need the content, unless for debug
    #my $content = $this->_getContent($request);

    if ( $this->_isLockNullResource($path) ) {
        _trace('Error: Lock-null') if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    my @errors = $this->_checkLocksAreSubmitted( $request, 0, 0, $path );
    if ( scalar(@errors) ) {
        return $this->_emitErrors( $request, $response, @errors );
    }

    my $indoc = _XMLParser->parse_string($content);
    if ( !$indoc ) {
        _trace('Error: No document') if T_ERROR;
        return HTTP_BAD_REQUEST;
    }
    if ( _hasNullNamespace($indoc) ) {
        _trace('Error: Null namespace') if T_ERROR;
        return HTTP_BAD_REQUEST;
    }

    my $multistat = _xml_new_reply('D:multistatus');
    my $xml = _xml_add_element( $multistat, 'D:response' );
    _xml_add_href( $xml, $path, 1 );

    my $pud = _firstChildNode($indoc);
    if ( _fullName($pud) ne '{DAV:}propertyupdate' ) {
        _trace('Error: propertyupdate expected') if T_ERROR;
        return HTTP_BAD_REQUEST;
    }

    my %statuses;
    for ( my $node = $pud->firstChild ; $node ; $node = $node->nextSibling ) {
        next unless ( $node->nodeType == 1 );
        my $method = _fullName($node);
        $method =~ s/^{DAV:}(set|remove)$/$1/;
        my $fn = $method . 'xattr';

        for ( my $prop = $node->firstChild ;
            $prop ; $prop = $prop->nextSibling )
        {
            next
              unless ( $prop->nodeType == 1
                && _fullName($prop) eq '{DAV:}prop' );
            my $pnode = _firstChildNode($prop);
            next unless $pnode;
            my $k = _fullName($pnode);
            my $v;
            if ( $pnode->firstChild ) {
                $v = $pnode->firstChild->nodeValue;
            }
            _trace( $method, $k,
                $method eq 'set' ? ( defined $v ? $v : "UNDEFINED" ) : '' )
              if T_ACTION;
            my $status = $filesys->$fn( $path, $k, $v );
            my $ns;
            my $newprop = $outdoc->createElement('D:prop');
            _xml_add_propel( $newprop, $k );
            $status = $status ? HTTP_FORBIDDEN : HTTP_OK;
            push( @{ $statuses{$status} }, $newprop );
        }
    }
    $this->_xml_add_propstat( $response, $xml, %statuses );

    _emitBody( $response, $outdoc->toString(0) );

    return HTTP_OK;
}

sub COPY {
    my ( $this, $path, $request, $response ) = @_;

    if ( $this->_isLockNullResource($path) ) {
        _trace('Error: Lock-null') if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    my $destination = $request->header('Destination');
    my $depth       = $request->header('Depth');
    my $overwrite   = uc( $request->header('Overwrite') || 'T' ) eq 'T';

    $destination =
      Encode::decode_utf8(
        URI::Escape::uri_unescape( URI->new($destination)->path() ) );

    _trace( 'COPY', $path, 'to', $destination ) if T_ACTION;

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    my @errors = $this->_checkLocksAreSubmitted( $request, 1, 0, $destination );
    if ( scalar(@errors) ) {
        return $this->_emitErrors( $request, $response, @errors );
    }

    # Plain files just get copied
    if ( $filesys->test( 'f', $path ) ) {

        # If the destination already exists and it's a directory,
        # we can't proceeed
        if ( $filesys->test( 'd', $destination ) ) {
            _trace( 'Error: Destination exists and is a dir', $destination ) if T_ERROR;
            return HTTP_NO_CONTENT;    # litmus/spec requires this...
        }

        if ( !$filesys->test( 'r', $path ) ) {
            _trace( 'Error: Source not readable', $path ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }

        # HTTP_PRECONDITION_FAILED return code specified by the litmus test
        if ( $filesys->test( 'e', $destination ) && !$overwrite ) {
            _trace( 'Error: Precondition failed', $destination ) if T_ERROR;
            return HTTP_PRECONDITION_FAILED;    # Precondition Failed?
        }

        # Finally, read the source file.
        my $fh = $filesys->open_read($path);
        my $contents = join '', <$fh>;
        $filesys->close_read($fh);

        # And write the destination file
        $fh = $filesys->open_write($destination);

        # Picked the 409 code because that's what the
        # litmus test says I should put here.
        if ( !$fh ) {
            _trace( 'Error: Cannot open the destination', $destination ) if T_ERROR;
            return HTTP_CONFLICT;    # huh?
        }

        print $fh $contents;
        if ( my $e = $filesys->close_write($fh) ) {
            _trace( 'Error: Cannot close the destination', $destination, $e ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }

        _duplicateAttrs( $path, $destination );

        return HTTP_CREATED;
    }

    # Otherwise, we're copying a collection.
    # The logic for this was taken from Net::DAV::Server.

    # 100 directory levels is as good as infinite
    $depth = 100 if defined($depth) && $depth =~ /^infinit/;

    # Find source files that we have to copy
    my @files =
      map { s|/+|/|g; $_ }    # simplify // to /
      File::Find::Rule::Filesys::Virtual->virtual($filesys)
      ->file->maxdepth($depth)->in($path);

    # Find source directories that we have to copy
    my @dirs = reverse sort
      map { s|/+|/|g; $_ }    # simplify // to /
      grep { $_ !~ m|/\.\.?$| }    # exclude /. and /..
      File::Find::Rule::Filesys::Virtual->virtual($filesys)
      ->directory->maxdepth($depth)->in($path);

    push @dirs, $path;

    # Create directories
    foreach my $dir ( sort @dirs ) {
        my $dest_dir = $dir;

        $dest_dir =~ s/^$path/$destination/;

        if ( $filesys->test( 'e', $dest_dir ) ) {
            if ($overwrite) {
                $this->_unlink($dest_dir);
            }
            else {
                _trace( 'Error: Destination dir already exists', $dest_dir ) if T_ERROR;
                return HTTP_UNAUTHORIZED;
            }
        }

        if ( !$filesys->mkdir($dest_dir) ) {
            _trace( 'Error: Failed to make dir', $dest_dir, $! ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }

        # If there are no files, we need to properly return from here.
        if ( !scalar(@files) ) {
            return HTTP_CREATED;
        }
        _duplicateAttrs( $dir, $dest_dir );
    }

    # Copy files
    local $/;    # ignore line terminations
    foreach my $file ( reverse sort @files ) {
        my $dest_file = $file;

        $dest_file =~ s/^$path/$destination/;

        my $fh       = $filesys->open_read($file);
        my $contents = <$fh>;
        $filesys->close_read($fh);

        # Don't write if the file exists and overwrite is FALSE
        if ( $filesys->test( 'e', $dest_file ) ) {
            if ($overwrite) {
                $this->_unlink($dest_file);
            }
            else {
                _trace( 'Error: File exists and !overwrite', $dest_file ) if T_ERROR;
                return HTTP_UNAUTHORIZED;
            }
        }

        # Write the new file
        $fh = $filesys->open_write($dest_file);
        print $fh $contents;
        if ( my $e = $filesys->close_write($fh) ) {
            _trace( 'Error: Cannot close_write', $dest_file, $e ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }

        _duplicateAttrs( $file, $dest_file );
    }

    return HTTP_CREATED;
}

sub _duplicateAttrs {
    my ( $path, $destination ) = @_;

    # Duplicate properties
    foreach my $attr ( $filesys->listxattr($path) ) {
        $filesys->setxattr( $destination, $attr,
            $filesys->getxattr( $path, $attr ) );
    }
}

sub DELETE {
    my ( $this, $path, $request, $response ) = @_;

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    return $this->_DELETE( $path, $request, $response );
}

sub _DELETE {
    my ( $this, $path, $request, $response ) = @_;

    unless ( $filesys->test( 'e', $path ) ) {
        _trace( 'Error: Cannot find', $path, $! ) if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    # Get a list of all files affected by the delete request (we have to do
    # them one by one).  The ->in() method gets a list of all files under the
    # specified path recursively.
    my @files =
      grep { $_ !~ m|/\.\.?$| }    # Filter . and ..
      map { s|/+|/|g; $_ }         # Simplify // to /
      File::Find::Rule::Filesys::Virtual->virtual($filesys)->in($path), $path;

    _trace( "Deleting ($path) = " . join( "\n", @files ) ) if T_ACTION;

    if ( $this->_isLockNullResource(@files) ) {
        _trace('Error: Lock-null') if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    my @errors = $this->_checkLocksAreSubmitted( $request, 1, 0, @files );
    if ( scalar(@errors) ) {
        return $this->_emitErrors( $request, $response, @errors );
    }

    # RFC4918: A server processing a successful DELETE request:
    # must destroy locks rooted on the deleted resource.
    # All locks on deleted resource should be removed

    my %did;
    unless ( scalar(@errors) ) {
        %did = ();
        foreach my $file (@files) {
            next if $did{$file};
            $did{$file} = 1;
            foreach my $lock ( $filesys->get_locks( $path, -1 ) ) {
                $filesys->remove_lock( $lock->{token} );
            }
            if ( $filesys->test( 'e', $file ) ) {
                my $stat = $this->_unlink($file);
                _trace( 'Error: Unlink failed:', $file, $! ) if T_ERROR && !$stat;
            }
        }
    }

    if ( !scalar(@errors) ) {
        return HTTP_NO_CONTENT;    # 204
    }

    # SMELL: (tip from CPAN:Apache::WebDAV) "WebDrive doesn't properly parse
    # HTTP_MULTI_STATUS multistatus responses for deletes.  So if it's
    # webdrive, just send a generic error code.  I know this sucks.
    #
    # Here is the response from their tech support:
    #
    # webdrive is not parsing the HTTP_MULTI_STATUS multistatus
    # response to look for the error code.  If the DELETE returns
    # an HTTP error like HTTP_FORBIDDEN instead of HTTP_MULTI_STATUS
    # then webdrive would recognize the error.  Webdrive should parse
    # the response but currently it doesn't for the DELETE command.
    # It's nothing you are doing wrong, it's just something that
    # wasn't fully implemented with webdrive and the delete command."
    return HTTP_FORBIDDEN if _clientIs( 'WebDrive', $request );

    # Otherwise return a HTTP_MULTI_STATUS
    return $this->_emitErrors( $request, $response, @errors );
}

sub GET {
    my ( $this, $path, $request, $response ) = @_;

    if ( $this->_isLockNullResource($path) ) {
        _trace('Error: Lock-null') if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    if ( !$filesys->test( 'r', $path ) ) {
        _trace( 'Error: Cannot read', $path ) if T_ERROR;
        return HTTP_FORBIDDEN;
    }

    # If the requested path is a readable file, use the Filesys::Virtual
    # interface to read the file and send it back to the client.
    if ( $filesys->test( 'f', $path ) ) {
        $response->header( 'Last-Modified' => '' . $filesys->modtime($path) );

        my $fh = $filesys->open_read($path);
        if ( !$fh ) {
            if ( $! == POSIX::ENOLCK ) {
                _trace( 'Error: Cannot lock', $path ) if T_ERROR;
                return HTTP_LOCKED;
            }
            elsif ( $! == POSIX::EACCES ) {
                _trace( 'Error: Cannot access', $path ) if T_ERROR;
                return HTTP_UNAUTHORIZED;
            }
            elsif ( $! == POSIX::ENOENT ) {
                _trace( 'Error: No such', $path ) if T_ERROR;
                return HTTP_UNPROCESSABLE_ENTITY;
            }
            elsif ( $! == POSIX::ENOTEMPTY ) {
                _trace( 'Error: Not empty', $path ) if T_ERROR;
                return HTTP_UNPROCESSABLE_ENTITY;
            }
            _trace( 'Error: Forbidden', $path ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }

        local $/;
        my $file = <$fh>;

        $filesys->close_read($fh);

        _emitBody( $response, $file, type => _deduceMimeType($path), no_conversion => 1 );

        _add_etag( $response, $path );

        return HTTP_OK;
    }

    # (8.4) The semantics of GET are unchanged when applied to a collection,
    # since GET is defined as, "retrieve whatever information (in the form
    # of an entity) is identified by the Request-URI" [RFC2068]. GET when
    # applied to a collection may return the contents of an "index.html"
    # resource, a human-readable view of the contents of the collection, or
    # something else altogether.
    if ( $filesys->test( 'd', $path ) ) {
        my $body = $filesys->list_details($path);
        _emitBody( $response, $body, type => 'text/html' );
        return HTTP_OK;
    }

    _trace( 'Error: Cannot find', $path ) if T_ERROR;
    return HTTP_NOT_FOUND;
}

sub HEAD {
    my ( $this, $path, $request, $response ) = @_;

    if ( !$filesys->test( 'e', $path ) ) {
        _trace( 'Error: Does not exist', $path ) if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    if ( $this->_isLockNullResource($path) ) {
        _trace( 'Error: Lock-null', $path ) if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    if ( $filesys->test( 'd', $path ) ) {

        # Collection
    }
    else {

        # Plain file
        $response->header( 'Last-Modified' => '' . $filesys->modtime($path) );

        _add_etag( $response, $path );
    }

    return HTTP_OK;
}

sub MKCOL {
    my ( $this, $path, $request, $response, $content ) = @_;

    if ( $filesys->test( 'e', $path ) ) {
        _trace( 'Error: Already exists', $path ) if T_ERROR;
        return HTTP_METHOD_NOT_ALLOWED;
    }
    if ($content) {
        return HTTP_UNSUPPORTED_MEDIA_TYPE;
    }

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    # There make be Lock-Nulls
    my @errors = $this->_checkLocksAreSubmitted( $request, 0, 0, $path );
    if ( scalar(@errors) ) {
        return $this->_emitErrors( $request, $response, @errors );
    }

    unless ( $filesys->mkdir($path) ) {
        _trace( 'Error: Failed to create', $path, $! ) if T_ERROR;
        return HTTP_CONFLICT;    # What?
    }

    return HTTP_CREATED;
}

sub MOVE {
    my ( $this, $path, $request, $response ) = @_;

    $path =~ s#/$##;

    if ( $this->_isLockNullResource($path) ) {
        _trace( 'Error: Lock-null', $path ) if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    my $destination = $request->header('Destination');
    $destination =
      Encode::decode_utf8(
        URI::Escape::uri_unescape( URI->new($destination)->path() ) );
    $destination =~ s#/$##;

    _trace( "MOVE ", $path, " to ", $destination ) if T_ACTION;

    my $overwrite = uc( $request->header('Overwrite') || 'T' ) eq 'T';
    my $status = HTTP_CREATED;

    if ( $filesys->test( 'e', $destination ) ) {

        # Already exists
        if ($overwrite) {

            # delete the target first - this will check the locks
            $this->_DELETE( $destination, $request, $response );
            $status = HTTP_NO_CONTENT;
        }
        else {
            _trace( 'Error: Target exists', $destination ) if T_ERROR;
            return HTTP_PRECONDITION_FAILED;
        }
    }

    # Check locks recursively
    my @errors =
      $this->_checkLocksAreSubmitted( $request, 1, 0, $path, $destination );
    if ( scalar(@errors) ) {
        _trace("Warning: Recursive lock check failed") if T_ERROR;
        return $this->_emitErrors( $request, $response, @errors );
    }

    unless ( $filesys->can('rename') ) {
        _trace("Warning: Filesys can't rename") if T_ERROR;

        # Rename not supported by the handler, or renaming to a different
        # handler. Perform a copy and then a delete, something that makes
        # sense but has specific drawbacks according to the WebDAV book.
        my $copy_result = $this->COPY($path, $request);

        if ( $copy_result >= 300 ) {
            _trace( $path, $destination, 'copy', $copy_result ) if T_ACTION;
            if ( $copy_result == HTTP_PRECONDITION_FAILED ) {
                return $copy_result;
            }
            elsif ( $copy_result == HTTP_NO_CONTENT ) {

                # Directory already existed
                return HTTP_FORBIDDEN;
            }
            else {
                return HTTP_FORBIDDEN;
            }
        }

        unless ( $filesys->test( 'e', $path ) ) {
            _trace( 'Error:', $path, 'does not exist' ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }

        if ( $filesys->test( 'd', $path ) ) {
            my @files =
              map { s|/+|/|g; $_ }
              grep { $_ !~ m|/\.\.?$| }
              File::Find::Rule::Filesys::Virtual->virtual($filesys)->in($path),
              $path;

            foreach my $file (@files) {
                if ( $filesys->test( 'e', $file ) ) {
                    $this->_unlink($file);
                }
            }
        }
        elsif ( !$filesys->delete($path) ) {
            _trace( 'Error: delete', $path, 'failed:', $! ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }
    }
    else {

        # rename supported in the handler. Note: the handler is
        # expected to move the properties as well.
        if ( !$filesys->test( 'r', $path ) ) {
            _trace( 'Error:', $path, 'is not readable' ) if T_ERROR;
            return HTTP_FORBIDDEN;
        }
        if ( !$filesys->rename( $path, $destination ) ) {
            if ( $! == POSIX::ENOLCK ) {
                _trace( 'Error:', $path, 'is locked' ) if T_ERROR;
                return HTTP_LOCKED;
            }
            _trace( 'Error:', $path, 'rename', $path, 'failed;', $! ) if T_ERROR;
            return HTTP_UNPROCESSABLE_ENTITY;
        }
    }

    return $status;
}

sub OPTIONS {
    my ( $this, $path, $request, $response ) = @_;

    $response->header(
        'Allow' => join( ',', grep { $this->can($_) } @METHODS ) );
    $response->header( 'DAV' => '1,2,<http://apache.org/dav/propset/fs/1>' );
    $response->header( 'MS-Author-Via' => 'DAV' );
    $response->header( 'Keep-Alive'    => 'timeout=15, max=96' );

    return HTTP_OK;
}

sub PROPFIND {
    my ( $this, $path, $request, $response, $content ) = @_;
    my $depth = $request->header('Depth');

    $depth = 'infinity' unless defined $depth;    # (9.1)

    # Make sure the resource exists
    if ( !$filesys->test( 'e', $path ) ) {
        _trace( 'Error: Resource does not exist', $path ) if T_ERROR;
        return HTTP_NOT_FOUND;
    }

    my @files;

    if ( $depth == 0 ) {
        @files = ($path);
    }
    elsif ( $depth == 1 ) {
        $path =~ s/\/$//;    # strip trailing slash, we don't store it in the db

        @files = $filesys->list($path);

        # remove . and .. from the list
        @files = grep( $_ !~ /^\.\.?$/, @files );

        # Add a trailing slash to the directory if there isn't one already
        if ( $path !~ /\/$/ ) {
            $path .= '/';
        }

        # Depth 1 also contains the container itself.
        # Otherwise an empty directory is not found.
        push( @files, '' );

        # Add the current folder to the front of the filename
        @files = map { $path . $_ } @files;

        my %seen = map { $_ => 1 } @files;

        # (7.4) Add lock-null resources. These are resources that have locks,
        # but don't exist in the filesystem.
        my @locks =
          map { $_->{path} }
          grep { !$seen{ $_->{path} } && $_->{path} =~ m#^$path/*[^/]+$# }
          $filesys->get_locks( $path, -1 );

        _trace( "Lock-nulls: ", @locks ) if T_ACTION;

        push( @files, @locks );
    }

    # (9.1) A client may choose not to submit a request body. An empty
    # PROPFIND request body MUST be treated as if it were an 'allprop' request.

    my $mode = '';
    my %named;
    if ($content) {

        my $indoc = _XMLParser->parse_string($content);

        if ( !$indoc ) {
            _trace('Error: No document') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }
        if ( _hasNullNamespace($indoc) ) {
            _trace('Error: Null namespace') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }
        my $fc = _firstChildNode($indoc);
        if ( _fullName($fc) ne '{DAV:}propfind' ) {
            _trace('Error: Not propfind') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }

        for ( my $node = $fc->firstChild ; $node ; $node = $node->nextSibling )
        {
            next unless ( $node->nodeType == 1 );
            if ( _fullName($node) eq '{DAV:}allprop' ) {
                if ($mode) {    # (14.20)
                    _trace( 'Error: allprop and', $mode, 'together' ) if T_ERROR;
                    return HTTP_BAD_REQUEST;
                }
                $mode = 'allprop';
            }
            elsif ( _fullName($node) eq '{DAV:}include' ) {
                if ( $mode ne 'allprop' ) {    # (14.20)
                    _trace( 'Error: include and', $mode, 'together' ) if T_ERROR;
                    return HTTP_BAD_REQUEST;
                }
                my $prop = $node->firstChild;
                while ($prop) {
                    if ( $prop->nodeType == 1 ) {
                        my $name = _fullName($prop);
                        $named{$name} = 1;
                    }
                    $prop = $prop->nextSibling;
                }
            }
            elsif ( _fullName($node) eq '{DAV:}propname' ) {
                if ($mode) {    # (14.20)
                    _trace( 'Error: propname and', $mode, 'together' ) if T_ERROR;
                    return HTTP_BAD_REQUEST;
                }
                return HTTP_BAD_REQUEST if $mode;    # (14.20)
                $mode = 'propname';
            }
            elsif ( _fullName($node) eq '{DAV:}prop' ) {
                if ($mode) {                         # (14.20)
                    _trace( 'Error: prop and', $mode, 'together' ) if T_ERROR;
                    return HTTP_BAD_REQUEST;
                }
                $mode = 'prop';
                my $prop = $node->firstChild;
                while ($prop) {
                    if ( $prop->nodeType == 1 ) {
                        my $name = _fullName($prop);
                        $named{$name} = 1;
                    }
                    $prop = $prop->nextSibling;
                }
            }
            else {
                _trace( "Error: BAD NODE ", _fullName($node) ) if T_ERROR;
            }
        }
        unless ($mode) {    # (14.20)
            _trace('Error: Empty propfind') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }
    }
    else {
        $mode = 'allprop';
    }

    # Loop through all the files and get the properties on them, and
    # compile the response.
    my $multistat = _xml_new_reply('D:multistatus');

    foreach my $path (@files) {
        my %want;
        if ( $mode eq 'propname' ) {

            # names of all properties on this resource, live and dead

            # live properties defined in this module
            no strict 'refs';
            %want = map { s/_prop_//; s/_/-/g; ( $_ => 1 ) }
              grep { /^_prop_/ && defined &$_ }
              keys %{ __PACKAGE__ . '::' };
            use strict 'refs';

            # dead properties from xattrs
            my @dead = $filesys->listxattr($path);
            pop(@dead);    # status
            map { $want{$_} = 1 } @dead;
        }
        elsif ( $mode eq 'allprop' ) {

            # dead properties and all live properties defined in the
            # WebDAV spec

            # Live properties defined in the spec
            %want = %default_props;

            # dead properties from xattrs
            my @dead = $filesys->listxattr($path);
            pop(@dead);    # status
                           # Add any named properties picked up in an 'include'
            map { $want{$_} = 1 } ( @dead, keys %named );
        }
        else {
            %want = %named;
        }

        my $xml = _xml_add_element( $multistat, 'D:response' );
        _xml_add_href( $xml, $path, 1 );

        my %statuses;
        foreach my $propname ( keys %want ) {
            _xml_find_props( $path, $propname, $mode, \%statuses );
        }
        $this->_xml_add_propstat( $response, $xml, %statuses );
    }

    _emitBody( $response, $outdoc->toString(0) );

    return HTTP_MULTI_STATUS;
}

sub PUT {
    my ( $this, $path, $request, $response, $content ) = @_;

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    my @errors = $this->_checkLocksAreSubmitted( $request, 0, 0, $path );
    if ( scalar(@errors) ) {
        return $this->_emitErrors( $request, $response, @errors );
    }

    if ( $filesys->test( 'd', $path ) ) {

        # RFC4918 9.7.2 A PUT request to an existing collection may
        # be treated as an error (405 Method Not Allowed).
        return HTTP_METHOD_NOT_ALLOWED;
    }

    my $fh = $filesys->open_write($path);
    if ( !$fh ) {
        if ( $! == POSIX::ENOLCK ) {
            _trace( 'Error:', $path, 'is filesystem locked' ) if T_ERROR;
            return HTTP_LOCKED;
        }
        elsif ( $! == POSIX::EACCES ) {
            _trace( 'Error:', $path, 'is filesystem unauthorized' ) if T_ERROR;
            return HTTP_UNAUTHORIZED;
        }
        elsif ( $! == POSIX::ENOENT ) {
            return HTTP_UNPROCESSABLE_ENTITY;
        }
        elsif ( $! == POSIX::ENOTEMPTY ) {
            return HTTP_UNPROCESSABLE_ENTITY;
        }
        return HTTP_FORBIDDEN;
    }

    binmode $fh;
    print $fh $content;

    if ( my $e = $filesys->close_write($fh) ) {
        _trace( 'Error: Cannot close the destination', $path, $e ) if T_ERROR;
        return HTTP_FORBIDDEN;
    }

    return HTTP_CREATED;
}

sub LOCK {
    my ( $this, $path, $request, $response, $content ) = @_;

    return HTTP_BAD_REQUEST unless ( $filesys->can('add_lock') );

    unless ( $this->_checkIfHeader( $request, $path ) ) {
        return HTTP_PRECONDITION_FAILED;
    }

    # Check ignoring shared locks
    my @errors = $this->_checkLocksAreSubmitted( $request, 0, 1, $path );
    if ( scalar(@errors) ) {
        return $this->_emitErrors( $request, $response, @errors );
    }

    # Get legal headers
    my $depth = $request->header('Depth');
    $depth = 'infinity' unless defined $depth;
    my $timeout = $request->header('Timeout');
    my %lock = ( depth => 0, timeout => -1 );

    # (10.2) 0, 1 and infinity are only legal values
    if ( lc($depth) eq 'infinity' ) {
        $lock{depth} = -1;
    }
    elsif ( $depth =~ /^[01]$/ ) {
        $lock{depth} = $depth;
    }
    else {
        _trace("'Error:', Bad depth $depth") if T_ERROR;
        return HTTP_BAD_REQUEST;
    }

    if ( defined $timeout ) {
        if ( $timeout =~ /Second-(\d+)/i ) {
            $lock{timeout} = $1;
        }
        elsif ( $timeout =~ /^infinit/i ) {
            $lock{timeout} = -1;
        }
        else {

            # SMELL: could do better
            _trace( "Error: Can't handle timeout $timeout") if T_ERROR;
            return HTTP_BAD_REQUEST;
        }
    }

    my $action;

    if ($content) {

        # We have content (must be a lockinfo)
        $action = 'new';

        my $indoc = _XMLParser->parse_string($content);
        if ( !$indoc ) {
            _trace('Error: No document') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }

        my $fc = _firstChildNode($indoc);
        if ( _fullName($fc) ne '{DAV:}lockinfo' ) {
            _trace( 'Error: lockinfo expected') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }

        for ( my $li = $fc->firstChild ; $li ; $li = $li->nextSibling ) {
            next unless $li->nodeType == 1;
            my $fn   = _fullName($li);
            my $brat = _firstChildNode($li);
            if ( $fn eq '{DAV:}lockscope' ) {
                next unless ( defined $brat );
                my $lockscope = _fullName($brat);
                if ( $lockscope eq '{DAV:}shared' ) {
                    $lock{exclusive} = 0;
                }
                elsif ( $lockscope eq '{DAV:}exclusive' ) {
                    $lock{exclusive} = 1;
                }
                else {
                    _trace( 'Error: Bad lockscope', $lockscope ) if T_ERROR;
                    return HTTP_BAD_REQUEST;
                }
            }
            elsif ( $fn eq '{DAV:}locktype' ) {
                next unless ( defined $brat );
                my $locktype = _fullName($brat);
                if ( $locktype ne '{DAV:}write' ) {
                    _trace( 'Error: Bad locktype', $locktype ) if T_ERROR;
                    return HTTP_BAD_REQUEST;
                }
            }
            elsif ( $fn eq '{DAV:}owner' ) {

                # (14.17) Must be treated as a dead property
                if ( defined $brat ) {

                    # Even though this can be a XML structure (such as
                    # an xref) we store it simply as a string, as it has
                    # no semantic interpretation here.
                    $lock{owner} = $brat->toString();

                    # SMELL: can there ever be more than one child?
                }
                else {
                    $lock{owner} = $li->textContent();
                }
            }
            else {
                _trace( 'Error: Unrecognised lockinfo', $fn ) if T_ERROR;
                return HTTP_BAD_REQUEST;
            }
        }
        $lock{token} = 'opaquelocktoken:' . $this->createUUID;
    }
    else {

        # No content, action must be refresh
        #
        # (9.10.2) This request must not have a body and it must
        # specify which lock to refresh by using the 'If' header with
        # a single lock token (only one lock may be refreshed at a time).
        $action = 'refresh';

        # If the resource has other (shared) locks, those locks are
        # unaffected by a lock refresh. Additionally, those locks do
        # not prevent the named lock from being refreshed.
        my $if = _parseIfHeader($request);
        unless ( $if && scalar(@$if) && scalar( @{ $if->[0] } ) ) {
            _trace( 'Error: Bad refresh') if T_ERROR;
            return HTTP_BAD_REQUEST;
        }
        $lock{token} = $if->[0]->[0]->{token};
    }

    # Check potentially blocking locks.
    # Current State	Shared Lock OK	Exclusive Lock OK
    # None		True		True
    # Shared Lock	True		False
    # Exclusive Lock	False		False
    my @failedPaths;
    foreach my $livelock ( $filesys->get_locks( $path, $lock{depth} ) ) {

	# Shared locks don't block unless the new $lock is
	# exclusive, but exclusive locks always block
	next unless ( $livelock->{exclusive} || $lock{exclusive} );

	if ( $livelock->{token} eq $lock{token} && $action eq 'refresh' ) {

	    # (6.6) The timeout counter must be restarted if a refresh
	    # lock request is successful.
	    $filesys->refresh_lock( $lock{token} );
	    next;
	}

	#_trace( 'Lock', $livelock, 'blocks', \%lock ) if T_ACTION;

	unless (_clientIs('LibreOffice', $request)) {
	    # LibreOffice lock handling is brain dead. So refresh the locks it
	    # gives us, but don't fail on a bad lock. This means there is a risk
	    # of simultaneous changes with LibreOffice.
	    push( @failedPaths, $livelock->{path} );
	}
    }

    if ( scalar(@failedPaths) ) {

        unless ( $lock{depth} ) {

            # Unless the Depth header is set to a non-zero, we
            # don't need a MUTLISTATUS, because only one examined
            # resource can possibly have been locked.
            return HTTP_LOCKED;
        }

        # Something could not be locked.
        my $multistat = _xml_new_reply('D:multistatus');
        foreach my $fp (@failedPaths) {
            my $xml = _xml_add_element( $multistat, 'D:response' );
            _xml_add_href( $xml, $fp, 1 );
            $this->_xml_add_status( $xml, HTTP_FORBIDDEN );
        }

        my $xml = _xml_add_element( $multistat, 'D:response' );
        _xml_add_href( $xml, $path, 1 );
        my $propstat = _xml_add_element( $multistat, 'D:propstat' );
        my $prop     = _xml_add_element( $propstat,  'D:prop' );
        my $disco    = _xml_add_element( $propstat,  'D:lockdiscovery' );
        _xml_fill_lockdiscovery( $disco,
            $filesys->get_locks( $path, $lock{depth} ) );
        $this->_xml_add_status( $propstat, HTTP_FAILED_DEPENDENCY );

        _emitBody( $response, $outdoc->toString(0) );

        return HTTP_MULTI_STATUS;
    }
    else {
        if ( $action eq 'new' ) {

            # (7.4) If the resource doesn't exist, the simple action
            # of creating the lock record will give it 'lock-null' status
            $filesys->add_lock( path => $path, %lock );
            $response->header( 'Lock-Token' => "<$lock{token}>" );
            _trace( "New lock ", $lock{token} ) if T_ACTION;
        }
        else {
            _trace( "Refresh lock ", $lock{token} ) if T_ACTION;
            $filesys->refresh_lock( $lock{token} );
        }

        # Resource was successfully locked. If the resource does not exist,
        # it will be seen as a lock-null resource.
        my $prop = _xml_new_reply('D:prop');
        my $disco = _xml_add_element( $prop, 'D:lockdiscovery' );
        _xml_fill_lockdiscovery( $disco, \%lock );

        _emitBody( $response, $outdoc->toString(0) );

        # M$ office really f***s up if this is not HTTP_OK
        return HTTP_OK;
    }
}

sub UNLOCK {
    my ( $this, $path, $request, $response ) = @_;

    my $locktoken = $request->header('Lock-Token');
    $locktoken =~ s/<(.*)>/$1/;
    if ( $filesys->remove_lock($locktoken) ) {
        return HTTP_NO_CONTENT;
    }
    _trace( 'Error: Could not remove lock', $locktoken, 'on', $path ) if T_ERROR;
    return HTTP_FORBIDDEN;
}

=begin TML

ObjectMethod getFilesys($uri, $request) -> $filesys_object

Return an instance of (a subclass of) Filesys::Virtual that will
handle low-level file operations. NOTE: it's a limitation of this
implementation that both the source and destination of MOVE and COPY
operations must use the same filesys.
   * $uri - request URI - if undef, will return a new instance of the
     last module used.
   * $request - the HTTP::Request
This method is designed to be overridden in subclasses; the default
uses the class name passed to the constructor of this, and passes
root_path and location arguments obtained the same way.

=cut

sub getFilesys {
    my ( $this, $uri, $request ) = @_;
    my $module;

    $module = $this->{filesys};
    eval "require $module" || die $@;

    return $module->new(
        {
            location  => $this->{location},     # url path
            root_path => $this->{root_path},    # file path
            trace     => $this->{trace} >> 16   # Pass trace bits to filesys
        }
    );
}

=begin TML

ObjectMethod createUUID() -> $uuid

Create a string UUID.
Designed to be overriddedn by subclasses, if needed. The default
implementation uses a combination of rand() and time()

=cut

sub createUUID {

    # Not a real UUID, but good enough for our purposes
    return sprintf(
        "%08x-%04x-%04x-%04x-%08x",
        time() & 0xFFFFFFFF,
        rand(0xFFFF) & 0xFFFF,
        rand(0xFFFF) & 0xFFFF,
        rand(0xFFFF) & 0xFFFF,
        rand(0xFFFF) & 0xFFFFFFFF
    );
}

=begin TML

ObjectMethod getMimeTypesFile -> $mime.types

Get the path of a file that contains MIME type mappings. The file
format must be compatible with Apache mod_mime TypesConfig

=cut

sub getMimeTypesFile {
    die "Must be implemented in subclass";
}

# Emit tracing information to the error log
sub _trace {
    if ( UNIVERSAL::isa( $_[0], __PACKAGE__ ) ) {
        shift;
    }
    my @data;
    foreach my $a (@_) {
        if ( ref($a) ) {
            if ( UNIVERSAL::can( $a, 'toString' ) ) {
                push @data, $a->toString();
            }
            elsif ( UNIVERSAL::can( $a, 'as_string' ) ) {
                push @data, $a->as_string();
            }
            else {
		my $desc = Data::Dumper->Dump( [$a] );
		$desc =~ s/^\$VAR1\s*=\s*//;
                push @data, $desc;
            }
        }
        elsif ( defined $a ) {
            push @data, $a;
        }
        else {
            push @data, 'undef';
        }
    }
    my $mess = Encode::encode( "utf-8", join( ' ', @data ) );
    binmode(STDERR, ":utf8");

    # Print to webserver log
    print STDERR 'WD@'.time.": $mess\n";
}

# Find the first non-text child node of an XML node
sub _firstChildNode {
    my $node  = shift;
    my $child = $node->firstChild;
    while ( $child && $child->nodeType != 1 ) {
        $child = $child->nextSibling;
    }
    return $child;
}

# Given an XML node, flatten the namespace out so we get (for example)
# <a:node xmlns="a:http://blah">
# as
# {http://blah:}node
# Read the doc for XML::Simple if that isn't clear
sub _fullName {
    my $node = shift;
    return '' unless $node;
    return $node->nodeName unless $node->nodeType eq 1;    # elements
    my $ns = $node->namespaceURI();
    if ( defined $ns ) {
        return "{$ns}" . $node->localname;
    }

    # Check for the null namespace, in case it was defined
    my @nses = $node->getNamespaces();
    foreach my $n (@nses) {
        if ( ref($n) eq 'XML::LibXML::Namespace' ) {
            return '{' . $n->getData() . '}' . $node->localname;
        }
    }

    # (8.1.3) all elements which do not explicitly state the
    # namespace to which they belong are members of the "DAV:"
    # namespace schema.
    return "{DAV:}" . $node->localname;
}

# Test for different user agents
sub _clientIs {
    my ( $id, $request ) = @_;
    return $request->header('User-Agent') =~ /$id/;
}

# (7.4) See if any of these resources are lock null (they don't exist in the
# filesystem, but have active locks)
sub _isLockNullResource {
    my ( $this, @files ) = @_;

    foreach my $file (@files) {
        my @locks = $filesys->get_locks($file);
        foreach my $lock (@locks) {

            # If the resource doesn't exist, this is a lock-null
            unless ( $filesys->test( 'e', $file ) ) {
                _trace( 'Error: Lock-null because of', $file ) if T_ERROR;
                return 1;
            }
        }
    }
    return 0;
}

# If: header handling
#
# 10.4.1 The first purpose is to make a request conditional by supplying a
# series of state lists with conditions that match tokens and ETags to a
# specific resource. If this header is evaluated and all state lists fail,
# then the request must fail with a 412 (Precondition Failed) status. On the
# other hand, the request can succeed only if one of the described state
# lists succeeds. The success criteria for state lists and matching functions
# are defined in Sections 10.4.3 and 10.4.4.
#
# Check the If: header and return true if at least one state list
# succeeds.
sub _checkIfHeader {

    # $default is the request path
    my ( $this, $request, $default ) = @_;
    my %did;
    my $if = _parseIfHeader($request);
    return 1 unless scalar(@$if);

    foreach my $state_list (@$if) {
        my $list_passed = 1;
        foreach my $condition (@$state_list) {
            my $resource = $condition->{resource} || $default;
            if ( $resource !~ /^\// ) {

                # SMELL: assumes same server!
                $resource =
                  Encode::decode_utf8(
                    URI::Escape::uri_unescape( URI->new($resource)->path() ) );
            }
            my $condition_passed = 0;
            if ( defined $condition->{etag} ) {
                my $etag = _get_etag($resource);
                if ( $condition->{etag} eq $etag ) {
                    $condition_passed = 1;
                }
                else {
                    _trace( "If:ETAG", $etag, $condition->{etag} ) if T_ACTION;
                }
            }
            elsif ( defined $condition->{token} ) {
                my @locks = $filesys->get_locks($resource);
                foreach my $lock (@locks) {
                    if ( $lock->{token} eq $condition->{token} ) {
                        $condition_passed = 1;
                        last;
                    }
                }
                unless ($condition_passed) {
                    _trace( 'If: lock condition failed:', $condition->{token} ) if T_ACTION;
                }
            }
            $condition_passed = !$condition_passed if ( $condition->{invert} );
            unless ($condition_passed) {
                $list_passed = 0;
                last;
            }
        }
        return 1 if $list_passed;    # This list passed
    }
    return 0;                        # no list passed
}

# 7.5 a lock token must be submitted by an authorized principal for all
# locked resources that a method may change or the method must fail. A
# lock token is submitted when it appears in an If header.
# 10.4.1 the mere fact that a state token appears in an If header
# means that it has been "submitted" with the request. In general, this is
# used to indicate that the client has knowledge of that state token.
sub _checkLocksAreSubmitted {

    # @files is the list of resources that may change
    # (may include duplicates)
    my ( $this, $request, $recurse, $ignoreShared, @files ) = @_;
    my %did;
    my @errors;
    my $if = _parseIfHeader($request);
    foreach my $file (@files) {
        next if $did{$file};
        $did{$file} = 1;
      LOCK:
        foreach my $lock ( $filesys->get_locks( $file, $recurse ) ) {
            next if ( $ignoreShared && !$lock->{exclusive} );

            # The resource is locked, check the tokens in the If:
            # header.
            foreach my $state_list (@$if) {
                foreach my $condition (@$state_list) {

                    # 10.4.1: a state token counts as being submitted
                    # independently of whether the server actually has
                    # evaluated the state list it appears in, and also
                    # independently of whether or not the condition it
                    # expressed was found to be true.
                    next LOCK
                      if defined $condition->{token}
                          && $condition->{token} eq $lock->{token};
                }
            }
            push(
                @errors,
                {
                    file   => $lock->{path},
                    status => HTTP_LOCKED
                }
            );
            _trace( 'Unsubmitted lock:',
                $lock->{token},
                $lock->{exclusive} ? '(exclusive)' : '(shared)' )
              if T_ACTION;
        }
    }
    return @errors;
}

# Emit a report of the errors in @errors, each of the format
# { file => ..., status => ... }
# @errors must not be empty
sub _emitErrors {
    my ( $this, $request, $response, @errors ) = @_;

    # You shouldn't respond with a MULTI_STATUS unless there's a Depth
    # header.
    if ( !$request->header('Depth') ) {
        return $errors[0]->{status};
    }

    my $multistat = _xml_new_reply('D:multistatus');
    foreach my $error (@errors) {
        my $xml = _xml_add_element( $multistat, 'D:response' );
        _xml_add_href( $xml, $error->{file}, 1 );
        $this->_xml_add_status( $xml, $error->{status} );
    }

    _emitBody( $response, $outdoc->toString(0) );

    return HTTP_MULTI_STATUS;
}

sub _xml_add_element {
    my ( $parent, $el ) = @_;
    my $node = $outdoc->createElement($el);
    $parent->addChild($node);
    return $node;
}

sub _xml_new_reply {
    my ($rootel) = @_;
    $outdoc = new XML::LibXML::Document( '1.0', 'utf-8' );
    my $root = $outdoc->createElement($rootel);
    $root->setAttribute( 'xmlns:D', 'DAV:' );
    $outdoc->setDocumentElement($root);
    return $root;
}

sub _xml_add_href {
    my ( $xresponse, $path, $encode ) = @_;
    if ($encode) {
        $path = join( '/',
            map { URI::Escape::uri_escape( Encode::encode_utf8($_) ) }
              split( /\/+/, $path ) );
    }

    # DAVE crashes when a D:href is empty, so default to the empty path
    $xresponse->appendTextChild( 'D:href' => $path || '/' );
}

# Generate the lockdiscovery content for the locks in @locks
sub _xml_fill_lockdiscovery {
    my ( $disco, @locks ) = @_;

    foreach my $lock (@locks) {
        my $alock = _xml_add_element( $disco, 'D:activelock' );

        my $e = _xml_add_element( $alock, 'D:lockscope' );
        _xml_add_element( $e,
            'D:' . ( $lock->{exclusive} ? 'exclusive' : 'shared' ) );

        $alock->appendTextChild(
            'D:depth' => $lock->{depth} < 0 ? 'Infinity' : $lock->{depth} );

        $e = _xml_add_element( $alock, 'D:locktype' );
        _xml_add_element( $e, 'D:write' );

        if ( $lock->{owner} ) {
            $e = _xml_add_element( $alock, 'D:owner' );
            $e->appendTextNode( $lock->{owner} );
        }

        $e = _xml_add_element( $alock, 'D:locktoken' );
        _xml_add_href( $e, $lock->{token}, 0 );

        $alock->appendTextChild(
              'D:timeout' => $lock->{timeout} < 0
            ? 'Infinite'
            : "Second-$lock->{timeout}"
        );
    }
}

# From the litmus FAQ:
# "If a request was sent with an XML body which included an empty
#  namespace prefix declaration (xmlns:ns1=""), then the server
#  must reject that with a "400 Bad Request" response, as it is
#  invalid according to the XML Namespace specification."
# This is tested by litmus using:
# <D:propfind xmlns:D="DAV:"><D:prop><bar:foo xmlns:bar=""/>
# </D:prop></D:propfind>
# So the definition of an "null namespace" is one with a
# declared prefix but no declared URI. Check it.
sub _hasNullNamespace {
    my $node = shift;
    my @nses = $node->getNamespaces();
    foreach my $n (@nses) {
        if ( ref($n) eq 'XML::LibXML::Namespace' ) {
            return 1 if $n->declaredPrefix() && !$n->declaredURI();
        }
    }
    for ( my $sn = $node->firstChild ; $sn ; $sn = $sn->nextSibling ) {
        next unless $sn->nodeType == 1;
        return 1 if _hasNullNamespace($sn);
    }
    return 0;
}

# Parse an If: header and return a simple hash representation.
# From RFC4918:
#
#  If = "If" ":" ( 1*No-tag-list | 1*Tagged-list )
#
#  No-tag-list = List
#  Tagged-list = Resource-Tag 1*List
#
#  List = "(" 1*Condition ")"
#  Condition = ["Not"] (State-token | "[" entity-tag "]")
#  ; entity-tag: see Section 3.11 of [RFC2616]
#  ; No LWS allowed between "[", entity-tag and "]"
#
#  State-token = Coded-URL
#
#  Resource-Tag = "<" Simple-ref ">"
#  ; Simple-ref: see Section 8.3
#  ; No LWS allowed in Resource-Tag

#  If = "If" ":" ( No-tag-list+ | Tagged-list+ )
#  No-tag-list = List
#  Tagged-list = Resource-Tag List+
#  List = "(" Condition+ ")"
#  Condition = ["Not"] (State-token | "[" entity-tag "]")
#  State-token = Coded-URL
#
# Returns a reference to a list of state lists
sub _parseIfHeader {
    my ($request) = @_;
    my $if = $request->header('If');
    return [] unless defined $if;

    my @state_lists;
    my $resource = undef;    # default resource from URI should be used

    while ( $if =~ /\S/ ) {
        if ( $if =~ /^\s*<(.*?)>/ ) {

            # Coded-URL, so must be "Resource-Tag"
            # SMELL: check it's a valid absolute URL
            $if =~ s/^\s*<(.*?)>//;
            $resource = $1;

            # A Resource-Tag applies to all subsequent Lists,
            # up to the next Resource-Tag (RFC4918).
        }

        # Expect 1*List
        unless ( $if =~ /^\s*\(/ ) {
            die "Bad If: '" . $request->header('If') . "' at '$if'";
        }
        while ( $if =~ s/^\s*\(// ) {
            my @state_list;

            # Expect 1*( ["Not"] ( State-token | "[" entity-tag "]" ))
            while ( $if =~ /\S/ && $if !~ /^\s*\)/ ) {
                my $condition = {};
                $condition->{resource} = $resource;

                # ["Not"] ( State-token | "[" entity-tag "]" )
                if ( $if =~ s/^\s*Not// ) {
                    $condition->{invert} = 1;
                }

                # State-token | "[" entity-tag "]"
                if ( $if =~ s/^\s*\[(.*?)\]// ) {

                    # entity-tag
                    $condition->{etag} = $1;
                }
                elsif ( $if =~ s/^\s*<(.*?)>// ) {

                    # State-token
                    $condition->{token} = $1;
                }
                else {
                    die "Bad If: '" . $request->header('If') . "' at '$if'";
                }
                push( @state_list, $condition );
            }
            unless ( $if =~ s/^\s*\)// ) {
                die "Bad If: '" . $request->header('If') . "' at '$if'";
            }
            push( @state_lists, \@state_list );
        }
    }
    return \@state_lists;
}

# Add <D:status> to an XML response
sub _xml_add_status {
    my ( $this, $xml, $code ) = @_;
    my $stat = _xml_add_element( $xml, 'D:status' );
    $stat->appendText(
        "HTTP/1.1 $code " . HTTP::Status::status_message($code) );
}

# Add <D:propstat> to an XML response
sub _xml_add_propstat {
    my ( $this, $response, $xml, %statuses ) = @_;

    my $doc = $xml->ownerDocument;
    foreach my $status ( keys %statuses ) {
        my $propstat = $doc->createElement('D:propstat');
        my $prop     = $doc->createElement('D:prop');
        foreach my $pel ( @{ $statuses{$status} } ) {
            next unless $pel->firstChild;
            $prop->addChild( $pel->firstChild );
        }
        $propstat->addChild($prop);
        $this->_xml_add_status( $propstat, $status );
        $xml->addChild($propstat);
    }
}

# Get XML for property values, storing the resulting elements in
# a hash keyed on the response status.
sub _xml_find_props {
    my ( $path, $propname, $mode, $statuses ) = @_;
    my $info   = {};
    my $status = HTTP_OK;
    my $propel = $outdoc->createElement('D:prop');

    my $datum = _xml_add_propel( $propel, $propname );
    if ( $mode ne 'propname' ) {

        # get the property value
        if ( $propname =~ /^{DAV:}(.*)/ ) {
            my $fn = '_prop_' . $1;
            $fn =~ s/-/_/g;
            if ( defined &$fn ) {
                no strict 'refs';
                unless ( &$fn( $datum, $path ) ) {

                    # A zero status from the _prop_ function signals
                    # that it's not able to handle this live prop
                    # (possibly because of a filesystem limitation)
                    $status = HTTP_NOT_FOUND;
                }
                use strict 'refs';
            }
            else {
                _trace( 'Error: No function for', $propname ) if T_ERROR;
                $status = HTTP_NOT_FOUND;
            }
        }
        else {
            my $val = $filesys->getxattr( $path, $propname );
            if ( defined $val ) {
                $datum->appendText($val);
            }
            else {
                $status = HTTP_NOT_FOUND;
            }
        }
    }

    push( @{ $statuses->{$status} }, $propel );
}

# Add an XML element for a property
sub _xml_add_propel {
    my ( $parent, $name ) = @_;
    my $datum;
    if ( $name =~ /{(.*)}(.*?)$/ ) {
        if ( $1 eq 'DAV:' ) {
            $datum = _xml_add_element( $parent, "D:$2" );
        }
        else {
            $datum = $outdoc->createElementNS( $1, $2 );
            $parent->addChild($datum);
        }
    }
    else {
        $datum = _xml_add_element( $parent, $name );
    }
    return $datum;
}

# Perform a stat() call on a filesystem path, and decode the
# results into a hash.
sub _stat {
    my $path = shift;

    my %stat;
    my @stata = $filesys->stat($path);
    my $i     = 0;
    foreach my $p (@STAT_PROPERTIES) {
        $stat{$p} = $stata[ $i++ ];
    }
    return \%stat;
}

# Get the etag for the given path
sub _get_etag {
    my ($path) = @_;

    my $stat = _stat($path);
    if ( $stat->{ino} ) {
        return sprintf( '%x-%x-%x',
            $stat->{ino},
            $stat->{getcontentlength} || 0,
            $stat->{getlastmodified}  || 0 );
    }
    else {
        return sprintf( '%x', $stat->{getlastmodified} || 0 );
    }
}

# Add a ETag to the response for the identified resource. At this
# time only GET and HEAD requests include ETags in the response
# headers (though a PROPFIND will return etags in the response body).
sub _add_etag {
    my ( $response, $path ) = @_;
    my $etag = _get_etag($path);
    $response->header( 'ETag', $etag );
}

# Properties specified by RFC4918

sub _prop_creationdate {
    my ( $datum, $path ) = @_;
    my $stat = _stat($path);
    $datum->appendText( _formatISOTime( $stat->{creationdate} || 0 ) );
    return 1;
}

=begin UNWANTED

# (15.2) Contains a description of the resource that is suitable for
# presentation to a user. This property is defined on the resource, and
# hence should have the same value independent of the Request-URI used to
# retrieve it (thus, computing this property based on the Request-URI is
# deprecated). While generic clients might display the property value to
# end users, client UI designers must understand that the method for
# identifying resources is still the URL. Changes to DAV:displayname do
# not issue moves or copies to the server, but simply change a piece of
# meta-data on the individual resource. Two resources can have the same
# DAV:displayname value even within the same collection.
#
# Since we want to use the filesystem-provided identifier for all
# resources, we don't implement this.
sub _prop_displayname {
    my ($datum, $path) = @_;
    $datum->appendText( $path ); # wild stab in the dark
}

=cut

=begin UNWANTED

# (15.3) The DAV:getcontentlanguage property must be defined on any
# DAV-compliant resource that returns the Content-Language header
# on a GET.
#
# Since we don't return this header on a GET, it doesn't have to be provided as a property.
sub _prop_getcontentlanguage {
    my ($datum, $path) = @_;
}

=cut

sub _prop_getcontentlength {
    my ( $datum, $path ) = @_;
    my $stat = _stat($path);
    $datum->appendText( $stat->{getcontentlength} || 0 );
    return 1;
}

sub _prop_getcontenttype {
    my ( $datum, $path ) = @_;
    if ( $filesys->test( 'd', $path ) ) {
        $datum->appendText('httpd/unix-directory');
    }
    else {
        my $type = _deduceMimeType($path) || 'application/octet-stream';
        $datum->appendText($type);
    }
    return 1;
}

sub _prop_getetag {
    my ( $datum, $path ) = @_;

    # Format consistent with mod_dav_fs
    my $etag = _get_etag($path);
    $datum->appendText($etag);
    return 1;
}

sub _prop_getlastmodified {
    my ( $datum, $path ) = @_;
    my $stat = _stat($path);
    $datum->appendText( _formatHTTPTime( $stat->{getlastmodified} || 0 ) );
    return 1;
}

sub _prop_lockdiscovery {
    my ( $datum, $path ) = @_;
    _xml_fill_lockdiscovery( $datum, $filesys->get_locks( $path, -1 ) );
    return 1;
}

sub _prop_resourcetype {
    my ( $datum, $path ) = @_;

    # Note: The MS web folder client displays all resources with a
    # non-empty <resourcetype> property as collection.
    if ( $filesys->test( 'd', $path ) ) {
        _xml_add_element( $datum, 'D:collection' );
    }
    return 1;
}

sub _prop_supportedlock {
    my ( $datum, $path ) = @_;

    return 0 unless $filesys->can('add_lock');

    my $info = $filesys->lock_types($path);

    my @types = ( exclusive => 1, shared => 2 );
    while ( scalar(@types) ) {
        my $k = shift(@types);
        my $n = shift(@types);
        if ( $info & $n ) {
            my $lockentry = _xml_add_element( $datum,     'D:lockentry' );
            my $lockscope = _xml_add_element( $lockentry, 'D:lockscope' );
            _xml_add_element( $lockscope, 'D:' . $k );

            # Write locks are the only supported lock type
            my $type = _xml_add_element( $lockentry, 'D:locktype' );
            _xml_add_element( $type, 'D:write' );
        }
    }
    return 1;
}

###### WebDrive specific props ############

# Quota information.  This isn't in the WebDAV spec, but if it's
# not here, WebDrive won't allow any uploads.
sub _prop_quotaused {
    my ( $datum, $path ) = @_;
    $datum->appendText('0');
    return 1;
}

sub _prop_quota_used_bytes {
    my ( $datum, $path ) = @_;
    $datum->appendText('0');
    return 1;
}

sub _prop_quota_available_bytes {
    my ( $datum, $path ) = @_;
    $datum->appendText('2000000000');
    return 1;
}

sub _prop_quota_assigned_bytes {
    my ( $datum, $path ) = @_;
    $datum->appendText('2000000000');
    return 1;
}

# If the handler requires a login, pass the auth from the request on to it.
sub _processAuth {
    my ( $this, $request, $response, $auth_provider ) = @_;

    if ( $filesys->can('login') ) {

        # Filesystem supports login; get the request user. Note
        # that the auth_provider may only return the user. That's fine,
        # so long as the filesystem is able to accept logins
        # without a password.
        my ( $loginName, $password ) = $auth_provider->user();

        unless ($loginName) {
            _trace( 'Error: Could not find login name') if T_ERROR;

            # Login failed; reject the request
            $auth_provider->auth_failed($response);
            _emitBody( $response, "ERROR: (401) Can't login", type => 'text/plain' );
            return 0;
        }

        _trace( 'Logging in', $loginName ) if T_AUTH;

        # Windows insists on sticking the domain in front of the the
        # username. Chop it off if the mini-redirector is requesting.
        my $userAgent = $request->header('User-Agent') || '';

        if (   $userAgent =~ m#^Microsoft-WebDAV-MiniRedir#
            && !$Foswiki::cfg{WebDAVContrib}{KeepWindowsDomain}
            && $loginName =~ /^.*\\(.+)$/ )
        {
            $loginName = $1;
        }
        $loginName ||= '';

        unless ( $filesys->login( $loginName, $password ) ) {
            _trace( 'Error: Login failed for', $loginName ) if T_ERROR;

            # Login failed; reject the request
            _emitBody( $response, "ERROR: (401) Can't login as $loginName",
                type => 'text/plain' );
            return 0;
        }
        _trace( $loginName, 'logged in' ) if T_AUTH;
    }
    return 1;
}

# Format ISO8601 date
sub _formatISOTime {
    my $t = shift;
    return "1970-01-01" unless defined $t;
    my ( $sec, $min, $hour, $day, $mon, $year, $wday, $tz_str ) = gmtime($t);
    return
        sprintf( '%.4u', $year + 1900 ) . "-"
      . sprintf( '%.2u', $mon + 1 ) . "-"
      . sprintf( '%.2u', $day ) . "T"
      . sprintf( '%.2u', $hour ) . ":"
      . sprintf( '%.2u', $min ) . ':'
      . sprintf( '%.2u', $sec ) . "Z";
}

sub _formatHTTPTime {
    my $t = shift;
    my ( $sec, $min, $hour, $day, $mon, $year, $wday, $tz_str ) = gmtime($t);
    return
        $WEEKDAY[$wday]
      . ", $day $ISOMONTH[$mon] "
      . sprintf( '%.4u', $year + 1900 ) . " "
      . sprintf( '%.2u', $hour ) . ":"
      . sprintf( '%.2u', $min ) . ':'
      . sprintf( '%.2u', $sec ) . " GMT";
}

# Emit the string as the body of a response. There should be only one
# call to _emitBody per request - otheriwse the last call always wins.
# $string defaults to ''
# $type defaults to 'text/xml'
sub _emitBody {
    my ( $response, $string, %options ) = @_;

    $string ||= '';
    # Note: text/xml would cause the charset in the <?xml to be ignored, so have
    # to use application/xml
    my $type = $options{type} || 'application/xml';

    if ( T_RESPONSE ) {
        if ( $type eq 'application/xml' ) {
            _trace( $string );
        } else {
            _trace( $type, 'response, ', length($string), 'characters' );
        }
    }

    # no_conversion is used to force 
    unless ( $options{no_conversion} ) {
        # Convert perl strings to UTF-8 bytes.
        utf8::encode($string);
        $type .= '; charset="utf-8"';
    }

    $response->header( 'Content-Type' => $type );

    # Have to use content-length because Windows Mini-Redirector doesn't
    # understand chunked encoding.
    $response->header( 'Content-Length' => length($string) );
    $response->header( 'FW-Signature'   => $RELEASE );
    $response->content( $string );
}

# Look up mime types DB to map a file extension to a mime type
sub _deduceMimeType {
    my ($path) = @_;

    return undef unless ( $path =~ /\.([^.]*)$/ );
    my $ext = $1;
    unless ( scalar keys %mimeTypes ) {
        my $f;
        open( $f, '<', $typesConfig ) || return $!;
        local $/ = "\n";
        while ( my $line = <$f> ) {
            next if $line =~ /^\s*#/;
            if ( $line =~ /(\S+)\s*(.*?)\s*$/ ) {
                my $type = $1;
                foreach my $extension ( split( /\s+/, $2 ) ) {
                    $mimeTypes{$extension} = $type;
                }
            }
        }
        close($f);
    }
    return $mimeTypes{$ext};
}

# Unlink file or dir
sub _unlink {
    my ( $this, $file ) = @_;
    my $result;
    if ( $filesys->test( 'd', $file ) ) {
        $result = $filesys->rmdir($file);
    }
    elsif ( $filesys->test( 'f', $file ) ) {
        $result = $filesys->delete($file);
    }
    unless ($result) {
        _trace( 'Error: unlink', $file, 'failed:', $! ) if T_ERROR;
    }
    return $result;
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
