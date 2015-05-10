# DAV script that connects to a webserver, safely makes
# a new directory and uploads all html files in
# the /tmp directory.

use HTTP::DAV;

$d   = new HTTP::DAV;
$url = "http://daphne/dav_basic/";

$d->credentials(
    -user  => "SimianApe",
    -pass  => "x",
    -url   => $url,
    -realm => "Foswiki"
);

$d->open( -url => $url )
  or die( "Could not open $url: " . $d->message . "\n" );

my $r = $d->propfind("/Flitmus");
if ( $r->is_collection ) {
    print $r->get_property('short_ls');
}
else {
    print $r->get_property("long_ls");
}

#copy(URL,DEST,[OVERWRITE],[DEPTH])#
#delete(URL)
#get(URL,[TO],[CALLBACK])
#lock([URL],[OWNER],[DEPTH],[TIMEOUT],[SCOPE],[TYPE])
#mkcol(URL)
#move(URL,DEST,[OVERWRITE],[DEPTH])
#open(URL)
#options([URL])
#propfind([URL],[DEPTH])
#proppatch([URL],[NAMESPACE],PROPNAME,PROPVALUE,ACTION,[NSABBR])
#put(LOCAL,[URL],[CALLBACK])
#set_prop([URL],[NAMESPACE],PROPNAME,PROPVALUE)
#steal([URL])
#unlock([URL])
#unset_prop([URL],[NAMESPACE],PROPNAME)

## Make a null lock on newdir
#$d->lock( -url => "$url/newdir", -timeout => "10m" )
#    or die "Won't put unless I can lock for 10 minutes\n";
#
## Make a new directory
#$d->mkcol( -url => "$url/newdir" )
#    or die "Couldn't make newdir at $url\n";
#
## Upload multiple files to newdir.
#if ( $d->put( -local => "/tmp/*.html", -url => $url ) ) {
#    print "successfully uploaded multiple files to $url\n";
#} else {
#    print "put failed: " . $d->message . "\n";
#}

$d->unlock( -url => $url );
