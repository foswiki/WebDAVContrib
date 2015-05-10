use strict;
use utf8;
use Encode;
  
my $url = "http://daphne/dav_basic/";
my $username = "SimianApe";
my $password = "x";
my $realm = "Foswiki";

# Size character strings with different width encodings
my $oneByte = "Onetwo"; # 6 bytes
my $twoByte = "אבגדהוז"; # 0x5d0..0x5d8, 12 bytes
my $threeByte = "ᇳᇴᇵᇶᇷᇸ"; # 0x11f3..0x11f8, 18 bytes

use HTTP::DAV ();
my $d = new HTTP::DAV();

$d->credentials( -user=>$username,-pass =>$password, 
		 -url =>$url,      -realm=>$realm );
  
$d->open( -url=>$url ) || die "Couldn't open " .$d->message;
  
my ($web, $topic);
if (1) {
    $web = "WebDAV$twoByte";
    $topic = "Topic$threeByte";
} else {
    $web = "WebDAVUTF8TestWeb";
    $topic = "SimpleTopic";
}

# Delete previous run, if necessary
$d->delete( -url => "$url/$web" );

# Make a new web
$d->mkcol( -url => "$url/$web" ) || die "Couldn't make web";
  
# Upload UTF8 topic to newdir.
my $data = Encode::encode('utf8', "Cogito $twoByte ergo $threeByte sum");
$d->put( -local => \$data, -url => "$url/$web/$topic.txt" ) ||
    die "Couldn't write topic " . $d->message;

#$d->delete( -url => "$url/$web" ) || die "Couldn't delete web";
