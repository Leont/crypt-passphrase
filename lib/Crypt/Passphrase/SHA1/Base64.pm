package Crypt::Passphrase::SHA1::Base64;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

use Digest::SHA 'sha1';
use MIME::Base64 'decode_base64';

sub new {
	my $class = shift;
	return bless {}, $class;
}

sub accepts_hash {
	my ($self, $hash) = @_;
	return $hash =~ m{ ^ [A-Za-z0-9+/]{27} =? $ }x;
}

sub verify_password {
	my ($self, $password, $hash) = @_;
	my $new_hash = sha1($password);
	return $new_hash eq decode_base64($hash);
}

1;

# ABSTRACT: Validate against base64ed SHA1 hashes with Crypt::Passphrase

=head1 SYNOPSIS

 my $passphrase = Crypt::Passphrase->new(
     encoder    => 'Argon2',
     validators => [ 'SHA1::Base64' ],
 );

=head1 DESCRIPTION

This module implements a validator for base64-encoded SHA-1 hashes.

This has no configuration and will try to match any value that looks like 20 bytes encoded in base64.
