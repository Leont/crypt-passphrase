package Crypt::Passphrase::SHA1::Hex;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

use Digest::SHA 'sha1';

sub new {
	my $class = shift;
	return bless {}, $class;
}

sub accepts_hash {
	my ($self, $hash) = @_;
	return $hash =~ / ^ [a-f0-9]{40} $/xi;
}

sub verify_password {
	my ($self, $password, $hash) = @_;
	return sha1($password) eq pack 'H40', $hash;
}

1;

# ABSTRACT: Validate against hexed SHA1 hashes with Crypt::Passphrase

=head1 SYNOPSIS

 my $passphrase = Crypt::Passphrase->new(
     encoder    => 'Argon2',
     validators => [ 'SHA1::Hex' ],
 );

=head1 DESCRIPTION

This module implements a validator for base64-encoded SHA-1 hashes.

This has no configuration and will try to match any value that looks like 20 bytes encoded in hex.
