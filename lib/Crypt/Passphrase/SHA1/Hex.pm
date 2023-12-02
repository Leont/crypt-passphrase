package Crypt::Passphrase::SHA1::Hex;

use strict;
use warnings;

use Crypt::Passphrase -validator;

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

=head1 DESCRIPTION

This module implements a validator for hex-encoded SHA-1 hashes.

=method new()

This creates a new SHA-1 validator. It takes no arguments.

=method accepts_hash($hash)

This (heuristically) determines if we may be dealing with a hex encoded sha1 sum.

=method verify_hash($password, $hash)

This determines if the password matches the hash when SHA1'ed.

