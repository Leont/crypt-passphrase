package Crypt::Passphrase::MD5::Hex;

use strict;
use warnings;

use Crypt::Passphrase -validator;

use Digest::MD5 'md5';

sub new {
	my $class = shift;
	return bless {}, $class;
}

sub accepts_hash {
	my ($self, $hash) = @_;
	return $hash =~ / ^ [a-f0-9]{32} $/xi;
}

sub verify_password {
	my ($self, $password, $hash) = @_;
	return md5($password) eq pack 'H32', $hash;
}

1;

# ABSTRACT: Validate against hexed MD5 hashes with Crypt::Passphrase

=head1 SYNOPSIS

 my $passphrase = Crypt::Passphrase->new(
     encoder    => 'Bcrypt',
     validators => [ 'MD5::Hex' ],
 );

=head1 DESCRIPTION

This module implements a validator for base64-encoded MD5 hashes.

This has no configuration and will try to match any value that looks like 16 bytes encoded in hex.
