package Crypt::Passphrase::PassphraseHash;

use strict;
use warnings;

sub new {
	my ($class, $crypt_passphrase, $hash) = @_;

	return bless {
		validator => $crypt_passphrase,
		raw_hash  => $hash,
	}, $class;
}

sub verify_password {
	my ($self, $password) = @_;
	return $self->{validator}->verify_password($password, $self->{raw_hash});
}

sub needs_rehash {
	my $self = shift;
	return $self->{validator}->needs_rehash($self->{raw_hash});
}

sub raw_hash {
	my $self = shift;
	return $self->{raw_hash};
}

1;

=head1 DESCRIPTION

This class can be useful for plugging C<Crypt::Passphrase> into some frameworks (e.g. ORMs).

=method new($crypt_passphrase, $hash)

This takes a Crypt::Passphrase object, and a hash string.

=method verify_password($password)

Verify that the password matches the hash in this object.

=method needs_rehash()

Check if the hash needs to be rehashed.

=method raw_hash()

This returns the hash of this object as a string.
