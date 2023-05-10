package Crypt::Passphrase::Encoder;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

use Crypt::URandom 0.037;

sub random_bytes {
	my ($self, $count) = @_;
	return Crypt::URandom::urandom_ub($count);
}

sub crypt_subtypes;

sub accepts_hash {
	my ($self, $hash) = @_;
	return 0 if not defined $hash;
	$self->{accepts_hash} //= do {
		my $string = join '|', $self->crypt_subtypes or return;
		qr/ \A \$ (?: $string ) \$ /x;
	};
	return $hash =~ $self->{accepts_hash};
}

sub binary_safe {
	return 1;
}

1;

#ABSTRACT: Base class for Crypt::Passphrase encoders

=head1 DESCRIPTION

This is a base class for password encoders. It is a subclass of C<Crypt::Passphrase::Validator>.

=method hash_password($password)

This hashes a password. Note that this will return a new value each time since it uses a unique hash every time.

=method needs_rehash($hash)

This method will return true if the password needs a rehash. This may either mean it's using a different hashing algoritm, or because it's using different parameters. This should be overloaded in your subclass.

=method crypt_subtypes()

This method returns the types of crypt entries this validator supports. This is used to implement C<accepts_hash>.

=method binary_safe()

This method returns true if the encoder can take arbitrary binary inputs.

=method random_bytes($count)

This is a utility method provided by the base class to aid in generating a good salt.

