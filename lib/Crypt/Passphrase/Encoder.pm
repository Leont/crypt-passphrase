package Crypt::Passphrase::Encoder;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

use Carp 'croak';

my $csprng = ($^O eq 'MSWin32') ?
	do {
	require Win32::API;
	my $genrand = Win32::API->new('advapi32', 'INT SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength)') or croak "Could not import SystemFunction036: $^E";
	sub {
		my $count = shift;
		$genrand->Call(my $buffer, $count) or croak "Could not read from csprng: $^E";
		return $buffer;
	}
} :
do {
	open my $urandom, '<:raw', '/dev/urandom' or croak 'Couldn\'t open /dev/urandom';
	sub {
		my $count = shift;
		read $urandom, my $buffer, $count or croak "Couldn't read from csprng: $!";
		return $buffer;
	}
};

sub random_bytes {
	my ($self, $count) = @_;
	return $csprng->($count);
}

sub crypt_subtypes {
	return;
}

sub accepts_hash {
	my ($self, $hash) = @_;
	my $subtypes = join '|', $self->crypt_subtypes or return;
	return $hash =~ / \A \$ (?: $subtypes ) \$ /x;
}

1;

#ABSTRACT: Base class for Crypt::Passphrase encoders

=head1 DESCRIPTION

This is a base class for password encoders. It is a subclass of C<Crypt::Passphrase::Validator>.

=method hash_password($password)

This hashes a password. Note that this will return a new value each time since it uses a unique hash every time.

=method needs_rehash($hash)

This method will return true if the password needs a rehash. This may either mean it's using a different hashing algoritm, or because it's using different parameters. This should be overloaded in your subclass.

=method crypt_types()

This method returns the types of crypt entries this validator supports. This is used to implement C<accepts_hash>.

=method random_bytes($count)

This is a utility method provided by the base class to aid in generating a good salt.

