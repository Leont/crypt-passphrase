package Crypt::Passphrase::Encoder;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

use Carp ();
use Errno ();

if ($^O eq 'MSWin32') {
	eval <<'END' or die $@;
	require Win32::API;
	my $genrand = Win32::API->new('advapi32', 'INT SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength)')
		or Carp::croak("Could not import SystemFunction036: $^E");
	sub random_bytes {
		my (undef, $count) = @_;
		my $buffer = chr(0) x $count;
		$genrand->Call($buffer, $count) or Carp::croak("Could not read from csprng: $^E");
		return $buffer;
	}
	1;
END
} elsif (eval { require Sys::GetRandom }) {
	eval <<'END' or die $@;
	sub random_bytes {
		my (undef, $count) = @_;
		my ($result, $offset) = ('', 0);
		do {
			my $read = Sys::GetRandom::getrandom($result, $count - $offset, 0, $offset);
			Carp::croak("Couldn't read from csprng: $!") if not defined $read and $! != Errno::EINTR;
			$offset += $read // 0;
		} while ($offset < $count);
		return $result;
	}
	1;
END
} else {
	eval <<'END' or die $@;
	open my $urandom, '<:raw', '/dev/urandom' or Carp::croak("Couldn't open /dev/urandom: $!");
	sub random_bytes {
		my (undef, $count) = @_;
		my ($result, $offset) = ('', 0);
		do {
			my $read = sysread $urandom, $result, $count - $offset, $offset;
			Carp::croak("Couldn't read from csprng: $!") if not defined $read and $! != Errno::EINTR;
			$offset += $read // 0;
		} while ($offset < $count);
		return $result;
	}
	1;
END
}

sub crypt_subtypes;

sub accepts_hash {
	my ($self, $hash) = @_;
	return !!0 if not defined $hash;
	$self->{accepts_hash} //= do {
		my $string = join '|', $self->crypt_subtypes or return;
		qr/ \A \$ (?: $string ) [\$,] /x;
	};
	return scalar $hash =~ $self->{accepts_hash};
}

sub recode_hash {
	my ($self, $hash, @args) = @_;
	return $hash;
}

1;

#ABSTRACT: Base class for Crypt::Passphrase encoders

=head1 DESCRIPTION

This is a base class for password encoders. It is a subclass of C<Crypt::Passphrase::Validator>.

=head1 SUBCLASSING

=head2 Mandatory methods

It expects the subclass to implement the following four methods:

=head3 hash_password

 $encoder->hash_password($password)

This hashes a C<$password>. Note that this will typically return a different value each time since it uses a unique salt every time.

=head3 verify_password

 $encoder->verify_password($password, $hash)

This checks if a C<$password> satisfies C<$hash>.

=head3 needs_rehash

 $encoder->needs_rehash($hash)

This method will return true if the password hash needs a rehash. This may either mean it's using a different hashing algoritm, or because it's using different parameters.

=head3 crypt_subtypes

 $encoder->crypt_subtypes

This method returns the types of crypt entries this validator supports. This is used to implement C<accepts_hash>.

=head3 Optional methods

=head3 recode_hash

 $encoder->recode_hash($hash)

This method recodes the C<$hash> if possible. By default it will just return the hash unmodified, this is usualy what you want.

=head2 Provided methods

It provides the following methods to aid in implementing encoders:

=head3 random_bytes

 $encoder->random_bytes($count)

This is a utility method to aid in generating a good salt.

=head3 secure_compare

 $encoder->secure_compare($left, $right)

This compares two strings in a way that resists timing attacks.
