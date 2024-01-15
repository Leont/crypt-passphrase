package Crypt::Passphrase::Validator;

use strict;
use warnings;

sub secure_compare {
	my ($self, $left, $right) = @_;
	return if length $left != length $right;
	my $r = 0;
	$r |= ord(substr $left, $_, 1) ^ ord(substr $right, $_, 1) for 0 .. length($left) - 1;
	return $r == 0 ? 1 : undef;
}

1;

#ABSTRACT: Base class for Crypt::Passphrase validators

=head1 DESCRIPTION

This is a base class for validators.

=head1 SUBCLASSING

=head2 Mandatory methods

It expects the subclass to implement the following methods:

=head3 accepts_hash

 $validator->accepts_hash($hash)

This method returns true if this validator is able to process a hash. Typically this means that it's crypt identifier matches that of the validator.

=head3 verify_password

 $validator->verify_password($password, $hash)

This checks if a C<$password> satisfies C<$hash>.

=head2 Provided methods

It provides the following helper method:

=head3 secure_compare

 $validator->secure_compare($left, $right)

This compares two strings in a way that resists timing attacks.
