package Crypt::Passphrase::Validator;

use strict;
use warnings;

1;

#ABSTRACT: Base class for Crypt::Passphrase validators

=head1 DESCRIPTION

This is a base class for validators. It requires any subclass to implement the following two methods:

=method accepts_hash($hash)

This method returns true if this validator is able to process a hash. Typically this means that it's crypt identifier matches that of the validator.

=method verify_password($password, $hash)

This checks if a C<$password> satisfies C<$hash>.
