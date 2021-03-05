package Crypt::Passphrase::Fallback;

use strict;
use warnings;

use parent 'Crypt::Passphrase::Validator';

sub new {
	my ($class, %args) = @_;
	return bless {
		callback => $args{callback},
		acceptor => $args{acceptor} || sub { 1 },
	}, $class;
}

sub accepts_hash {
	my ($self, $hash) = @_;
	return $self->{acceptor}->($hash);
}

sub verify_password {
	my ($self, $password, $hash) = @_;
	return $self->{callback}->($password, $hash);
}

1;

#ABSTRACT: a fallback validator for Crypt::Passphrase

=method new(%args)

This method takes two named arguments

=over 4

=item * callback

The C<verify_password> method will call this with the password and the hash, and return its return value.

=item * acceptor

This callback will decide if this object will take a hash. By default it accepts anything.

=back
