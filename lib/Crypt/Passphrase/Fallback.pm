package Crypt::Passphrase::Fallback;

use strict;
use warnings;

use Crypt::Passphrase -validator;

sub new {
	my ($class, %args) = @_;
	return bless {
		callback => $args{callback},
		acceptor => $args{acceptor} // sub { 1 },
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

=head1 SYNOPSIS

 sub plaintext {
	my ($password, $hash) = @_;
	return $password eq $hash;
 }

 my $passphrase = Crypt::Passphrase->new(
     encoder    => 'Argon2',
     validators => [ \&plaintext ],
 );

=head1 DESCRIPTION

This is a helper class to write ad-hoc validators. If passing a subref as a validator C<Crypt::Passphrase> will automatically wrap it in a fallback object, but it can also passed explicitly.

=head1 CONFIGURATION

This takes two named arguments:

=over 4

=item * callback

The C<verify_password> method will call this with the password and the hash, and return its return value. C<This is mandatory>.

=item * acceptor

This callback will decide if this object will try to match a hash. By default it always return true (so always accepts 

=back
