package Crypt::Passphrase::Pepper::Base;

use strict;
use warnings;

use Carp 'croak';
use Crypt::Passphrase -encoder, -integration;
use MIME::Base64 'encode_base64';

sub new {
	my ($class, %args) = @_;
	my $inner = delete $args{inner} // croak('No inner encoder given to pepper');
	my $encoder = Crypt::Passphrase::_load_encoder($inner);

	croak('No peppers given') if not defined $args{active};
	croak("Invalid pepper name '$args{active}'") if $args{active} =~ /\W/;

	my $self = bless {
		%args,
		inner => $encoder,
	}, $class;

	return $self;
}

sub _to_inner {
	my $hash = shift;
	if ($hash =~ s/ (?<= \A \$) ([\w-]+?)-pepper-([\w-]+) \$ v=1 , id=([^\$,]+) /$1/x) {
		return ($hash, $2, $3);
	} elsif ($hash =~ s/ (?<= \A \$) peppered-(\w+) \$ v=1 , alg=([^\$,]+) , id=([^\$,]+) /$1/x) {
		return ($hash, $2, $3);
	} else {
		return;
	}
}

sub prehash_password;

sub hash_password {
	my ($self, $password) = @_;

	my $prehashed = $self->prehash_password($password, $self->{algorithm}, $self->{active});
	my $wrapped = encode_base64($prehashed, '') =~ tr/=//dr;
	my $hash = $self->{inner}->hash_password($wrapped);
	return $hash =~ s/ (?<= \A \$) ([^\$]+) /$1-pepper-$self->{algorithm}\$v=1,id=$self->{active}/rx;
}

sub crypt_subtypes {
	my $self = shift;
	my @result;
	my @supported = $self->supported_hashes;
	for my $inner ($self->{inner}->crypt_subtypes) {
		push @result, $inner, map { "$inner-pepper-$_" } @supported;
	}
	return @result;
}

sub needs_rehash {
	my ($self, $hash) = @_;
	my ($primary, $type, $id) = _to_inner($hash) or return 1;
	return "$type,$id" ne join(',', @{$self}{qw/algorithm active/}) || $self->{inner}->needs_rehash($primary);
}

sub verify_password {
	my ($self, $password, $hash) = @_;

	if (my ($primary, $type, $id) = _to_inner($hash)) {
		my $prehashed = eval { $self->prehash_password($password, $type, $id) } or return !!0;
		my $wrapped = encode_base64($prehashed, '') =~ tr/=//dr;
		return $self->{inner}->verify_password($wrapped, $primary);
	}
	elsif ($self->{inner}->accepts_hash($hash)) {
		return $self->{inner}->verify_password($password, $hash);
	}
	else {
		return !!0;
	}
}

1;

# ABSTRACT: A base class for pre-hashing pepper implementations

=head1 DESCRIPTION

This is a base-class for pre-peppering implementations. You probably want to use L<Crypt::Passphrase::Pepper::Simple> instead.

=method new(%args)

This creates a new C<Crypt::Passphrase::Pepper::Base>. As it's an abstract class you shouldn't call this unless you're writing a subclass.

=method hash_password($password)

This hashes the passwords with the active pepper.

=method needs_rehash($hash)

This returns true if the hash uses a different cipher or pepper, or if any of the encoder parameters is lower that desired by the encoder.

=method crypt_subtypes()

This returns all the types supported by the underlaying encoder cross joined with all supported hashes using the string C<"-pepper-"> (e.g. C<"argon2id-pepper-sha512-hmac">), as well as the underlaying types themselves.

=method verify_password($password, $hash)

This will check if a password matches the hash, supporting both peppered and unpeppered hashed with the encoder.

=method supported_hashes()

This returns the hashes that are supported for prehashing.
