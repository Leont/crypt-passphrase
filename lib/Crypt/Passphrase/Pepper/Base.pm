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

=head1 SUBCLASSING

=head2 Creation

Any subclass is expected to call this class' method new with at least the following arguments.

=head3 inner

This must contain an encoder specification identical to the C<encoder> field of C<Crypt::Passphrase>.

=head3 active

The identifier of the active pepper.

=head3 algorithm

The hash that is used for password creation, it must be one from the C<supported_hashes> list

=head2 Mandatory methods

It expects the subclass to implement the following method:

=head3 prehash_password

 $pepper->prehash_password($password, $algorithm, $id)

This should prehash the C<$password> with C<$algorithm> and the pepper named by C<$id>.
