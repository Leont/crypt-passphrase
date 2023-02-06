#!perl

use strict;
use warnings;

use Test::More;

use Crypt::Passphrase;
use Crypt::Passphrase::MD5::Hex;

my $validator = Crypt::Passphrase::MD5::Hex->new;

ok($validator->accepts_hash('098f6bcd4621d373cade4e832627b4f6'));
ok($validator->verify_password('test', '098f6bcd4621d373cade4e832627b4f6'));

my $passphrase = Crypt::Passphrase->new(encoder => $validator); # naughty
ok $passphrase->verify_password('test', '098f6bcd4621d373cade4e832627b4f6');
ok !$passphrase->verify_password('test', '098f6bcd4621d373');

done_testing;
