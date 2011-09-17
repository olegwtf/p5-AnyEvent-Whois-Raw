#!/usr/bin/env perl

use Net::Whois::Raw;

my $domain = shift;
my $info = whois $domain;
print $info;
