#!/usr/bin/env perl

use Test::More;
use strict;
BEGIN { use_ok('AnyEvent::Whois::Raw') }

my @domains = (
	'google.com',
	'mail.ru',
	'perl.org',
);

my $cv = AnyEvent->condvar;
$cv->begin for 1..scalar(@domains);

foreach my $domain (@domains) {
	whois $domain, sub {
		my ($data, $srv) = @_;
		utf8::encode($data);
		$data =~ s/\r//g;
		$data =~ s/\s+$//;
		
		my $nwr_data = `perl t/whois.pl $domain`;
		$nwr_data =~ s/\r//g;
		$nwr_data =~ s/\s+$//;
		is_deeply($data, $nwr_data, "Net::Whois::Raw::whois($domain) eq AnyEvent::Whois::Raw::whois($domain)");
		$cv->end;
	}
}

$cv->recv;
done_testing();
