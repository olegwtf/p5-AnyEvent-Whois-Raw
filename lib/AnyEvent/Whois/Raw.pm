package AnyEvent::Whois::Raw;

use base 'Exporter';
use Net::Whois::Raw ();
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::HTTP;
use strict;
no warnings 'redefine';

our @EXPORT_OK = qw(whois get_whois);
our $stash;

sub whois {
	my $cb = pop;
	local $stash = {};
	
	my ($res_text, $res_srv);
	while (1) {
		eval {
			($res_text, $res_srv) = Net::Whois::Raw::whois(@_);
		} and last;
	}
	
	$cb->($res_text, $res_srv);
}

sub whois_get {
	my $cb = pop;
	local $stash = {};
	
	my ($res_text, $res_srv);
	while (1) {
		eval {
			($res_text, $res_srv) = Net::Whois::Raw::get_whois(@_);
		} and last;
	}
	
	$cb->($res_text, $res_srv);
}

sub Net::Whois::Raw::whois_query {
	
}

sub whois_query_ae {
	
}

sub Net::Whois::Raw::www_whois_query {
	
}

sub www_whois_query_ae {
	
}

1;
