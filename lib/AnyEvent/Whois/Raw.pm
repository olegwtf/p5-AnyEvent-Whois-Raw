package AnyEvent::Whois::Raw;

use base 'Exporter';
use Net::Whois::Raw ();
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::HTTP;
use strict;
no warnings 'redefine';

our @EXPORT_OK = qw(whois get_whois);
our %stash;

sub whois {
	local %stash = (
		caller => \&_whois,
		args => [@_]
	);
	
	&_whois;
}

sub _whois {
	my $cb = pop;
	
	my ($res_text, $res_srv);
	eval {
		($res_text, $res_srv) = Net::Whois::Raw::whois(@_);
	}
	and $cb->($res_text, $res_srv);
}

sub whois_get {
# 	my $cb = pop;
# 	local %stash = {};
# 	
# 	my ($res_text, $res_srv);
# 	while (1) {
# 		eval {
# 			($res_text, $res_srv) = Net::Whois::Raw::get_whois(@_);
# 		} and last;
# 	}
# 	
# 	$cb->($res_text, $res_srv);
}

sub Net::Whois::Raw::whois_query {
	
}

sub whois_query_ae {
	
}

sub Net::Whois::Raw::www_whois_query {
	my $call = ++$stash{call}{www_whois_query_ae};
	if ($call % 2 == 0) {
		return $stash{results}{www_whois_query}[-1];
	}
	
	www_whois_query_ae(@_);
	die "Call me later";
}

sub www_whois_query_ae {
	my ($dom) = (lc shift);
	
	my ($resp, $url);
	my ($name, $tld) = Net::Whois::Raw::Common::split_domain( $dom );
	my @http_query_urls = @{Net::Whois::Raw::Common::get_http_query_url($dom)};
	
	www_whois_query_ae_request(\@http_query_urls, $tld);
}

sub www_whois_query_ae_request {
	my ($urls, $tld) = @_;
	
	my $qurl = shift @$urls;
	unless ($qurl) {
		push @{$stash{results}{www_whois_query}}, undef;
		$stash{caller}->(@{$stash{args}});
	}
	
	my $referer = delete $qurl->{form}{referer} if $qurl->{form} && defined $qurl->{form}{referer};
	my $method = ( $qurl->{form} && scalar(keys %{$qurl->{form}}) ) ? 'POST' : 'GET';
	
	my $cb = sub {
		my ($resp, $headers) = @_;
		
		if (!$resp || $headers->{Status} > 299) {
			www_whois_query_ae_request($urls, $tld);
		}
		else {
			chomp $resp;
			$resp =~ s/\r//g;
			$resp = Net::Whois::Raw::Common::parse_www_content($resp, $tld, $qurl->{url}, $Net::Whois::Raw::CHECK_EXCEED);
			push @{$stash{results}{www_whois_query}}, $resp;
			$stash{caller}->(@{$stash{args}});
		}
	};
	
	if ($method eq 'POST') {
		require URI::URL;
		
		my $curl = URI::URL->new("http:");
	    $curl->query_form( %{$qurl->{form}} );
	    http_post $qurl->{url}, $curl->equery, $cb;
	}
	else {
		http_get $qurl->{url}, $cb;
	}
}

1;
