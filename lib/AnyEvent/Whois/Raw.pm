package AnyEvent::Whois::Raw;

use base 'Exporter';
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::HTTP;
use strict;
no warnings 'redefine';

our @EXPORT_OK = qw(whois get_whois);
our $stash;

BEGIN {
	sub Net::Whois::Raw::smart_eval(&) {
		my @rv = eval {
			$_[0]->();
		};
		if ($@ && $@ =~ /^Call me later/) {
			die $@;
		}
		
		return @rv;
	}
	
	sub require_hook {
		my ($self, $fname) = @_;
		
		return if $fname ne 'Net/Whois/Raw.pm';
		for my $i (1..$#INC) {
			if (-e (my $tname = $INC[$i] . '/Net/Whois/Raw.pm')) {
				open(my $fh, $tname) or next;
				return ($fh, \&eval_filter);
			}
		}
		return;
	}
	
	sub eval_filter {
		return 0 if $_ eq '';
		s/\beval\s*{/smart_eval{/;
		return 1;
	}
	
	unshift @INC, \&require_hook;
	require Net::Whois::Raw;
}

sub whois {
	local $stash = {
		caller => \&_whois,
		args => [@_]
	};
	
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

sub get_whois {
	local $stash = {
		caller => \&_get_whois,
		args => [@_]
	};
	
	&_get_whois;
}

sub _get_whois {
	my $cb = pop;
	
	my ($res_text, $res_srv);
	eval {
		($res_text, $res_srv) = Net::Whois::Raw::get_whois(@_);
	}
	and $cb->($res_text, $res_srv);
}

sub Net::Whois::Raw::whois_query {
	my $call = $stash->{call}{whois_query}++;
	if ($call <= $#{$stash->{results}{whois_query}}) {
		return $stash->{results}{whois_query}[$call];
	}
	
	whois_query_ae(@_);
	die "Call me later";
}

sub whois_query_ae {
	my ($dom, $srv, $is_ns) = @_;
	
	my $whoisquery = Net::Whois::Raw::Common::get_real_whois_query($dom, $srv, $is_ns);
	my $stash_ref = $stash;
	
	tcp_connect $srv, 43, sub {
		my $fh = shift;
		unless ($fh) {
			local $stash = $stash_ref;
			$stash->{call}{whois_query} = 0;
			push @{$stash->{results}{whois_query}}, undef;
			$stash->{caller}->(@{$stash->{args}});
			return;
		}
		
		my @lines;
		my $handle; $handle = AnyEvent::Handle->new(
			fh => $fh,
			on_read => sub {
				my @l = split /(?<=\n)/, $_[0]->{rbuf};
				if (@lines && substr($lines[-1], -1) ne "\n") {
					$lines[-1] .= shift(@l);
				}
				push @lines, @l;
				$_[0]->{rbuf} = '';
			},
			on_eof => sub { 
				local $stash = $stash_ref;
				$handle->destroy();
				$stash->{call}{whois_query} = 0;
				push @{$stash->{results}{whois_query}}, \@lines;
				$stash->{caller}->(@{$stash->{args}});
			}
		);
		
		$handle->push_write($whoisquery."\015\012");
	};
}

sub Net::Whois::Raw::www_whois_query {
	my $call = $stash->{call}{www_whois_query}++;
	if ($call <= $#{$stash->{results}{www_whois_query}}) {
		return $stash->{results}{www_whois_query}[$call];
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
		push @{$stash->{results}{www_whois_query}}, undef;
		$stash->{call}{www_whois_query} = 0;
		$stash->{caller}->(@{$stash->{args}});
		return;
	}
	
	my $referer = delete $qurl->{form}{referer} if $qurl->{form} && defined $qurl->{form}{referer};
	my $method = ( $qurl->{form} && scalar(keys %{$qurl->{form}}) ) ? 'POST' : 'GET';
	my $stash_ref = $stash;
	
	my $cb = sub {
		my ($resp, $headers) = @_;
		
		if (!$resp || $headers->{Status} > 299) {
			www_whois_query_ae_request($urls, $tld);
		}
		else {
			chomp $resp;
			$resp = Net::Whois::Raw::Common::parse_www_content($resp, $tld, $qurl->{url}, $Net::Whois::Raw::CHECK_EXCEED);
			local $stash = $stash_ref;
			push @{$stash->{results}{www_whois_query}}, $resp;
			$stash->{call}{www_whois_query} = 0;
			$stash->{caller}->(@{$stash->{args}});
		}
	};
	
	my $headers = {Referer => $referer};
	if ($method eq 'POST') {
		require URI::URL;
		
		my $curl = URI::URL->new("http:");
	    $curl->query_form( %{$qurl->{form}} );
	    http_post $qurl->{url}, $curl->equery, headers => $headers, $cb;
	}
	else {
		http_get $qurl->{url}, headers => $headers, $cb;
	}
}

1;
