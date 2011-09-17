package AnyEvent::Whois::Raw;

use base 'Exporter';
use AnyEvent;
use AnyEvent::Socket;
use AnyEvent::Handle;
use AnyEvent::HTTP;
use strict;
no warnings 'redefine';

our @EXPORT = qw(whois get_whois);
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

sub extract_known_params {
	my $args = shift;
	my %known_params = (
		timeout => 1,
		on_prepare => 1,
	);
	
	my %params;
	eval {
		for my $i (-2, -4) {
			if (exists($known_params{$args->[$i-1]})) {
				$params{$args->[$i-1]} = $args->[$i];
				delete $known_params{$args->[$i-1]};
			}
			else {
				last;
			}
		}
	};
	
	return \%params;
}

sub whois {
	local $stash = {
		caller => \&_whois,
		args => [@_],
		params => extract_known_params(\@_)
	};
	
	&_whois;
}

sub _whois {
	my $cb = pop;
	
	my ($res_text, $res_srv);
	eval {
		($res_text, $res_srv) = Net::Whois::Raw::whois(@_);
	};
	if (!$@) {
		$cb->($res_text, $res_srv);
	}
	elsif ($@ !~ /^Call me later/) {
		$cb->(undef, $@);
	}
}

sub get_whois {
	local $stash = {
		caller => \&_get_whois,
		args => [@_],
		params => extract_known_params(\@_)
	};
	
	&_get_whois;
}

sub _get_whois {
	my $cb = pop;
	
	my ($res_text, $res_srv);
	eval {
		($res_text, $res_srv) = Net::Whois::Raw::get_whois(@_);
	};
	if (!$@) {
		$cb->($res_text, $res_srv);
	}
	elsif ($@ !~ /^Call me later/) {
		$cb->(undef, $@);
	}
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
			$stash_ref->{args}->[-1]->(undef, "Connection to $srv failed: $!");
			return;
		}
		
		my @lines;
		my $handle;
		my $timer = AnyEvent->timer(
			after => exists $stash_ref->{params}{timeout} ?
					$stash_ref->{params}{timeout} :
					30,
			cb => sub {
				if ($handle && !$handle->destroyed) {
					$handle->destroy();
					$stash_ref->{args}->[-1]->(undef, "Connection to $srv timed out");
				}
			}
		);
		$handle = AnyEvent::Handle->new(
			fh => $fh,
			on_read => sub {
				my @l = split /(?<=\n)/, $_[0]->{rbuf};
				if (@lines && substr($lines[-1], -1) ne "\n") {
					$lines[-1] .= shift(@l);
				}
				push @lines, @l;
				$_[0]->{rbuf} = '';
			},
			on_error => sub {
				undef $timer;
				$handle->destroy();
				$stash_ref->{args}->[-1]->(undef, "Read error form $srv: $!");
			},
			on_eof => sub {
				undef $timer;
				local $stash = $stash_ref;
				$handle->destroy();
				$stash->{call}{whois_query} = 0;
				push @{$stash->{results}{whois_query}}, \@lines;
				$stash->{caller}->(@{$stash->{args}});
			}
		);
		
		$handle->push_write($whoisquery."\015\012");
	},
	sub {
		my ($fh) = @_;
		
		my $timeout = 30;
		if (exists $stash_ref->{params}{on_prepare}) {
			$timeout = $stash_ref->{params}{on_prepare}->($fh);
		}
		
		return exists $stash_ref->{params}{timeout} ?
			$stash_ref->{params}{timeout} :
			$timeout;
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
	    http_post $qurl->{url}, $curl->equery, headers => $headers, %{$stash->{params}}, $cb;
	}
	else {
		http_get $qurl->{url}, headers => $headers,  %{$stash->{params}}, $cb;
	}
}

1;

__END__

How Net::Whois::Raw works:
whois
	get_whois
		get_all_whois  __
		|                \
		recursive_whois   www_whois_query
		|                 [BLOCKING]  
		whois_query
		[BLOCKING]        

There are two blocking functions.

What we do:
First of all redefine two blocking functions to non-blocking AnyEvent equivalents.
Now when get_all_whois will call whois_query or www_whois_query our AnyEvent
equivalents will be started. But when AnyEvent based function called result not ready
yet and we should interrupt get_all_whois. We do it using die("Call me later").
_whois and _get_whois ready to receive exception, they uses eval to catch it and calls
callback only if there was no exceptions. When result from AnyEvent based function becomes
ready it saves result and calls _whois or _get_whois again with same arguments as before interrupt.
So, now get_all_whois will not block because result already ready. Net::Whois::Raw::whois() or
Net::Whois::Raw::get_whois() will return without exceptions and so, callback will be called.
To store current state we are using localized stash.
recursive_whois() has one problem, it catches exceptions and our die("Call me later") will not interrupt
it. We using require hook to workaround it. We replace eval with our
defined smart_eval, which will rethrow exception if it was our exception.
