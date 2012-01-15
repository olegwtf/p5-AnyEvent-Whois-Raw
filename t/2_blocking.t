#!/usr/bin/env perl

use Test::More;
use Errno;
use strict;
use AnyEvent::Whois::Raw;

if( $^O eq 'MSWin32' ) {
	plan skip_all => 'Fork ~~ Windows -> False';
}

if ($< != 0) {
	plan skip_all => 'You should be root to run this test';
}

if (is_addr_in_use('127.0.0.1', 43)) {
	plan skip_all => '43 port is already in use';
}

my %rules = (
	'google.com' => {
		sleep => 2,
		info => 'Google Inc.'
	},
	'mail.com' => {
		sleep => 10,
		info => 'PSI-USA, Inc.'
	},
	'www.com' => {
		sleep => 0,
		info => 'Diagonal Axis Limited'
	},
	'2gis.com' => {
		sleep => 1,
		info => '"DoubleGIS" Ltd'
	},
	'academ.org' => {
		sleep => 3,
		info => 'Pervaya Milya'
	}
);

my ($pid, $sock) = make_whois_server(%rules);
my $start = time();
my $cv = AnyEvent->condvar;
$cv->begin for 1..scalar(keys %rules);

delete $rules{'mail.com'};
whois 'mail.com', '127.0.0.1', timeout => 3, sub {
	my ($info, $srv) = @_;
	is($info, '', 'mail.com timeout');
	ok(time()-$start < 10, 'mail.com timed out');
	$cv->end;
};

while (my ($domain, $rule) = each(%rules)) {
	whois $domain, '127.0.0.1', sub {
		my ($info, $srv) = @_;
		is($info, $rule->{info}, "$domain info");
		ok(time()-$start < $rule->{sleep}+2, "$domain was not blocked ");
		$cv->end;
	};
}

$SIG{INT} = $SIG{TERM} = sub { $sock->close() };

$cv->recv;
kill 15, $pid;
done_testing();

sub is_addr_in_use {
	my ($host, $port) = @_;
	my $sock = IO::Socket::INET->new(
		LocalHost => $host,
		LocalPort => $port,
		Listen => 1
	);
	
	if ($sock) {
		$sock->close();
		return 0;
	}
	
	return $! == Errno::EADDRINUSE;
}

sub make_whois_server {
	my %rules = @_;
	my $serv = IO::Socket::INET->new(Listen => 3, LocalAddr => '127.0.0.1', LocalPort => 43)
		or die $@;
	
	my $child = fork();
	die 'fork: ', $! unless defined $child;
	
	if ($child == 0) {
		local $/ = "\012";
		while (1) {
			my $client = $serv->accept()
				or next;
			
			my $child = fork();
			die 'subfork: ', $! unless defined $child;
			
			if ($child == 0) {
				my $domain = <$client>;
				$domain =~ s/\s*$//;
				if (exists $rules{$domain}) {
					sleep $rules{$domain}{sleep};
					print $client $rules{$domain}{info};
				}
				exit;
			}
		}
		
		exit;
	}
	
	return ($child, $serv);
}
