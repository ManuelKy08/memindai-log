#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use Time::Piece;
use Term::ANSIColor;

my $banner = <<'EOB';
██╗  ██╗ ██████╗ ██╗  ██╗ ██████╗ ██╗  ██╗     ███████╗███████╗ ██████╗
██║ ██╔╝██╔═══██╗██║ ██╔╝██╔═══██╗██║ ██╔╝     ██╔════╝██╔════╝██╔════╝
█████╔╝ ██║   ██║█████╔╝ ██║   ██║█████╔╝█████╗███████╗█████╗  ██║     
██╔═██╗ ██║   ██║██╔═██╗ ██║   ██║██╔═██╗╚════╝╚════██║██╔══╝  ██║     
██║  ██╗╚██████╔╝██║  ██╗╚██████╔╝██║  ██╗     ███████║███████╗╚██████╗
╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝     ╚══════╝╚══════╝ ╚═════╝
 ====================================================================
 **                  Instagram : @risky.manuel                     **
 **                  Telegram  : @kikikokok9                       **
 **                  Email     : riskymanuel08@proton.me           **
 ====================================================================
EOB

print color('bold cyan'), $banner, color('reset');

my $log_file;
my $output_file;
my $time_window = 300;
my $login_threshold = 5;
my $dos_threshold = 100;
my $scan_threshold = 10;
my $verbose = 0;

GetOptions(
    "R=s" => \$log_file,
    "output=s" => \$output_file,
    "window=i" => \$time_window,
    "login-threshold=i" => \$login_threshold,
    "dos-threshold=i" => \$dos_threshold,
    "scan-threshold=i" => \$scan_threshold,
    "verbose" => \$verbose
) or die "Error in command line arguments\n";

die "Error: Anda harus memberikan file log dengan -R <log_file>\n" unless $log_file;
die "Error: File log '$log_file' tidak ditemukan.\n" unless -e $log_file;

my %ip_requests;
my %failed_logins;
my %port_scans;
my %user_agents;
my %http_methods;
my %status_codes;

open(my $fh, '<', $log_file) or die "Could not open file '$log_file': $!";

print color('bold green'), "Mencari log file: $log_file\n", color('reset');

while (my $line = <$fh>) {
    chomp $line;
    if ($line =~ /(\S+) (\S+) \[(.+?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/) {
        my ($ip, $timestamp, $method, $url, $status, $user_agent) = ($1, $3, $4, $5, $7, $10);
        my $time = Time::Piece->strptime($timestamp, "%d/%b/%Y:%H:%M:%S %z")->epoch;

        $failed_logins{$ip}{$time}++ if $status eq '401' || $status eq '403';
        $ip_requests{$ip}{$time}++;
        $port_scans{$ip}{$1} = 1 if $url =~ /:(\d+)/;
        $user_agents{$user_agent}++;
        $http_methods{$method}++;
        $status_codes{$status}++;
    }
}

close $fh;

my $current_time = time;
my @alerts;

foreach my $ip (keys %failed_logins) {
    my $recent_fails = grep { $_ > $current_time - $time_window } keys %{$failed_logins{$ip}};
    push @alerts, colored(['bold red'], "Potential brute force attack detected from IP: $ip (Failed logins: $recent_fails)") if $recent_fails >= $login_threshold;
}

foreach my $ip (keys %ip_requests) {
    my $recent_requests = grep { $_ > $current_time - $time_window } keys %{$ip_requests{$ip}};
    push @alerts, colored(['bold red'], "Potential DoS attack detected from IP: $ip (Requests: $recent_requests)") if $recent_requests >= $dos_threshold;
}

foreach my $ip (keys %port_scans) {
    my $unique_ports = keys %{$port_scans{$ip}};
    push @alerts, colored(['bold red'], "Potential port scan detected from IP: $ip (Unique ports: $unique_ports)") if $unique_ports >= $scan_threshold;
}

if (@alerts) {
    print color('bold yellow'), "\nDetected Threats:\n", color('reset');
    print join("\n", @alerts), "\n";
} else {
    print color('bold green'), "\nTidak ada ancaman yang terdeteksi.\n", color('reset');
}

print color('bold blue'), "\nStatistics:\n", color('reset');
print "Top 5 User Agents:\n";
print_top_5(\%user_agents);
print "\nHTTP Methods Distribution:\n";
print_distribution(\%http_methods);
print "\nStatus Codes Distribution:\n";
print_distribution(\%status_codes);

if ($output_file) {
    open(my $out_fh, '>', $output_file) or die "Could not open file '$output_file': $!";
    print $out_fh "Log Analysis Results\n\n";
    print $out_fh "Detected Threats:\n", map { s/\e\[[\d;]*m//g; "$_\n" } @alerts;
    print $out_fh "\nStatistics:\n";
    print_to_file($out_fh, \%user_agents, "Top User Agents");
    print_to_file($out_fh, \%http_methods, "HTTP Methods Distribution");
    print_to_file($out_fh, \%status_codes, "Status Codes Distribution");
    close $out_fh;
    print color('bold green'), "\nResults written to $output_file\n", color('reset');
}

print color('bold green'), "Scan Log Berhasil Pak.\n", color('reset');

sub print_top_5 {
    my ($hash_ref) = @_;
    my @sorted = sort { $hash_ref->{$b} <=> $hash_ref->{$a} } keys %$hash_ref;
    my @top5 = @sorted[0..4];
    foreach my $key (@top5) {
        printf "%-40s: %d\n", substr($key, 0, 40), $hash_ref->{$key};
    }
}

sub print_distribution {
    my ($hash_ref) = @_;
    foreach my $key (sort keys %$hash_ref) {
        printf "%-10s: %d\n", $key, $hash_ref->{$key};
    }
}

sub print_to_file {
    my ($fh, $hash_ref, $title) = @_;
    print $fh "\n$title:\n";
    foreach my $key (sort { $hash_ref->{$b} <=> $hash_ref->{$a} } keys %$hash_ref) {
        printf $fh "%-40s: %d\n", substr($key, 0, 40), $hash_ref->{$key};
    }
}

sub format_alerts {
    my @alerts = @_;
    return join("\n", map { s/\e\[[\d;]*m//gr } @alerts);
}
