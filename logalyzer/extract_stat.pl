#!/usr/bin/perl -w

use strict;

use FindBin;                 # locate this script
use lib $FindBin::Bin; 
use Getopt::Long;
use List::MoreUtils qw(any);
use Data::Dumper;

# defaults
my $options = { };

GetOptions (
    'stats=s' => \$options->{stats},
);

unless ($options->{stats}) { die "No stats provided (--stats).\n" }

my @stats = split (/[,;]/, $options->{stats});

# assume all same run, same columns
open (my $in, '<', 'stats-all') or die "Can't open stats-all.\n";
my $line = <$in>;
close ($in);


my @columns = split (/\s+/, $line);
my %column_map = ();
for (my $i = 0; $i <= $#columns; $i++) {
    if (any { $columns[$i] eq $_ } @stats) {
        $column_map{$columns[$i]} = $i;
    }
}

#print Dumper \@columns;

#print Dumper \%column_map;

my @files = sort <stats-*.out>;

#print "@files\n";


foreach my $stat (@stats) {

    open (my $out, '>', "$stat.report") or die "Can't open $stat-report for write.\n";
    open (my $in, '<', 'stats-all') or die "Can't open stats-all.\n";

    my $column_number = $column_map{$stat};

    my $current_timestamp = "0000";
    my $current_total = 0;
    my $total = 0;

    my $ignore_headers = <$in>;

    foreach my $line (<$in>) {
        chomp $line;
        my ($timestamp, $source, $value) = (split (/\t/, $line))[0, 1, $column_number];
        $timestamp = substr ($timestamp, 0, 19);
        unless ($value =~ /^\d+$/) {
            print STDERR "Bad stat line ($line)\n";
            next;
        }
        unless ($value > 0) { next }
        if ($timestamp ne $current_timestamp) {
            # dump total from last, save as current
            if ($current_total > 0) { print $out "  total:  $current_total\n\n" }
            print $out "$timestamp\n--------------\n";
            $current_timestamp = $timestamp;
            $current_total = 0;
        }
        $current_total += $value;
        $total += $value;
        print $out "$source:  $value\n";
    }

    print $out "\n\ntotal:  $total\n";

    close ($in);
    close ($out);
}






