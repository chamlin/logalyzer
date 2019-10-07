#!/usr/bin/perl -w

use strict;

use FindBin;                 # locate this script
use lib $FindBin::Bin; 
use Logalyzer::ParseState;

my $state = new Logalyzer::ParseState();

my ($start, $end) = @ARGV;

if ($start) { $start =~ s/T/ /; $start = "'$start'" } else { $start = '*' }
if ($end) { $end =~ s/T/ /; $end = "'$end'" } else { $end = '*' }

opendir my $DIR, '.';
my @stats = grep { /^stats-.+out$/ } readdir $DIR;
#my @stats = grep { /\.tsv$/ } readdir $DIR;
closedir $DIR;

if ((scalar @stats) < 1) { die "no files found.\n" }

# assume all same run, same columns
open (my $in, '<', $stats[0]) or die "Can't open $stats[0].\n";
my $line = <$in>;
close ($in);

$line =~ s/^#//;
chomp ($line);
my @columns = split (/\t/, $line);
unless ($#columns > 0) { @columns = split (/\s*,\s*/, $line) }

for (my $i = 1; $i <= $#columns; $i++) {
    print '.';
    my $index = $i + 1;
    my $col = $columns[$i];
    my $title = $col;
if ($title =~ /^Forest/) { 
    next
}
    # underbar does sub a la TeX
    $title =~ s/_/\\_/g;
    my $filename = "$col.plot";
    my $ylabel = $state->event_label ($col);
    open (my $plot, '>', $filename) or die "Can't open $filename.\n";
    print $plot "set terminal pdf\n";
    print $plot "set output '$col.pdf'\n";
    print $plot "set title '$title'\n";
    print $plot "set datafile separator '\\t'\n";
    print $plot "set style data points\n";
    print $plot "set xlabel 'Time'\n";
    print $plot "set timefmt '%Y-%m-%d %H:%M:%S'\n";
    print $plot "set xdata time\n";
    print $plot "set xrange [$start:$end]\n";
    print $plot "set ylabel '$ylabel'\n";
    print $plot "set yrange [0:*]\n";
    my @plots = ();
    for my $stats (@stats) {
        my $title = $stats;
        $title =~ s/^stats-//;  $title =~ s/\.out$//;
        $title =~ s/_/\\_/g;
        push @plots, "'$stats' using 1:(\$$index == 0 ? NaN : \$$index)  title '$title'";
    }
    print $plot "plot ", join (', ', @plots), "\n";
    close ($plot);
    system "gnuplot $filename";
}

print "\n@columns\n";



