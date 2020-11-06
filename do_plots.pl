#!/usr/bin/perl -w

use strict;

use FindBin;                 # locate this script
use lib $FindBin::Bin; 
use Getopt::Long;
use Logalyzer::ParseState;
use Data::Dumper;

# defaults
my $options = { start => '*', end => '*', };

GetOptions (
    'start=s' => \$options->{start},
    'end=s' => \$options->{end},
    'keys=s' => \$options->{keys},
    'plots=s' => \$options->{plots},
    'nokey' => \$options->{nokey},
    'nonodes' => \$options->{nonodes},
);

my ($start, $end) = @$options{'start','end'};
if ($start ne '*') { $start =~ s/T/ /; $start = "'$start'" }
if ($end ne '*') { $end =~ s/T/ /; $end = "'$end'" }

my @key_list = ();
if ($options->{keys}) {
    @key_list = split (/\s*,\s*/, $options->{keys});
}

my $plots_defined = 0;
my @plot_list = ();
my %plot_hash = ();

if ($options->{plots}) {
    @plot_list = split (/\s*,\s*/, $options->{plots});
    print STDERR "plotting ", join (', ', @plot_list), "\n";
    $plots_defined = 1;
    foreach my $plot (@plot_list) { $plot_hash{$plot}++ }
}

my $state = new Logalyzer::ParseState();

opendir my $DIR, '.';
my @stats_files = grep { /^stats-.+out$/ } readdir $DIR;
closedir $DIR;


if (scalar @key_list) {
    # only use those that match
    print "limiting work to node keys:  @key_list.\n";
    my %keyhash;
    map { my $stats_file = "stats-$_.out"; $keyhash{$stats_file}++; } @key_list;
    @stats_files = grep { $keyhash{$_} } @stats_files;
}


if ((scalar @stats_files) < 1) { die "no node/key files found.\n" }

# assume all same run, same columns
open (my $in, '<', $stats_files[0]) or die "Can't open $stats_files[0].\n";
my $line = <$in>;
close ($in);

# read back in the dumper data, for the dynamic stats?
#open my $in, '<', 'dump_struct' or die $!;
#my $data;
#{
#    local $/;    # slurp mode
#    $data = eval <$in>;
#}
#close $in;

$line =~ s/^#//;
chomp ($line);
my @columns = split (/\t/, $line);
unless ($#columns > 0) { @columns = split (/\s*,\s*/, $line) }

for (my $i = 1; $i <= $#columns; $i++) {
    my $index = $i + 1;
    my $col = $columns[$i];
    my $title = $col;
    # skip forest stuff
    if ($title =~ /^Forest/) { next }

    print "<$col>";
    # underbar does sub a la TeX
    $title =~ s/_/\\_/g;

    # check if plots defined
    if ($plots_defined && !$plot_hash{$col}) { print '-skipping-'; next }
    if ($options->{nonodes} && $col =~ /^node-/) { print '-skipping-'; next }

    my $filename = "$col.plot";
    my $ylabel = $state->event_label ($col);
    open (my $plot, '>', $filename) or die "Can't open $filename.\n";
    if ($options->{nokey}) {
        print $plot "unset key\n";
    }
    print $plot "set terminal pdf\n";
    print $plot "set output '$col.pdf'\n";
    print $plot "set title '$title'\n";
    print $plot "set datafile separator '\\t'\n";
    print $plot "set style data points\n";
    print $plot "set xlabel 'Time'\n";
    print $plot "set timefmt '%Y-%m-%d %H:%M:%S'\n";
    print $plot "set xdata time\n";
    print $plot "set xrange [$start:$end]\n";
    #print $plot "set xtics '2020-03-11 00:00:00', '2020-03-12 00:00:00', '2020-03-13 24:00:00'\n";
    #print $plot "set xtics format '%H'\n";
    #print $plot "set xtics '2020-03-11 00:00:00',  86400, '2020-03-13 24:00:00'\n";
    #print $plot "set xtics 8640\n";  # hour
    #print $plot "set xtics 86400\n";  # day
    #print $plot "set xtics 43200\n";  # day
    print $plot "set ylabel '$ylabel'\n";
    print $plot "set yrange [0:*]\n";
    my @plots = ();
    for my $stats (@stats_files) {
        my $title = $stats;
        $title =~ s/^stats-//;  $title =~ s/\.out$//;
        $title =~ s/_/\\_/g;
        push @plots, "'$stats' using 1:(\$$index == 0 ? NaN : \$$index)  title '$title'";
    }
    print $plot "plot ", join (', ', @plots), "\n";
    close ($plot);
    system "gnuplot $filename ";
}

print "\n@columns\n";



