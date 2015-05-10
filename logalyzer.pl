#!/opt/local/bin/perl -w

# $Id: logalyzer.pl 28 2015-04-07 17:54:54Z chamlin $

# separator
# usage
# stats file

use strict;
use Getopt::Long;
use Data::Dumper;
use FindBin;                 # locate this script
use lib $FindBin::Bin; 
use Logalyzer::ParseState;

use open qw< :encoding(UTF-8) >;

my $state = new Logalyzer::ParseState();

GetOptions (
    'file=s' => \$state->{file},
    'glob=s' => \$state->{glob},
    'outdir=s' => \$state->{outdir},
    'junk=s' => \$state->{junk},
    'granularity=s' => \$state->{granularity},
    'testconfig' => \$state->{testconfig},
    'namefrom=s' => \$state->{namefrom},
    'nameto=s' => \$state->{nameto},
    #'min_level=s' => \$state{min_level},
    #'stats_out=s' => \$state{stats_out},
);

$state->resolve_options ();

$state->process_files ();

#dump_stats ($state);


$state->end_run;

dump_state ($state);

############## subs

sub dump_stats {
    my ($state) = @_;
    # get all rows (timestamps), ordered
    foreach my $filename (keys %{$state->{stats}}) {
        foreach my $timestamp (keys %{$state->{stats}{$filename}{stats}}) {
            $state->{timestamps}{$timestamp} = 1;
        }
    }
    my @rows = sort keys %{$state->{timestamps}};
    # get all columns (events)
    my @columns = sort keys %{$state->{events_seen}};
    foreach my $filename (keys %{$state->{stats}}) {
        my $file_stats = $state->{stats}{$filename}{stats};
        my $stats_filename = get_stats_filename ($state, $filename);
        my $stats_fh = $state->get_fh ($stats_filename);
        # header
        print $stats_fh ("#timestamp\t", join ($state->{separator}, @columns), "\n");
        foreach my $row (@rows) {
            my @vals = ($row);
            foreach my $column (@columns) {
                if (defined $file_stats->{$row}{$column}) { 
                    push @vals, get_stats_value ($state, $column, $file_stats->{$row}{$column});
                } else {
                    push @vals, 0;
                }
            }
            print $stats_fh (join ($state->{separator}, @vals, "\n"));
        }
    }
}

sub get_stats_value {
    my ($state, $event, $stats) = @_;
    my $retval = $stats;
    my $op = $state->event_op ($event);
    if ($op eq 'avg') {
        my $sum = 0;
        foreach my $stat (@$stats) { $sum += $stat }
        $retval = int ( ($sum / scalar (@$stats)) + 0.5 );
    }
    return $retval;
};

sub get_stats_filename {
    my ($state, $filename) = @_;
    # watch for directorys in filenames
    $filename =~ s/^\.\///;
    $filename =~ s/\//_/g;
    return $state->{outdir} . '/stats-' . $filename . '.out';
}

