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

my $state = new Logalyzer::ParseState();

GetOptions (
    'file=s' => \$state->{file},
    'glob=s' => \$state->{glob},
    'outdir=s' => \$state->{outdir},
    'granularity=s' => \$state->{granularity},
    #'min_level=s' => \$state{min_level},
    #'stats_out=s' => \$state{stats_out},
);

$state->resolve_options ();

foreach my $filename (@{$state->{filenames}}) {
    print "$filename\n";
    process_file ($filename, $state);
}

dump_stats ($state);

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
        my $stats_fh = get_fh ($state, $stats_filename);
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
    return $state->{outdir} . '/stats-' . $filename . '.out';
}

sub dump_state {
    my ($state) = @_;
    my $dumper_filename = $state;
    my $dumper_fh = get_fh ($state, $state->{outdir} . '/Dumper.out');
    print $dumper_fh (Dumper $state);
}

sub process_file {
    my ($filename, $state) = @_;
    $state->{current_file} = $filename;
    $state->{stats}{$filename} = {
        'level_counts' => {},
        'stats' => {},
    };
    open (my $in, '<', $filename) or die "Can't open $filename.\n";
    while ($state->{current_line}{line} = <$in>) {
        classify_line ($state);
        process_line ($state)
    }
    close $in;
}

sub process_line {
    my ($state) = @_;
    my $stats = $state->current_stats();

    my $line_info = $state->current_line();
    foreach my $classify (@{$line_info->{events}}) {
        my $event = $classify->{classify};
        if ($event eq 'JUNK') { return };
        my $op = $classify->{op};
        if ($op eq 'sum') {
            $stats->{$line_info->{grouping_time}}{$event} += $classify->{value};
        } elsif ($op eq 'avg') {
            push @{$stats->{$line_info->{grouping_time}}{$event}}, $classify->{value};
        } else {
            # default is count
            if (exists $stats->{$line_info->{grouping_time}}{$event}) {
                $stats->{$line_info->{grouping_time}}{$event}++;
            } else {
                $stats->{$line_info->{grouping_time}}{$event} = 1;
            }
        }
        $state->{events_seen}{$event} = 1;
        dump_line ($state, $event);
    }
    $state->{last_line} = $state->{current_line};
}

sub dump_line {
    my ($state, $event) = @_;
    my $line_info = $state->{current_line};
    my $outfile = $state->{outdir} . '/' . $event;
    # file is outdir/log-as
    # line is time line (logfile)
    my $event_fh = get_fh ($state, $outfile);
    my $to_print = join ("\t", (
        (exists $line_info->{date_time} ? $line_info->{date_time} : join ('', $state->{last_date_time}, '+')),
        $state->{current_file},
        $line_info->{line},
    ));
    print $event_fh $to_print;
    # print level-based logging
    if (exists $line_info->{level} && $state->{levels}{$line_info->{level}} >= $state->{min_level_number}) {
        $outfile = "$state->{outdir}/level-$line_info->{level}";
        $event_fh = get_fh ($state, $outfile);
        print $event_fh $to_print;
    }
}

sub get_fh {
    my ($state, $outfile) = @_;
    my $out = $state->{fh}{$outfile};
    unless ($out) {
        open ($out, '>', $outfile) or die "Can't open $outfile.\n";
        $state->{fh}{$outfile} = $out;
    }
}

sub current_line_is_junk {
    my ($line) = @_;
    if ($line =~ /^\s*$/) { return 1 }
    if ($line =~ /Info: EON_XDBC: render/) { return 1 }
    return 0;
}

sub classify_line {
    my ($state) = @_;
    # current line info
    my $line = $state->{current_line}{line};
    # current file stats
    my $stats = $state->current_file_stats();
    # default

    # quick out.  just work on this function.
    if (current_line_is_junk ($line)) {
        $state->{current_line}{events} = [{ classify => 'JUNK'}];
        return;
    }

    if ($line =~ /^(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) (\S+):\s(.*)/) {
        # default
        $state->{current_line}{events} = [{ classify => 'misc', 'op' => 'count' }];
        my ($dt, $level, $text) = ($1, $2, $3);
        $state->{date_time} = $dt;
        my $grouping_time = grouping_time ($dt, $state->{granularity});
        @{$state->{current_line}}{'date_time', 'level', 'text', 'grouping_time'}
            = ($dt, $level, $text, $grouping_time);
        # count per level
        $stats->{level_counts}{$level}++;
        # ML codes
        my $code = app_code ($text, $state->{prefixes});
        if ($code) {
            $state->{current_line}{events} = [{ classify => $code, 'op' => 'count' }];
        } elsif ($text =~ /^Merged (\d+) MB in \d+ sec at (\d+) MB/) {
            $state->{current_line}{events} = [
                { classify => 'merge', op => 'sum', value => $1 },
                { classify => 'merge-rate', op => 'avg', value => $2 },
            ];
        } elsif ($text =~ /^Hung (\d+) sec/) {
            $state->{current_line}{events} = [{ classify => 'hung', op => 'sum', value => $1 }];
        } elsif ($text =~ /^Mounted forest \S+ locally/) {
            $state->{current_line}{events} = [{ classify => 'mount', op => 'count', }];
        } elsif ($text =~ /^Starting MarkLogic Server /) {
            $state->{current_line}{events} = [{ classify => 'restart', op => 'count', }];
        }
    } elsif (length ($line) > 0) {
        $state->{current_line}{events} = [{ classify => 'sys', op => 'count', }];
    }
}

sub app_code {
    my ($text, $prefixes) = @_;
    foreach my $match ($text =~ /([A-Z]+)-([A-Z]+): /g) {
        if (exists $prefixes->{$1}) {
            return "$1-$2";
        }
    }
    return ();
}


sub grouping_time {
    my ($dt, $granularity) = @_;
    if      ($granularity eq 'minutes') {
        substr ($dt, 0, 17) . '00'
    } elsif ($granularity eq 'hours') {
        substr ($dt, 0, 14) . '00:00'
    } elsif ($granularity eq 'ten-minutes') {
        substr ($dt, 0, 15) . '0:00'
    } else {
        # seconds, or unknown
        $dt
    }
}

