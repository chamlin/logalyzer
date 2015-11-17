# $Id: ParseState.pm 29 2015-04-07 18:23:55Z chamlin $

package Logalyzer::ParseState;

use Data::Dumper;

my $_prefixes = {
    ADMIN => 1,
    ALERT => 1,
    BUILD => 1,
    CPF => 1,
    DBG => 1,
    DHF => 1,
    DLS => 1,
    FLEXREP => 1,
    HADOOP => 1,
    ICN => 1,
    INFO => 1,
    MANAGE => 1,
    OI => 1,
    PKG => 1,
    PKI => 1,
    PROF => 1,
    RESTAPI => 1,
    REST => 1,
    SEARCH => 1,
    SEC => 1,
    SER => 1,
    SQL => 1,
    SSL => 1,
    SVC => 1,
    TEMPORAL => 1,
    THSR => 1,
    TRGR => 1,
    TS => 1,
    VIEW => 1,
    X509 => 1,
    XDMP => 1,
    XI => 1,
    XSLT => 1,
};



my $_levels = {
    'Finest' => 0,
    'Finer' => 1,
    'Fine' => 2,
    'Debug' => 3,
    'Config' => 4,
    'Info' => 5,
    'Notice' => 6,
    'Warning' => 7,
    'Error' => 8,
    'Critical' => 9,
    'Alert' => 10,
    'Emergency' => 11,
};

my $_event_info = {
    merge => { op => 'sum',  label => 'total (MB)' },
    'merge-rate' => { op => 'avg',  label => 'mean (MB/s)' },
    'delete-rate' => { op => 'avg',  label => 'mean (MB/s)' },
    'save-rate' => { op => 'avg',  label => 'mean (MB/s)' },
    hung => { op => 'sum',  label => 'total (s)' },
    default => { op => 'count',  label => 'count' },
};

sub new {
    my $class = shift;
    my $blank = {
        'file' => undef,
        'glob' => undef,
        'namefrom' => '',
        'nameto' => '',
        'filenames' => [],
        'min_level' => 'Notice',
        'granularity' => 'none',
        'legal_granularities' => { minutes => 1, hours => 1, 'ten-minutes' => 1 },
        'separator' => "\t",
        'level-counts' => [],
        'levels' => $_levels,
        'prefixes' => $_prefixes,
        'event_info' => $_event_info,
        'states' => {},
        'testconfig' => 0,
        'junk' => undef,
        'outdir' => 'logalyzer-out',
        'fn' => {},
        'stats' => {},
        'started' => time(),
        'min_time' => undef,
        'max_time' => undef,
    };
    return bless $blank, $class;
}

# get it, open if needed.
sub get_fh {
    my ($self, $outfile) = @_;
    my $out = $self->{fh}{$outfile};
    unless ($out) {
        open ($out, '>', $outfile) or die "Can't open $outfile.\n";
        print STDERR "> $outfile\n";
        $self->{fh}{$outfile} = $out;
    }
    return $out;
}

sub close_fh {
    my ($state, $outfile) = @_;
    my $out = $state->{fh}{$outfile};
    if ($out) {
        close ($out);
        delete $state->{fh}{$outfile};
    }
}


sub end_run {
    my ($self) = @_;
    $self->{timer} = time() - $self->{started};
    delete $self->{started};
}

sub current_line {
    my ($self) = @_;
    return $self->{current_line};
}

sub event_label { 
    my ($self, $event) = @_;
    if (exists $self->{event_info}{$event}) {
        return $self->{event_info}{$event}{label};
    }
    return $self->{event_info}{default}{op};
}

sub event_op { 
    my ($self, $event) = @_;
    if (exists $self->{event_info}{$event}) {
        return $self->{event_info}{$event}{op};
    }
    return $self->{event_info}{default}{op};
}

sub get_logfile_key {
    my ($state, $filename) = @_;
    my $back = $filename;
    # watch for directorys in filenames
    if ($state->{namefrom}) {
        $back =~ s/$state->{namefrom}/$state->{nameto}/;
    }
    return $back;
}

# get options, set up config
sub resolve_options {
    my ($self) = @_;

    my $exit_with_usage = 0;

    $self->{min_level_number} = $self->{levels}{$self->{min_level}};

    # check files in
    if   ($self->{glob}) { $self->{filenames} = [grep { -f } glob ($self->{glob}) ]}
    elsif ($self->{file}) { $self->{filenames} = [grep { -f } (split (',', $self->{file}))] }
    else { }
    unless (scalar @{$self->{filenames}}) { print STDERR "No filenames provided/found.\n"; $exit_with_usage = 1; }
    # for testing, so keys dump in config run
    foreach my $filename (@{$self->{filenames}}) {
        push @{$self->{filekeys}}, $self->get_logfile_key ($filename);
    }

    $self->init_files();

    if ($self->{testconfig}) {
        $self->end_run;
        print STDERR "Config only: \n", Dumper $self;
        exit 1;
    }

    # dir out
    unless ($self->{outdir}) { $self->{outdir} = "logalyzer-out" }
    $self->{outdir} =~ s{/+$}{};
    unless (-d $self->{outdir}) { mkdir $self->{outdir} }
    unless (-d $self->{outdir}) { print STDERR "Can't find/make dir $self->{outdir}.\n"; $exit_with_usage = 1; }
    my $granularity = $self->{granularity};
    if ($granularity eq 'none') {
        $self->{granularity} = 'minutes'
    } else {
        unless ($self->{legal_granularities}{$granularity}) {
            my $s = "$granularity not legal granularity (legal: " . join (', ', (keys %{$self->{legal_granularities}})) . ").\n";
            print STDERR $s;
            $exit_with_usage = 1;;
        }
    }

    if ($exit_with_usage) {
        $self->usage();
        exit 1;
    }
}

# get a line for fileinfo structure, classify it
sub get_log_line {
    my ($self, $filename) = @_;
    my $file_info = $self->{file_info}{$filename};
    if ($file_info->{done}) { return }
    my $fh = $file_info->{fh};
    unless ($fh) { die "Read on closed fh $filename.\n" }

    my $continue = 1;
    while ($continue) {
        # TODO eventually, multiline events
        my $line = <$fh>;
        $file_info->{lines_read}++;
        if (defined ($line)) {
            $file_info->{current_line}{line} = $line;
            $self->classify_line ($file_info);
            # stop if final (over max time) and  get out when you don't have junk, otherwise continue
            if ($file_info->{current_line}{events}[0]{classify} eq '_FINAL_') {
                $file_info->{current_line}{line} = undef;
                close $file_info->{fh};
                delete $file_info->{fh};
                $file_info->{done} = 1;
                $continue = 0;
            } elsif ($file_info->{current_line}{events}[0]{classify} ne '_JUNK_') {
                $continue = 0;
            }
        } else {
            # eof
            $file_info->{current_line}{line} = undef;
            close $file_info->{fh};
            delete $file_info->{fh};
            $file_info->{done} = 1;
            $continue = 0;
        }
    }
};


sub grouping_time {
    my ($self, $dt) = @_;
    my $granularity = $self->{granularity};
    if      ($granularity eq 'minutes') {
        substr ($dt, 0, 17) . '00'
    } elsif ($granularity eq 'ten-minutes') {
        substr ($dt, 0, 15) . '0:00'
    } elsif ($granularity eq 'hours') {
        substr ($dt, 0, 14) . '00:00'
    } elsif ($granularity eq 'days') {
        substr ($dt, 0, 12) . '00:00:00'
    } else {
        # seconds, or unknown
        $dt
    }
}

sub process_files {
    my ($self) = @_;
    while (scalar @{$self->{logfh}}) { $self->process_line (); }
}

my $min_fh = { current_line => { date_time => '9999-99-99'}, done => 1 };

sub process_line {
    my ($self) = @_;
    
    # go through fh array, get min-time line
    my @not_done = ();
    # phony baloney sentinel
    my $min = $min_fh;
    for (my $i = 0; $i <= $#{$self->{logfh}}; $i++) {
        my $filefh = $self->{logfh}[$i];
        if (! $filefh->{done}) {
            push @not_done, $filefh;
            if ($filefh->{current_line}{date_time} lt $min->{current_line}{date_time}) {
                $min = $filefh
            }
        }
    }

    # keep the ones not done
    $self->{logfh} = \@not_done;

    if ($min->{done}) { return }

    # use the line in the min
    unless (exists $self->{stats}{$min->{key}}{stats})  { $self->{stats}{$min->{key}}{stats} = {} }
    my $stats = $self->{stats}{$min->{key}}{stats};

    my $line_info = $min->{current_line};

    foreach my $classify (@{$line_info->{events}}) {
        my $event = $classify->{classify};
        if ($event eq '_JUNK_') { last }
        $self->{events_seen}{$event} += 1;
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
    }

    $self->dump_line ($min);

    # refresh the min
    $self->get_log_line ($min->{filename});
}

# print line out
sub dump_line {
    my ($self, $logfh) = @_;
    my $line_info = $logfh->{current_line};
    if ($line_info->{done}) { return }
    my $to_print = join ("\t", (
        $line_info->{date_time},
        $logfh->{filename},
        $line_info->{line},
    ));
    foreach my $event (@{$line_info->{events}}) {
        my $outfile = $self->{outdir} . '/' . $event->{classify};
        # file is outdir/log-as
        # line is time line (logfile)
        my $event_fh = $self->get_fh ($outfile);
        print $event_fh $to_print;
    }
}

sub app_code {
    my ($self, $text) = @_;
    my $prefixes = $self->{prefixes};
    my @codes = ();
    while ($text =~ /([A-Z]+|X509)-([A-Z]+): /g) {
        if (exists $prefixes->{$1}) {
            push @codes, "$1-$2";
        }
    }
    return @codes;
}


sub classify_line {
    my ($self, $file_info) = @_;

    my $line_info = $file_info->{current_line};
    my $line = $line_info->{line};

    # for default
    $line_info->{date_time} = $file_info->{date_time};
    $line_info->{grouping_time} = $file_info->{grouping_time};

    # quick out.  just work on this function.
    if ($self->{junk} && $line =~ /$self->{junk}/) {
        $line_info->{events} = [{ classify => '_JUNK_'}];
        return;
    }

    if ($line =~ /^(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) (\S+):\s(.*)/) {
        my ($dt, $level, $text) = ($1, $2, $3);
        if    ($self->{min_time} && ($self->{min_time} gt $dt)) {
            # ignore if too early
            $line_info->{events} = [{ classify => '_JUNK_'}];
            return;
        } elsif ($self->{max_time} && ($self->{max_time} le $dt)) {
            # stop if too late
            $line_info->{events} = [{ classify => '_FINAL_'}];
            return;
        }
        my $grouping_time = $self->grouping_time ($dt);
        @{$line_info}{'date_time', 'level', 'text', 'grouping_time'}
            = ($dt, $level, $text, $grouping_time);
        $file_info->{date_time} = $dt;
        $file_info->{grouping_time} = $grouping_time;
        # count per level
        $stats->{level_counts}{$level}++;
        $line_info->{events} = [];
        my $events = $line_info->{events};
        # ML codes
        foreach my $code ($self->app_code ($text)) {
            push @$events, { classify => $code, 'op' => 'count' };
        }
        # levels
        if ($self->{levels}{$level} >= $self->{min_level_number}) {
            push @$events, { classify => $level, op => 'count', value => 1 };
        }
        # other stuff
        if ($text =~ /^Merged (\d+) MB in \d+ sec at (\d+) MB/) {
            push @$events, (
                { classify => 'merge', op => 'sum', value => $1 },
                { classify => 'merge-rate', op => 'avg', value => $2 },
            );
        } elsif ($text =~ /^Deleted (\d+) MB in \d+ sec at (\d+) MB/) {
            push @$events, (
                { classify => 'delete', op => 'sum', value => $1 },
                { classify => 'delete-rate', op => 'avg', value => $2 },
            );
        } elsif ($text =~ /^Saved (\d+) MB in \d+ sec at (\d+) MB/) {
            push @$events, (
                { classify => 'save', op => 'sum', value => $1 },
                { classify => 'save-rate', op => 'avg', value => $2 },
            );
        } elsif ($text =~ /^Hung (\d+) sec/) {
            push @$events, { classify => 'hung', op => 'sum', value => $1 };
        } elsif ($text =~ /^Mounted forest \S+ locally/) {
            push @$events, { classify => 'mount', op => 'count', };
        } elsif ($text =~ /^Merging /) {
            push @$events, { classify => 'merging', op => 'count', };
        } elsif ($text =~ /^Saving /) {
            push @$events, { classify => 'saving', op => 'count', };
        } elsif ($text =~ /^Detecting (indexes|compatability) for database/) {
            push @$events, { classify => 'detecting', op => 'count', };
        } elsif ($text =~ /^Retrying /) {
            push @$events, { classify => 'retry', op => 'count', };
        } elsif ($text =~ /^Starting MarkLogic Server /) {
            push @$events, { classify => 'restart', op => 'count', };
        }
        # default
        unless (scalar @$events) {
            $line_info->{events} = [{ classify => 'misc', 'op' => 'count' }];
        }
    } elsif (length ($line) > 0) {
        $line_info->{events} = [{ classify => 'sys', op => 'count', }];
    } else {
        # empty line?
    }
}

sub init_files {
    my ($self) = @_;
# init stats, init fh
    foreach my $filename (@{$self->{filenames}}) {
        my $key = $self->get_logfile_key ($filename);
        my $fh = undef;
        open ($fh, '<', $filename) or die "Can't open $filename.\n";
        print STDERR '< ', $filename, "\n";
        my $file_info = {
            'filename' => $filename,
            'key' => $key,
            'fh' => $fh,
            'lines_read' => 0,
            'date_time' => '1900-01-01 00:00:00',
            'grouping_time' => $self-> grouping_time ('1900-01-01 00:00:00'),
        };
        $self->{file_info}{$filename} = $file_info;
        # read list, removed when done
        push @{$self->{logfh}}, $file_info;
        $self->get_log_line ($filename);
    }
};

sub dump_state {
    my ($self) = @_;
    my $dumper_filename = $self;
    my $dumper_fh = $self->get_fh ($self->{outdir} . '/Dumper.out');
    print $dumper_fh (Dumper $self);
}

#### stats

sub dump_stats_new {
    my ($self) = @_;

    my $outfile = $self->{outdir} . '/' . 'stats-all';
    my $stats_fh = $self->get_fh ($outfile);

    my %all = ();
    $self->{all} = \%all;
    # file as timestamp, node, event, value(s)
    foreach my $key (keys %{$self->{stats}}) {
        $self->{keys}{$key}++;
        foreach my $timestamp (keys %{$self->{stats}{$key}{stats}}) {
            $self->{timestamps}{$timestamp} = 1;
            $all{$timestamp}{$key} = $self->{stats}{$key}{stats}{$timestamp};
        }
    }

    # get all columns (events)
    my @columns = sort keys %{$self->{events_seen}};

    # header
    print $stats_fh ("timestamp\tsource\t", join ($self->{separator}, @columns), "\n");

    foreach my $timestamp (sort keys %{$self->{timestamps}}) {
        foreach my $key (sort keys %{$self->{keys}}) {

            my @vals = ($timestamp, $key);

            my $stats = $self->{all}{$timestamp}{$key};

            foreach my $column (@columns) {

                if (defined $stats->{$column}) { 
                    push @vals, $self->get_stats_value ($column, $stats->{$column});
                } else {
                    push @vals, '0';
                }
            }

            print $stats_fh (join ($self->{separator}, @vals), "\n");
        }
    }
}

sub dump_stats {
    my ($self) = @_;
    # get all rows (timestamps), ordered
    foreach my $filename (keys %{$self->{stats}}) {
        foreach my $timestamp (keys %{$self->{stats}{$filename}{stats}}) {
            $self->{timestamps}{$timestamp} = 1;
        }
    }

    my @rows = sort keys %{$self->{timestamps}};
    # get all columns (events)
    my @columns = sort keys %{$self->{events_seen}};
    foreach my $filename (keys %{$self->{stats}}) {
        my $file_stats = $self->{stats}{$filename}{stats};
        my $stats_filename = $self->get_stats_filename ($filename);
        my $stats_fh = $self->get_fh ($stats_filename);
        # header
        print $stats_fh ("#timestamp\t", join ($self->{separator}, @columns), "\n");
        foreach my $row (@rows) {
            my @vals = ($row);
            foreach my $column (@columns) {
                if (defined $file_stats->{$row}{$column}) { 
                    push @vals, $self->get_stats_value ($column, $file_stats->{$row}{$column});
                } else {
                    push @vals, 0;
                }
            }
            print $stats_fh (join ($self->{separator}, @vals, "\n"));
        }
    }

# my $op = $self->event_op ($event);
}

sub get_stats_value {
    my ($self, $event, $stats) = @_;
    my $retval = $stats;
    my $op = $self->event_op ($event);
    if ($op eq 'avg') {
        my $sum = 0;
        foreach my $stat (@$stats) { $sum += $stat }
        $retval = int ( ($sum / scalar (@$stats)) + 0.5 );
    }
    return $retval;
};

sub get_stats_filename {
    my ($self, $filename) = @_;
    # watch for directorys in filenames
    $filename =~ s/^\.\///;
    $filename =~ s/\//_/g;
    return $self->{outdir} . '/stats-' . $filename . '.out';
}


sub usage {
  my ($self) = @_;

  my $legal_granularities = join (', ', keys %{$self->{legal_granularities}});

  my $usage = <<"END_MESSAGE";

Logalyzer: 

    Splits up MarkLogic logs into events and levels, keeps stats.

    Output:  files for each message; for certain events (e.g., restarts); and for log levels.  Also stats files for events.

Options:

    --testconfig
        resolve options, dump state, and stop.

    --file XXX
        XXX is a filename, or filenames together separated by commas.
    --glob XXX
        XXX is a glob pattern.  For example, --glob "Err*.txt"  will select all ErrorLogs in the current directory.

        One of file or glob must be specified.

    --mintime
        timestamps lexically greater than or equal to this are retained (e.g., --mintime '2015-04-12 12:00:00')

    --maxtime
        timestamps lexically less than this are retained (e.g., --maxtime '2015-04-12 13:00:00')

    --namefrom
        regex to match in filenames, to transform them to a key for stats.  (\$from in "\$key = \$filename; \$key =~ s/\$from/\$to/")

    --nameto
        rhs in sub, to transform filenames to a key for stats.  (\$to in "\$key = \$filename; \$key =~ s/\$from/\$to/")

    --outdir
        Output directory; default is ./logalyzer.out; will be created.

    --granularity
        granularity of the time-related stats.  Default is minutes.
        Legal:  $legal_granularities.


END_MESSAGE

  print STDERR $usage;
}


1;
