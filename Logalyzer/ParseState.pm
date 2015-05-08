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

# stats that will be dumped, and also level counts, for current file
sub current_file_stats {
    my ($self) = @_;
    return $self->{stats}{$self->{current_file}};
}

# stats that will be dumped
sub current_stats {
    my ($self) = @_;
    return $self->{stats}{$self->{current_file}}{stats};
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

sub resolve_options {
    my ($self) = @_;

    my $exit_with_usage = 0;

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
    $self->{min_level_number} = $self->{levels}{$self->{min_level}};
    my $granularity = $self->{granularity};
    if ($granularity eq 'none') {
        $self->{granularity} = 'hours'
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

sub get_log_line {
    my ($self, $file_info) = @_;
    my $fh = $file_info->{fh};
    unless ($fh) { die "Read on closed fh $filename.\n" }
    $file_info->{current_line}{line} = <$fh>;
    $self->classify_line ($file_info);
};


sub grouping_time {
    my ($self, $dt) = @_;
    my $granularity = $self->{granularity};
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


sub app_code {
    my ($self, $text) = @_;
    my $prefixes = $self->{prefixes};
    foreach my $match ($text =~ /([A-Z]+)-([A-Z]+): /g) {
        if (exists $prefixes->{$1}) {
            return "$1-$2";
        }
    }
    return ();
}


sub classify_line {
    my ($self, $file_info) = @_;

    my $line = $file_info->{current_line}{line};

    # quick out.  just work on this function.
    if ($self->{junk} && $line =~ /$self->{junk}/) {
        $file_info->{current_line}{events} = [{ classify => 'JUNK'}];
        return;
    }

    if ($line =~ /^(\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) (\S+):\s(.*)/) {
        # default
        $file_info->{current_line}{events} = [{ classify => 'misc', 'op' => 'count' }];
        my ($dt, $level, $text) = ($1, $2, $3);
        $file_info->{date_time} = $dt;
        my $grouping_time = $self->grouping_time ($dt);
        @{$file_info->{current_line}}{'date_time', 'level', 'text', 'grouping_time'}
            = ($dt, $level, $text, $grouping_time);
        # count per level
        $stats->{level_counts}{$level}++;
        # ML codes
        my $code = $self->app_code ($text);
        if ($code) {
            $file_info->{current_line}{events} = [{ classify => $code, 'op' => 'count' }];
        } elsif ($text =~ /^Merged (\d+) MB in \d+ sec at (\d+) MB/) {
            $file_info->{current_line}{events} = [
                { classify => 'merge', op => 'sum', value => $1 },
                { classify => 'merge-rate', op => 'avg', value => $2 },
            ];
        } elsif ($text =~ /^Hung (\d+) sec/) {
            $file_info->{current_line}{events} = [{ classify => 'hung', op => 'sum', value => $1 }];
        } elsif ($text =~ /^Mounted forest \S+ locally/) {
            $file_info->{current_line}{events} = [{ classify => 'mount', op => 'count', }];
        } elsif ($text =~ /^Starting MarkLogic Server /) {
            $file_info->{current_line}{events} = [{ classify => 'restart', op => 'count', }];
        }
    } elsif (length ($line) > 0) {
        $file_info->{current_line}{events} = [{ classify => 'sys', op => 'count', }];
    }
}

sub init_files {
    my ($self) = @_;
# init stats, init fh
    foreach my $filename (@{$self->{filenames}}) {
        my $key = $self->get_logfile_key ($filename);
        my $fh = undef;
        open ($fh, '<', $filename) or die "Can't open $filename.\n";
        my $file_info = {
            'filename' => $filename,
            'key' => $key,
            'fh' => $fh,
        };
        push @{$self->{logfh}}, $file_info;
        $self->get_log_line ($file_info);
    }
};

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

    --namefrom
        regex to match in filenames, to transform them to a key for stats.  (\$from in "\$key = \$filename; \$key =~ s/\$from/\$to/")

    --nameto
        rhs in sub, to transform filenames to a key for stats.  (\$to in "\$key = \$filename; \$key =~ s/\$from/\$to/")

    --outdir
        Output directory; default is ./logalyzer.out; will be created.

    --granularity
        granularity of the time-related stats.  Default is hours.
        Legal:  $legal_granularities.


END_MESSAGE

  print STDERR $usage;
}


1;
