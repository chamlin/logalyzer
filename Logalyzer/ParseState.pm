# $Id: ParseState.pm 29 2015-04-07 18:23:55Z chamlin $

package Logalyzer::ParseState;

use Data::Dumper;

use List::Util qw (sum);

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
    'timestamp-lag-count' => { op => 'count', label => 'ts lag (count)', no_dump => 1 },
    'timestamp-lag' => { op => 'avg', label => 'ts lag (ms avg)' },
    'journaling' => { op => 'sum', label => 'slow journal time (ms total)' },
    'journaling-count' => { op => 'count', label => 'slow journal time (message count)', no_dump => 1 },
    'journal-stuff' => { op => 'count', label => 'general journal messages' },
    'jlag-semaphore' => { op => 'sum', label => 'journal lag time, semaphore (ms total)' },
    'jlag-semaphore-count' => { op => 'count', label => 'journal lag time, semaphore (message count)', no_dump => 1 },
    'jlag-disk' => { op => 'sum', label => 'journal lag time, disk (ms total)' },
    'jlag-disk-count' => { op => 'count', label => 'journal lag time, disk (message count)', no_dump => 1 },
    'jlag-jarchive' => { op => 'sum', label => 'journal lag time, archiving (ms total)' },
    'jlag-jarchive-count' => { op => 'count', label => 'journal lag time, archiving (message count)', no_dump => 1 },
    'jlag-dbrep' => { op => 'sum', label => 'journal lag time, dbrep (ms total)' },
    'jlag-dbrep-count' => { op => 'count', label => 'journal lag time, dbrep (message count)', no_dump => 1 },
    'jlag-localrep' => { op => 'sum', label => 'journal lag time, local rep (ms total)' },
    'jlag-localrep-count' => { op => 'count', label => 'journal lag time, local rep (message count)', no_dump => 1 },
     merge => { op => 'sum',  label => 'total (MB)' },
    'merge-size' => { op => 'avg',  label => 'mean size (MB)' },
    'merge-rate' => { op => 'avg',  label => 'mean (MB/s)', no_dump => 1 },
    'merge-count' => { op => 'count', no_dump => 1 },
    'delete' => { op => 'sum',  label => 'total (MB)' },
    'delete-rate' => { op => 'avg',  label => 'mean (MB/s)' },
    save => { op => 'sum',  label => 'total (MB)' },
    'save-rate' => { op => 'avg',  label => 'mean (MB/s)', no_dump => 1 },
    'detecting' => { op => 'count',  label => 'detecting messages' },
    hung => { op => 'sum',  label => 'total (s)' },
    canary => { op => 'sum',  label => 'total (s)' },
    logline => { op => 'count',  label => 'logged line', no_dump => 1 },
    rollback => { op => 'count',  label => 'rollback (messages)' },
    'authticket-update-avg' => { op => 'avg',  label => 'avg ms' },
    'authticket-get-feed-avg' => { op => 'avg',  label => 'avg ms' },
    'mem-percent' => { op => 'avg',  label => 'mem %' },
    'mem-mb' => { op => 'avg',  label => 'mem MB' },
    'mem-swap-p' => { op => 'avg',  label => 'swap %' },
    'mem-swap-mb' => { op => 'avg',  label => 'swap MB' },
    'mem-virt-p' => { op => 'avg',  label => 'virt %' },
    'mem-virt-mb' => { op => 'avg',  label => 'virt MB' },
    'mem-rss-p' => { op => 'avg',  label => 'rss %' },
    'mem-rss-mb' => { op => 'avg',  label => 'rss MB' },
    'mem-anon-p' => { op => 'avg',  label => 'anon %' },
    'mem-anon-mb' => { op => 'avg',  label => 'anon MB' },
    'mem-file-p' => { op => 'avg',  label => 'file %' },
    'mem-file-mb' => { op => 'avg',  label => 'file MB' },
    'mem-forest-p' => { op => 'avg',  label => 'forest %' },
    'mem-forest-mb' => { op => 'avg',  label => 'forest MB' },
    'mem-cache-p' => { op => 'avg',  label => 'cache %' },
    'mem-cache-mb' => { op => 'avg',  label => 'cache MB' },
    'mem-registry-p' => { op => 'avg',  label => 'registry %' },
    'mem-registry-mb' => { op => 'avg',  label => 'registry MB' },
    'mem-huge-p' => { op => 'avg',  label => 'huge %' },
    'mem-huge-mb' => { op => 'avg',  label => 'huge MB' },
    'mem-join-p' => { op => 'avg',  label => 'join %' },
    'mem-join-mb' => { op => 'avg',  label => 'join MB' },
    'mem-unclosed-p' => { op => 'avg',  label => 'unclosed %' },
    'mem-unclosed-mb' => { op => 'avg',  label => 'unclosed MB' },
    'mem-forest-cache-p' => { op => 'avg',  label => 'forest+cached %' },
    'mem-huge-anon-swap-file-p', => { op => 'avg',  label => 'hu+an+sw+fi %' },
    'rebalance' => { op => 'avg',  label => 'avg frag/sec' },
    'slow-count' => { op => 'sum',  label => 'slow messages' },
    'stand-stuff' => { op => 'sum',  label => 'stand messages'},
    'keystore' => { op => 'sum',  label => 'keystore messages'},
    'deadlock' => { op => 'count',  label => 'deadlock messages'},
    'quorum' => { op => 'avg',  label => 'quorum avg'},
    'on-disk-stand' => { op => 'count',  label => 'on-disk stand creation' },
    'in-memory-stand' => { op => 'count',  label => 'in-memory stand creation' },
    'backup' => { op => 'count',  label => 'backup messages' },
    'start-backup' => { op => 'count',  label => 'start backup messages' },
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
        'legal_granularities' => { minutes => 1, hours => 1, 'ten-minutes' => 1, 'seconds' => 1, 'days' => 1 },
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

sub PT_to_seconds {
    my ($test) = @_;
    my ($h, $m, $s) = ($test =~ /PT(?:(\d+)H)?(?:(\d+)M)?(?:([0-9.]+)S)?/);
    unless (defined $h) { $h = 0 }
    unless (defined $m) { $m = 0 }
    unless (defined $s) { $s = 0 }
    my $seconds = $h * 3600 + $m * 60 + $s;
    return $seconds;
}

# get it, open if needed.
sub get_fh {
    my ($self, $outfile) = @_;
    my $out = $self->{fh}{$outfile};
    unless ($out) {
        unless (open ($out, '>', $outfile)) {
            print STDERR Dumper $self;
            die "Can't open $outfile.\n";
        }
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
    if (exists $self->{event_info}{$event}{label}) {
        return $self->{event_info}{$event}{label};
    }
    return $event
}

sub event_op { 
    my ($self, $event) = @_;
    my $op = $self->{event_info}{default}{op};
    if (exists $self->{event_info}{$event}{op}) {
        $op = $self->{event_info}{$event}{op};
    }
    return $op;
}

sub get_logfile_keyxx {
    my ($state, $filename) = @_;
    $filename =~ /(psml\dc\d\d\d)/;
    return $1;
}

sub get_logfile_key {
    my ($state, $filename) = @_;
    my $back = $filename;
    # watch for directorys in filenames
    if ($state->{namefrom}) {
        my $from = $state->{namefrom};
        my $to = $state->{nameto};
        if ($to =~ /\$\d/) { $back =~ s|$from|$to|ee } else { $back =~ s|$from|$to| }
    }
    return $back;
}

# get options, set up config
sub resolve_options {
    my ($self) = @_;

    my $exit_with_usage = 0;

    $self->{min_level_number} = $self->{levels}{$self->{min_level}};

    # check files in
    if   ($self->{glob}) {
        foreach my $glob (split (/\s*,\s*/, $self->{glob})) {
            push @{$self->{filenames}}, grep { -f } glob ($glob);
        }
    }
    elsif ($self->{file}) { $self->{filenames} = [grep { -f } (split (',', $self->{file}))] }
    else { }
    unless (scalar @{$self->{filenames}}) { print STDERR "No filenames provided/found.\n"; $exit_with_usage = 1; }
    # for testing, so keys dump in config run
    foreach my $filename (@{$self->{filenames}}) {
        push @{$self->{filekeys}}, $self->get_logfile_key ($filename);
    }

    if ($self->{testconfig}) {
        $self->end_run;
        print STDERR "Config only: \n", Dumper $self;
        exit 1;
    }

    $self->init_files();

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
    if      ($granularity eq 'seconds') {
        substr ($dt, 0, 19)
    } elsif ($granularity eq 'minutes') {
        substr ($dt, 0, 17) . '00'
    } elsif ($granularity eq 'ten-minutes') {
        substr ($dt, 0, 15) . '0:00'
    } elsif ($granularity eq 'hours') {
        substr ($dt, 0, 14) . '00:00'
    } elsif ($granularity eq 'days') {
        substr ($dt, 0, 11) . '00:00:00'
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

# get most recent line of all files, and process it (has already been classified).
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
        # find out operator, and process as needed (sum, push to list).
        #my $op = $classify->{op};
        my $op = $self->event_op ($classify->{classify});
        if ($op eq 'sum') {
            $stats->{$line_info->{grouping_time}}{$event} += $classify->{value};
        } elsif ($op eq 'avg') {
            push @{$stats->{$line_info->{grouping_time}}{$event}}, $classify->{value};
        } elsif ($op eq 'count') {
            if (exists $stats->{$line_info->{grouping_time}}{$event}) {
                $stats->{$line_info->{grouping_time}}{$event}++;
            } else {
                $stats->{$line_info->{grouping_time}}{$event} = 1;
            }
        } else {
            die "Unknown op $op for line", Dumper ($line_info), ".\n";
        }
        # add the filename_index to see log continuity
        $stats->{$line_info->{grouping_time}}{logline} = $self->{file_info}{$min->{key}}{filename_index};
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
        $logfh->{key},
        $line_info->{line},
    ));
    foreach my $event (@{$line_info->{events}}) {
        my $class = $event->{classify};
        # don't print out some stuff
        if ($self->{event_info}{$class}{no_dump})  { next }
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
        if (index ($text, 'XDQP') >= 1) {
            push @$events, { classify => 'XDQP', op => 'count', value => 1 };
        }
        if ($text =~ /UserName=.*\*\*\*\*([^*]+?)\*\*\*\*.*TIME\s(\d+\.\d+)/) {
            my ($call, $time) = ($1, $2);
            $call =~ s/API PROCESS TIME//;
            $call =~ s/\s//g;
            push @$events, { classify => $call, value => $time };
        } elsif ($text =~ /-api-authticket: .*maxhits greater than/) {
            push @$events, { classify => "authticket-maxhits", };
        }
        if ($text =~ /unable to configure logging/) {
            push @$events, { classify => 'logging-configure', op => 'count', value => 1 };
        }
        if ($text =~ /^\[Event:id=([^]]+)/) {
            my $trace_event = "Event-$1";  $trace_event =~ s/[ :;,]/-/; 
            push @$events, { classify => $trace_event, };
        }
        # other stuff
        if ($text =~ /^Merged (\d+) MB (in \d+ sec )?at (\d+) MB\/sec to (.+)\/[^\/]+$/) {
            my ($mb, $junk, $rate, $stand) = ($1, $2, $3, $4);
            push @$events, (
                { classify => 'merge', op => 'sum', value => $mb },
                { classify => 'merge-count', value => 1 },
                { classify => 'merge-size', value => $mb },
                { classify => 'merge-rate', value => $rate },
            );
            #if ($s > 2) { push @$events, { classify => 'merge-rate', op => 'avg', value => $2 } }
            open my $csv, '>>', 'merge-rate-vs-size.csv';
            print $csv "$rate,$mb\n";
            close $csv;
        } elsif ($text =~ m/^Slow /) {
            push @$events, (
                { classify => 'slow-count', value => 1 },
            );
        } elsif ($text =~ m/^Memory (\d+)%/) {
            my ($mem_p, $phys_k, $rest) = ($text =~ m/^Memory (\d+)% phys=(\d+) (.*)/);
            my %values = (
                'mem-percent' => $mem_p,
                'mem-mb' => $phys_k,
            );
            #my ($mem_p, $mem_phys_k, $mem_virt_k, $mem_virt_p, $mem_rss) = ($1, $2, $3, $4);
            foreach $stat (split /\s/, $rest) {
                my ($name, $value_k, $value_p) = ($stat =~ /(\w+)=(\d+)\((\d+)%\)/);
                #print "$stat: $name, $value_k, $value_p\n";
                $values{'mem-'.$name.'-mb'} = $value_k;
                $values{'mem-'.$name.'-p'} = $value_p;
            }
            foreach $stat (keys %values) {
                push @$events, (
                    { classify => $stat, value => $values{$stat} },
                );
            }
            my $big_sum = 0;
            foreach $value ('mem-huge-p', 'mem-anon-p', 'mem-swap-p', 'mem-file-p') {
                if (exists $values{$value}) { $big_sum += $values{$value} }
            }
            if ($big_sum) {
                push @$events, (
                    { classify => 'mem-huge-anon-swap-file-p', value => $big_sum },
                );
            }
            if (exists $values{'mem-forest-p'} && exists $values{'mem-cache-p'}) {
                push @$events, (
                    { classify => 'mem-forest-cache-p', value => ($values{'mem-forest-p'} + $values{'mem-cache-p'}) },
                );
            }
#die Dumper \%values; 
        
        } elsif ($text =~ /^Deleted (\d+) MB .*?at (\d+) MB/) {
            push @$events, (
                { classify => 'delete', op => 'sum', value => $1 },
                { classify => 'delete-rate', op => 'avg', value => $2 },
            );
        } elsif ($text =~ /^Saved (\d+) MB .*?at (\d+) MB/) {
            push @$events, (
                { classify => 'save', op => 'sum', value => $1 },
                { classify => 'save-rate', op => 'avg', value => $2 },
            );
        } elsif ($text =~ /^Keystore: /) {
            push @$events, (
                { classify => 'keystore', value => 1 },
            );
        } elsif ($text =~ /^((Closing|Creating) journal|JournalBackup)/) {
            push @$events, (
                { classify => 'journal-stuff', value => 1 },
            );
        } elsif ($text =~ /^(~?)(OnDiskStand|InMemoryStand)/) {
            push @$events, (
                { classify => 'stand-stuff', value => 1 },
            );
            my ($tilde, $op) = ($1, $2);
            if ($op eq 'OnDiskStand' && ! $tilde) {
                 push @$events, { classify => 'on-disk-stand' };
            } elsif ($op eq 'InMemoryStand' && ! $tilde) {
                 push @$events, { classify => 'in-memory-stand' };
            }
        } elsif ($text =~ /^Hung (\d+) sec/) {
            push @$events, { classify => 'hung', op => 'sum', value => $1 };
        # 2017-01-31 03:00:42.422 tcffmppr6db29   2017-01-31 03:00:42.422 Warning: Canary thread sleep was 2186 ms
        } elsif ($text =~ /^Deadlock /) {
            push @$events, { classify => 'deadlock', value => 1 };
        } elsif ($text =~ /^Canary thread sleep was (\d+) ms/) {
            push @$events, { classify => 'canary', op => 'sum', value => $1 };
        } elsif ($text =~ /^Forest (\S+) state/) {
            push @$events, { classify => 'forest-state', op => 'count', };
        } elsif ($text =~ /^Mounted forest (\S+) locally/) {
            push @$events, { classify => 'mount', op => 'count', };
        # Warning: forest FFE-0099 journal frame took 1093 ms to journal (sem=0 disk=0 ja=0 dbrep=0 ld=1093) ...
        # Warning: Forest documents-001a journal frame took 1498 ms to journal: {{fsn=16888580, chksum=0x37046c00, words=21}, op=fastQueryTimestamp, time=1490167217, mfor=18020475790424908369, mtim=14819566813715610, mfsn=16888580, fmcl=436132992065430578, fmf=18020475790424908369, fmt=14819566813715610, fmfsn=16888580, sk=14997162585762723488}
        # 
        } elsif ($text =~ /Rebalanced .* at (\d+) fragments\/sec/) {
            push @$events, { classify => 'rebalance', op => 'avg', value => $1 };
        } elsif ($text =~ /journal frame took (\d+) ms to journal:? (?:\(sem=(\d+) disk=(\d+) ja=(\d+) dbrep=(\d+) ld=(\d+)\))?/) {
            push @$events, { classify => 'journaling', value => $1 };
            push @$events, { classify => 'journaling-count' };
            if ($2) {
                push @$events, { classify => 'jlag-semaphore', value => $2 };
                push @$events, { classify => 'jlag-semaphore-count' };
            }
            if ($3) {
                push @$events, { classify => 'jlag-disk', value => $3 };
                push @$events, { classify => 'jlag-disk-count' };
            }
            if ($4) {
                push @$events, { classify => 'jlag-jarchive', value => $4 };
                push @$events, { classify => 'jlag-jarchive-count' };
            }
            if ($5) {
                push @$events, { classify => 'jlag-dbrep', value => $5 };
                push @$events, { classify => 'jlag-dbrep-count' };
            }
            if ($6) {
                push @$events, { classify => 'jlag-localrep', value => $6 };
                push @$events, { classify => 'jlag-localrep-count' };
            }
        } elsif ($text =~ / rolling back/) {
            push @$events, { classify => 'rollback', value => $1 };
        } elsif ($text =~ /lags commit timestamp \(\d+\) by (\d+) ms/) {
            push @$events, { classify => 'timestamp-lag', value => $1 };
            push @$events, { classify => 'timestamp-lag-count' };
        } elsif ($text =~ /^Merging /) {
            push @$events, { classify => 'merging', op => 'count', };
        } elsif ($text =~ /^Saving /) {
            push @$events, { classify => 'saving', op => 'count', };
        } elsif ($text =~ /^(Detecting|Detected) (indexes|compat[ai]bility) /) {
            push @$events, { classify => 'detecting' };
        } elsif ($text =~ /^New configuration state retrieved/) {
            push @$events, { classify => 'config', op => 'count', };
        } elsif ($text =~ /^Retrying /) {
            push @$events, { classify => 'retry', op => 'count', };
        } elsif ($text =~ /^Detect.* quorum \((\d+) /) {
            push @$events, { classify => 'quorum', value => $1 };
        } elsif ($text =~ / REQUEST: /) {
            push @$events, { classify => 'REQUEST', op => 'count', };
        } elsif ($text =~ /^(Start|Finish|Cancel).* backup/) {
            if ($1 =~ /^Start/) { push @$events, { classify => 'start-backup' } }
            push @$events, { classify => 'backup' };
        } elsif ($text =~ /^Starting MarkLogic Server /) {
            push @$events, { classify => 'restart', op => 'count', };
        }
        if ($text =~ /java.net.ConnectException/) {
            push @$events, { classify => "java.net.ConnectException", op => 'count', };
        }
        if ($text =~ /orest (\S\S+)/) {
            my $forest = $1;
            $forest =~ s/[:,;]$//;
            # sanity check
            if ($forest =~ /^[a-zA-Z0-9-_]+$/) {
                push @$events, { classify => "Forest-$forest", op => 'count', };
            } else {
                # print STDERR "Bad forest name ($forest)? Text: $text.\n";
            }
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
    my $filename_index = 0;
    foreach my $filename (@{$self->{filenames}}) {
        my $key = $self->get_logfile_key ($filename);
        my $fh = undef;
        open ($fh, '<', $filename) or die "Can't open $filename ($!).\n";
        print STDERR '< ', $filename, " (key: $key)\n";
        my $file_info = {
            'filename' => $filename,
            'key' => $key,
            'fh' => $fh,
            'lines_read' => 0,
            'date_time' => '1900-01-01 00:00:00',
            'grouping_time' => $self-> grouping_time ('1900-01-01 00:00:00'),
            'filename_index' => $filename_index,
        };
        $self->{file_info}{$filename} = $file_info;
        # read list, removed when done
        push @{$self->{logfh}}, $file_info;
        $self->get_log_line ($filename);
        $filename_index++;
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

    my @row_timestamps = sort keys %{$self->{timestamps}};
    # get all columns (events)
    my @columns = sort keys %{$self->{events_seen}};
    foreach my $filename (keys %{$self->{stats}}) {
        my $file_stats = $self->{stats}{$filename}{stats};
        my $stats_filename = $self->get_stats_filename ($filename);
        my $stats_fh = $self->get_fh ($stats_filename);
        # header
        print $stats_fh ("#timestamp\t", join ($self->{separator}, @columns), "\n");
        foreach my $row_ts (@row_timestamps) {
            my @vals = ($row_ts);
            foreach my $column (@columns) {
                if (defined $file_stats->{$row_ts}{$column}) { 
                    push @vals, $self->get_stats_value ($column, $file_stats->{$row_ts}{$column});
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
    my $retval = undef;
    my $op = $self->event_op ($event);
    if ($op eq 'avg') {
        my $sum = 0;
        foreach my $stat (@$stats) { $sum += $stat }
        #$retval = int ( ($sum / scalar (@$stats)) + 0.5 );
        $retval = $sum / scalar (@$stats);
    } elsif ($op eq 'sum') {
        # summed as part of classification
        $retval = $stats;
    } elsif ($op eq 'count') {
        # counted as part of classification
        $retval = $stats;
    } else {
        print STDERR "Can't get val for $event with op $op.\n";
        print STDERR "Can't get val from stats ", Dumper ($stats), ".\n";
        die;
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

        Multiple patterns can be given, separated by commas.
        One of file or glob must be specified.

    --mintime
        timestamps lexically greater than or equal to this are retained (e.g., --mintime '2015-04-12 12:00:00')

    --maxtime
        timestamps lexically less than this are retained (e.g., --maxtime '2015-04-12 13:00:00')

    --namefrom
        regex to match in filenames, to transform them to a key for stats.  (\$from in "\$key = \$filename; \$key =~ s/\$from/\$to/")

    --nameto
        rhs in sub, to transform filenames to a key for stats.  can capture in namefrom and insert in nameto.  (\$to in "\$key = \$filename; \$key =~ s/\$from/\$to/")

    --outdir
        Output directory; default is ./logalyzer.out; will be created.

    --granularity
        granularity of the time-related stats.  Default is minutes.
        Legal:  $legal_granularities.


END_MESSAGE

  print STDERR $usage;
}


1;
