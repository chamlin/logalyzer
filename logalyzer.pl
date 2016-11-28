#!/usr/bin/perl -w

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
    'mintime=s' => \$state->{min_time},
    'maxtime=s' => \$state->{max_time},
    #'min_level=s' => \$state{min_level},
    #'stats_out=s' => \$state{stats_out},
);

$state->resolve_options ();

$state->process_files ();

#die;

$state->dump_stats ();
$state->dump_stats_new ();

$state->end_run;

$state->dump_state;

