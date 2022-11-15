#! /opt/local/bin/perl

use JSON::PP;
use Data::Dumper;

# example run:
# ./json2csv.pl -constants node,1,port,8023 -first time,node,port -file 8023_RequestLog.txt > 1-8023.csv 

# constant key/value to add to each request in a file
my %constants = ();
my @first = qw(time);
# separator for columns in output
my $separator = ",";

# get args and parse
my %args = @ARGV;
# columns to put first
# -first time,node,port
if (exists($args{'-first'})) {
    @first = split (/\s*,\s*/, $args{'-first'});
}
# constant columns to add (e.g., node, port)
# -constants key1,val1,key2,val2
if (exists($args{'-constants'})) {
    %constants = split (/\s*,\s*/, $args{'-constants'});
}

my $filename = %args{'-file'};

open my $fh, '<', $filename or die "Can't open '$filename' for read: $!\n";

my @constant_keys = keys %constants;

my $columns_found = {};
my @line_hashes = ();

while (<$fh>) {
    chomp;
    my $line_hash = JSON::PP->new->utf8->decode($_);
    foreach my $key (keys %$line_hash) { 
        if (exists $constants{$key}) {
            print STDERR "Found values in log for constant value $key, will be overwritten by constant value ($line_hash->{$key} -> $constants{$key})!\n";
            print STDERR $_, "\n";
        }
    }
    @$line_hash{@constant_keys} = @constants{@constant_keys};
    #@$line_hash{keys %$line_hash} = keys %$line_hash;
    @$columns_found{keys %$line_hash} = keys %$line_hash;

    push @line_hashes, $line_hash;
}

print STDERR "Parsed ", scalar(@line_hashes), " lines.\n";


my $headers = get_sorted_headers (\%constants, $columns_found, \@first);

print (join ($separator, @$headers), "\n");

foreach my $line_hash (@line_hashes) {
    my @values = map { exists $line_hash->{$_} ? $line_hash->{$_} : '' } @$headers;
    my @values = map { index($_, $separator) >= 0 ? "\"$_\"" : $_ } @values;
    print (join ($separator, @values), "\n");
}

#########

sub get_sorted_headers {
    # columns:  %constants, %found, @first
    my ($constants, $found, $first) = @_;
    my @headers = ();
    foreach my $first_col (@$first) {
        # if it was found, add it to front of headers
        if (exists $found->{$first_col}) {
            delete ($found->{$first_col});
            push @headers, $first_col;
        }
    }
    # add the rest of the headers found
    push @headers, sort keys %$found;
    return \@headers;
}


