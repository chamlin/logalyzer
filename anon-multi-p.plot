set terminal pdf size 20, 20
set output 'anon-multi-p.pdf'

set multiplot layout 3,1
set title 'anon memory %'

set datafile separator '\t'
set style data points
set xlabel 'Time'
set timefmt '%Y-%m-%d %H:%M:%S'
set xdata time
set xrange [*:*]
set ylabel 'anon %'
set yrange [0:*]

plot 'stats-01.out' using 1:($60 == 0 ? NaN : $60)  title '01'


plot 'stats-02.out' using 1:($60 == 0 ? NaN : $60)  title '02'

plot 'stats-03.out' using 1:($60 == 0 ? NaN : $60)  title '03'

unset multiplot
