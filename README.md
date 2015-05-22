# logalyzer

## is

It analyzes MarkLogic error logs (a bit).

Goal:  decent, fast.

  - Can transform log names to consolidate by node name.
  - Granularity by hour, ten minutes, minutes.
  - Junk events by regex.
  - Pretty fast.

## use

### logalyzer

Requires only basic install.

Run logalyzer.pl and options will be shown.

### plots

Requires gnuplot.

After the logalyzer runs, move to that directory and run do\_plots.pl.  If on a Mac, then just 

    open *.pdf

and preview will open all the plots so you can flip through.

## status

useable

will change but shouldn't break now


