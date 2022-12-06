# logalyzer


It analyzes MarkLogic error logs (a bit).

Further doc at https://github.com/chamlin/logalyzer/wiki

Also utils for
  - combining logs
  - creating plots
  - extracting reports

Goal:  decent, fast.

  - Can transform log names to consolidate by node name.
  - Granularity by hour, ten minutes, minutes.
  - Junk events by regex.
  - Pretty fast.
  - requires only basic perl, plots require gnuplot

# json2csv.pl

Does
  - parse request log lines
  - outputs as csv
  - will put quotes around values that contain the separater
  - can config for first columns and can add constant columns (node, port, for example) 

Example run:

    ./json2csv.pl -constants node,1,port,8023 -first time,node,port -file 8023_RequestLog.txt > 1-8023.csv 
    
This will parse the json from the log file, add columns node and port with values 1 and 8028 respectively for each row, start the output with columns time, node, port and then alphabetically.

