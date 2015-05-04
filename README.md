# logalyzer

It analyzes MarkLogic error logs (a bit).

Goal:  decent, fast.

Treats each log file separately in stats, so probably cat the logs for each node into a big file named after the node.

# use

Run, 

# todo

  - read all events from all files in order, to avoid sort at end
  - use sar stuff
  - transform file name to some node name, so you don't have to cat files
  - R plots
  - time slices
  - day granularity?  or multiple-hours?
  - event read as more than a single line

  - document:  adding extra events and stats operators
  - document:  junking events (should be command-line option for this)


