# Some ideas for an ECH probe

This note describes a possible command line tool to help a zone factory publish
ECH configs.  This is still a bit preliminary.

## Functions

1) Given a DNS name, check if there's an ECHConfigList
    - by checking for a .well-known/origin-svcb (a)
    - by checking for a relevant HTTPS RR (b)

2) Given a DNS name check if ECH works (with explosion of ECHConfigLists into
singletons):
    - using (a) and (b) as appropriate
    - by using a bogus ECHConfig and checking (at the .well-known) for
      retry-configs (c)
    - construct the set of 'working' ECHConfig values (d)
    - construct a set of 'guessed-preferred' (e) ECHConfig values, maybe with
      just one ECHConfig or following other (TBD) heuristics

3) Spit out the HTTPS RRs we'd like to see for (e)

4) Spit out the nsupdate commands we'd use to get (e) in the DNS

5) Spit out the pdnsutil commands we'd use to get (e) in the DNS

## Implementation

The [echprobe.go](./echprobe.go) script does functions 1 and 2 as
described above (though in a different order).

Next up is to figure out some sensible implementation for step 3.
Likely to try:

- allow inputs for "minmial"/"maximal" set of HTTPS RRs
- the order in which we most believe ECHConfig values are
  likely timely/correct is:
    - retry-configs (runtime demonstrated)
    - origin-svcb (under web server control)
    - HTTPS RRs (under DNS admin control)

## Timeline

We want this "done" by mid-Nov latest.


