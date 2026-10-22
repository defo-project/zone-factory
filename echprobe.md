# The ECH probe tool...

This describes a command line tool to help a zone factory publish
ECH configs.

## Functions

1) Given a DNS name, check if there's an ECHConfigList
    - by checking for a .well-known/origin-svcb (a)
    - by checking for a relevant HTTPS RR (b)

2) Given a DNS name check if ECH works (with explosion of ECHConfigLists into
singletons):
    - using (a) and (b) as appropriate
    - by using a bogus ECHConfig and checking (at the .well-known) for
      retry-configs (c)
    - list (sub)set(s) of 'working' ECHConfig values (d)

3) Output the set of ECHConfigList values we see using (1) and (2)

4) Output the nsupdate commands we'd use to get (d) in the DNS (if you're using
bind)

5) Output the pdnsutil commands we'd use to get (d) in the DNS (if you're using
PowerDNS)

## Implementation

[echprobe.go](./echprobe.go) script does the above (though in a different
order).

## Extended Usage text 

TODO: build this into the program, when it's done...

If you're using this tool, you probably already know what Encrypted Client
Hello [ECH](https://datatracker.ietf.org/doc/rfc9849/) is and are interested in
deploying that for some web server, or want to check what's deployed. There is
a challnege in doing so, namely that the web server is where the ECH private
keys reside, but we'd like the ECH public keys to be published in the DNS, so
that browsers can make use of ECH.  This tool aims to help web and DNS
adminstrators bridge that gap to make it easier to see how ECH is configured on
a web server and how to publish usable values in the DNS so that browsers will
use ECH.

`echprobe` takes a DNS name (and optional port) as it's main input and probes
for ECH support for a web server there and outputs descriptions of that state
that aim to help administrators get the right values published in the DNS. 

The data required to enable use of ECH at a web server includes cryptograhpic
key(s) and other meta-data (algorithm details etc.) that are usually packaged
in an `ECHConfig`. As more than one set of options may be supported at a given
web server, lists of those values are what is typically distributed to clients
in an `ECHConfigList` structure that can be published in the DNS as a (base64
encoded value) in an HTTP resource record (RR) for the relevant domain name.
Browsers will attempt ECH if they see the right ECHConfigList in the DNS for
the web server concerned.

In addition the set of HTTPS RRs published in the DNS, there are two other
sources for ECHConfigList values for a web server that can provide additional
information: retry-configs and a well-known URL:

- The retry-configs value (an ECHConfigList) may be returned as part of the TLS
  exchange when ECH is tried and fails at an ECH-supporting server. The idea is
that a client could use that value in a subsequent connection-attempt to use
ECH with that server.  The set of values provided in retry-configs may be a
subset of the set of ECHconfig values that will work with that server (at that
time). If a client attempts to use ECH with a server, but uses the wrong key,
then it is highly likely that the server will return the current set of
retry-configs that work with the server.

- There is also an
  [Internet-draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech)
that defines a method for a web server (administrator) to publish the set of
ECHConfig values (using a well-known URL) that they would like to see published
in the DNS so that browser can make use of ECH. That is very very far from
widely deployed, but is another source of information.

Considering those three sets of (possibly conflicting) information, we
can say that:

- retry-configs are closest to "ground truth" as they reflect the web server's
  current runtime configuration
- the well-known URL (aka "origin-svcb" file) are also under the control of the
  web server administrators, so should also be close to "ground truth"
- the HTTPS RRs in the DNS may be somewhat "distant" from ground truth if the
  web server and DNS administrators are less well co-ordinated

However the best configuration is likely site-dependent so while probing the
ECH configurations is helpful, it does not but itself produce an authoritative
description of what should be published in the DNS.

### Basic Usage

`echprobe` is a golang command line tool that aims to help checking the current
ECH setup for a web server, and with using that to publish relevant
ECHConfigList values in the DNS. The command line options supported are:

```bash
$ echprobe -h
Usage of ./echprobe:
  -doh string
        DoH URL (default "https://cloudflare-dns.com/dns-query")
  -g string
        Group ECHConfig values 'as-found', or 'one-by-one' (default "as-found")
  -n string
        DNS name to probe (default "defo.ie")
  -o string
        Output type desired (default "summary")
  -p string
        service port to probe (default "443")
  -pn string
        ECH public name
  -s string
        Source for output desired (default "all")
  -v    verbosity
  -vv
        lots of verbosity
```

### Details...

TODO: explain those in more detail, with caveats...
