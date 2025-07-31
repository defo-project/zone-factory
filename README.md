# zone-factory
Tools for publishing and updating DNS records to carry ECH configuration data

- [wkech-zf.py](./wkech-zf.py)
  validates WKECH data and sends zone update transaction directly as a DNS
  query
    - [test-doms.csv](./test-doms.csv),
      a list of domains to test the above
- [ECHLib.py](./ECHLib.py),
  library providing functions to support the above
- [updzone-from-wkech.py](./updzone-from-wkech.py)
  validates WKECH data and builds zone update transaction command stream 
  for external BIND9 *nsupdate*; now abandoned, kept for reference.

- [wkech-web-server.sh](./wkech-web-server.sh) is a bash script for managing
  ECH keys for a set of web servers and/or client-facing-servers (if those
  differ)
    - [wkech-web-server-var.sh](./wkech-web-server-vars.sh) is a file that's
      included in the above for setting the specific names/paths to use.
