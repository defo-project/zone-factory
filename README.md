# zone-factory
Tools for publishing and updating DNS records to carry ECH configuration data

- *updzone-from-wkech.py* (WIP) \
  validate WKECH data and build zone update transaction for BIND9 *nsupdate*

- [wkech-web-server.sh](./wkech-web-server.sh) is a bash script for managing
  ECH keys for a set of web servers and/or client-facing-servers (if those
  differ)
    - [wkech-web-server-var.sh](./wkech-web-server-vars.sh) is a file that's
      included in the above for setting the specific names/paths to use.
