import os, sys
import bind9_parser

'''
This is the main ZF implementation script as defined in 
https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech

The general plan is to read a list of domain names from a
CSV file (plus port if != 443 and refresh interval), to
then poll DNS and the relevant web server to see if there
is any mismatch. If there is, then we'll validate the 
content at the WKECH URL and all being well, update the
relevant HTTPS RR, in this implementation using bind9
specific tools.

This currently implements the -07 version of the spec.

'''

# Load in a set of library functions
if 'ECH_PY_LIB' in os.environ:
    epl=os.getenv('ECH_PY_LIB')
    sys.path.append(epl)
from ECHLib import *

def load_keyring(keyfile):
    '''
        Initialize a keyring from a configuration file in named.conf syntax,
        typically /run/named/session.key.

        That file is updated every time named is restarted so we read from it
        each time. We don't want to be root or the bind user though so we've
        added our user to the bind group and chmod'd that file to 640.

        We return a bogus entry rather than fail.
    '''
    keydict = {}
    if not os.access(keyfile, os.R_OK):
        logging.warning(f"Can't open key file: '{keyfile}'")
    else:
        try:
            with open(keyfile) as f:
                cfg = f.read()
            clauses = bind9_parser.clause_statements()
            d = clauses.parseString(cfg).asDict()
            for entry in d['key']:
                keydict[entry['key_id'].strip('"')] = entry['secret'].strip('"')
        except Exception as e:
            logging.warning(f"{e}")
            keydict = {}
    if not keydict:
        logging.warning(f"Loading dummy entry in keyring")
        keydict = { '__.': 'invalid_invalid_invalid_invalid_' }
    result = dns.tsigkeyring.from_text(keydict)
    logging.debug(f"Loaded keyring")
    return result

def apply_update(args, hostname, port, target=None, regeninterval=3600):
    result = []
    dryrun = args.dryrun

    # Reload each time in case it might change as we do a long list of updates
    # TODO: is there a way to lock the file while processing? 
    # TODO: what if we hit timeouts? processing might take a long time if list is long
    keyring = load_keyring(args.keyfile)

    logging.info(f"Processing update for ({hostname}, {port}, {target})")
    checked = check_wkech(hostname, port=port, target=target, regeninterval=regeninterval, tout=args.timeout)
    if not checked['OK']:
        logging.warning(f"Validation failed for ({hostname}, {port}, {target})")
    elif not checked['Update']:
        logging.info(f"No update needed for ({hostname}, {port}, {target})")
    else:
        for item in checked['Update']:
            if not item:
                continue
            logging.debug(f"Preparing to apply update {repr(item)}")
            logging.debug(f"  DETAIL:  hostname: '{item.name}'")
            logging.debug(f"  DETAIL:      zone: '{dns.resolver.zone_for_name(item.name)}'")
            logging.debug(f"  DETAIL:       TTL: '{item.ttl}'")
            logging.debug(f"  DETAIL:     CLASS: '{item.rdclass.to_text(item.rdclass)}'")
            logging.debug(f"  DETAIL:      TYPE: '{item.rdtype.to_text(item.rdtype)}'")
            # TODO: What if HMAC_SHA256 is wrong?
            lupdate = dns.update.Update(dns.resolver.zone_for_name(item.name),
                                        keyring=keyring, keyalgorithm=dns.tsig.HMAC_SHA256)
            lupdate.replace(item.name, item.to_rdataset())
            logging.debug(f"Ready to apply update: {lupdate}")
            if dryrun:
                logging.info("Dry run in progress: skipping update")
                continue
            if dns.name.from_text('__') in keyring:
                logging.debug(f"Attempting update {repr(lupdate)} with invalid key")
            try:
                # local policy requires updates to be to/from localhost only, not to a public IP
                # lresponse = dns.query.tcp(lupdate, ChosenResolver.active.nameservers[0], timeout=10)
                # TODO: figure resolver thing better
                lresponse = dns.query.tcp(lupdate, '::1', timeout=10)
                logging.debug(f"Update response: {lresponse}")
                logging.info(f"Success updating ({hostname}, {port}, {target})")
            except dns.exception.DNSException as e:
                logging.error(f"DNS Exception: {e}")
                
    return result

def run_batch(args):
    result = []
    todo=args.domains_csv
    with open(todo, newline='') as csvfile:
        readCSV = csv.reader(csvfile, delimiter=",")
        for row in readCSV:
            logging.debug(f"Parsing row from file '{todo}': {row}")
            if len(row) < 1 or not row[0]:
                continue    # skip empties
            if str(row[0])[0] in ';#': # allow comments
                continue               # and skip them
            alias = None
            port = None
            regeninterval = 3600
            row = list(map(str.strip, row))
            hostname = row[0]
            if len(row) > 3 and row[3]:
                regeninterval = int(row[3])
            if len(row) > 2 and row[2]:
                alias = str(row[2])
            if len(row) > 1 and row[1]:
                port = int(row[1])
            result += apply_update(args, hostname, port, target=alias, regeninterval=regeninterval)
    return result

def main() -> None:
    parser = argparse.ArgumentParser(
        description="A Python tool for updating a DNS zone from WKECH data",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "-n", "--dryrun", "--dry-run", action="store_true",
        help="disable update transaction"
    )
    parser.add_argument(
        "-s", "--nameserver", "--name-server", default=None, nargs='?',
        help="DNS name server to use instead of system resolver"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, nargs='?',
        help="Timeout for DNS and/or web accesses"
    )
    parser.add_argument(
        "-d", "--domains_csv", dest="domains_csv",
        help="file containing list of origins"
    )
    parser.add_argument(
        "-k", "--keyfile", "--key-file", dest="keyfile", nargs='?', default='/run/named/session.key',
        help="configuration file for TSIG key to use (default: /run/named/session.key)"
    )
    
    args = parser.parse_args()
    if args.nameserver:
        ChosenResolver.activate(args.nameserver)
    if args.timeout:
        ChosenResolver.set_timeout(args.timeout)

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    # log args to help reconstruct if needed
    logging.info(f"Command line arguments: {args}")

    # check we have a sane set of args
    if args.domains_csv is None:
        print("no domains to process - exiting")
        sys.exit(1)
    run_batch(args);

if __name__ == "__main__":
    main()
