import os, sys
import bind9_parser
import signal, time

'''
This is the main ZF implementation script as defined in 
https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech

The general plan is to read a list of domain names from a
CSV file (plus port if != 443 and regeninterval), to
then poll DNS and the relevant web server to see if there
is any mismatch. If there is, then we'll validate the 
content at the WKECH URL and all being well, update the
relevant HTTPS RR, in this implementation using bind9
specific tools.

This currently implements the -08 version of the spec.

DNS queries in suppor of HTTPS requests (e.g. to acquire
the wkech JSON) use the system stub resolver. DNS queries
and updates related to checking HTTPS RR values use a
hard-coded stub resolver talking to '::1.53'. If that
doesn't match the local (e.g. bind) setup for update
policy, then you'll need to modify this code.

'''

# Load in a set of library functions
if 'ECH_PY_LIB' in os.environ:
    epl=os.getenv('ECH_PY_LIB')
    sys.path.append(epl)
from ECHLib import *

# We setup a general timeout per origin, in case some n/w or file access
# fails slowly
class TimeOutException(Exception):
   pass

def alarm_handler(signum, frame):
    raise TimeOutException()

def map_tsig_alg(instring):
    '''
        Bind's session key file uses different strings for TSIG algs
        compared to dnspython's so we need to map strings we know and
        like.  If we don't like the input (or get crap) we return
        hmac-256 which will break (or work, if correct)
    '''
    try:
        # possible inputs listed at:
        # https://bind9.readthedocs.io/en/stable/chapter4.html#rndcconf-statement-algorithm
        # https://www.dnspython.org/docs/1.14.0/dns.tsig-pysrc.html
        # says that dns.name.from_text here should do the right thing
        print(f"Mapping {instring}")
        return dns.name.from_text(instring)
    except Exception as e:
        return dns.tsig.HMAC_SHA256
    return dns.tsig.HMAC_SHA256


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
    tsig_alg = dns.tsig.HMAC_SHA256
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
                tsig_alg = map_tsig_alg(entry['algorithm'])
        except Exception as e:
            logging.warning(f"{e}")
            keydict = {}
    if not keydict:
        logging.warning(f"Loading dummy entry in keyring")
        keydict = { '__.': 'invalid_invalid_invalid_invalid_' }
    result = [ dns.tsigkeyring.from_text(keydict), tsig_alg ]
    logging.debug(f"Loaded keyring")
    return result

def apply_update(args, hostname, port, target=None, regeninterval=3600):
    result = []
    dryrun = args.dryrun

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
            # Reload each time in case it might change as we do a long list of updates
            keyring = load_keyring(args.keyfile)
            lupdate = dns.update.Update(dns.resolver.zone_for_name(item.name),
                                        keyring=keyring[0], keyalgorithm=keyring[1])
            lupdate.replace(item.name, item.to_rdataset())
            logging.debug(f"Ready to apply update: {lupdate}")
            if dryrun:
                logging.info("Dry run in progress: skipping update")
                continue
            if dns.name.from_text('__') in keyring[0]:
                logging.debug(f"Attempting update {repr(lupdate)} with invalid key")
            try:
                lresponse = dns.query.tcp(lupdate, '::1', timeout=args.timeout)
                logging.debug(f"Update response: {lresponse}")
                logging.info(f"Success updating ({hostname}, {port}, {target})")
            except dns.exception.DNSException as e:
                logging.error(f"DNS Exception: {e}")
                
    return result

def run_batch(args):
    result = []
    todo=args.domains_csv
    with open(todo, newline='') as csvfile:
        try:
            signal.signal(signal.SIGALRM, alarm_handler)
            signal.alarm(int(args.timeout))
            readCSV = csv.reader(csvfile, delimiter=",")
            for row in readCSV:
                logging.debug(f"Parsing row from file '{todo}': {row}")
                if len(row) < 1 or not row[0]:
                    continue    # skip empties
                if str(row[0])[0] in ';#': # allow comments
                    continue               # and skip them
                try:
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
                except Exception as e:
                    logging.error(f"Exception processing {row}, {e}")
            signal.alarm(0)
        except TimeOutException as t:
            logging.error(f"Timeout processing {rpw}, {e}")
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
    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    logging.info(f"Command line arguments: {args}")
    # check we have a sane set of args
    if args.domains_csv is None:
        print("no domains to process - exiting")
        sys.exit(1)
    run_batch(args);

if __name__ == "__main__":
    main()
