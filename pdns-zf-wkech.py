from ssl import ECHStatus       # FAIL if ECH support not included

import argparse                 # parse CLI
import textwrap
import logging                  # handle messages

from typing import List, OrderedDict, TypedDict, NotRequired, Union, Tuple, Sequence, Optional

# for configuration
from pathlib import Path        # locate configuration file 
import csv                      # decode configuration file 
import string                   # validate DNS non-IDN- and A- labels

import urllib.parse
from urllib.parse import ParseResult

import certifi
import httptools

import json                     # parse WKECH content
import base64                   # manipulate ECHConfig data

import dns.name                 # manipulate DNS names
import dns.resolver             # place queries to DNS

import ssl                      # manage TLS connections
import socket
import subprocess               # for invoking pdnsutil


class ECHresult(TypedDict):
    servername: NotRequired[str]
    outername: NotRequired[str]
    ech_status: ssl.ECHStatus
    response: bytes


class WKECHendpoint(TypedDict):
    pass


class WKECHdata(TypedDict):
    regeninterval: int
    endpoints: List[WKECHendpoint]

class ECHConfigList:
    import base64
    import logging

    def __len__(self):
        return len(self.body)

    def analyze(self):
        singletons = tuple()
        if len(self):
            base = 2
            span = int.from_bytes(self.body[0:2])
            if (base + span) != len(self.body):
                logging.warning("Invalid ECH value")
            else:
                while base < len(self.body):
                    cfglen = int.from_bytes(self.body[base+2:base+4])
                    span = 4 + cfglen
                    segment = self.body[base:base+span]
                    seglen = span.to_bytes(2)
                    singletons += tuple([seglen + segment])
                    base += span
        return singletons

    def merge(self, singletons):
        load = b''
        for this in singletons:
            load += this[2:]
        span = len(load)
        return ECHConfigList(span.to_bytes(2) + load)

    def __init__(self, source=None):
        self.body = bytes()
        if source: 
            if isinstance(source, bytes) or isinstance(source, bytearray):
                self.body = bytes(source)
            elif isinstance(source, str):
                self.body = base64.b64decode(source)
            else:
                self.body = bytes()



class ChosenResolver:
    from dns.resolver import get_default_resolver, make_resolver_at
    active = get_default_resolver()

    def activate(server):
       ChosenResolver.active = ChosenResolver.make_resolver_at(server)

class HTTPResponseParser:
    def __init__(self):
        self.headers = {}
        self.body = bytearray()
        self.status_code = None
        self.reason = None
        self.http_version = None
        self.parser = httptools.HttpResponseParser(self)

    def on_status(self, status):
        self.reason = status.decode("utf-8", errors="replace")

    def on_header(self, name, value):
        self.headers[name.decode("utf-8")] = value.decode("utf-8")

    def on_body(self, body):
        self.body.extend(body)

    def feed_data(self, data):
        self.parser.feed_data(data)

def rectify(j, regeninterval=3600):                 # in use
    """ Convert content at WK URI from earlier format to current """
    logging.debug("Entered rectify with args:")
    logging.debug(f"                j: {j}")
    logging.debug(f"    regeninterval: {regeninterval}")
    if "endpoints" not in j:
        # Nothing to work with
        return None
    if "regeninterval" not in j:
        j['regeninterval'] = min(list(map(
            lambda x: int(
                x['regeninterval'] if "regeninterval" in x else regeninterval),
            j['endpoints'])))
    for ep in j['endpoints']:
        if "regeninterval" in ep:
            del ep['regeninterval']
        if "params" not in ep:
            ep['params'] = {}
        keylist = list(ep.keys())
        for k in keylist:
            if k not in ("priority", "target", "alias", "params"):
                if k in ("ipv4hint", "ipv6hint", "alpn"):
                    if isinstance(ep[k], str):
                        ep['params'][k] = list(map(
                            lambda x: x.strip(), ep[k].split(',')))
                else:
                    ep['params'][k] = ep[k]
                del ep[k]
    return j

def wkech_to_HTTPS_rrset(svcbname: dns.name.Name|str,
                         wkechdata: dict, target = None,
                         regeninterval=3600): # reference is earlier ???
    rrset = []
    if not wkechdata:
        return []
    ttl = int(wkechdata['regeninterval'] / 2 if 'regeninterval' in wkechdata else regeninterval / 2)
    dnstype = 'HTTPS'
    for endpoint in wkechdata['endpoints']:
        if 'alias' in endpoint:
            priority = 0
            target = endpoint['alias']
            rr = f"{dns.name.from_text(svcbname)} {ttl} {dnstype} {priority} {target}"
            # logging.debug(f"RR generated from WKECH: {rr}")
            rrset.append(rr)
        else:
            if 'target' in endpoint:         # WKECH specifies target
                target = endpoint['target']  # - obey, ignoring arg -- NOTE: GIGO risk
                logging.debug(f"WKECH specifies target: '{target}'")
            if not target:                   # target missing from both WKECH and arg
                if svcbname.startswith('_'): # svcbname no good
                    pass                     # - avoid using it
                else:                        # svcbname OK
                    target = '.'             # - use compact equivalent
            elif target.startswith('_'):
                target = None
                logging.warning(f"Target is invalid: '{target}'")
            if target:
                if target == svcbname:
                    target = '.'
                svcparams = []
                priority = endpoint['priority'] if 'priority' in endpoint else 1 # TODO: improve this
                params = endpoint['params']
                for tag, val in params.items():
                    if tag in ('ipv4hint', 'ipv6hint', 'alpn', 'mandatory'):
                        svcparams.append(f"{tag}={','.join(val)}")
                    # TODO: Add further special handling as needed (ALPN?, MANDATORY, ...)
                    elif tag in ('port', 'ech'):
                        svcparams.append(f"{tag}={val}")
                    elif tag in ('no-default-alpn'): 
                        svcparams.append(f"{tag}")
                    else:
                        pass    # Don't propagate unrecognized parameters
                rr = f"{dns.name.from_text(svcbname)} {ttl} {dnstype} {priority} {target} {' '.join(svcparams)}"
                # logging.debug(f"RR generated from WKECH: {rr}")
                rrset.append(rr)
            else:
                logging.warning(f"No valid target found for endpoint: {endpoint}")
    if not rrset:
        return rrset                                  # Empty list
    logging.debug(f"Invoking read_rrsets() with {rrset}")
    return dns.zonefile.read_rrsets('\n'.join(rrset)) # List (singleton) of dns.rrset objects



def parse_http_response(response_bytes): # in use
    parser = HTTPResponseParser()
    parser.feed_data(response_bytes)
    return {
        "status_code": parser.parser.get_status_code(),
        "reason": parser.reason,
        "headers": parser.headers,
        "body": bytes(parser.body),
    }

def access_origin(hostname, port, path='', ech_configs=None, enable_retry=True, target=None) -> ECHresult: # in use
    logging.debug(f"Accessing service providing 'https://{hostname}:{port}/' with target '{target}'")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certifi.where())
    context.options |= ssl.OP_ECH_GREASE
    for config in ech_configs:
        try:
            context.set_ech_config(config)
            context.check_hostname = False
        except ssl.SSLError as e:
            logging.error(f"SSL error for {hostname}:{port} -- {e}")
            pass
    try:
        with socket.create_connection((target or hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False) as ssock:
                try:
                    status = None
                    ssock.do_handshake()
                    status = ssock.get_ech_status()
                    logging.debug("Handshake completed with ECH status: %s", ssock.get_ech_status().name)
                    logging.debug("Inner SNI: %s, Outer SNI: %s", ssock.server_hostname, ssock.outer_server_hostname)
                except ssl.SSLError as e:
                    if enable_retry:
                        retry_config = ssock._sslobj.get_ech_retry_config()
                        if retry_config:
                            logging.debug("Received a retry config: %s", base64.b64encode(retry_config))
                            return access_origin(hostname, port, path, [retry_config], False, target)
                    logging.error(f"SSL error for {hostname}:{port} -- {e}")

                response = b''
                if path != None:
                    logging.debug(f"Performing GET request for https://{hostname}:{port}{path}")
                    request = f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'
                    ssock.sendall(request.encode('utf-8'))
                    while True:
                        data = ssock.recv(4096)
                        if not data:
                            break
                        response += data
                return ECHresult({"ech_status": status, "response": response})
    except socket.gaierror as e:
        logging.warning(f"socket error for {target or hostname}:{port} -- {e}")
        return ECHresult({'ech_status': None, 'response': b''})


def get_http(hostname, port, path, ech_configs, target=None) -> bytes: # in use
    logging.debug(f"Getting HTTP data from 'https://{hostname}:{port}{path}' with target '{target}'")
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, target=target)["response"]

def probe_ech(hostname, port, path, ech_configs, target=None): # in use
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, enable_retry=False, target=target)["ech_status"]



def get_https_rrchain(domain: dns.name.Name|str, follow_alias: bool = True, depth = 8 # in use
                    ) -> List[Optional[dns.resolver.Answer]]:
    result: list[Optional[dns.resolver.Answer]] = []
    try:
        # ans = dns.resolver.resolve(domain, "HTTPS")
        ans = ChosenResolver.active.resolve(domain, "HTTPS")
    except dns.resolver.NoAnswer:
        logging.warning(f"No HTTPS record found for {domain}")
    except Exception as e:
        logging.critical(f"DNS query failed: {e}")
        return result + [None]
    result = [ans]
    rrs = list(filter(lambda a: a.rdtype == 65, ans))
    if len(rrs):
        rrs.sort(key=lambda a: a.priority)
        if rrs[0].priority == 0:
            result +=  get_https_rrchain(rrs[0].target, follow_alias=(depth>0), depth=depth-1)
    return result


def check_wkech(hostname, regeninterval=3600, target=None, port=None) -> dict: # in use
    """Compare WKECH data against existing HTTPS RRset (if any), and validate WKECH data"""
    logging.debug(f"Entered check_wkech with args:")
    logging.debug(f"          hostname: '{hostname}'")
    logging.debug(f"              port: '{port}'")
    logging.debug(f"            target: '{target}'")
    logging.debug(f"    regenintervsal: '{regeninterval}'")
    result = {
        'OK': False,            # until we know better
        'Update': []            # List of RRsets to update
    }                           # return value
    alias = None
    ech_configs = []
    scheme = "https"
    if scheme not in ("http", "https"):
        logging.warning(f"Scheme '{scheme}' not supported")
        return result

    # hostname = urllib.parse.urlparse(url).hostname
    # port = urllib.parse.urlparse(url).port
    if not port or port in (443, 80):
        port = 443
    wkurl = f"{scheme}://{hostname}:{port}/.well-known/svcb-origin"
    svcbname = hostname if port == 443 else f"_{port}._HTTPS.{hostname}"
    chain = get_https_rrchain(svcbname)
    depth = len(chain)
    #
    # Notes:
    #  - First RRset in chain is to be compared to WKECH data
    #  - Last RRset in chain is only one relevant for ECHConfig validation
    #  - After successful validation, first RRset is to be updated
    #    unless it matches WKECH data
    #
    if depth == 0:              # No HTTPS record found
        logging.warning(f"No HTTPS record found for '{svcbname}'")
    else:                       # Chain of AliasMode HTTPS RRsets
        if depth > 1:
            logging.debug(f"HTTPS RRset chain (depth {depth}) found for '{svcbname}'")
        focus = chain[-1].rrset
        logging.debug(f"Focus on RRset '{focus}'")
        rrs = list(filter(lambda a: a.rdtype == 65, focus))
        rrs.sort(key=lambda a: a.priority)
        select_rr = rrs[0]
        if select_rr.priority == 0:
            logging.warning(f"HTTPS RRset chain for '{svcbname}' has unresolved AliasMode RRset")
        else:
            logging.debug(f"HTTPS RRset chain for '{svcbname}' ends with a ServiceMode RRset")
            echparam = select_rr.params.get(5)
            if echparam:
                ech_configs.append(echparam.ech)
            alias = str(select_rr.target)
            if alias == '.':
                alias = None if depth == 1 else str(focus.name)
        
    logging.debug(f"Using alias '{alias}', "
                  f"echconfigs {list(map(lambda x: base64.b64encode(x).decode('utf-8'), ech_configs))}")

    response = parse_http_response(get_http(hostname, port, "/.well-known/origin-svcb", ech_configs, alias))
    if response['status_code'] == 200: # or could test 'reason' for 'OK'
        rectified = rectify(json.loads(response['body']), regeninterval=regeninterval)
    else:
        rectified = None
        logging.warning(f"Unable to retrieve data from {wkurl}")

    if not rectified:
        logging.warning(f"Data retrieved from {wkurl} is invalid")
    else:
        logging.debug(f"Data retrieved from {wkurl}: {rectified}")
        rrset = wkech_to_HTTPS_rrset(svcbname, rectified, target=hostname, regeninterval=regeninterval)
        logging.debug(f"Generated RRset: {rrset[0]}")
        logging.debug(f"Published RRset: {chain[0].rrset}")
        if rrset[0] != chain[0].rrset or rrset[0].ttl != chain[0].rrset.ttl:
            # TODO: consider whether to check TTL
            logging.debug(f"Generated RRset differs from published one")

            bad_endpoints = 0   # none seen yet
            for endpoint in rectified['endpoints']:
                endpoint['_OK_'] = False # until we know better
                if 'params' not in endpoint or 'ech' not in endpoint['params']:
                    # nothing to validate
                    endpoint['_OK_'] = True
                    continue

                conflist = ECHConfigList(endpoint['params']['ech'])
                configs = conflist.analyze() # break out individual configs from ECHConfigList
                cfcount = len(configs)
                cftally = 0
                bad_configs = 0
                for echconfig in configs:
                    # Visit target using just this config
                    cftally += 1
                    echstatus = probe_ech(hostname, port, None, ech_configs=[echconfig], target=target)
                    logging.debug(f"Result from probing with ECHConfig {cftally}/{cfcount}: {echstatus}")
                    if echstatus != ssl.ECH_STATUS_SUCCESS:
                        bad_configs += 1
                    # Next echconfig
                if bad_configs:
                    bad_endpoints += 1
                else:
                    endpoint['_OK_'] = True
                # Next endpoint
            if bad_endpoints == 0:
                result['OK'] = True
                result['Update'] = rrset[:1]
            
        else:
            logging.debug(f"WIP: Generated RRset matches published one")
            result['OK'] = True

    return result


def pdnsutil_update(hostname, port,
                    target=None, regeninterval=3600, options={}):
    logging.debug(f"Checking consistency for ({hostname}, {port}, {target})")
    checked = check_wkech(hostname, port=port, target=target, regeninterval=regeninterval)
    if not checked['OK']:
        logging.warning(f"Validation failed for ({hostname}, {port}, {target})")
    elif not checked['Update']:
        logging.info(f"No update needed for ({hostname}, {port}, {target})")
    else:
        logging.info(f"Update required for ({hostname}, {port}, {target})")
        logging.debug(f"Count of items to update: {len(checked['Update'])}")
        for item in checked['Update']:
            if not item:
                continue
            if type(item) != dns.rrset.RRset:
                logging.warning(f"Item is not an RRset: '{item}'")
                continue
            if item.rdtype != dns.rdatatype.HTTPS:
                logging.warning(
                    f"Item has unexpected RRTYPE '{str(item.rdtype)}'")
                continue
            logging.debug(f"Examining {type(item)} item '{item}'")
            updname = str(item.name)
            if len(updname) > 1 and updname[-1] == '.':
                updname = updname[:-1]
            updzone = str(dns.resolver.zone_for_name(item.name))
            if len(updzone) > 1 and updzone[-1] == '.':
                updzone = updzone[:-1]
            updtype = str(item.rdtype.to_text(item.rdtype))
            updrdata = ' '.join(list(map(lambda x: f"'{x}'", item)))
            command = []
            if options['become']:
                if options['become']['method'] == 'sudo':
                    command += ['sudo', '-u', options['become']['user'] ]
                else:
                    logging.error(
                        f"Unrecognized privilege-escalation method:"
                        f"'{options['become']['method']}'")
                    break       # no point processing further items
            prefix_length = len(command)
            command += ['pdnsutil', 'rrset', 'replace',
                        updzone, updname, updtype, str(item.ttl) ]
            command += list(map(lambda x: str(x), item))
            logging.debug(f"Plan to apply update using command:")
            logging.debug(f"\n  {('\n    '.join(command))}")

            # dryrun = options['dryrun'] if 'dryrun' in options else False

            if 'dryrun' not in options or not options['dryrun']:
                outcome = subprocess.run(command, capture_output=True)
                if outcome.returncode:
                    logging.error(
                        f"Unable to perform update for {updname}")
                else:
                    command = command[:prefix_length]
                    command += [ 'pdnsutil', 'zone', 'increase-serial',
                                 updzone ]
                    logging.debug(f"Plan to advance SOA serial using command:")
                    logging.debug(f"\n  {('\n    '.join(command))}")
                    outcome = subprocess.run(command, capture_output=True)
                    if outcome.returncode:
                        logging.error(f"SOA serial not advanced for {updzone}")
                        logging.info(f"{outcome}")
            else:
                logging.info(f"DRY RUN: skipping update")


def do_visit(visit, args):
    pdnsutil_update(visit['origin'], visit['port'],
                    target=visit['alias'],
                    regeninterval=visit['regeninterval'],
                    options={
                        'dryrun': args.dryrun,
                        'format': args.format,
                        'become': {
                            'enabled': args.become,
                            'method':  args.become_method,
                            'user':    args.become_user
                            } if args.become else {},
                        'keyring': None})


def defaultConfig() -> str:
    found = None
    p = Path.home()
    q = p / '.zfconfig'
    if q.is_file():
        found = str(q)
    else:
        for p in [
                Path(Path.home(), '.config'),
                Path('/usr/local/etc'),
                Path('/etc')
        ]:
            logging.debug(f"Seeking configuration file in '{p}'")
            q = [x for x in [(p / 'zone-factory.csv'),
                       (p / 'zone-factory.cfg')] if x.is_file()]
            if q:
                found = str(q[0])
                break
    return found


def validHostname(given: str) -> bool:
    ldh = string.digits + string.ascii_letters + '-' 
    if given == '.':            # special case
        return True
    if not given:               # void
        return False
    trimmed = given if given[-1] != '.' else given[:-1]
    if len(trimmed) > 253:      # too long for wire-encoding
        return False
    for label in trimmed.split('.'):
        if (not label                       # void (consecutive dots)
            or '-' in [label[0], label[-1]] # begins or ends with '-'
            or len(label) > 63):            # label too long
            return False
        for x in label:
            if x not in ldh:    # invalid host name
                return False

    # looks good!
    return True

def loadConfig(config) -> list:
    if not Path(config).is_file:
        logging.warning(f"Configuration '{config}' not available")
        return []

    # TODO: allow for other configuration file formats (YAML, JSON, ...)
    return loadCSVConfig(config, delimiter=',')


def loadCSVConfig(config, delimiter=',') -> list:
    result = [ ]
    errors = 0
    with open(config, newline='', encoding="utf-8") as csvfile:
        readCSV = csv.reader(csvfile, delimiter=delimiter)
        for asread in readCSV:
            if not asread:
                continue    # skip empties
            show = ', '.join(list(map(
                lambda x: x.rstrip() if x.rstrip() else x,
                asread)))
            row = list(map(lambda x: x.strip(), asread))
            origin = row[0]
            if not origin:
                logging.error(f"Invalid entry in {config}:"
                              f" '{show}'")
                errors += 1
                continue
            if origin[0] in ';#': # allow comments
                continue               # and skip them
            if not validHostname(origin):
                logging.error(f"Invalid entry in {config}:"
                              f" '{show}'")
                errors += 1
                continue
            if errors:
                logging.debug(f"Skipping configuration entry:"
                              f" '{show}'")
            else:
                logging.debug(f"Accepting row from file '{config}': '{show}'")
                item = {'alias': None,
                        'port': None,
                        'regeninterval': 3600}
                row = list(map(str.strip, row))
                if len(row) > 3 and row[3]:
                    item['regeninterval'] = int(row[3])
                if len(row) > 2 and row[2]:
                    alias = row[2].strip()
                    if not validHostname(alias):
                        logging.error(f"Invalid entry in {config}:"
                                      f" '{show}'")
                        errors += 1
                        continue
                    item['alias'] = alias
                if len(row) > 1 and row[1]:
                    item['port'] = int(row[1])
                item['origin'] = origin
                result.append(item)
    if errors:
        logging.warning(f"Ignoring configuration due to errors")
        result = []
    elif not result:
        logging.warning(f"No valid configuration data: '{config}'")
    return result


def setupLogging(verbosity:int=1) -> None:
    logging.basicConfig(
        level=list(map(lambda x:logging._nameToLevel[x],
                       ('ERROR', 'WARNING', 'INFO', 'DEBUG'))
                   )[min(3,max(0,verbosity))],
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

def cliparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        # formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""
        This script implements the Zone Factory synchronization function
        described in section 6.2 of the Internet Draft specifying
        "A well-known URI for publishing service parameters"
        (https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech)."""),
        epilog=textwrap.dedent("""
        Implementation restrictions:

        1.  Periodic synchronization is not implemented. The zone
            administrator must arrange for the script to be invoked
            by a job scheduler or daemon, as required.

        2.  Support for arbitrary SVCB-compatible record types
            is neither implemented nor planned.""")
    )
    parser.add_argument(
        'config', nargs='?', default=None,
        help=textwrap.dedent('''\
        file specifying which HTTP origins are to be processed
        (required; default: %(default)s).
        ''')
    )
    parser.add_argument(
        "-n", "--dryrun", "--dry-run", action="store_true",
        help="disable update transaction"
    )
    parser.add_argument(
        '-v', '--verbose', default=1, action='count',
        help=textwrap.dedent("""\
        make logging (progressively) more verbose.
        By default, WARNING messages are shown;
        to add INFO messages, use '-v';
        for DEBUG messages as well, use '-v -v' or '-vv'.
        """)
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_const', const=0, dest='verbose',
        help='limit logging to ERROR and CRITICAL levels'
    )
    parser.add_argument(
        "-s", "--nameserver", "--name-server", default="::1", nargs='?',
        help=textwrap.dedent("""\
        DNS name server to use instead of system resolver
        (default: %(default)s).
        """)
    )
    parser.add_argument(
        "-b", "--become", action="store_true",
        help=textwrap.dedent("""\
        Use privilege escalation for invoking pdnsutil
        (see also: '--become-method', '--become-user').""")
    )
    parser.add_argument(
        "--become-method", default="sudo", nargs="?",
        help=textwrap.dedent("""\
        Utility to use to escalate privilege for pdnsutil
        (default: %(default)s).""")
    )
    parser.add_argument(
        "--become-user", default="pdns", nargs="?",
        help=textwrap.dedent("""\
        User ID to use to escalate privilege for pdnsutil
        (default: %(default)s).""")
    )
    parser.add_argument(
        "-f", "--format", default="CSV", choices=['CSV'],
        help="format of configuration file (CSV only for now)")

    # -- more, as needed

    return parser


def main() -> None:
    parser = cliparser()
    args = parser.parse_args()

    setupLogging(args.verbose)
    args.config = args.config or defaultConfig()
    if not args.config:
        parser.print_help()
        return
    if args.nameserver:
        ChosenResolver.activate(args.nameserver)

    logging.debug(f"Options in effect: {args}")

    for visit in loadConfig(args.config):
        logging.debug(f"Visiting: {visit}")
        do_visit(visit, args)
        

if __name__ == "__main__":
    main()
