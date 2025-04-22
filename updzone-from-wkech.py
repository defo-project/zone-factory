import argparse
import base64
import json
import logging
import socket
import ssl
import sys
import os
import urllib.parse
from typing import List, OrderedDict, TypedDict, NotRequired, Union, Tuple, Sequence, Optional
from urllib.parse import ParseResult

import certifi
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.zonefile
import httptools
import csv


class ChosenResolver:
    from dns.resolver import get_default_resolver, make_resolver_at
    active = get_default_resolver()

    def activate(server):
       ChosenResolver.active = ChosenResolver.make_resolver_at(server)


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


def parse_http_response(response_bytes): # in use
    parser = HTTPResponseParser()
    parser.feed_data(response_bytes)
    return {
        "status_code": parser.parser.get_status_code(),
        "reason": parser.reason,
        "headers": parser.headers,
        "body": bytes(parser.body),
    }


def svcbname(parsed: ParseResult): # in use
    """Derive DNS name of SVCB/HTTPS record corresponding to target URL"""
    if parsed.scheme == "https":
        if (parsed.port or 443) == 443:
            return parsed.hostname
        else:
            return f"_{parsed.port}._https.{parsed.hostname}"
    elif parsed.scheme == "http":
        if (parsed.port or 80) in (443, 80):
            return parsed.hostname
        else:
            return f"_{parsed.port}._https.{parsed.hostname}"
    else:
        # For now, no other scheme is supported
        return None


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


def get_ech_configs(domain, follow_alias: bool = True, depth = 0) -> Tuple[Optional[str], List[bytes]]: # in use
    """Look up HTTPS record, following aliases as needed"""
    maxdepth = 8                # Arbitrary constant
    try:
        # ans = dns.resolver.resolve(domain, "HTTPS")
        ans = ChosenResolver.active.resolve(domain, "HTTPS")
    except dns.resolver.NoAnswer:
        logging.warning(f"No HTTPS record found for {domain}")
        return None, []
    except Exception as e:
        logging.critical(f"DNS query failed: {e}")
        sys.exit(1)

    rrs = list(filter(lambda a: a.rdtype == 65, ans))

    if len(rrs) == 0:
        logging.warning(f"No echconfig found in HTTPS record for {domain}")
        return None, []

    rrs.sort(key=lambda a: a.priority)
    if rrs[0].priority == 0:
        if depth > maxdepth:
            logging.critical(f"Alias recursion depth {depth} exceeds limit {maxdepth}")
            sys.exit(1)
        logging.debug(f"HTTPS record using AliasMode (0). Looking instead at {rrs[0].target}")
        return get_ech_configs(rrs[0].target.to_text(True), False, depth=depth+1)

    configs = []

    for rdata in rrs:
        if hasattr(rdata, "params"):
            params = rdata.params
            echconfig = params.get(5)
            if echconfig:
                configs.append(echconfig.ech)

    if follow_alias:
        return None, []

    return domain, configs


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


def get(url: str, force_grease: bool=False, target: Optional[str]=None): # in use
    logging.debug(f"Getting data for URL '{url}' with target '{target}'")
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname
    if force_grease:
        alias, ech_configs = None, []
    else:
        # chain = get_https_rrchain(svcbname(parsed))
        # logging.debug(f"HTTPS RRset(s): {list(map(lambda x: x.rrset, chain))}")
        alias, ech_configs = get_ech_configs(svcbname(parsed))
    target = target or alias
    logging.debug(f"  target now set to '{target}'")
    logging.debug("Discovered ECHConfig values: %s", [base64.b64encode(config) for config in ech_configs])
    request_path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
    raw = get_http(domain, parsed.port or 443, request_path, ech_configs, target)
    return parse_http_response(raw)


def rectify(j):                 # in use
    """ Convert content at WK URI from earlier format to current """
    if "endpoints" not in j:
        # Nothing to work with
        return None
    if "regeninterval" not in j:
        j['regeninterval'] = min(list(map(
            lambda x: int(
                x['regeninterval'] if "regeninterval" in x else 3600),
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


def get_wkech(url, target=None): # in use
    """Retrieve effective WKECH data, following alias if appropriate"""
    logging.debug(f"Fetching WKECH data for url {url}")
    parsed = urllib.parse.urlparse(url)
    wkurl = f"{parsed.scheme}://{parsed.netloc}/.well-known/origin-svcb"
    response = get(wkurl, target=target)
    if response['status_code'] == 200: # or could test 'reason' for 'OK'
        rectified = rectify(json.loads(response['body']))
        if not rectified:
            logging.warning(f"Data retrieved from {wkurl} is invalid")
    else:
        rectified = None
        logging.warning(f"Unable to retrieve data from {wkurl}")
    return rectified


def check_wkech(url, regeninterval=3600, target=None) -> dict: # in use
    """Compare WKECH data against existing HTTPS RRset (if any), and validate WKECH data"""
    result = {
        'OK': False,            # until we know better
        'Update': []            # List of RRsets to update
    }                           # return value
    alias = None
    ech_configs = []
    scheme = urllib.parse.urlparse(url).scheme
    if scheme not in ("http", "https"):
        logging.warning(f"Scheme '{scheme}' not supported")
        return result

    hostname = urllib.parse.urlparse(url).hostname
    port = urllib.parse.urlparse(url).port
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
        rectified = rectify(json.loads(response['body']))
    else:
        rectified = None
        logging.warning(f"Unable to retrieve data from {wkurl}")

    if not rectified:
        logging.warning(f"Data retrieved from {wkurl} is invalid")
    else:
        logging.debug(f"Data retrieved from {wkurl}: {rectified}")
        rrset = wkech_to_HTTPS_rrset(svcbname, rectified, target=hostname)
        logging.debug(f"Generated RRset: {rrset[0]}")
        logging.debug(f"Published RRset: {chain[0].rrset}")
        if rrset[0] != chain[0].rrset: # TODO: consider checking TTL also
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
                    logging.debug(f"Result from probing with ECHConfig {cftally}/{cfcount}: {echstatus.name}")
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


def wkech_to_HTTPS_rrset(svcbname: dns.name.Name|str, wkechdata: dict, target = None): # reference is earlier ???
    rrset = []
    if not wkechdata:
        return []
    ttl = int(wkechdata['regeninterval'] / 2 if 'regeninterval' in wkechdata else 1800)
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
    return dns.zonefile.read_rrsets('\n'.join(rrset)) # List (singleton) of dns.rrset objects


def prepare_update(url, target=None): # in use
    result = []
    checked = check_wkech(url, target=target)
    if not checked['OK']:
        logging.warning(f"Validation failed for '{url}'")
    elif not checked['Update']:
        logging.info(f"No update needed for '{url}'")
    else:
        for item in checked['Update']:
            result.append(f"update delete {item.name} 0 IN {dns.rdatatype.to_text(item.rdtype)}")
            for rr in item:
                result.append(f"update add {item.name} {item.ttl}"
                              f" {dns.rdataclass.to_text(item.rdclass)}"
                              f" {dns.rdatatype.to_text(item.rdtype)} {rr.to_text()}")
            result.append("send")
            result.append("")
    return result


def cmd_get(args) -> None:      # in use, but maybe not really
    """Retrieves data from a given URL."""
    print(get(args.url, args.force_grease))


class GetTarget(TypedDict):     # in use
    description: NotRequired[str]
    expected: NotRequired[str]
    url: str


def cmd_fetch(args) -> None:    # in use
    """ Retrieve data from WKECH URL corresponding to given url """
    url = args.url
    loaded = get_wkech(url, args.alias)
    if loaded:
        while loaded:
            print(f"WKECH data for {url}:")
            print(json.dumps(loaded))
            endpoints = loaded['endpoints']
            loaded = None
            for endpoint in endpoints:
                if 'alias' in endpoint:
                    url = f"{urllib.parse.urlparse(url).scheme}://{endpoint['alias']}"
                    loaded = get_wkech(url)
    else:
        logging.warning(f"Found no WKECH data for {url}")


def cmd_check_wkech(args) -> None: # in use
    """ Retrieve data from WKECH URL and validate each ECHConfig found """
    checked = check_wkech(args.url, target=args.alias)
    if checked['OK']:
        logging.info(f"Validation succeeded")
        count = len(checked['Update'])
        if count:
            logging.info(f"{count} RRset{'s' if count > 1 else ''} must be updated for DNS to match WKECH data")
        else:
            logging.info(f"DNS matches WKECH data")


def cmd_publish_rrset(args) -> None: # future work
    """ Update DNS directly with HTTPS RRset from validated WKECH data """
    # TODO: consider more elaborate interface for this command
    logging.warning("This subcommand is not yet implemented")


def run_batch(action, todo, delimiter=','):
    with open(todo) as csvfile:
        readCSV = csv.reader(csvfile, delimiter=delimiter)
        for row in readCSV:
            logging.debug(f"Parsing row from file '{todo}': {row}")
            if len(row) < 1 or not row[0]:
                continue    # skip empties
            if str(row[0])[0] in ';#': # allow comments
                continue               # and skip them
            alias = None
            port = None
            thisurl = f"https://{row[0]}"
            if len(row) > 2 and row[2]:
                alias = str(row[2])
            if len(row) > 1 and row[1]:
                port = int(row[1])
            if port and port != 443:
                thisurl += f":{port}/"
            else:
                thisurl += "/"
            if alias:
                logging.info(f"Processing URL {thisurl} (alias {alias})")
            else:
                logging.info(f"Processing URL {thisurl}")
            #
            # TODO: move print() to invoked function (perhaps wrapper around action)
            #
            update = action(thisurl, target=alias)
            for command in update:
                print(command)


def ready_batch(action, args):
    url = args.url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ['', 'csv']:
        descr = '(presumed CSV)' if not parsed.scheme else 'CSV'
        logging.info(f"Processing batch {descr} file: '{parsed.path}'")
        run_batch(action, parsed.path)
    elif parsed.scheme in ['https']: # Maybe HTTP also?
        logging.info(f"Processing single URL '{url}'")
        update = action(url, target=args.alias)
        # TODO: move print() (se above)
        for command in update:
            print(command)
    else:
        logging.info(f"Scheme not supported: '{url}'")


def cmd_prepare_update(args) -> None: # in use
    """ Prepare HTTPS Update (as input stream for BIND9 NSUPDATE) from validated WKECH data """
    action = prepare_update
    ready_batch(action, args)
    

# def cmd_dummy(args) -> None:
#     """ Dummy command handler for testing """
#     action = prepare_update
#     ready_batch(action, args)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "A Python tool for updating a DNS zone from WKECH data"
            if os.path.basename(sys.argv[0]).startswith('updzone')
            else "A Python HTTPS client with TLS ECH support."),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "-n", "--nameserver", "--name-server", default=None, nargs='?',
        help="DNS name server to use instead of system resolver"
    )

    subparsers = parser.add_subparsers(
        title="subcommands", dest="command", help="Available subcommands"
    )

    # dummy_parser = subparsers.add_parser(
    #     "dummy",
    #     help="Dummy command for testing")
    # dummy_parser.add_argument("url", help="URL to use for testing")
    # dummy_parser.add_argument('--alias', '-a', nargs='?', default=None)
    # dummy_parser.set_defaults(func=cmd_dummy)

    prepare_update_parser = subparsers.add_parser(
        # "prepare_update",
        "generate",
        help="Fetch WKECH data and, if valid, generate zone update commands")
    prepare_update_parser.add_argument("url",
                                       # help="URL from which to construct WKECH URL"
                                       help="URL with either 'https:' authority, or 'csv:' path to batch file"
                                       )
    prepare_update_parser.add_argument('--alias', '-a', nargs='?', default=None)
    prepare_update_parser.set_defaults(func=cmd_prepare_update)

    check_wkech_parser = subparsers.add_parser(
        # "check_wkech",
        "validate",
        help="Fetch and validate WKECH data")
    check_wkech_parser.add_argument("url", help="URL from which to construct WKECH URL")
    check_wkech_parser.add_argument('--alias', '-a', nargs='?', default=None)
    check_wkech_parser.set_defaults(func=cmd_check_wkech)

    getwkech_parser = subparsers.add_parser(
        # "getwkech",
        "fetch",
        help="Fetch WKECH data without validation")
    getwkech_parser.add_argument("url",
                                 # [alternative for list of URLs] nargs='*',
                                 help="Origin URL from which to construct WKECH URL")
    getwkech_parser.add_argument('--alias', '-a', nargs='?', default=None)
    getwkech_parser.set_defaults(func=cmd_fetch)

    # publish_rrset_parser = subparsers.add_parser("publish_rrset", help="Update DNS directly")
    # publish_rrset_parser.add_argument("url", help="URL from which to construct WKECH URL")
    # publish_rrset_parser.set_defaults(func=cmd_publish_rrset)

    args = parser.parse_args()
    if args.nameserver:
        ChosenResolver.activate(args.nameserver)

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logging.debug(f"Command line arguments: {args}")

    if args.command is None:
        parser.print_help()
        return

    # if args.command == "getlist":
    #     args.func(args.demo)
    #     return

    try:
        args.func(args)
    except AttributeError as e:
        logging.critical(
            f"Error: Subcommand '{args.command}' was called, but it requires no additional arguments: {e}"
        )


if __name__ == "__main__":
    main()
