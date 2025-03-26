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
import dns.name
import dns.resolver
import httptools


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


def parse_http_response(response_bytes):
    parser = HTTPResponseParser()
    parser.feed_data(response_bytes)
    return {
        "status_code": parser.parser.get_status_code(),
        "reason": parser.reason,
        "headers": parser.headers,
        "body": bytes(parser.body),
    }


def svcbname(parsed: ParseResult):
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


# def get_ech_configs(domain) -> List[bytes]:
#     # TODO: refactor following new pyclient.py, which returns a Tuple
#     try:
#         answers = dns.resolver.resolve(domain, "HTTPS")
#     except dns.resolver.NoAnswer:
#         logging.warning(f"No HTTPS record found for {domain}")
#         return []
#     except Exception as e:
#         logging.critical(f"DNS query failed: {e}")
#         sys.exit(1)

#     configs = []

#     for rdata in answers:
#         if hasattr(rdata, "params"):
#             params = rdata.params
#             echconfig = params.get(5)
#             if echconfig:
#                 configs.append(echconfig.ech)

#     if len(configs) == 0:
#         logging.warning(f"No echconfig found in HTTPS record for {domain}")

#     return configs

def get_ech_configs(domain, follow_alias: bool = True) -> Tuple[Optional[str], List[bytes]]:
    try:
        answers = dns.resolver.resolve(domain, "HTTPS")
    except dns.resolver.NoAnswer:
        logging.warning(f"No HTTPS record found for {domain}")
        return None, []
    except Exception as e:
        logging.critical(f"DNS query failed: {e}")
        sys.exit(1)

    answers = list(filter(lambda a: a.rdtype == 65, answers))

    if len(answers) == 0:
        logging.warning(f"No echconfig found in HTTPS record for {domain}")
        return None, []

    answers.sort(key=lambda a: a.priority)
    if answers[0].priority == 0:
        logging.debug(f"HTTPS record using AliasMode (0). Looking instead at {answers[0].target}")
        return get_ech_configs(answers[0].target.to_text(True), False)

    configs = []

    for rdata in answers:
        if hasattr(rdata, "params"):
            params = rdata.params
            echconfig = params.get(5)
            if echconfig:
                configs.append(echconfig.ech)

    return None if follow_alias else domain, configs


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


def access_origin(hostname, port, path='', ech_configs=None, enable_retry=True, target=None) -> ECHresult:
    logging.debug(f"Accessing service providing https://{hostname}:{port}/")
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
    logging.debug(f"Target is {target} and hostname is {hostname}:{port}")
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
                            # return get_http(hostname, port, path, [retry_config])
                            return access_origin(hostname, port, path, [retry_config], False, target)
                    logging.error(f"SSL error for {hostname}:{port} -- {e}")

                response = b''
                if path != None:
                    logging.debug(f"Performing GET request for https://{hostname}:{port}/{path}")
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


def get_http(hostname, port, path, ech_configs, target=None) -> bytes:
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, target=target)["response"]


def probe_ech(hostname, port, path, ech_configs, target=None):
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, enable_retry=False, target=target)["ech_status"]


def get(url: str, force_grease: bool=False, target: Optional[str]=None):
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname
    if force_grease:
        alias, ech_configs = None, []
    else:
        alias, ech_configs = get_ech_configs(svcbname(parsed))
    target = target or alias
    logging.debug("Discovered ECHConfig values: %s", [base64.b64encode(config) for config in ech_configs])
    request_path = (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')
    raw = get_http(domain, parsed.port or 443, request_path, ech_configs, target)
    return parse_http_response(raw)


def rectify(j):
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


def get_wkech(url, target=None):
    """Retrieve effective WKECH data, following alias if appropriate"""
    logging.debug(f"Fetching WKECH data for url {url}")
    parsed = urllib.parse.urlparse(url)
    wkurl = f"{parsed.scheme}://{parsed.netloc}/.well-known/origin-svcb"
    # response = get(f"{parsed.scheme}://{target or parsed.netloc}/.well-known/origin-svcb")
    response = get(wkurl, target=target)
    if response['status_code'] == 200: # or could test 'reason' for 'OK'
        rectified = rectify(json.loads(response['body']))
        if not rectified:
            logging.warning(f"Data retrieved from {wkurl} is invalid")
    else:
        rectified = None
        logging.warning(f"Unable to retrieve data from {wkurl}")
    return rectified


def get_aliased_wkech(wkech, scheme='https'):
    "Chase SINGLE-STAGE aliasing, if any, and return corresponding ServiceMode WKECH data"
    #
    # TODO: recursive aliasing
    #
    result = OrderedDict({})
    if (not wkech) or ('endpoints' not in wkech):
        return result
    endpoints = wkech['endpoints']
    aliased = list(filter(lambda x: 'alias' in x, endpoints))
    if aliased:
        if len(endpoints) != len(aliased):
            logging.warning("Invalid WKECH data: AliasMode and Service mode are mixed")
        for endpoint in aliased:
            domain = endpoint['alias']
            if domain not in result:
                result[domain] = get_wkech(f"{scheme}://{domain}")
    return result


def check_wkech(url, regeninterval=3600, target=None): # TODO: work out what type to return
    scheme = urllib.parse.urlparse(url).scheme
    hostname = urllib.parse.urlparse(url).hostname
    port = urllib.parse.urlparse(url).port
    if not port or port == 80:
        port = 443
    loaded = get_wkech(url, target=target)

    # TODO: finish refactoring needed because alias handling was wrong

    if loaded:
        for endpoint in loaded['endpoints']: # visit each endpoint
            endpoint['_OK_'] = False         # until we know better
            if 'alias' in endpoint:
                pass                


    #         loaded['endpoints'] = aliased
    #         for endpoint in aliased:
    #             logging.debug(f"Checking endpoint {endpoint}")
    #             endpoint['_OK_'] = False
    #             checked = check_wkech(
    #                 f"{scheme}://{endpoint['alias']}/", regeninterval=regeninterval, target=aliased[0]['alias'])
    #             if list(filter(lambda x: x['_OK_'] == True, checked['endpoints'])):
    #                 endpoint['_OK_'] = True
                
    #         return loaded
                                   
    #     epcount = len(loaded['endpoints'])
    #     eptally = 0
    #     epvalid = 0
    #     for endpoint in loaded['endpoints']:
    #         eptally += 1
    #         endpoint['_OK_'] = False # until we know better
    #         params = endpoint['params']
    #         # TODO: 
    #         if 'ech' not in params:
    #             logging.warning(f"Endpoint {eptally}/{epcount} has no ECHConfigList parameter: marking it 'OK'")
    #             endpoint['_OK_'] = True # or None?
    #         else:
    #             badconfigs = []
    #             successcount = 0
    #             conflist = ECHConfigList(params['ech'])
    #             configs = conflist.analyze() # break out individual configs from ECHConfigList
    #             cfcount = len(configs)
    #             cftally = 0
    #             logging.debug(f"Endpoint {eptally}/{epcount} has an ECHConfigList with {cfcount} entries")
    #             for echconfig in configs:
    #                 # Visit target using just this config
    #                 cftally += 1
    #                 echstatus = probe_ech(hostname, port, None, ech_configs=[echconfig], target=target)
    #                 logging.debug(f"Result from probing with ECHConfig {cftally}/{cfcount}: {echstatus.name}")
    #                 if echstatus == ssl.ECH_STATUS_SUCCESS:
    #                     successcount += 1
    #                 else:
    #                     badconfigs.append(config)
    #             if successcount == len(configs):
    #                 endpoint['_OK_'] = True
    #                 epvalid += 1
    #             else:
    #                 logging.warning(f"ECHConfigList for endpoint {eptally}/{epcount} has only {successcount}/{cfcount} valid ECHConfigs")
    #     if target and epvalid:
    #         return {"endpoints": [{"alias": target, "params": {}, "_OK_": True}], "regeninterval": regeninterval}
    return loaded


def rdata_from_params(ep: dict) -> str:
    rdata = ''
    params = ep['params']
    for paramkey in params:
        if paramkey == 'alpn':
            pass                # TODO!
        elif paramkey in (('ipv4hint', 'ipv6hint')):
            rdata += f" {paramkey}={','.join(params[paramkey])}"
        elif paramkey == 'ech':
            rdata += f" {paramkey}={params[paramkey]}"
        else:
            pass
    return rdata

def prepare_update(url, target=None):
    updcmds = []
    endpoints = []
    parsed = urllib.parse.urlparse(url)
    ownername = dns.name.from_text(svcbname(parsed)).canonicalize()
    checked = check_wkech(url, target=target)
    if checked:
        updttl = int(checked['regeninterval'] / 2)
        endpoints = list(filter(lambda x: x['_OK_'] == True, checked['endpoints']))
    if endpoints:
        epcount = len(endpoints)
        updzone = dns.resolver.zone_for_name(ownername).canonicalize()
        updbase = f"{ownername} {updttl} IN HTTPS"
        prio = 0
        s = '' if epcount == 1 else 's'
        updcmds.append(f"zone {updzone}")
        updcmds.append(f"update delete {ownername} 0 IN HTTPS")
        for ept in endpoints:
            prio = ept['priority'] if 'priority' in ept else prio + 1
            if 'alias' in ept:
                prio = 0
                target = ept['alias']
            elif 'target' in ept:
                target = ept['target']
            else:
                target = '.'
            if prio == 0:
                updcmds.append(f"update add {updbase} {prio} {dns.name.from_text(target).canonicalize()}")
            else:
                # construct RDATA from params
                updcmds.append(f"update add {updbase} {prio} {dns.name.from_text(target).canonicalize()}"
                               f"{rdata_from_params(ept)}")
    else:
        logging.warning(f"No valid WKECH data: unsafe to update HTTPS RRset for {ownername} -- skipped")
    return '\n'.join(updcmds)


def cmd_get(args) -> None:
    """Retrieves data from a given URL."""
    print(get(args.url, args.force_grease))


def cmd_echconfig(args) -> None:
    """Print the bas64-encoded ECHConfig values for a given URL."""
    parsed = urllib.parse.urlparse(args.url)
    # TODO: review and possibly refactor for get_ech_configs() from new pyclient.py
    for config in get_ech_configs(svcbname(parsed)):
        print(base64.b64encode(config).decode("utf-8"))


class GetTarget(TypedDict):
    description: NotRequired[str]
    expected: NotRequired[str]
    url: str


# def read_targets_list() -> List[GetTarget]:
def read_targets_list() -> Sequence[GetTarget]: # ? -- mypy suggests Sequence instead of List
    try:
        input_json = sys.stdin.read()
        input_data = json.loads(input_json)

        if not isinstance(input_data, list):
            logging.critical("Invalid input format: JSON input must be a list")
            sys.exit(1)

        for item in input_data:
            if isinstance(item, dict):
                if "url" not in item:
                    logging.error(f"Invalid input format, missing url: {item}")
                    sys.exit(1)
                continue
            if not isinstance(item, str):
                logging.critical(
                    f"Invalid format: Each entry must be a string or object, but got {item}"
                )
                sys.exit(1)
        return input_data
    except json.JSONDecodeError as e:
        logging.critical(f"Error decoding JSON input: {e}")
        sys.exit(1)


def cmd_getlist(demo: bool) -> None:
    # targets: List[Union[GetTarget, str]]
    targets: Sequence[Union[GetTarget, str]] # ? -- mypy suggests Sequence instead of List
    if demo:
        targets = json.load(open("targets.json"))
    else:
        targets = read_targets_list()
    for target in targets:
        logging.debug("--------------------------------------------------------")
        if isinstance(target, str):
            cmd_get(target)
            continue
        logging.debug("Target description: %s", target["description"])
        logging.debug("Expected ECH status: %s", target["expected"])
        cmd_get(target["url"])


def cmd_fetch(args) -> None:
    """ Retrieve data from WKECH URL corresponding to given url """
    url = args.url
    loaded = get_wkech(url, args.alias)
    if loaded:
        while loaded:
            print(f"WKECH data for {url}:")
            print(json.dumps(loaded))
            # for pair in get_aliased_wkech(loaded, urllib.parse.urlparse(args.url).scheme).items():
            #     domain, wkechdata = pair
            #     print(f"WKECH data for alias {domain}:")
            #     print(json.dumps(wkechdata))
            endpoints = loaded['endpoints']
            loaded = None
            for endpoint in endpoints:
                if 'alias' in endpoint:
                    url = f"{urllib.parse.urlparse(url).scheme}://{endpoint['alias']}"
                    loaded = get_wkech(url)
    else:
        logging.warning(f"Found no WKECH data for {url}")


def cmd_check_wkech(args) -> None:
    """ Retrieve data from WKECH URL and validate each ECHConfig found """
    checked = check_wkech(args.url, target=args.alias)
    if checked:
        print(json.dumps(checked))
    logging.warning("This subcommand is not yet fully implemented")


def cmd_prepare_update(args) -> None:
    """ Prepare HTTPS Update (as input stream for BIND9 NSUPDATE) from validated WKECH data """
    update = prepare_update(args.url, target=args.alias)
    if update:
        print(update)
    logging.warning("This subcommand is not yet fully implemented")
    

def cmd_publish_rrset(args) -> None:
    """ Update DNS directly with HTTPS RRset from validated WKECH data """
    # TODO: consider more elaborate interface for this command
    logging.warning("This subcommand is not yet implemented")


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

    subparsers = parser.add_subparsers(
        title="subcommands", dest="command", help="Available subcommands"
    )

    if not os.path.basename(sys.argv[0]).startswith('updzone'):
        echconfig_parser = subparsers.add_parser(
            "echconfig", help="Print ECHConfig values from DNS (base64 encoded)."
        )
        echconfig_parser.add_argument("url", help="URL to fetch config for.")
        echconfig_parser.set_defaults(func=cmd_echconfig)

        get_parser = subparsers.add_parser("get", help="Fetch a URL.")
        get_parser.add_argument("url", help="URL to fetch")
        get_parser.add_argument(
            "-g", "--force-grease", action="store_true", help="Force GREASE"
        )
        get_parser.set_defaults(func=cmd_get)

        getlist_parser = subparsers.add_parser(
            "getlist", help="Iterate through a list of targets."
        )
        getlist_parser.add_argument("--demo", help="Use a set of demo targets.", action="store_true")
        getlist_parser.set_defaults(func=cmd_getlist)

    prepare_update_parser = subparsers.add_parser(
        # "prepare_update",
        "generate",
        help="Fetch WKECH data and, if valid, generate zone update commands")
    prepare_update_parser.add_argument("url", help="URL from which to construct WKECH URL")
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
    getwkech_parser.add_argument("url", help="URL from which to construct WKECH URL")
    getwkech_parser.add_argument('--alias', '-a', nargs='?', default=None)
    getwkech_parser.set_defaults(func=cmd_fetch)

    # publish_rrset_parser = subparsers.add_parser("publish_rrset", help="Validate data from WKECH URL")
    # publish_rrset_parser.add_argument("url", help="URL from which to construct WKECH URL")
    # publish_rrset_parser.set_defaults(func=cmd_publish_rrset)

    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logging.debug(f"Command line arguments: {args}")

    if args.command is None:
        parser.print_help()
        return

    if args.command == "getlist":
        args.func(args.demo)
        return

    try:
        args.func(args)
    except AttributeError as e:
        logging.critical(
            f"Error: Subcommand '{args.command}' was called, but it requires no additional arguments: {e}"
        )


if __name__ == "__main__":
    main()
