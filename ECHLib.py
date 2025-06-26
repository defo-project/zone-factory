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
import httptools
import csv
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.zonefile
import dns.tsigkeyring
import dns.update
import dns.exception

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

class ECHresult(TypedDict):
    servername: NotRequired[str]
    outername: NotRequired[str]
    ech_status: ssl.ECHStatus
    response: bytes

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

def check_wkech_by_url(url, regeninterval=3600, target=None) -> dict: # in use
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

    return check_wkech(hostname, regeninterval=regeninterval, target=target, port=port)

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
    return dns.zonefile.read_rrsets('\n'.join(rrset)) # List (singleton) of dns.rrset objects

def prepare_update_by_url(url, target=None): # in use
    result = []
    checked = check_wkech_by_url(url, target=target)
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

if __name__ == "__main__":
    print("This is a library:-)")
    sys.exit(1)
