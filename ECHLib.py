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

class ECHConfigList:
    import base64
    import logging

    def __len__(self):
        return len(self.body)

    def explode(self):
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

def get_https_rrchain(domain: dns.name.Name|str, follow_alias: bool = True, depth = 8 # in use
                    ) -> List[Optional[dns.resolver.Answer]]:
    result: list[Optional[dns.resolver.Answer]] = []
    try:
        lres = dns.resolver.make_resolver_at('::1')
        ans = lres.resolve(domain, "HTTPS")
    except dns.resolver.NoAnswer:
        logging.warning(f"No HTTPS record found for {domain}")
        return result
    except Exception as e:
        logging.critical(f"DNS query failed: {e}")
        return result
    result = [ans]
    # We wondered if this might this accept an HTTPS RR from the additional section.
    # testing seems to indicate not.
    rrs = list(filter(lambda a: a.rdtype == 65, ans))
    if len(rrs):
        rrs.sort(key=lambda a: a.priority)
        if follow_alias and rrs[0].priority == 0:
            result +=  get_https_rrchain(rrs[0].target, follow_alias=(depth>0), depth=depth-1)
    return result

def access_origin(hostname, port, path='', ech_configs=None, enable_retry=True, target=None, tout=1.0) -> ECHresult: # in use
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
            sock.settimeout(tout)
            logging.debug(f"Set socket timeout to {tout}")
            with context.wrap_socket(sock, server_hostname=hostname, do_handshake_on_connect=False) as ssock:
                try:
                    status = None
                    ssock.do_handshake()
                    status = ssock.get_ech_status()
                    logging.debug("Handshake completed with ECH status: %s", ssock.get_ech_status().name)
                    logging.debug("Inner SNI: %s, Outer SNI: %s", ssock.server_hostname, ssock.outer_server_hostname)
                except ssl.SSLError as e:
                    if enable_retry:
                        try:
                            retry_config = ssock._sslobj.get_ech_retry_config()
                            if retry_config:
                                logging.debug("Received a retry config: %s", base64.b64encode(retry_config))
                                return access_origin(hostname, port, path, [retry_config], False, target, tout)
                        except:
                            logging.error(f"retry-configs error for {hostname}:{port} -- {e}")
                            return ECHresult({'ech_status': None, 'response': b''})
                    logging.error(f"SSL error for {hostname}:{port} -- {e}")
                    return ECHresult({'ech_status': None, 'response': b''})

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

def get_http(hostname, port, path, ech_configs, target=None, tout=1.0) -> bytes: # in use
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, target=target, tout=tout)["response"]

def probe_ech(hostname, port, path, ech_configs, target=None, tout=1.0): # in use
    return access_origin(hostname, port, path=path, ech_configs=ech_configs, enable_retry=False, target=target, tout=tout)["ech_status"]

def wkech_to_HTTPS_rrset(svcbname: dns.name.Name|str,
                         wkechdata: dict, target = None,
                         regeninterval=3600): # reference is earlier ???
    rrset = []
    if not wkechdata:
        return []
    ttl = int(wkechdata['regeninterval'] / 2 if 'regeninterval' in wkechdata else regeninterval / 2)
    dnstype = 'HTTPS'
    # default priority if none explicitly specified
    priority = 1
    for endpoint in wkechdata['endpoints']:
        if 'alias' in endpoint:
            alias_priority = 0
            target = endpoint['alias']
            rr = f"{dns.name.from_text(svcbname)} {ttl} {dnstype} {alias_priority} {target}"
            # logging.debug(f"RR generated from WKECH: {rr}")
            rrset.append(rr)
        else:
            if 'target' in endpoint:         # WKECH specifies target
                # TODO: check if wkech-zf.py supplies args as expected here
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
                # if a priority was explicitly set, then use that and
                # latch it for subsequent records (if any)
                if 'priority' in endpoint:
                    priority = endpoint['priority']
                params = endpoint['params']
                for tag, val in params.items():
                    # Further code is a NOOP for now, but if/when other params supported
                    # then those might need code here, at least depending on whether they
                    # are single-valued (like ech) or a list (list alpn)
                    if tag in ('ipv4hint', 'ipv6hint', 'alpn', 'mandatory'):
                        svcparams.append(f"{tag}={','.join(val)}")
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

# TODO: check what happens if JSON is empty (spec says
#       that means delete, but we probably dislike that)
def check_wkech(hostname, regeninterval=3600, target=None, port=None, tout=1.0) -> dict: # in use
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
    if not port or port in (443, 80):
        port = 443
    wkurl = f"https://{hostname}:{port}/.well-known/svcb-origin"
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
    response = parse_http_response(get_http(hostname, port, "/.well-known/origin-svcb", ech_configs, alias, tout))
    if response['status_code'] == 200: # or could test 'reason' for 'OK'
        wkresponse = json.loads(response['body'])
    else:
        wkresponse = None
        logging.warning(f"Unable to retrieve data from {wkurl}")
    if not wkresponse:
        logging.warning(f"Data retrieved from {wkurl} is invalid")
    else:
        logging.debug(f"Data retrieved from {wkurl}: {wkresponse}")
        rrset = wkech_to_HTTPS_rrset(svcbname, wkresponse, target=hostname, regeninterval=regeninterval)
        logging.debug(f"Generated RRset: {rrset[0]}")
        logging.debug(f"Published RRset: {chain[0].rrset}")
        # we check rrset and TTL, because we really need to be talking direct
        # to authoritative and not via OS's stub because in the latter case,
        # we'd be vulnerable to spoofed answers (unless DNSSEC is deployed and
        # checked, which is uncommon)
        if rrset[0] != chain[0].rrset or rrset[0].ttl != chain[0].rrset.ttl:
            logging.debug(f"Generated RRset differs from published one")
            bad_endpoints = 0   # none seen yet
            # TODO: maybe structure the empty endoints list thing better
            if len(wkresponse['endpoints']) <= 0:
                bad_endoints = 1000 # just to not trigger success return
            for endpoint in wkresponse['endpoints']:
                endpoint['_OK_'] = False # until we know better
                if 'params' not in endpoint or 'ech' not in endpoint['params']:
                    # nothing to validate
                    endpoint['_OK_'] = True
                    continue
                conflist = ECHConfigList(endpoint['params']['ech'])
                configs = conflist.explode() # break out individual configs from ECHConfigList
                cfcount = len(configs)
                cftally = 0
                bad_configs = 0
                for echconfig in configs:
                    # Visit target using just this config
                    cftally += 1
                    echstatus = probe_ech(hostname, port, None, ech_configs=[echconfig], target=target, tout=tout)
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
                # TODO: check this is correct
                #       rrset[0] is question, so rrset[:1] is "all but question"
                result['Update'] = rrset[:1]
        else:
            logging.debug(f"Generated RRset matches published one")
            result['OK'] = True
    return result

if __name__ == "__main__":
    print("This is a library:-)")
    sys.exit(1)
