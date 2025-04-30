import sys, os, dns.query, dns.update, dns.tsigkeyring
import dns.resolver
from datetime import datetime
import bind9_parser


def load_keyring(keyfile):
    '''
        Initialize a keyring from a configuration file in named.conf syntax,
        typically /run/named/session.key.

        That file is updated every time named is restarted so we read from it
        each time. We don't want to be root or the bind user though so we've
        added our user to the bind group and chmod'd that file to 640.

    '''
    keydict = dict()
    try:
        with open(keyfile) as f:
            cfg = f.read()
        clauses = bind9_parser.clause_statements()
        d = clauses.parseString(cfg).asDict()
        for entry in d['key']:
            keydict[entry['key_id'].strip('"')] = entry['secret'].strip('"')
    except Exception as e:
        print(f"{e}")
        sys.exit(2)
    return dns.tsigkeyring.from_text(keydict)


def readkeyfromfile(kfile):
    '''
        Read a key from a bind session key, typically /run/named/session,key
        That file is updated every time named is restarted so we read from it
        each time. We don't want to be root or the bind user though so we've
        added our user to the bind group and chmod'd that file to 640.
    '''
    with open(kfile) as f:
        line = f.readline().strip('\n')
        line = f.readline().strip('\n')
        line = f.readline().strip('\n')
        words = line.split()
        key = words[1]
    keyring = dns.tsigkeyring.from_text({
        'local-ddns': key
        })
    return keyring


def addtxtmarker(key, bindhost, zone, owner, ttl, prefix, str2p):
    '''
        Replace only the TXT RR that starts with the prefix
        with the string to publisn (str2p)
    '''
    answers=dns.resolver.resolve(owner, 'TXT')
    # set ttl to longest of seen and desired
    lttl = answers.rrset.ttl
    if lttl > ttl:
        ttl = lttl
    keepdata = []
    for rdata in answers:
        # skip over all prefix'd things - we want to drop those
        tval = rdata.to_text().replace('"','')
        if not tval.startswith(prefix):
            keepdata.append(rdata)
    lupdate = dns.update.Update(zone, keyring=key,
                                keyalgorithm=dns.tsig.HMAC_SHA256)
    lupdate.delete(owner, 'TXT')
    lupdate.add(owner, ttl, 'TXT', str2p)
    for rdata in keepdata:
        lupdate.add(owner, ttl, rdata.rdtype, rdata.to_text())
    lresponse = dns.query.tcp(lupdate, bindhost, timeout=10)
    return lresponse


# check we can read the key file
kfile="/run/named/session.key"
if not os.access(kfile, os.R_OK):
    print("Can't open key file", kfile, "exiting")
    sys.exit(1)

# read key from key file
### key=readkeyfromfile(kfile)
###
key = load_keyring(kfile)
# we're localhost only for this
bindhost='::1'
# choose this as my-oen.net has an SPF TXT RR so we don't disturb
# while debugging
owner="_8443._HTTPS.my-own.net."
# Need to set zone we want to update; it can be derived from the owner
zone = dns.resolver.zone_for_name(owner)
# we do need a TTL :-)
ttl=100
# we'll ditch old TXT RRs starting with this..
prefix = "WKECH-07:"
# and replace with one that says this...
str2p = f"{prefix} {datetime.now()}"
# leaving any other TXT RRs as were (modulo TTL)

print(f"Adding a TXT RR for {owner}: {str2p}")

# fire...
lresponse = addtxtmarker(key, bindhost, zone, owner, ttl, prefix, str2p)


