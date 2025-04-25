import sys, os, dns.query, dns.update, dns.tsigkeyring
import dns.resolver
from datetime import datetime

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


# Check we can read the key file
# Note that bind resets file perms for this to 600 on
# re-start to we need to do something to allow us to
# read that file. Our local plan is that we add the
# UID running this to the bind group, and change the
# perms for this file to 640. We follow the recipe
# given at the URL below when doing that.
# https://serverfault.com/questions/1149093/how-can-i-change-the-default-permissions-for-run-named-session-key-in-bind9
kfile="/run/named/session.key"
if not os.access(kfile, os.R_OK):
    print("Can't open key file", kfile, "exiting")
    sys.exit(1)

# read key from key file
key=readkeyfromfile(kfile)
# we're localhost only for this
bindhost='::1'
# set zone we want to update, this may be needed for e.g.
# owners like draft-13.esni.defo.ie where the zone is defo.ie
zone="my-own.net"
# choose this as my-oen.net has an SPF TXT RR so we don't disturb
# while debugging
owner="_8443._HTTPS.my-own.net."
# we do need a TTL :-)
ttl=100
# we'll ditch old TXT RRs starting with this..
prefix = "WKECH-07:"
# and replace with one that says this...
str2p = f"{prefix} {datetime.now()}"
# leaving any other TXT RRs as were (modulo TTL)

print(f"Adding a TXXT RR for {str2p}")

# fire...
lresponse = addtxtmarker(key, bindhost, zone, owner, ttl, prefix, str2p)


