# small test script to check if our use of dnspython leaves us open
# to ingesting HTTPS RRs that are in the additional section.
# Spoiler: no:-)
import dns.name
import dns.message
import dns.query
import dns.flags
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.zonefile
import dns.tsigkeyring
import dns.update
import dns.exception

# domain = 'google.com'
# name_server = '8.8.8.8'
domain = 'd343ohixkzst9h.cloudfront.net'
name_server = '205.251.198.4' # ns-1540.awsdns-00.co.uk
domain = 'tcd.ie'
name_server = '134.226.14.26' # auth-ns1.tcd.ie
ADDITIONAL_RDCLASS = 65535

domain = dns.name.from_text(domain)
if not domain.is_absolute():
    domain = domain.concatenate(dns.name.root)

# request = dns.message.make_query(domain, dns.rdatatype.ANY)
request = dns.message.make_query(domain, dns.rdatatype.NS)
request.flags |= dns.flags.AD
request.find_rrset(request.additional, dns.name.root, ADDITIONAL_RDCLASS,
                   dns.rdatatype.OPT, create=True, force_unique=True)
response = dns.query.udp(request, name_server)


print(response.answer)
print(response.additional)
print(response.authority)

# now mimic wkech way

class ChosenResolver:
    from dns.resolver import get_default_resolver, make_resolver_at
    # We default to use a new stub talking direct to the authoritative
    # at '::1' as our chosen resolver. This can be over-ridded on the
    # command line, but if so, TSIG needs to be setup to work for
    # that configuration
    # Note that use of ::1 means we do not expect to see TTLs decremented
    # (we would if we used the default systemd stub).
    # TODO: test with a name rather than address for server and CLI
    server_addr = "::1"
    active = make_resolver_at(server_addr)
    def activate(server):
        ChosenResolver.active = ChosenResolver.make_resolver_at(server)
        server_addr = server
    def set_timeout(tout):
        ChosenResolver.timeout = tout

ChosenResolver.activate(name_server)
ans = ChosenResolver.active.resolve(domain, "NS")
print(ans)
rrs = list(filter(lambda a: a.rdtype == 2 or a.rdtype == 1, ans))
print(rrs)
for a in ans:
    print(a)
