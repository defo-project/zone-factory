# The `echprobe` tool...

This describes a command line tool to help understand ECH deployments
that should also help a zone factory publish ECH configs.

## Functions

1) Given a DNS name, check if there's an ECHConfigList
    - by checking for a .well-known/origin-svcb (a)
    - by checking for a relevant HTTPS RR (b)
    - by using a bogus ECHConfig and checking for retry-configs (c)

2) Given a DNS name check if ECH works (with explosion of ECHConfigLists into
singletons):
    - using (a), (b) and (c) as appropriate
    - list (sub)set(s) of 'working' ECHConfig values (d)

3) Output the set(s) of ECHConfigList values seen using (1) and (2)

4) Output the nsupdate commands we'd use to get (d) in the DNS (if you're using
bind)

5) Output the pdnsutil commands we'd use to get (d) in the DNS (if you're using
PowerDNS)

## Implementation

The [echprobe.go](./echprobe.go) script does the above (though in a different
order). Assuming you have a working and recent golang setup, (I'm on 1.27.3)
you should be able to build that via:

```bash
$ go build echprobe.go
$
```

## Extended Usage text 

TODO: build this into the program, when it's done...

If you're using this tool, you probably already know what Encrypted Client
Hello ([ECH](https://datatracker.ietf.org/doc/rfc9849/)) is and are interested
in deploying that for some web server, or want to check what's deployed. There
is a challnege in doing so, namely that the web server is where the ECH private
keys reside, but we'd usually like the ECH public keys to be published in the
DNS, so that browsers can make use of ECH.  This tool aims to help web and DNS
adminstrators bridge that gap to make it easier to see how ECH is configured on
a web server and how to publish usable values in the DNS so that browsers will
use ECH.

`echprobe` takes a DNS name (and optional port) as it's main input and probes
for ECH support at the web server there, and outputs descriptions of that state
that aim to help administrators get the right values published in the DNS. 

The data required to enable use of ECH at a web server includes cryptograhpic
key(s) and other meta-data (algorithm details etc.) that are usually packaged
in an `ECHConfig`. As more than one set of options may be supported at a given
web server, lists of those values are what is typically distributed to clients
in an `ECHConfigList` structure that can be published in the DNS as a (base64
encoded value) in an HTTP resource record (RR) for the relevant domain name.
Browsers will attempt ECH if they see a usable ECHConfigList in the DNS for
the web server concerned.

In addition the set of HTTPS RRs published in the DNS, there are two other
sources for ECHConfigList values for a web server that can provide additional
information: retry-configs and a well-known URL:

- The retry-configs value (an ECHConfigList) may be returned as part of the TLS
  exchange when ECH is tried and fails at an ECH-supporting server. The idea is
that a client could use that value in a subsequent connection-attempt to use
ECH with that server.  The set of values provided in retry-configs may be a
subset of the set of ECHConfig values that will work with that server (at that
time). If a client attempts to use ECH with a server, but uses the wrong key,
then it is highly likely that the server will return the current set of
retry-configs that work with the server.

- There is also an
  [Internet-draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-wkech)
that defines a method for a web server (administrator) to publish the set of
ECHConfig values (using a well-known URL) that they would like to see published
in the DNS so that browser can make use of ECH. That is very very far from
widely deployed, (currently, only by the [DEfO project](https://defo.ie) but is
another potential source of ECH information.

Considering those three sets of (possibly conflicting) information, we
can say that:

- retry-configs are closest to "ground truth" as they reflect the web server's
  current runtime configuration
- the well-known URL (aka "origin-svcb" file) are also under the control of the
  web server administrators, so should also be close to "ground truth"
- the HTTPS RRs in the DNS may be somewhat "distant" from ground truth if the
  web server and DNS administrators are less well co-ordinated

However the desired configuration is likely site-dependent so while probing the
ECH configurations is helpful, it cannot by itself produce an authoritative
description of what should be published in the DNS. For example, if the `ipv4hints`
value should be changed, the tool cannot know what new value is needed. One
should treat the outputs of this tool as advisory and edit those to meet 
actual needs.

### Validation and "Singletons"

When it finds an ECHConfigList, which might contain multiple ECHConfig values,
`echprobe` will "explode" the list into what we term a set of "singleton"
ECHConfig values, each with one public key. The tool then checks whether or not
ECH works with the server concerned for each singleton, and annotates the
outputs accordingly. 

### Basic Usage

`echprobe` is a golang command line tool that aims to help checking the current
ECH setup for a web server, and with using that to publish relevant
ECHConfigList values in the DNS. The command line options supported are:

```bash
$ ./echprobe -h
Usage of ./echprobe:
  -doh string
        DoH URL (default "https://cloudflare-dns.com/dns-query")
  -g string
        Group ECHConfig values 'as-found', or 'one-by-one' (default "as-found")
  -n string
        DNS name to probe (default "defo.ie")
  -o string
        Output type desired (default "summary")
  -p string
        service port to probe (default "443")
  -pn string
        ECH public name
  -s string
        Source for output desired (default "all")
  -v    verbosity
  -vv
        lots of verbosity
```

### Details...

By default `echprobe` will produce a summary of the EHCConfigList values
it sees for the given DNS name, for example:

```bash
$ ./echprobe -n test.defo.ie
List 0, source retry-configs:
	name: test.defo.ie
	List: AEP+DQA/TwAgACANGCk5QZ0GWrmu1p7U3L2M73gyADqZkxhSy8x2/EIBLAAEAAEAAQAQY2QyLnRlc3QuZGVmby5pZQAA
		Singleton 0
		Version: 0xfe0d, config_id: 0x4f, checked: true
		public_name: cd2.test.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEP+DQA/TwAgACANGCk5QZ0GWrmu1p7U3L2M73gyADqZkxhSy8x2/EIBLAAEAAEAAQAQY2QyLnRlc3QuZGVmby5pZQAA
List 1, source dns:
	name: test.defo.ie
	List: AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+Y9MExbIyuLpLcgTORIdi69uewAEAAEAAQATcHVibGljLnRlc3QuZGVmby5pZQAA
		Singleton 0
		Version: 0xfe0d, config_id: 0xa9, checked: true
		public_name: public.test.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+Y9MExbIyuLpLcgTORIdi69uewAEAAEAAQATcHVibGljLnRlc3QuZGVmby5pZQAA
```

The above shows that the retry-configs value differs from the value published
in the DNS for this test server. (We won't try explain that server's odd setup
here:-)

The defo.ie server also supports the origin-svcb source, so we get the output
below. For that server, the ECHConfigs are rotated hourly, so if one probes
during the right time, you would see a difference between the origin-svcb
and DNS values, as those are in the process of being updated.

```bash
$ ./echprobe -n defo.ie
List 0, source origin-svcb:
	name: defo.ie
	List: AMD+DQA8EwAgACA9gWCgyTQBlvUlXoItDnIeaumMePNOEAww9hC4VmaKegAEAAEAAQANY292ZXIuZGVmby5pZQAA/g0APD4AIAAgh4AVlS4pWKFScCSkjoTpxKjIKM8UsYiy+OWKIUounTUABAABAAEADWNvdmVyLmRlZm8uaWUAAP4NADxyACAAIE2RGg4cSDAiX/qP6azGhXT+97tPseElVgtqzQkyJ2RMAAQAAQABAA1jb3Zlci5kZWZvLmllAAA=
		Singleton 0
		Version: 0xfe0d, config_id: 0x13, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8EwAgACA9gWCgyTQBlvUlXoItDnIeaumMePNOEAww9hC4VmaKegAEAAEAAQANY292ZXIuZGVmby5pZQAA
		Singleton 1
		Version: 0xfe0d, config_id: 0x3e, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8PgAgACCHgBWVLilYoVJwJKSOhOnEqMgozxSxiLL45YohSi6dNQAEAAEAAQANY292ZXIuZGVmby5pZQAA
		Singleton 2
		Version: 0xfe0d, config_id: 0x72, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8cgAgACBNkRoOHEgwIl/6j+msxoV0/ve7T7HhJVYLas0JMidkTAAEAAEAAQANY292ZXIuZGVmby5pZQAA
List 1, source retry-configs:
	name: defo.ie
	List: AED+DQA8/wAgACBzTCryqQPp4BMWlgSdlVVOgP3jL9V+l2azlYJrlXs0TgAEAAEAAQANY292ZXIuZGVmby5pZQAA
		Singleton 0
		Version: 0xfe0d, config_id: 0xff, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8/wAgACBzTCryqQPp4BMWlgSdlVVOgP3jL9V+l2azlYJrlXs0TgAEAAEAAQANY292ZXIuZGVmby5pZQAA
List 2, source dns:
	name: defo.ie
	List: AMD+DQA8EwAgACA9gWCgyTQBlvUlXoItDnIeaumMePNOEAww9hC4VmaKegAEAAEAAQANY292ZXIuZGVmby5pZQAA/g0APD4AIAAgh4AVlS4pWKFScCSkjoTpxKjIKM8UsYiy+OWKIUounTUABAABAAEADWNvdmVyLmRlZm8uaWUAAP4NADxyACAAIE2RGg4cSDAiX/qP6azGhXT+97tPseElVgtqzQkyJ2RMAAQAAQABAA1jb3Zlci5kZWZvLmllAAA=
		Singleton 0
		Version: 0xfe0d, config_id: 0x13, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8EwAgACA9gWCgyTQBlvUlXoItDnIeaumMePNOEAww9hC4VmaKegAEAAEAAQANY292ZXIuZGVmby5pZQAA
		Singleton 1
		Version: 0xfe0d, config_id: 0x3e, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8PgAgACCHgBWVLilYoVJwJKSOhOnEqMgozxSxiLL45YohSi6dNQAEAAEAAQANY292ZXIuZGVmby5pZQAA
		Singleton 2
		Version: 0xfe0d, config_id: 0x72, checked: true
		public_name: cover.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AED+DQA8cgAgACBNkRoOHEgwIl/6j+msxoV0/ve7T7HhJVYLas0JMidkTAAEAAEAAQANY292ZXIuZGVmby5pZQAA
```

Golang supports post-quantum suites for ECH and we have a test server that also
supports that (via a not-yet upstreamed OpenSSL), if we probe that name, then
we get the output below:

```bash
$ ./echprobe -n pq-ng.test.defo.ie
List 0, source retry-configs:
	name: pq-ng.test.defo.ie
	List: AEP+DQA/TwAgACANGCk5QZ0GWrmu1p7U3L2M73gyADqZkxhSy8x2/EIBLAAEAAEAAQAQY2QyLnRlc3QuZGVmby5pZQAA
		Singleton 0
		Version: 0xfe0d, config_id: 0x4f, checked: true
		public_name: cd2.test.defo.ie
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEP+DQA/TwAgACANGCk5QZ0GWrmu1p7U3L2M73gyADqZkxhSy8x2/EIBLAAEAAEAAQAQY2QyLnRlc3QuZGVmby5pZQAA
List 1, source dns:
	name: pq-ng.test.defo.ie
	List: BOb+DQTiymR6BMB5RZSj+mNG8srNpbfh5ljjk2UrR3GhwjfsBxkx92QhG4EfMi8B2G6piGPwKbKYtV8JxspMzBFtNy6+GaI7aizcSqFps6vGuDvrQZq8EKg7E13WloIUE5+3yT20A2KNwjVmjFRLqQ+wNUtZNcCqk6Q4VL//Mchyh00LlQZpXHPeCLa1li7C4QBPBw+qYAKTw8X4OaqlJGOjhlg+CQmDMSIHmLxJYT38CDsmqQriojzOaCa0Qle8sYN/ckbMlzGeg8GlDB9F0i2RCXO8kxn2xg24FJOMFIUNyhIFwhxztKcj5HMzpZWV+52Ai8gN5QsLACi6e8bfWs0IUbXCKjgaKhnzacWRyMs/pYqp6nxlkUMD5HF9c00LtLAbFa2uSUqYnBTpPIovJ6ZCoinP+JMX0Mm8NrvcSVMHNxnziJFulXlNqDQgMHfE0qeLVa2bC007Y6sGxaloeZgPwgtbdABGAYK3rDgWGRlbTEhs8A4ZZC3w6Zove3ONEA6clEhrCESjPJIL8SJxuRcbaUqTIc+0mp0AGE9+clglEZ+ohIGUlW6EMB8u/K4Yhja61MROsM4CCGYc4kDJAbx/91CMQUft5BrAiccVijxbI7s1nCpK2sipysQBNrEomSNGSUTWcj1fYsdboiPZsMDWN18YghMg13RFxRapoGovLLRrILWjNsGtZrPRszxZ8m/Uhgk3iL29MnWQODHfmwBVJxXcxEx960hMdjhwY1B1ALFaG6a2QIPdoayQtSzp8y7kfGP3ISmBUguuBTA+dc0x9Ra8fIlPKqJ5RyqfdEJGs7QR1XquWQsShqoe4yei4yrYaycbaFhQaz5Zd39vQGgvoFzfXG/JNz6NKgOHRq9IPJhXFjWzwcLerFPrxAz76W7asnX+N84VgAgOJoPTxp9GSsdhvK0hdGhW2Xes88cBAiMliSmbMpMGuzntw7jzJ2vmxxKJR7RLO0Vj9Xovd3g/iMtgWG4HpTAoiKD/qTPg0Va4qjy+Kc7oOLovEi8vm04LaCDrETLRcrqBsHjjkzHfkTXMAMAMSZnOigCREgCuaX5yDKPLo7VDaF2cUQFEu6hA2XDC5qXpI4qb6IdZmA3OlL/30DiK97RYxFg+jMsFWGbkY48NtBfzSYeVqGscUSQzSD4zuMTIlqG5clybErboyV4BhjckEgSKAiheQVFEWaL6OB84bJFGlRh1mEne84jYmVPh2c3v4FBKhoMstll82FqgbCzp61GcYYIYN7RIQU3rKM1wAFrFQ7OfmorLIgNIbENaOTUJG8mrhkiocH3Tl2vlonaN63o5KXFTXBiqdLkn/MO6I5HpGVWg6gd6Cwu2CJtrAJgOBhIBKMVquZq1+pewHDGtZL5SlpjqM37bgAQ1UMSYcYkk1IapN3AlkGfeeR6eYJwzOCzEOBxf6DwhAqNIliQH5jtZQQiU0gxXq65jujC8Aq9y+ywTtLwnI2QpQ6MXk0RDVlYKhn64k0rT2it3VwW8BaZJ4x10hEJp18V9qxxQ5361BE9GJKsy11+aAGJANAKrBS7ltosNMXj0pGnqIAr63igNVN9q4cULCNuPEpXw/lLjBojC3YpFhXBVgkqiPKaJNkhjk7Om2hzB+kMd1QQyvIgjAAQAAQACABNwdWJsaWMudGVzdC5kZWZvLmllAAA=
		Singleton 0
		Version: 0xfe0d, config_id: 0xca, checked: true
		public_name: public.test.defo.ie
		HPKE suites: 0x647a/0x0000/0x0001
		Singleton: BOb+DQTiymR6BMB5RZSj+mNG8srNpbfh5ljjk2UrR3GhwjfsBxkx92QhG4EfMi8B2G6piGPwKbKYtV8JxspMzBFtNy6+GaI7aizcSqFps6vGuDvrQZq8EKg7E13WloIUE5+3yT20A2KNwjVmjFRLqQ+wNUtZNcCqk6Q4VL//Mchyh00LlQZpXHPeCLa1li7C4QBPBw+qYAKTw8X4OaqlJGOjhlg+CQmDMSIHmLxJYT38CDsmqQriojzOaCa0Qle8sYN/ckbMlzGeg8GlDB9F0i2RCXO8kxn2xg24FJOMFIUNyhIFwhxztKcj5HMzpZWV+52Ai8gN5QsLACi6e8bfWs0IUbXCKjgaKhnzacWRyMs/pYqp6nxlkUMD5HF9c00LtLAbFa2uSUqYnBTpPIovJ6ZCoinP+JMX0Mm8NrvcSVMHNxnziJFulXlNqDQgMHfE0qeLVa2bC007Y6sGxaloeZgPwgtbdABGAYK3rDgWGRlbTEhs8A4ZZC3w6Zove3ONEA6clEhrCESjPJIL8SJxuRcbaUqTIc+0mp0AGE9+clglEZ+ohIGUlW6EMB8u/K4Yhja61MROsM4CCGYc4kDJAbx/91CMQUft5BrAiccVijxbI7s1nCpK2sipysQBNrEomSNGSUTWcj1fYsdboiPZsMDWN18YghMg13RFxRapoGovLLRrILWjNsGtZrPRszxZ8m/Uhgk3iL29MnWQODHfmwBVJxXcxEx960hMdjhwY1B1ALFaG6a2QIPdoayQtSzp8y7kfGP3ISmBUguuBTA+dc0x9Ra8fIlPKqJ5RyqfdEJGs7QR1XquWQsShqoe4yei4yrYaycbaFhQaz5Zd39vQGgvoFzfXG/JNz6NKgOHRq9IPJhXFjWzwcLerFPrxAz76W7asnX+N84VgAgOJoPTxp9GSsdhvK0hdGhW2Xes88cBAiMliSmbMpMGuzntw7jzJ2vmxxKJR7RLO0Vj9Xovd3g/iMtgWG4HpTAoiKD/qTPg0Va4qjy+Kc7oOLovEi8vm04LaCDrETLRcrqBsHjjkzHfkTXMAMAMSZnOigCREgCuaX5yDKPLo7VDaF2cUQFEu6hA2XDC5qXpI4qb6IdZmA3OlL/30DiK97RYxFg+jMsFWGbkY48NtBfzSYeVqGscUSQzSD4zuMTIlqG5clybErboyV4BhjckEgSKAiheQVFEWaL6OB84bJFGlRh1mEne84jYmVPh2c3v4FBKhoMstll82FqgbCzp61GcYYIYN7RIQU3rKM1wAFrFQ7OfmorLIgNIbENaOTUJG8mrhkiocH3Tl2vlonaN63o5KXFTXBiqdLkn/MO6I5HpGVWg6gd6Cwu2CJtrAJgOBhIBKMVquZq1+pewHDGtZL5SlpjqM37bgAQ1UMSYcYkk1IapN3AlkGfeeR6eYJwzOCzEOBxf6DwhAqNIliQH5jtZQQiU0gxXq65jujC8Aq9y+ywTtLwnI2QpQ6MXk0RDVlYKhn64k0rT2it3VwW8BaZJ4x10hEJp18V9qxxQ5361BE9GJKsy11+aAGJANAKrBS7ltosNMXj0pGnqIAr63igNVN9q4cULCNuPEpXw/lLjBojC3YpFhXBVgkqiPKaJNkhjk7Om2hzB+kMd1QQyvIgjAAQAAQACABNwdWJsaWMudGVzdC5kZWZvLmllAAA=
```

With `echprobe` you can also see the ECHConfig values supported by
sites that don't publish any HTTPS RR values in the DNS, for example:

```bash
$ ./echprobe -n facebook.com
List 0, source retry-configs:
	name: facebook.com
	List: AsH+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAD+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAD+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAD+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAD+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAD+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA/g0ASwYAIAAgti54XaD8VhwGEmxjGpaxUkuAz3VmpQSMOFSRgSPchR0ABAABAAEyHHNjb250ZW50LWxheDMtMi54eC5mYmNkbi5uZXQAAP4NAEgEACAAINQS+ceVTWrz9nffBM163+nvpZ9k5F5WK51t4DAGG3ReAAQAAQABZBl2aWRlby1sYXgzLTIueHguZmJjZG4ubmV0AAD+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=
		Singleton 0
		Version: 0xfe0d, config_id: 0x00, checked: true
		public_name: facebook.com
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AD/+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAA=
		Singleton 1
		Version: 0xfe0d, config_id: 0x05, checked: true
		public_name: graph.facebook.com
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEX+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAA=
		Singleton 2
		Version: 0xfe0d, config_id: 0x08, checked: true
		public_name: scontent.xx.fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEj+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA=
		Singleton 3
		Version: 0xfe0d, config_id: 0x09, checked: true
		public_name: video.xx.fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEX+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAA=
		Singleton 4
		Version: 0xfe0d, config_id: 0x01, checked: true
		public_name: ech-public.atmeta.com
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=
		Singleton 5
		Version: 0xfe0d, config_id: 0x03, checked: true
		public_name: video.xx.fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEX+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAA=
		Singleton 6
		Version: 0xfe0d, config_id: 0x07, checked: true
		public_name: video-lax3-2.xx.fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEz+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA
		Singleton 7
		Version: 0xfe0d, config_id: 0x06, checked: true
		public_name: scontent-lax3-2.xx.fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AE/+DQBLBgAgACC2LnhdoPxWHAYSbGMalrFSS4DPdWalBIw4VJGBI9yFHQAEAAEAATIcc2NvbnRlbnQtbGF4My0yLnh4LmZiY2RuLm5ldAAA
		Singleton 8
		Version: 0xfe0d, config_id: 0x04, checked: true
		public_name: video-lax3-2.xx.fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: AEz+DQBIBAAgACDUEvnHlU1q8/Z33wTNet/p76WfZOReViudbeAwBht0XgAEAAEAAWQZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA
		Singleton 9
		Version: 0xfe0d, config_id: 0x02, checked: true
		public_name: fbcdn.net
		HPKE suites: 0x0020/0x0000/0x0001
		Singleton: ADz+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=
```

## Output options

You can limit the set of ECHConfig values displayed via the `-s` option
that allows you to specify the source to use, the values can be one of
`-s origin-svcb`, `-s retry-configs`, `-s dns` or (the default) `-s all`.

You can also ask for the output to be formatted so as to produce command
snippets that can be used to update an authoritative DNS server via the
`-o` option. The values can be `-o summary` (the default), or `-o nsupdate`
to produce stanzas usable with bind's nsupdate command, or `-o pdns` to
producs stanza usable with the PowerDNS `pdns-util` command. For example,

```bash
$ ./echprobe -s retry-configs -o nsupdate
update delete HTTPS defo.ie
update add defo.ie 3600 HTTPS 1 . AED+DQA8/wAgACBzTCryqQPp4BMWlgSdlVVOgP3jL9V+l2azlYJrlXs0TgAEAAEAAQANY292ZXIuZGVmby5pZQAA
```

or...

```bash
$ ./echprobe -s retry-configs -o pdns
pdnsutil rrset replace defo.ie defo.ie HTTPS 3600 1 . AED+DQA8/wAgACBzTCryqQPp4BMWlgSdlVVOgP3jL9V+l2azlYJrlXs0TgAEAAEAAQANY292ZXIuZGVmby5pZQAA
```

For either bind or pdns, you can also choose to group the ECHConfigLists
presented as they were discovered (`-g as-found`) or as singletons (`-g
one-by-one`), for example:

```bash
$ ./echprobe -s retry-configs -o nsupdate -n facebook.com -g one-by-one
update delete HTTPS facebook.com
update add facebook.com 3600 HTTPS 1 . AD/+DQA7AAAgACBKTLEeFRxf7iC7wIdiRa2umX+yPtIeglGqBP7tfrgFdwAEAAEAAWQMZmFjZWJvb2suY29tAAA=
update add facebook.com 3600 HTTPS 1 . AEX+DQBBBQAgACCEpikd9ey1gwO/XpN3lcToJ/wzH7QlYfY3DZVicyiPAgAEAAEAATISZ3JhcGguZmFjZWJvb2suY29tAAA=
update add facebook.com 3600 HTTPS 1 . AEj+DQBECAAgACBoagCiXnMAHTpss2UZ+fW/N/wRflRdwnBsica6bun8NgAEAAEAATIVc2NvbnRlbnQueHguZmJjZG4ubmV0AAA=
update add facebook.com 3600 HTTPS 1 . AEX+DQBBCQAgACDP0okJjRYtkh5AWEPcjqA1Z9xWn2JkE49qj7n+gwY3GgAEAAEAATISdmlkZW8ueHguZmJjZG4ubmV0AAA=
update add facebook.com 3600 HTTPS 1 . AEj+DQBEAQAgACAdd+scUi0IYFsXnUIU7ko2Nd9+F8M26pAGZVpz/KrWPgAEAAEAAWQVZWNoLXB1YmxpYy5hdG1ldGEuY29tAAA=
update add facebook.com 3600 HTTPS 1 . AEX+DQBBAwAgACC2SuomaKhQlkusWMQiUkCjuz8+0WR6jyC0DIsANT6gAQAEAAEAAWQSdmlkZW8ueHguZmJjZG4ubmV0AAA=
update add facebook.com 3600 HTTPS 1 . AEz+DQBIBwAgACBH8Vs19gc3DIDfTChp3+G6H71KivZY4dtweKazCugIQgAEAAEAATIZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA
update add facebook.com 3600 HTTPS 1 . AE/+DQBLBgAgACC2LnhdoPxWHAYSbGMalrFSS4DPdWalBIw4VJGBI9yFHQAEAAEAATIcc2NvbnRlbnQtbGF4My0yLnh4LmZiY2RuLm5ldAAA
update add facebook.com 3600 HTTPS 1 . AEz+DQBIBAAgACDUEvnHlU1q8/Z33wTNet/p76WfZOReViudbeAwBht0XgAEAAEAAWQZdmlkZW8tbGF4My0yLnh4LmZiY2RuLm5ldAAA
update add facebook.com 3600 HTTPS 1 . ADz+DQA4AgAgACD+3t6VFcOw4TgdcWhjku+MWmbhq5VMyaPg3THh0iZNSAAEAAEAAWQJZmJjZG4ubmV0AAA=
```

That last example shows up some of the limits of `echprobe` - if one
wanted to publish HTTPS RRs with those values, then it seems likely
one might want to use different priorities (all "1" in the above) and
perhaps a different TTL setting. So the DNS tool stanzas are likely
to need editing before being used to udpate an actual authoritative
DNS server.



