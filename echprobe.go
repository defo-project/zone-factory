/*
 * Copyright (C) 2026 Stephen Farrell, stephen.farrell@cs.tcd.ie
 * Copyright (C) 2026 Tolerant Networks Limited
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package main

import (
    "crypto/tls"
    "encoding/base64"
    "encoding/json"
    "errors"
    "flag"
    "fmt"
    "io"
    "log"
    "net/http"
    "net/url"
    "slices"
    "strings"
)

type ECHConfigDets struct {
    works bool
    version string
    config_id string
    max_name_len int
    public_name string
    kem string
    kdf string // comma-sep string
    aead string // comma-sep string
    exts bool // true if some present
    singleton []byte // the encoded singleton ECHConfigList
}

type ECHConfigListDets struct {
    name string // what'd be in an inner SNI
    port string // service port (usually 443)
    source string // retry-config or origin-svcb or dns
    original any // original form in which we got this (e.g. DNS transaction)
    list []byte // the encoded ECHConfigList
    details []ECHConfigDets
}

var verbose bool = false
var super_verbose bool = false
var doh_url string = ""
var thepile []ECHConfigListDets
var total_checked_good int

func get_target_url(host string, port string) (string) {
    var url string
    if port == "443" || port == "80" {
        url = "https://" + host + "/.well-known/origin-svcb"
    } else {
        url = "https://" + host + ":" + port + "/.well-known/origin-svcb"
    }
    return url
}

func get_origin_svcb(host string, port string) ([]byte, error) {
    targetURL := get_target_url(host, port)
    url, err := url.Parse(targetURL)
    if err != nil {
        if super_verbose {
            fmt.Printf("url.Parse failed for %s: %v", targetURL, err)
        }
        return nil, err
    }
    client := &http.Client{}
    resp, err := client.Do(&http.Request{
        Method: "GET",
        Header: map[string][]string{
            "Accept": {"application/json"},
        },
        URL: url,
    })
    if err != nil {
        if super_verbose {
            fmt.Printf("failed to perform request %s: %v", targetURL, err)
        }
        return nil, err
    }
    defer resp.Body.Close()
    if super_verbose {
        fmt.Printf("%s resp status code: %d\n", targetURL, resp.StatusCode)
    }
    if resp.StatusCode != 200 {
        return nil, err
    }
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Printf("failed to read response body: %v", err)
        return nil, err
    }
    if super_verbose {
        fmt.Printf("%s\n", string(bodyBytes))
    }
    return bodyBytes, err
}

func parse_cfg_list(cfg []byte) ([]ECHConfigDets, error) {
    // parse the ECHConfigList input into an ECHConfigDets array
    olen := len(cfg)
    offset := 4
    count := 0
    var dets []ECHConfigDets

    for offset <= olen {
        var det ECHConfigDets
        det.works = false // not yet checked

        // break into singleton ECHConfig values
        thislen := int(cfg[offset]) * 256 + int(cfg[offset+1])
        if thislen <= 0 || offset + thislen >= olen {
            fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
                        olen, offset, thislen)
            return nil, errors.New("ECHConfigList too short (1)")
        }
        thiscfg := []byte { byte((thislen+4)/256), byte((thislen+4)%256),
                            0xfe, 0x0d }
        thiscfg = slices.Concat(thiscfg, cfg[offset:offset+thislen+2])
        if super_verbose {
            fmt.Printf("Config %d: %s\n", count,
                base64.StdEncoding.EncodeToString(thiscfg))
            fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
                        olen, offset, thislen)
        }

        tlen := len(thiscfg)
        det.version = fmt.Sprintf("0x%04x", int(thiscfg[2])*256+int(thiscfg[3]))
        det.config_id = fmt.Sprintf("0x%02x", int(thiscfg[6]))
        det.kem = fmt.Sprintf("0x%04x", int(thiscfg[7])*256+int(thiscfg[8]))
        publen := int(thiscfg[9])*256+int(thiscfg[10])
        suiteoff := 11 + publen
        if (suiteoff + 2) >= tlen {
            return nil, errors.New("ECHConfigList too short (2)")
        }
        suitelen := int(thiscfg[suiteoff]) * 256 + int(thiscfg[suiteoff+1])
        // there better be one suite, at least
        kdf := int(thiscfg[suiteoff + 2]) * 256 + int(thiscfg[suiteoff+3])
        det.kdf = fmt.Sprintf("0x%04x", kdf)
        aead := int(thiscfg[suiteoff + 4]) * 256 + int(thiscfg[suiteoff+5])
        det.aead = fmt.Sprintf("0x%04x", aead)
        for suitenum := 1; suitenum < suitelen/4; suitenum++ {
            kdf := int(thiscfg[suiteoff+2+suitenum*4]) * 256 +
                   int(thiscfg[suiteoff+3+suitenum*4])
            det.kdf += fmt.Sprintf(",0x%04x", kdf)
            aead := int(thiscfg[suiteoff+4+suitenum*4]) * 256 +
                    int(thiscfg[suiteoff+5+suitenum*4])
            det.aead += fmt.Sprintf(",0x%04x", aead)
        }
        pnoff := suiteoff + 2 + suitelen + 1
        if pnoff >= tlen {
            fmt.Printf("tlen: %d, publen: %d, suiteoff: %d\n",
                        tlen, publen, suiteoff)
            fmt.Printf("suitelen: %d, pnoff: %d\n", suitelen, pnoff)
            return nil, errors.New("ECHConfigList too short (3)")
        }
        pnlen := int(thiscfg[pnoff])
        if (pnoff + 1 + pnlen) >= tlen {
            return nil, errors.New("ECHConfigList too short (4)")
        }
        pns := thiscfg[pnoff+1:pnoff+1+pnlen]
        if super_verbose {
            fmt.Printf("tlen: %d, publen: %d, suiteoff: %d\n",
                    tlen, publen, suiteoff)
            fmt.Printf("suitelen: %d, pnoff: %d, pnlen: %d\n",
                    suitelen, pnoff, pnlen)
            fmt.Println(pns)
        }
        pn := string(pns)
        det.public_name = pn
        if (pnoff + 1 + pnlen + 2) > tlen {
            return nil, errors.New("ECHConfigList too short (5)")
        }
        if pnoff+1+pnlen+2 == tlen &&
           thiscfg[pnoff+1+pnlen] == 0x00 &&
           thiscfg[pnoff+1+pnlen+1] == 0x00 {
            det.exts = false
        } else {
            det.exts = true // which is as much as we say
        }
        det.singleton = thiscfg
        dets = append(dets, det)
        offset += (thislen + 4)
    }
    return dets, nil
}

func get_public_name_conn(host string, port string) (string, error) {
    // we expect a cert error initially as the public name in the fake
    // ECH below will be wrong we use the error from that to get the
    // correct public_name
    targetURL := get_target_url(host, port)
    // a bad ECHConfig to try elicit retry-configs
    fakeECH, err := base64.StdEncoding.DecodeString(
        "AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+" +
        "YAMExbIyuLpLcgTORIdi69uewAEAAEAAQ" +
        "ATcHVibGljLnRlc3QuZGVmcy5pZQAA")
    // This is fragile, but good enough for now - the string below is
    // the public name in the above config
    suffix := ", not public.test.defs.ie"

    tlsConfig := &tls.Config{
        EncryptedClientHelloConfigList: fakeECH,
    }
    httpClient := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }
    if _, err := httpClient.Get(targetURL); err != nil {
        var certErr *tls.CertificateVerificationError
        if errors.As(err, &certErr) {
            serr := certErr.Error()
            if super_verbose {
                fmt.Printf("serr: %v\n", serr)
            }
            terr, found := strings.CutSuffix(serr, suffix)
            if !found {
                return "", err
            }
            if super_verbose {
                fmt.Printf("terr: %v\n", terr)
            }
            li := strings.LastIndex(terr, ", ")
            if li == -1 {
                li = strings.LastIndex(terr, "is valid for ")
                if li == -1 {
                    return "", err
                }
                li += len("is valiue for ") - 3
            }
            pn := terr[li+2:]
            if pn[0] == '*' { // handle possible wildcard
                pn = strings.Replace(pn, "*.", "a.", -1)
            }
            if super_verbose {
                fmt.Printf("public_name detected: %s\n", pn)
            }
            return pn, nil
        }
        if super_verbose {
            fmt.Printf("err: %v\n", err)
        }
    }
    // nothing to say, sorry
    if super_verbose {
        fmt.Printf("nothing to say, sorry : %v\n", err)
    }
    return "", err
}

func get_retry_configs(host string, port string,
                       public_name string) ([]byte, error) {
     // value from test.defo.ie, 0xFF values are to-be-fixed lengths
    part_fakeECH := []byte {
        0xFF, 0xFF, 0xfe, 0x0d, 0xFF, 0xFF, 0xa9, 0x00,
        0x20, 0x00, 0x20, 0x65, 0x9b, 0xb7, 0x1f, 0x0f,
        0x1f, 0xe0, 0x2a, 0xe5, 0x00, 0xc1, 0x14, 0xde,
        0xf9, 0x8f, 0x4c, 0x13, 0x16, 0xc8, 0xca, 0xe2,
        0xe9, 0x2d, 0xc8, 0x13, 0x39, 0x12, 0x1d, 0x8b,
        0xaf, 0x6e, 0x7b, 0x00, 0x04, 0x00, 0x01, 0x00,
        0x01, 0x00 }
    // will need public name and 2 zero octets for
    // empty extensions appended

    var fakeECH_good_pn []byte
    if public_name != "" {
        pnlen := byte(len(public_name) % 255)
        p1 := []byte { pnlen }
        p2 := []byte(public_name)
        p3 := []byte { 0x00, 0x00 }
        fakeECH_good_pn = slices.Concat(part_fakeECH, p1, p2, p3)
    } else { // use host
        pnlen := byte(len(host) % 255)
        p1 := []byte { pnlen }
        p2 := []byte(host)
        p3 := []byte { 0x00, 0x00 }
        fakeECH_good_pn = slices.Concat(part_fakeECH, p1, p2, p3)
    }
    // fixup lengths
    elen := len(fakeECH_good_pn)
    fakeECH_good_pn[0]=byte((elen-2)/256)
    fakeECH_good_pn[1]=byte((elen-2)%256)
    fakeECH_good_pn[4]=byte((elen-6)/256)
    fakeECH_good_pn[5]=byte((elen-6)%256)

    if super_verbose {
        fmt.Printf("\nFake ECHConfig to try get retry-configs  %s\n",
            base64.StdEncoding.EncodeToString(fakeECH_good_pn))
    }

    tlsConfig := &tls.Config{
        EncryptedClientHelloConfigList: fakeECH_good_pn,
    }
    httpClient := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    }
    targetURL := get_target_url(host, port)
    if _, err := httpClient.Get(targetURL); err != nil {
        var echErr *tls.ECHRejectionError
        if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
            return echErr.RetryConfigList, nil
        }
        if super_verbose {
            fmt.Printf("failed to get retry_configs %v\n", err)
        }
        return []byte{}, err
    }
    return []byte{}, nil
}

func get_https_rrs(host string, port string) ([]byte, error) {
    var qname = host;
    if port != "443" && port != "" {
        qname = "_" + port + "._https." + host
    }
    if super_verbose {
        fmt.Println("qname = ", qname)
    }
    qtype := "HTTPS"
    url, err := url.Parse(fmt.Sprintf("%s?name=%s&type=%s",
                            doh_url, qname, qtype))
    if err != nil {
        return nil, err
    }
    client := &http.Client{}
    resp, err := client.Do(&http.Request{
        Method: "GET",
        Header: map[string][]string{
            "Accept": {"application/dns-json"},
        },
        URL: url,
    })
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    if super_verbose {
        fmt.Println("DoH answer:\n", string(data))
    }
    return data, nil
}

func verify_configs(host string, port string,
                    configs []byte) (int, []byte, error) {
    count := int(0)
    olen := len(configs)
    offset := int(4)
    goodones := []byte{ 0x00, 0x00 }
    goodlen := 0

    for offset <= olen {
        // break into singleton ECHConfig values
        thislen := int(configs[offset]) * 256 + int(configs[offset+1])
        if thislen <= 0 || offset + thislen >= olen {
            fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
                        olen, offset, thislen)
            return 0, nil, errors.New("ECHConfigList decode error (1)")
        }
        thiscfg := []byte { byte((thislen+4)/256), byte((thislen+4)%256),
                            0xfe, 0x0d }
        thiscfg = slices.Concat(thiscfg, configs[offset:offset+thislen+2])
        if super_verbose {
            fmt.Printf("Config %d: %s\n", count,
                base64.StdEncoding.EncodeToString(thiscfg))
            fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
                        olen, offset, thislen)
        }
        // try that ECHConfig singleton
        tlsConfig := &tls.Config{
            EncryptedClientHelloConfigList: thiscfg,
        }
        httpClient := &http.Client{
            Transport: &http.Transport{
                TLSClientConfig: tlsConfig,
            },
        }
        targetURL := get_target_url(host, port)
        if _, nerr := httpClient.Get(targetURL); nerr != nil {
            if super_verbose {
                fmt.Printf("Config %d failed: %s\n", count,
                    base64.StdEncoding.EncodeToString(thiscfg))
            }
        } else {
            count += 1
            goodones = slices.Concat(goodones, thiscfg[2:])
            goodlen += (thislen + 4)
        }
        offset += (thislen + 4)
    }
    // fix overall length
    goodones[0]=byte(goodlen/256)
    goodones[1]=byte(goodlen%256)

    return count, goodones, nil
}

func add_to_pile(host string, port string, source string, original any,
                 list []byte) (error) {
    // we'll add another entry to the pile, it'll be verified later
    // if desired
    if super_verbose {
        fmt.Printf("Adding to pile: %s:%s from %s\n", host, port, source)
    }
    var entry ECHConfigListDets
    entry.name = host
    entry.port = port
    entry.source = source
    entry.list = list
    entry.original = original
    var err error
    entry.details, err = parse_cfg_list(list)
    if err != nil {
        fmt.Printf("get https_rrs fail: %v\n", err)
        return err
    }
    thepile = append(thepile, entry)
    return nil
}

// IANA registries for this are at https://www.iana.org/assignments/hpke
// this code was sync'd with that on 2026-10-25
// Given that almost nobody publishes ECHConfig values with >1 kdf or aead
// suite, we'll take the simple approach and only print 'nice' strings for
// cases with just one suite. If someone uses >1 then we'll just see the
// comma-sep hex values.
var aead_map = map[string]string {
    "0x0000": "Reserved", 
    "0x0001": "AES-128-GCM", 
    "0x0002": "AES-256-GCM", 
    "0x0003": "ChaCha20Poly1305", 
    "0xffff": "Export-only",
}

var kdf_map = map[string]string {
    "0x0001": "HKDF-SHA256",
    "0x0002": "HKDF-SHA384",
    "0x0003": "HKDF-SHA512",
    "0x0010": "SHAKE128",
    "0x0011": "SHAKE256",
    "0x0012": "TurboSHAKE128",
    "0x0013": "TurboSHAKE256",
}

var kem_map = map[string]string {
    "0x0010": "DHKEM(P-256, HKDF-SHA256)",
    "0x0011": "DHKEM(P-384, HKDF-SHA384)",
    "0x0012": "DHKEM(P-521, HKDF-SHA512)",
    "0x0013": "DHKEM(CP-256, HKDF-SHA256)",
    "0x0014": "DHKEM(CP-384, HKDF-SHA384)",
    "0x0015": "DHKEM(CP-521, HKDF-SHA512)",
    "0x0016": "DHKEM(secp256k1, HKDF-SHA256)",
    "0x0020": "DHKEM(X25519, HKDF-SHA256)",
    "0x0021": "DHKEM(X448, HKDF-SHA512)",
    "0x0022": "DHKEM(X25519+Elligator, HKDF-SHA256)",
    "0x0030": "X25519Kyber768Draft00",
    "0x0040": "ML-KEM-512",
    "0x0041": "ML-KEM-768",
    "0x0042": "ML-KEM-1024",
    "0x0050": "MLKEM768-P256",
    "0x0051": "MLKEM1024-P384",
    "0x647a": "X-Wing",
}

func print_suites(d ECHConfigDets) (string) {
    aead, ok := aead_map[d.aead]
    if !ok {
        aead = d.aead
    }
    kdf, ok := kdf_map[d.kdf]
    if !ok {
        kdf = d.kdf
    }
    kem, ok := kem_map[d.kem]
    if !ok {
        kem = d.kem
    }
    rv := fmt.Sprintf("%s/%s/%s", kem, kdf, aead)
    return rv
}

func verify_thepile() {
    // iterate over the pile, checking if the singletons work
    // note using 'range' gets copies so we seemingly need to
    // iterate using the loop form below to change values in
    // 'thepile'
    for i := 0; i < len(thepile); i++ {
        p := thepile[i]
        for j := 0; j < len(p.details); j++ {
            d := p.details[j]
            count, _, err := verify_configs(p.name, p.port, d.singleton)
            if err == nil && count == 1 {
                if verbose {
                    fmt.Printf("Verified %s:%s singleton %d from %s\n",
                               p.name, p.port, j, p.source)
                }
                thepile[i].details[j].works = true
                total_checked_good += 1
            } else {
                if verbose {
                    fmt.Printf("Failed to verify %s:%s entry %d\n",
                               p.name, p.port, j)
                }
            }
        }
    }
}

func print_pile(pile []ECHConfigListDets, source string) {
    // summary print for the pile
    for i,p := range pile {
        if source != "all" && source != p.source {
            continue
        }
        fmt.Printf("List %d, source %s:\n",i, p.source)
        if p.port != "443" {
            fmt.Printf("\tname: %s:%s\n", p.name, p.port)
        } else {
            fmt.Printf("\tname: %s\n", p.name)
        }
        fmt.Printf("\tList: %s\n",
                   base64.StdEncoding.EncodeToString(p.list))
        for j,d := range p.details {
            fmt.Printf("\t\tSingleton %d\n", j)
            fmt.Printf("\t\tVersion: %s, config_id: %s, checked: %t\n",
                       d.version, d.config_id, d.works)
            fmt.Printf("\t\tpublic_name: %s\n", d.public_name)
            fmt.Printf("\t\tHPKE suites: %s\n", print_suites(d))
            fmt.Printf("\t\tSingleton: %s\n",
                       base64.StdEncoding.EncodeToString(d.singleton))
        }
    }
}


func nsupdate_stanza(ownername string, ttl int, priority int,
                     targ string, ecl []byte) {
    fmt.Printf("update add %s %d HTTPS %d %s %s\n",
        ownername, ttl, priority, targ,
        base64.StdEncoding.EncodeToString(ecl))
}

func pdns_stanza(ownername string, ttl int, priority int,
                     targ string, ecl []byte) {
    // pdns needs the (I guess) zone name (e.g. 2LD) so we guess
    // it's the last two labels of the ownername
    var two_ld string
    tldind := strings.LastIndex(ownername, ".")
    if tldind == -1 {
        two_ld = "example.com"
    } else {
        two_ldind := strings.LastIndex(ownername[0:tldind],".")
        if two_ldind == -1 {
            two_ld = ownername
        } else {
            two_ld = ownername[two_ldind+1:]
        }
    }
    fmt.Printf("pdnsutil rrset replace %s %s HTTPS %d %d %s %s\n",
        two_ld, ownername, ttl, priority, targ,
        base64.StdEncoding.EncodeToString(ecl))
}

func print_dns_instrs(pile []ECHConfigListDets, otype string,
                      source string, grouping string) {
    // print dns update commands as directed
    // TODO: extract/guess ttl/priority/targ-name from elsewhere
    // TODO: consider other HTRPS RR content (ipv4hint etc.)
    ttl := 3600
    priority := 1
    targetname := "."
    // we're looking ahead a bit here to get ownername before we
    // start into loop, it's ok, given name/port are the same in
    // all cases
    var ownername string
    if thepile[0].port == "443" {
        ownername = thepile[0].name
    } else {
        ownername = "_" + thepile[0].port + "_https." + thepile[0].name
    }
    if otype == "nsupdate" {
        fmt.Printf("update delete HTTPS %s\n", ownername)
    } // nothing similar needed for pdns afaik (but I may be wrong)
    for _,p := range pile {
        if source != "all" && source != p.source {
            continue
        }
        if grouping == "as-found" {
            if otype == "nsupdate" {
                nsupdate_stanza(ownername, ttl, priority, targetname, p.list)
            } else if otype == "pdns" {
                pdns_stanza(ownername, ttl, priority, targetname, p.list)
            }
        } else {
            for _,d := range p.details {
                // do one-by-one
                if otype == "nsupdate" {
                    nsupdate_stanza(ownername, ttl, priority, targetname,
                                    d.singleton)
                } else if otype == "pdns" {
                    pdns_stanza(ownername, ttl, priority, targetname,
                                        d.singleton)
                }
            }
        }
    }
}

func main() {
    var targetName string
    var targetPort string
    var retry_configs []byte
    var outputtype string
    var outputsource string
    var outputgrouping string
    public_name := ""
    total_checked_good = 0

    // command line args
    flag.StringVar(&targetName, "n", "defo.ie", "DNS name to probe")
    flag.StringVar(&targetPort, "p", "443", "service port to probe")
    flag.StringVar(&public_name, "pn", "", "ECH public name")
    flag.StringVar(&doh_url, "doh", "https://cloudflare-dns.com/dns-query",
                    "DoH URL")
    flag.StringVar(&outputtype, "o", "summary", "Output type desired")
    flag.StringVar(&outputsource, "s", "all", "Source for output desired")
    flag.StringVar(&outputgrouping, "g", "as-found",
                   "Group ECHConfig values 'as-found', or 'one-by-one'")
    flag.BoolVar(&verbose, "v", false, "verbosity")
    flag.BoolVar(&super_verbose, "vv", false, "lots of verbosity")
    flag.Parse()

    if super_verbose {
        verbose = true
    }

    // check if we have an origin-svcb
    origin_svcb, err := get_origin_svcb(targetName, targetPort)
    // extract ECH from that
    if err == nil {
        var os_j map[string]any
        if err = json.Unmarshal(origin_svcb, &os_j); err != nil {
            if verbose {
                log.Printf("origin_svcb unmarshal fail: %v\n", err)
            }
        } else {
            if os_j["endpoints"] != nil {
                eps := os_j["endpoints"]
                parr := eps.([]any)
                for _, val := range parr {
                    d0 := (val).(map[string]any)
                    if d0["params"] == nil {
                        continue
                    }
                    p0 := d0["params"].(map[string]any)
                    if p0["ech"] == nil {
                        continue
                    }
                    e0 := p0["ech"].(string)
                    ec, err := base64.StdEncoding.DecodeString(e0)
                    if err != nil {
                        fmt.Printf("error parsing origin-svcb: %v\n", err)
                    }
                    if verbose && err == nil {
                        fmt.Printf("ECHConfigList value from origin_svcb %s\n", e0)
                    }
                    if add_to_pile(targetName, targetPort,
                                   "origin-svcb", origin_svcb, ec) != nil {
                        fmt.Printf("add_to_pile error for origin-svcb: %v\n", err)
                    }
                }
            }
        }
    }

    // check if we get some retry-configs
    retry_configs, err = get_retry_configs(targetName, targetPort,
                                              public_name)
    if verbose && err == nil {
        fmt.Printf("ECHConfigList value from retry-configs %s\n",
            base64.StdEncoding.EncodeToString(retry_configs))
    }
    if retry_configs != nil && add_to_pile(targetName, targetPort,
                   "retry-configs", nil, retry_configs) != nil {
        log.Fatalf("add_to_pile error for retry-configs: %v\n", err)
    }

    // check for HTTPS RRs
    https_rrs, err := get_https_rrs(targetName, targetPort)
    if err != nil {
        if super_verbose {
            fmt.Printf("get https_rrs fail: %v\n", err)
        }
    }
    // unmarshall and pull out ech= strings
    var https_rrs_json map[string]any
    if err = json.Unmarshal(https_rrs, &https_rrs_json); err != nil {
        if super_verbose {
            fmt.Printf("unmarshal fail: %v\n", err)
        }
    }
    var dns_configs [][]byte
    dns_ans := https_rrs_json["Answer"]
    if super_verbose {
        fmt.Println("DNS Ans:\n", dns_ans)
    }
    var ansarr []any
    if dns_ans == nil {
        if verbose {
            fmt.Println("No real Answer in DNS response\n")
        }
        ansarr = nil
    } else {
        ansarr = dns_ans.([]any)
    }
    for _, val := range ansarr {
        d0 := (val).(map[string]any)
        if d0["type"].(float64) == 65 {
            rrval := d0["data"].(string)
            fvals := strings.Fields(rrval)
            for _, v := range fvals {
                place := strings.LastIndex(v, "ech=")
                if place != -1 {
                    if verbose {
                        fmt.Println("ECHConfigList from HTTPS RR", v[place+4:])
                    }
                    dec, err := base64.StdEncoding.DecodeString(v[place+4:])
                    if err == nil {
                        dns_configs = append(dns_configs, dec)
                    }
                }
            }
        }
    }
    for _, d := range dns_configs {
        if add_to_pile(targetName, targetPort,
                       "dns", https_rrs_json, d) != nil {
            log.Fatalf("add_to_pile error for retry-configs: %v\n", err)
        }
    }
    if verbose {
        for i, d := range dns_configs {
            fmt.Printf("ECHConfigList value %d from DNS: %s\n", i,
                base64.StdEncoding.EncodeToString(d))
        }
    }

    // for each singleton, check if it works
    verify_thepile()

    if total_checked_good == 0 {
        log.Fatal("No checked good ECHConfig values found")
    }

    // produce some output
    if outputtype == "summary" {
        print_pile(thepile, outputsource)
    }
    if outputtype == "nsupdate" || outputtype == "pdns" {
        print_dns_instrs(thepile, outputtype, outputsource, outputgrouping)
    }
}
