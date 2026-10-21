// Add LICENSE stuff

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
        log.Fatal(err)
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
        log.Fatalf("failed to perform request %s: %v", targetURL, err)
    }
    defer resp.Body.Close()
    if super_verbose {
        fmt.Printf("origin-svcb resp status code: %d\n", resp.StatusCode)
    }
    if resp.StatusCode != 200 {
        return []byte{}, err
    }
    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Fatalf("failed to read response body: %v", err)
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
        suitelen := int(thiscfg[suiteoff])*256+int(thiscfg[suiteoff+1])
        // there better be one suite, at least
        det.kdf = fmt.Sprintf("0x%04x", int(thiscfg[suiteoff+2]))
        det.aead = fmt.Sprintf("0x%04x", int(thiscfg[suiteoff+3]))
        for suitenum := 1; suitenum < suitelen/4; suitenum++ {
            det.kdf += fmt.Sprintf(",0x%04x",
                                   int(thiscfg[suiteoff+2+4*suitenum]))
            det.aead += fmt.Sprintf(",0x%04x",
                                    int(thiscfg[suiteoff+3+4*suitenum]))
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

    pnlen := byte(len(public_name) % 255)
    p1 := []byte { pnlen }
    p2 := []byte(public_name)
    p3 := []byte { 0x00, 0x00 }
    fakeECH_good_pn := slices.Concat(part_fakeECH, p1, p2, p3)
    // fixup lengths
    elen := len(fakeECH_good_pn)
    fakeECH_good_pn[0]=byte((elen-2)/256)
    fakeECH_good_pn[1]=byte((elen-2)%256)
    fakeECH_good_pn[4]=byte((elen-6)/256)
    fakeECH_good_pn[5]=byte((elen-6)%256)

    if super_verbose {
        fmt.Printf("Fake ECHConfig %s\n",
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
        log.Fatal(err)
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
        log.Fatal(err)
        return nil, err
    }
    defer resp.Body.Close()
    data, err := io.ReadAll(resp.Body)
    if err != nil {
        log.Fatal(err)
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
            log.Fatal("bad encoding\n")
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

func print_suites(d ECHConfigDets) (string) {
	// make this nicer later via names for codepoints
	rv := fmt.Sprintf("%s/%s/%s", d.kem, d.kdf, d.aead)
	return rv
}

func print_pile(pile []ECHConfigListDets) {
	// basic print for the pile
	for i,p := range pile {
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

func main() {
    var targetName string
    var targetPort string
    var retry_configs []byte
    public_name := ""

    // command line args
    flag.StringVar(&targetName, "n", "defo.ie", "DNS name to probe")
    flag.StringVar(&targetPort, "p", "443", "service port to probe")
    flag.StringVar(&public_name, "pn", "", "ECH public name")
    flag.StringVar(&doh_url, "doh", "https://cloudflare-dns.com/dns-query",
                    "DoH URL")
    flag.BoolVar(&verbose, "v", false, "verbosity")
    flag.BoolVar(&super_verbose, "vv", false, "verbosity")
    flag.Parse()

    if super_verbose {
        verbose = true
    }

    // check if we have an origin-svcb
    origin_svcb, err := get_origin_svcb(targetName, targetPort)
    if super_verbose && err == nil {
        fmt.Printf("origin svcb: %s\n", string(origin_svcb))
    }
    // extract ECH from that
    if err == nil {
        var os_j map[string]any
        if err = json.Unmarshal(origin_svcb, &os_j); err != nil {
            if verbose {
                log.Printf("origin_svcb unmarshal fail: %v\n", err)
            }
        } else {
            //fmt.Println("osj:", os_j)
            //fmt.Printf("type osj: %T\n", os_j)
            //fmt.Println(os_j["regeninterval"])
            eps := os_j["endpoints"]
            //fmt.Println("eps:", eps)
            parr := eps.([]any)
            //fmt.Printf("type eps: %T\n", eps)
            for _, val := range parr {
                d0 := (val).(map[string]any)
                //p1 := d0["priority"]
                //fmt.Println("priority:", p1)
                p0 := d0["params"].(map[string]any)
                //fmt.Println("params:", p0)
                //fmt.Printf("type p0: %T\n", p0)
                e0 := p0["ech"].(string)
                //fmt.Println(e0)
                ec, err := base64.StdEncoding.DecodeString(e0)
                if err != nil {
                    fmt.Printf("error parsing origin-svcb: %v\n", err)
                }
				if verbose && err == nil {
					fmt.Printf("ECHConfigList value from origin_svcb %s\n", ec)
				}
                if add_to_pile(targetName, targetPort,
                               "origin-svcb", origin_svcb, ec) != nil {
                    fmt.Printf("add_to_pile error for origin-svcb: %v\n", err)
                }
            }
        }
    }

    // try get public_name if not provided on command line
    if public_name == "" {
        public_name, err = get_public_name_conn(targetName, targetPort)
        if verbose && err == nil {
            fmt.Printf("public name from conn: %s\n", public_name)
        }
    }

    // check if we get some retry-configs, if we have a public name
    if public_name != "" {
        retry_configs, err = get_retry_configs(targetName, targetPort,
                                                     public_name)
        if verbose && err == nil {
            fmt.Printf("ECHConfigList value from retry-configs %s\n",
                base64.StdEncoding.EncodeToString(retry_configs))
        }
        if add_to_pile(targetName, targetPort,
                       "retry-configs", nil, retry_configs) != nil {
            log.Fatalf("add_to_pile error for retry-configs: %v\n", err)
        }
    }

    // check for HTTPS RRs
    https_rrs, err := get_https_rrs(targetName, targetPort)
    if err != nil {
        log.Fatalf("get https_rrs fail: %v\n", err)
    }
    // unmarshall and pull out ech= strings
    var https_rrs_json map[string]any
    if err = json.Unmarshal(https_rrs, &https_rrs_json); err != nil {
        log.Fatalf("unmarshal fail: %v\n", err)
    }
    var dns_configs [][]byte 
    dns_ans := https_rrs_json["Answer"]
    if super_verbose {
        fmt.Println("DNS Ans:\n", dns_ans)
    }
    ansarr := dns_ans.([]any)
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

	print_pile(thepile)
    //fmt.Println(thepile)

    // TODO: apply heuristics to produce inferred HTTPS RR desiderata
    // principle: try just replace ECHConfig values and leave all else the same
    // whenever change is needed
    desiredECH := retry_configs

    // verify if desiderata function
    var count int
    var goodones []byte
    if count, goodones, err = verify_configs(targetName, targetPort,
                                             desiredECH); err != nil {
        log.Fatalf("desiredECH fail %s:%s %v", targetName, targetPort,
                        desiredECH, err)
    }
    if verbose {
        fmt.Printf("goodones %d: %s\n", count,
            base64.StdEncoding.EncodeToString(goodones))
    }
    // TODO: verify if desiderata differ from status quo
    // status quo

    // TODO: if status quo != desiderata output suggested nsupdate or
    // pdns_util stanzas or HTTPS RR values
}
