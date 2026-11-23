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

// Given a DNS name, this script probes for Encrypted Client Hello (ECH,
// RFC9849) configurations (public keys etc) in order to assist admins
// in checking or fixing their setups. There are 3 possible
// sources for ECH configs: 1) in HTTPS RRs in the DNS, 2) via
// ECH retry-configs and 3) via a .well-known URL.
// The set of ECH configs found are then tested and listed in output.
// The output optionally can be formatted so as to be suitable for use with
// bind's nsupdate or PowerDNS's pdns-util

// This code has something in common with happy-eyeballs v3, in that we want
// to try the various options (e.g. h3) but we're not concerned here with
// speed, so it's not quite the same.

package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	// apparently "golang.org/x/net/internal/http3" is closer
	// to "official" but that doesn't seem to work for me, so
	// we'll go with that...
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	// using those needed an install for me:
	//     $ go install github.com/quic-go/quic-go/http3@latest
	// which picked up dependencies too
	// I also needed a go.mod file which I created via:
	//     $ go mod init defo.ie/echprobe
	//     $ go mod tidy
)

type ECHOptionals struct {
	// things that may optionally accompany an ECHConfigList
	// there are more things one could add here later
	regeninterval   int    // from orivin-svcb
	currentttl      int    // current-TTL in HTTP answer
	priority        int    // from orivin-svcb or HTTPS
	target          string // target from origin-svcb or HTTPS
	ipv4hint        string // from orivin-svcb or HTTPS
	ipv6hint        string // from orivin-svcb or HTTPS
	alpn            string // from orivin-svcb or HTTPS
	mandatory       string // mandatory svcparamkeys
	no_default_alpn bool   // that one:-)
}

type ECHConfigDets struct {
	// This represents a singleton ECHConfigList
	works        bool   // Set to TRUE when validated as working
	works_via    string // set when setting the above
	version      string
	config_id    string
	max_name_len int
	public_name  string
	kem          string
	kdf          string // comma-sep string
	aead         string // comma-sep string
	exts         bool   // true if some present
	singleton    []byte // the encoded singleton ECHConfigList
}

type ECHConfigListDets struct {
	// This represents a full ECHConfigList
	name      string          // what'd be in an inner SNI
	port      string          // service port (usually 443)
	source    string          // retry-config or origin-svcb or dns
	original  any             // original form in which we got this (e.g. DNS transaction)
	list      []byte          // the encoded ECHConfigList
	details   []ECHConfigDets // the singletons
	optionals ECHOptionals
}

var verbose bool = false
var duration time.Duration
var super_verbose bool = false
var doh_url string = ""
var thepile []ECHConfigListDets
var total_checked_good int

// just special case port 80/443
func get_target_url(host string, port string) string {
	var url string
	if port == "443" || port == "80" {
		url = "https://" + host + "/.well-known/origin-svcb"
	} else {
		url = "https://" + host + ":" + port + "/.well-known/origin-svcb"
	}
	return url
}

// return a retry-configs if relevant and found
func get_rc(err error) ([]byte, error) {
	var echErr *tls.ECHRejectionError
	if errors.As(err, &echErr) && len(echErr.RetryConfigList) > 0 {
		return echErr.RetryConfigList, nil
	}
	return nil, errors.New("no r-c")
}

/*
  Try URL via QUIC, then, if needed, TLS/TCP, return bytes found or error
  in the optionals we may have:

    target (another name), ipv[46]hint (addresses), alpn

  	alpn:
      if alpn set to h3 only try that
      if alpn set to h2/http1.1 only try that
    if other alpn, try both, setting the alpn
    if no alpn, try h3 then tls/tcp with no alpn

    addresses: we do nothing in parallel, we don't need to be fast
    candidate addresses:
        try ipv6hint, then ipv4hint, then target if set
        if target set only go there
        if no target just go to origin in URL

	we make a list of addresses/names to check, with ipv6hints
	firsts, then ipv4hints, then the target name (if present)
	and work our way through those, trying QUIC 1st (if needed),
	then tls/tcp for each

    we might wanna modify optionals to say what worked?

	we also input whether we want retry-configs as an output in
	which case an ECH-required error is a success:-)
*/

func my_quic_then_tcp(echcfg []byte, host string, port string,
	optionals *ECHOptionals, wantrc bool) (*http.Response, string, error) {

	// various vars as to which are the effective ("e_") values to use
	var viastr string
	var e_alpn []string
	var e_addrs []string
	skip_h3 := false

	the_url := get_target_url(host, port)
	tport, err := strconv.Atoi(port)
	if err != nil || tport >= 65536 {
		log.Fatalf("Bad port %s: %v\n", port, err)
		return nil, "", err
	}
	e_alpn = nil
	e_addrs = nil
	if optionals != nil {
		if optionals.alpn != "" {
			e_alpn = strings.Split(optionals.alpn, ",")
			// check if h3 in specifically provided alpn
			if !strings.Contains(optionals.alpn, "h3") {
				skip_h3 = true
			}
		} else {
			if !optionals.no_default_alpn {
				// try this as default
				e_alpn = []string{"h3", "h3", "http/1.1"}
			}
		}
		// array of ipv6hints 1st, then ipv4hint, then host name
		if optionals.ipv6hint != "" {
			e_addrs = strings.Split(optionals.ipv6hint, ",")
		}
		if optionals.ipv4hint != "" {
			t_addrs := strings.Split(optionals.ipv4hint, ",")
			e_addrs = append(e_addrs, t_addrs[:]...)
		}
	}
	e_addrs = append(e_addrs, host)

	targetURL, err := url.Parse(the_url)
	if err != nil {
		if super_verbose {
			fmt.Printf("url.Parse failed for %s: %v\n", the_url, err)
		}
		return nil, "", err
	}

	if super_verbose {
		fmt.Printf("addrs: %v\n", e_addrs)
	}
	for _, myaddr := range e_addrs {
		viastr = myaddr + ":" + port
		if !skip_h3 {
			if super_verbose {
				fmt.Printf("trying addr via h3: %s:%s\n", myaddr, port)
			}
			h3tr := &http3.Transport{
				TLSClientConfig: &tls.Config{
					EncryptedClientHelloConfigList: echcfg,
					NextProtos:                     e_alpn,
				},
				QUICConfig: &quic.Config{},
				Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
					// this isn't entirely right but is good enough
					var pconn net.PacketConn
					var perr error
					if strings.Contains(myaddr, ":") { // v6 case
						laddr, err := net.ResolveUDPAddr("udp6", ":::0")
						if err != nil {
							return nil, fmt.Errorf("quic local listener resolve failed: %w", err)
						}
						pconn, perr = net.ListenUDP("udp6", laddr)
						if perr != nil {
							return nil, fmt.Errorf("quic local listener binding failed: %w", err)
						}
					} else {
						laddr, err := net.ResolveUDPAddr("udp6", ":::0")
						if err != nil {
							return nil, fmt.Errorf("quic local listener resolve failed: %w", err)
						}
						pconn, perr = net.ListenUDP("udp6", laddr)
						if perr != nil {
							return nil, fmt.Errorf("quic local listener binding failed: %w", err)
						}
					}
					a, err := net.ResolveUDPAddr("udp", myaddr+":"+port)
					if err != nil {
						return nil, err
					}
					return quic.Dial(ctx, pconn, a, tlsConf, quicConf)
				},
			}
			defer h3tr.Close()
			h3client := &http.Client{
				Timeout:   duration,
				Transport: h3tr,
			}
			h3resp, h3err := h3client.Do(&http.Request{
				Method: "GET",
				Header: map[string][]string{
					"Accept": {"application/json"},
				},
				URL: targetURL,
			})
			if wantrc {
				_, isone := get_rc(h3err)
				if isone == nil {
					if super_verbose {
						fmt.Printf("h3 request failed as desired %s: via %s:%s %s\n", the_url, myaddr, port, h3resp.Proto)
					}
					return h3resp, viastr, h3err
				}
			}
			if h3err == nil && h3resp.StatusCode == 200 {
				if super_verbose {
					fmt.Printf("h3 request worked for %s: via %s:%s %s\n", the_url, myaddr, port, h3resp.Proto)
				}
				return h3resp, viastr, h3err
			}
			if super_verbose {
				fmt.Printf("h3 request failed for %s: via %s:%s : %v\n", the_url, myaddr, port, h3err)
			}
		}

		if super_verbose {
			fmt.Printf("trying addr via http/tls/tcp: %v\n", myaddr)
		}
		// fallback to trying tls/tcp
		ttr := &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := tls.Dial(network, myaddr+":"+port, &tls.Config{
					MinVersion:                     tls.VersionTLS13,
					EncryptedClientHelloConfigList: echcfg,
					NextProtos:                     e_alpn,
				})
				return conn, err
			},
		}
		tclient := &http.Client{
			Transport: ttr,
		}
		tresp, terr := tclient.Do(&http.Request{
			Method: "GET",
			Header: map[string][]string{
				"Accept": {"application/json"},
			},
			URL: targetURL,
		})
		if wantrc {
			_, isone := get_rc(terr)
			if isone == nil {
				if super_verbose {
					fmt.Printf("http/tls/tcp request failed as desired %s: via %s:%s %v\n", the_url, myaddr, port, terr)
				}
				return tresp, viastr, terr
			}
		}
		if terr != nil && super_verbose {
			fmt.Printf("http/tls/tcp request failed for %s: via %s:%s %v\n", the_url, myaddr, port, terr)
		}
		if terr == nil {
			if super_verbose {
				fmt.Printf("http/tls/tcp request worked for %s: via %s:%s\n", the_url, myaddr, port)
			}
			return tresp, viastr, terr
		}
	}
	return nil, "", nil
}

func get_origin_svcb(host string, port string) ([]byte, error) {
	targetURL := get_target_url(host, port)
	resp, _, err := my_quic_then_tcp(nil, host, port, nil, false)
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
		fmt.Printf("failed to read response body: %v", err)
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
		thislen := int(cfg[offset])*256 + int(cfg[offset+1])
		if thislen <= 0 || offset+thislen >= olen {
			fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
				olen, offset, thislen)
			return nil, errors.New("ECHConfigList too short (1)")
		}
		thiscfg := []byte{byte((thislen + 4) / 256), byte((thislen + 4) % 256),
			0xfe, 0x0d}
		thiscfg = slices.Concat(thiscfg, cfg[offset:offset+thislen+2])
		if super_verbose {
			fmt.Printf("Config %d: %s\n", count,
				base64.StdEncoding.EncodeToString(thiscfg))
		}

		tlen := len(thiscfg)
		det.version = fmt.Sprintf("0x%04x", int(thiscfg[2])*256+int(thiscfg[3]))
		det.config_id = fmt.Sprintf("0x%02x", int(thiscfg[6]))
		det.kem = fmt.Sprintf("0x%04x", int(thiscfg[7])*256+int(thiscfg[8]))
		publen := int(thiscfg[9])*256 + int(thiscfg[10])
		suiteoff := 11 + publen
		if (suiteoff + 2) >= tlen {
			return nil, errors.New("ECHConfigList too short (2)")
		}
		suitelen := int(thiscfg[suiteoff])*256 + int(thiscfg[suiteoff+1])
		// there better be one suite, at least
		kdf := int(thiscfg[suiteoff+2])*256 + int(thiscfg[suiteoff+3])
		det.kdf = fmt.Sprintf("0x%04x", kdf)
		aead := int(thiscfg[suiteoff+4])*256 + int(thiscfg[suiteoff+5])
		det.aead = fmt.Sprintf("0x%04x", aead)
		for suitenum := 1; suitenum < suitelen/4; suitenum++ {
			kdf := int(thiscfg[suiteoff+2+suitenum*4])*256 +
				int(thiscfg[suiteoff+3+suitenum*4])
			det.kdf += fmt.Sprintf(",0x%04x", kdf)
			aead := int(thiscfg[suiteoff+4+suitenum*4])*256 +
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
		pns := thiscfg[pnoff+1 : pnoff+1+pnlen]
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
		count += 1
	}
	return dets, nil
}

func get_public_name_conn(host string, port string) (string, error) {
	// we expect a cert error initially as the public name in the fake
	// ECH below will be wrong we use the error from that to get the
	// correct public_name
	// a bad ECHConfig to try elicit retry-configs
	fakeECH, err := base64.StdEncoding.DecodeString(
		"AEb+DQBCqQAgACBlm7cfDx/gKuUAwRTe+" +
			"YAMExbIyuLpLcgTORIdi69uewAEAAEAAQ" +
			"ATcHVibGljLnRlc3QuZGVmcy5pZQAA")
	// This is fragile, but good enough for now - the string below is
	// the public name in the above config
	suffix := ", not public.test.defs.ie"

	if _, _, err := my_quic_then_tcp(fakeECH, host, port, nil, false); err != nil {
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
	part_fakeECH := []byte{
		0xFF, 0xFF, 0xfe, 0x0d, 0xFF, 0xFF, 0xa9, 0x00,
		0x20, 0x00, 0x20, 0x65, 0x9b, 0xb7, 0x1f, 0x0f,
		0x1f, 0xe0, 0x2a, 0xe5, 0x00, 0xc1, 0x14, 0xde,
		0xf9, 0x8f, 0x4c, 0x13, 0x16, 0xc8, 0xca, 0xe2,
		0xe9, 0x2d, 0xc8, 0x13, 0x39, 0x12, 0x1d, 0x8b,
		0xaf, 0x6e, 0x7b, 0x00, 0x04, 0x00, 0x01, 0x00,
		0x01, 0x00}
	// will need public name and 2 zero octets for
	// empty extensions appended

	var fakeECH_good_pn []byte
	if public_name != "" {
		pnlen := byte(len(public_name) % 255)
		p1 := []byte{pnlen}
		p2 := []byte(public_name)
		p3 := []byte{0x00, 0x00}
		fakeECH_good_pn = slices.Concat(part_fakeECH, p1, p2, p3)
	} else { // use host
		pnlen := byte(len(host) % 255)
		p1 := []byte{pnlen}
		p2 := []byte(host)
		p3 := []byte{0x00, 0x00}
		fakeECH_good_pn = slices.Concat(part_fakeECH, p1, p2, p3)
	}
	// fixup lengths
	elen := len(fakeECH_good_pn)
	fakeECH_good_pn[0] = byte((elen - 2) / 256)
	fakeECH_good_pn[1] = byte((elen - 2) % 256)
	fakeECH_good_pn[4] = byte((elen - 6) / 256)
	fakeECH_good_pn[5] = byte((elen - 6) % 256)

	if super_verbose {
		fmt.Printf("\nFake ECHConfig to try get retry-configs  %s\n",
			base64.StdEncoding.EncodeToString(fakeECH_good_pn))
	}
	_, _, err := my_quic_then_tcp(fakeECH_good_pn, host, port, nil, true)
	rc, gerr := get_rc(err)
	if gerr == nil {
		return rc, gerr
	}
	return nil, errors.New("no retry_configs somehow")
}

func get_https_rrs(host string, port string) ([]byte, error) {
	var qname = host
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
	if resp.StatusCode != 200 || err != nil {
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
	configs []byte, optionals *ECHOptionals) (int, []byte, string, error) {
	var viastr string
	count := int(0)
	olen := len(configs)
	offset := int(4)
	goodones := []byte{0x00, 0x00}
	goodlen := 0

	for offset <= olen {
		// break into singleton ECHConfig values
		thislen := int(configs[offset])*256 + int(configs[offset+1])
		if thislen <= 0 || offset+thislen >= olen {
			fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
				olen, offset, thislen)
			return 0, nil, "", errors.New("ECHConfigList decode error (1)")
		}
		thiscfg := []byte{byte((thislen + 4) / 256), byte((thislen + 4) % 256),
			0xfe, 0x0d}
		thiscfg = slices.Concat(thiscfg, configs[offset:offset+thislen+2])
		if super_verbose {
			fmt.Printf("Config %d: %s\n", count,
				base64.StdEncoding.EncodeToString(thiscfg))
			//fmt.Printf("olen: %d, offset, %d, thislen: %d\n",
			//olen, offset, thislen)
		}
		_, xviastr, nerr := my_quic_then_tcp(thiscfg, host, port, optionals, false)
		viastr = xviastr
		if nerr != nil {
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
	goodones[0] = byte(goodlen / 256)
	goodones[1] = byte(goodlen % 256)

	return count, goodones, viastr, nil
}

func add_to_pile(host string, port string, source string, original any,
	list []byte, optionals *ECHOptionals) error {
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
	if optionals != nil {
		entry.optionals = *optionals
	}
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
var aead_map = map[string]string{
	"0x0000": "Reserved",
	"0x0001": "AES-128-GCM",
	"0x0002": "AES-256-GCM",
	"0x0003": "ChaCha20Poly1305",
	"0xffff": "Export-only",
}

var kdf_map = map[string]string{
	"0x0001": "HKDF-SHA256",
	"0x0002": "HKDF-SHA384",
	"0x0003": "HKDF-SHA512",
	"0x0010": "SHAKE128",
	"0x0011": "SHAKE256",
	"0x0012": "TurboSHAKE128",
	"0x0013": "TurboSHAKE256",
}

var kem_map = map[string]string{
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

func print_suites(d ECHConfigDets) string {
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
			count, _, viastr, err := verify_configs(p.name, p.port, d.singleton,
				&p.optionals)
			if err == nil && count == 1 {
				if verbose {
					fmt.Printf("Verified %s:%s singleton %d from %s\n",
						p.name, p.port, j, p.source)
				}
				thepile[i].details[j].works = true
				thepile[i].details[j].works_via = viastr
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
	for i, p := range pile {
		if source != "all" && source != p.source {
			continue
		}
		fmt.Printf("List %d, source %s:\n", i, p.source)
		if p.port != "443" {
			fmt.Printf("\tname: %s:%s\n", p.name, p.port)
		} else {
			fmt.Printf("\tname: %s\n", p.name)
		}
		fmt.Printf("\tList: %s\n",
			base64.StdEncoding.EncodeToString(p.list))
		if p.source == "origin-svcb" {
			fmt.Printf("\torigin-svcb regeninterval: %d, ", p.optionals.regeninterval)
			fmt.Printf("priority: %d, ", p.optionals.priority)
			fmt.Printf("target: %s\n", p.optionals.target)
		}
		if p.source == "dns" {
			fmt.Printf("\tHTTPS RR TTL seen: %d, ", p.optionals.currentttl)
			fmt.Printf("priority: %d, ", p.optionals.priority)
			fmt.Printf("target: %s\n", p.optionals.target)
		}
		if p.source != "retry-configs" {
			fmt.Printf("\tipv4hint: %s, ", p.optionals.ipv4hint)
			fmt.Printf("ipv6hint: %s\n", p.optionals.ipv6hint)
			fmt.Printf("\talpn: %s, ", p.optionals.alpn)
			fmt.Printf("mandatory: %s, ", p.optionals.mandatory)
			fmt.Printf("no-default-alpn: %v\n", p.optionals.no_default_alpn)
		}
		for j, d := range p.details {
			fmt.Printf("\t\tSingleton %d\n", j)
			fmt.Printf("\t\tVersion: %s, config_id: %s, checked: %t, via: %s\n",
				d.version, d.config_id, d.works, d.works_via)
			fmt.Printf("\t\tpublic_name: %s\n", d.public_name)
			fmt.Printf("\t\tHPKE suites: %s\n", print_suites(d))
			fmt.Printf("\t\tSingleton: %s\n",
				base64.StdEncoding.EncodeToString(d.singleton))
		}
	}
}

func nsupdate_stanza(ownername string, ttl int, priority int,
	targ string, ecl []byte, addedparams string) {
	fmt.Printf("update add %s %d HTTPS %d %s %s %s\n",
		ownername, ttl, priority, targ,
		base64.StdEncoding.EncodeToString(ecl), addedparams)
}

func pdns_stanza(ownername string, ttl int, priority int,
	targ string, ecl []byte, addedparams string) {
	// pdns needs the (I guess) zone name (e.g. 2LD) so we guess
	// it's the last two labels of the ownername
	var two_ld string
	tldind := strings.LastIndex(ownername, ".")
	if tldind == -1 {
		two_ld = "example.com"
	} else {
		two_ldind := strings.LastIndex(ownername[0:tldind], ".")
		if two_ldind == -1 {
			two_ld = ownername
		} else {
			two_ld = ownername[two_ldind+1:]
		}
	}
	fmt.Printf("pdnsutil rrset replace %s %s HTTPS %d %d %s %s %s\n",
		two_ld, ownername, ttl, priority, targ,
		base64.StdEncoding.EncodeToString(ecl), addedparams)
}

// TODO: handle optionals
func print_dns_instrs(pile []ECHConfigListDets, otype string,
	source string, grouping string) {
	// print dns update commands as directed
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
	for _, p := range pile {
		ttl := 3600
		priority := 1
		targetname := "."
		addedparamstr := ""
		if p.source == "origin-svcb" {
			ttl = p.optionals.regeninterval / 2
			priority = p.optionals.priority
		}
		if p.source == "dns" {
			ttl = p.optionals.currentttl
			priority = p.optionals.priority
		}
		targetname = p.optionals.target
		if p.optionals.ipv4hint != "" {
			addedparamstr += " ipv4hint=" + p.optionals.ipv4hint
		}
		if p.optionals.ipv6hint != "" {
			addedparamstr += " ipv6hint=" + p.optionals.ipv6hint
		}
		if p.optionals.alpn != "" {
			addedparamstr += "alpn=" + p.optionals.alpn
		}
		if p.optionals.mandatory != "" {
			addedparamstr += "mandatory=" + p.optionals.mandatory
		}
		if p.optionals.no_default_alpn == true {
			addedparamstr += "no-default-alon"
		}
		if source != "all" && source != p.source {
			continue
		}
		if grouping == "as-found" {
			if otype == "nsupdate" {
				nsupdate_stanza(ownername, ttl, priority, targetname, p.list, addedparamstr)
			} else if otype == "pdns" {
				pdns_stanza(ownername, ttl, priority, targetname, p.list, addedparamstr)
			}
		} else {
			for _, d := range p.details {
				// do one-by-one
				if otype == "nsupdate" {
					nsupdate_stanza(ownername, ttl, priority, targetname,
						d.singleton, addedparamstr)
				} else if otype == "pdns" {
					pdns_stanza(ownername, ttl, priority, targetname,
						d.singleton, addedparamstr)
				}
			}
		}
	}
}

func main() {
	var targetName string
	var targetPort string
	var outputtype string
	var outputsource string
	var outputgrouping string
	var timeoutstr string
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
	flag.StringVar(&timeoutstr, "t", "100ms", "Timeout for connections in ms (default 100)")
	flag.Parse()

	if super_verbose {
		verbose = true
	}
	var derr error
	duration, derr = time.ParseDuration(timeoutstr)
	if derr != nil {
		log.Fatalf("Badly formatted timeout: '%s' (default '100ms') %v\n", timeoutstr, derr)
		os.Exit(1)
	}

	if outputsource == "all" || outputsource == "origin-svcb" {
		// check if we have an origin-svcb
		origin_svcb, err := get_origin_svcb(targetName, targetPort)
		// try extract ECH, and other details from that
		if err == nil {
			var os_j map[string]any
			if err = json.Unmarshal(origin_svcb, &os_j); err != nil {
				if verbose {
					fmt.Printf("origin_svcb unmarshal fail: %v\n", err)
				}
			} else {
				if os_j["endpoints"] != nil {
					var optionals ECHOptionals
					var ok bool
					var tmp_fl float64
					optionals.regeninterval = 3600
					tmp_fl, ok = os_j["regeninterval"].(float64)
					if ok {
						optionals.regeninterval = int(tmp_fl)
					}
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
							continue
						}
						// check for some optional things
						optionals.priority = 1
						tmp_fl, ok = d0["priority"].(float64)
						if ok {
							optionals.priority = int(tmp_fl)
						}
						optionals.target = "."
						if d0["target"] != nil {
							optionals.target = d0["target"].(string)
						}
						if p0["ipv4hint"] != nil {
							for k, v := range p0["ipv4hint"].([]any) {
								if k == 0 {
									optionals.ipv4hint = v.(string)
								} else {
									optionals.ipv4hint += "," + v.(string)
								}
							}
						}
						if p0["ipv6hint"] != nil {
							for k, v := range p0["ipv6hint"].([]any) {
								if k == 0 {
									optionals.ipv6hint = v.(string)
								} else {
									optionals.ipv6hint += "," + v.(string)
								}
							}
						}
						if p0["alpn"] != nil {
							for k, v := range p0["alpn"].([]any) {
								if k == 0 {
									optionals.alpn = v.(string)
								} else {
									optionals.alpn += "," + v.(string)
								}
							}
						}
						if p0["mandatory"] != nil {
							for k, v := range p0["mandatory"].([]any) {
								if k == 0 {
									optionals.mandatory = v.(string)
								} else {
									optionals.mandatory += "," + v.(string)
								}
							}
						}
						if p0["no-default-alpn"] != nil {
							optionals.no_default_alpn = true
						}
						if verbose && err == nil {
							fmt.Printf("origin-svcb ECHConfigList value: %s\n", e0)
						}
						if add_to_pile(targetName, targetPort,
							"origin-svcb", origin_svcb, ec, &optionals) != nil {
							fmt.Printf("origin-svcb add_to_pile error: %v\n", err)
						}
					}
				}
			}
		}
	}

	if outputsource == "all" || outputsource == "retry-configs" {
		// check if we get some retry-configs
		retry_configs, err := get_retry_configs(targetName, targetPort,
			public_name)
		if verbose && err == nil {
			fmt.Printf("ECHConfigList value from retry-configs %s\n",
				base64.StdEncoding.EncodeToString(retry_configs))
		}
		if retry_configs != nil && add_to_pile(targetName, targetPort,
			"retry-configs", nil, retry_configs, nil) != nil {
			log.Fatalf("add_to_pile error for retry-configs: %v\n", err)
		}
	}

	if outputsource == "all" || outputsource == "dns" {
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
				var tmp_ttl float64
				var ok bool
				currentttl := 0
				tmp_ttl, ok = d0["TTL"].(float64)
				if ok {
					currentttl = int(tmp_ttl)
				}
				rrval := d0["data"].(string)
				fvals := strings.Fields(rrval)
				var optionals ECHOptionals
				var dec []byte
				var err error
				echfound := false
				optionals.currentttl = currentttl
				for pi, part := range fvals {
					if pi == 0 {
						optionals.priority, err = strconv.Atoi(part)
						if err != nil {
							break
						}
						continue
					}
					if pi == 1 {
						optionals.target = part
						continue
					}
					if strings.HasPrefix(part, "ech=") {
						if verbose {
							fmt.Println("ECHConfigList from HTTPS RR", part[4:])
						}
						dec, err = base64.StdEncoding.DecodeString(part[4:])
						if err == nil {
							dns_configs = append(dns_configs, dec)
						}
						echfound = true
					}
					if strings.HasPrefix(part, "ipv4hint=") {
						optionals.ipv4hint = part[9:]
					}
					if strings.HasPrefix(part, "ipv6hint=") {
						optionals.ipv6hint = part[9:]
					}
					if strings.HasPrefix(part, "alpn=") {
						optionals.alpn = part[5:]
					}
					if strings.HasPrefix(part, "mandatory=") {
						optionals.mandatory = part[10:]
					}
					if strings.HasPrefix(part, "no-default-alpn") {
						optionals.no_default_alpn = true
					}
				}
				if echfound && add_to_pile(targetName, targetPort,
					"dns", https_rrs_json, dec, &optionals) != nil {
					log.Fatalf("add_to_pile error for HTTPS RR configs: %v\n", err)
				}
			}
		}
		if verbose {
			for i, d := range dns_configs {
				fmt.Printf("ECHConfigList value %d from DNS: %s\n", i,
					base64.StdEncoding.EncodeToString(d))
			}
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
