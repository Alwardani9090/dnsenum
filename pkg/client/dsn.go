package client

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var Types = map[string]uint16{
	"A":     dns.TypeA,
	"AAAA":  dns.TypeAAAA,
	"CNAME": dns.TypeCNAME,
	"MX":    dns.TypeMX,
	"NS":    dns.TypeNS,
	"SRV":   dns.TypeSRV,
}

var DefaultResolvers = []string{
	"udp:1.1.1.1:53",
	"udp:1.0.0.1:53",
	"udp:8.8.8.8:53",
	"udp:8.8.4.4:53",
	"udp:9.9.9.9:53",
	"udp:149.112.112.112:53",
	"udp:208.67.222.222:53",
	"udp:208.67.220.220:53",
}

type Result struct {
	RecordName string
	Values     []string
	DnsStatus  string
}

func Query(host string, timeout int, record uint16, resolver string) (*Result, error) {
	network, addr, err := parseResolver(resolver)
	if err != nil {
		return nil, err
	}

	c := new(dns.Client)
	c.Timeout = time.Duration(timeout) * time.Second
	c.Net = network

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), record)

	msg, _, err := c.Exchange(m, addr)
	if err != nil {
		return nil, err
	}
	var values []string
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			values = append(values, v.A.String())
		case *dns.AAAA:
			values = append(values, v.AAAA.String())
		case *dns.CNAME:
			values = append(values, v.Target)
		case *dns.MX:
			values = append(values, fmt.Sprintf("%d %s", v.Preference, v.Mx))
		case *dns.NS:
			values = append(values, v.Ns)

		}
	}
	return &Result{
		RecordName: dns.TypeToString[record],
		Values:     values,
		DnsStatus:  convertStatusToString(msg.Rcode),
	}, nil
}

func convertStatusToString(status int) string {
	switch status {
	case dns.RcodeSuccess:
		return "NOERROR"
	case dns.RcodeNameError:
		return "NXDOMAIN"
	case dns.RcodeServerFailure:
		return "SERVFAIL"
	case dns.RcodeRefused:
		return "REFUSED"
	case dns.RcodeFormatError:
		return "FORMERR"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", status)
	}

}

func parseResolver(r string) (string, string, error) {
	split := strings.Split(r, ":")

	if len(split) != 3 {
		return "", "", fmt.Errorf("invalid resolver format: %s", r)
	}
	return split[0], split[1] + ":" + split[2], nil

}
