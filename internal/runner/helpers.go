package runner

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/Alwardani9090/dnsenum/pkg/dnsprobe"

	"github.com/miekg/dns"
)

func convertRecordsToUint16(records []string) []uint16 {
	if len(records) == 0 {
		return []uint16{}
	}
	for _, record := range records {
		record = strings.ToUpper(record)
	}

	recordMap := map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"NS":    dns.TypeNS,
		"SRV":   dns.TypeSRV,
		"TXT":   dns.TypeTXT,
		"PTR":   dns.TypePTR,
		"SOA":   dns.TypeSOA,
	}
	var results []uint16
	for _, record := range records {
		if rt, ok := recordMap[record]; ok {
			results = append(results, rt)
		}
	}
	return results
}

type OutputJSON struct {
	Subdomains []*SubdomainResult `json:"subdomains"`
}

type SubdomainResult struct {
	Host             string              `json:"host"`
	Records          map[string][]string `json:"records"`
	ResolversChecked int                 `json:"resolvers_checked"`
}

func writeJSONOutput(filename string, results []*dnsprobe.ProbeResult) error {
	output := OutputJSON{
		Subdomains: []*SubdomainResult{},
	}

	for _, result := range results {
		if result == nil || len(result.Results) == 0 {
			continue
		}

		records := make(map[string][]string)
		for _, r := range result.Results {
			if r == nil {
				continue
			}
			if r.DnsStatus == "NOERROR" && len(r.Values) > 0 {
				records[r.RecordName] = r.Values
			}
		}

		if len(records) > 0 {
			output.Subdomains = append(output.Subdomains, &SubdomainResult{
				Host:             result.Host,
				Records:          records,
				ResolversChecked: result.ResolversChecked,
			})
		}
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
