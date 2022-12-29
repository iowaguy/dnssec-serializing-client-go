package benchmark

import (
	"github.com/miekg/dns"
	"log"
)

func PrepareDNSQueryWithDOBit(hostname string, dnsType uint16) []byte {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(hostname), dnsType)
	query.SetEdns0(4096, true)
	queryBytes, err := query.Pack()
	if err != nil {
		log.Fatalf("unable to pack the DNS query for %v into byte serialization\n.Error: %v\n", hostname, err)
	}
	return queryBytes
}
