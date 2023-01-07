package resolver

import (
	"errors"
	"github.com/miekg/dns"
	"log"
	"strings"
)

func reverse(labels []string) {
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
}

func makeDNSQuery(name string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), queryType)
	msg.Id = dns.Id()
	msg.SetEdns0(4096, true)
	return msg
}

func preComputeNecessaryDNSQueries(baseQuery *dns.Msg) ([]*dns.Msg, error) {
	// Consider only the first query of multiple questions asked.
	if len(baseQuery.Question) <= 0 {
		return nil, errors.New("no question in the DNS query")
	}
	queryName := baseQuery.Question[0].Name
	queryType := baseQuery.Question[0].Qtype

	domainLabels := dns.SplitDomainName(queryName)

	intermediateQueries := make([]string, 0)
	for index, _ := range domainLabels {
		dl := dns.Fqdn(strings.Join(domainLabels[index:], "."))
		intermediateQueries = append(intermediateQueries, dl)
	}
	intermediateQueries = append(intermediateQueries, ".")
	reverse(intermediateQueries)

	queries := make([]*dns.Msg, 0)

	for index, zoneName := range intermediateQueries {
		if zoneName == "." {
			// Only DNSKEY
			q := makeDNSQuery(zoneName, dns.TypeDNSKEY)
			queries = append(queries, q)
			continue
		}

		// DNSKEY and DS records
		dnskeyQuery := makeDNSQuery(zoneName, dns.TypeDNSKEY)
		queries = append(queries, dnskeyQuery)
		dsQuery := makeDNSQuery(zoneName, dns.TypeDS)
		queries = append(queries, dsQuery)

		if index == len(intermediateQueries)-1 {
			// Last query
			// Actual QueryType to be used.
			q := makeDNSQuery(zoneName, queryType)
			queries = append(queries, q)
		}
	}

	return queries, nil
}

func ResolveQueryWithResolver(q *dns.Msg, r resolver) ([]byte, int, int, error) {
	querySizeBytesOnWire := 0
	responseSizeBytesOnWire := 0

	queryId := q.Id
	dnssecRequestedOpts := q.IsEdns0()
	dnssecRequested := false
	if dnssecRequestedOpts != nil {
		dnssecRequested = dnssecRequestedOpts.Do()
	}

	resolverResults := make(map[*dns.Msg]*dns.Msg)

	queries, err := preComputeNecessaryDNSQueries(q)
	if err != nil {
		log.Printf("unable to precompute necessary DNS queries ....\n")
	}

	for _, query := range queries {
		querySizeBytesOnWire += query.Len()
		res, resolverErr := r.resolve(query)
		if resolverErr != nil {
			log.Printf("failed to receive response ...\n")
			continue
		}
		responseSizeBytesOnWire += res.Len()
		resolverResults[query] = res
	}

	requiredDNSSECRecords := make([]dns.RR, 0)
	for _, query := range queries {
		if res, ok := resolverResults[query]; ok {
			answers := res.Answer
			requiredDNSSECRecords = append(requiredDNSSECRecords, answers...)
		}
	}

	resp, ok := resolverResults[queries[len(queries)-1]]
	if ok {
		// Clear glue records from resolver and replace with proof in ADDITIONAL section
		resetExtras := make([]dns.RR, 0)
		resp.Extra = resetExtras
		// Include the proof.
	} else {
		resp = new(dns.Msg)
	}

	// Force set response ID to match query ID for dig warnings
	resp.Id = queryId

	if !dnssecRequested {
		answerRR := resp.Answer
		newRR := make([]dns.RR, 0)
		for _, rr := range answerRR {
			if rr.Header().Rrtype == dns.TypeRRSIG {
				continue
			}
			newRR = append(newRR, rr)
		}
		resp.Answer = newRR
		resp.Extra = make([]dns.RR, 0)
	}

	response, err := resp.Pack()

	return response, querySizeBytesOnWire, responseSizeBytesOnWire, err
}
