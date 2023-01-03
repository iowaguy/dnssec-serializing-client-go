package benchmark

import (
	"fmt"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/urfave/cli/v2"
	"time"
)

func BenchmarkDoHWithDNSSEC(c *cli.Context) error {
	inputFile := c.String("input")
	outputDir := c.String("output")
	requestRate := c.Int("rate")
	dnsTypeString := c.String("type")
	resolverHostname := c.String("resolver")
	dnssec := c.Bool("dnssec")

	outputPath := fmt.Sprintf("%v/results-%v-DO-proof-%v-%v.csv", outputDir, "DoH", dnssec, time.Now().UnixNano())

	anchor := bootstrap.CheckAndValidateDNSRootAnchors()

	dnsType := common.DnsQueryStringToType(dnsTypeString)

	CheckIfDirectoryExistsOrCreate(outputDir)
	queries := ReadInputQueryList(inputFile)
	fmt.Printf("Number of queries: %v\n", len(queries))
	fmt.Printf("Number of query request batches: %v @ %v q/exec\n", len(queries)/requestRate+1, requestRate)

	serializedQueryMap := make(map[BenchQuery][]byte, 0)
	for _, q := range queries {
		dnsQ := PrepareDNSQuery(q, dnsType, dnssec)
		benchQ := BenchQuery{
			Query:     dnsQ.Question[0].Name,
			QueryType: dnsQ.Question[0].Qtype,
		}

		serQ, _ := dnsQ.Pack()
		serializedQueryMap[benchQ] = serQ
	}

	return bench("DoH", serializedQueryMap, nil, resolverHostname, requestRate, anchor, outputPath)
}
