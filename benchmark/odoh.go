package benchmark

import (
	"fmt"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/cloudflare/odoh-client-go/network"
	"github.com/cloudflare/odoh-go"
	"github.com/urfave/cli/v2"
	"time"
)

func BenchmarkODoHWithDNSSEC(c *cli.Context) error {
	inputFile := c.String("input")
	outputDir := c.String("output")
	requestRate := c.Int("rate")
	dnsTypeString := c.String("type")
	odohTargetHostname := c.String("target")
	//odohProxyHostname := c.String("proxy")
	dnssec := c.Bool("dnssec")

	outputPath := fmt.Sprintf("%v/results-%v-DO-proof-%v-%v.csv", outputDir, "ODoH", dnssec, time.Now().UnixNano())

	anchor := bootstrap.CheckAndValidateDNSRootAnchors()
	dnsType := common.DnsQueryStringToType(dnsTypeString)
	CheckIfDirectoryExistsOrCreate(outputDir)
	queries := ReadInputQueryList(inputFile)

	serializedQueryMap := make(map[BenchQuery][]byte, 0)
	odohQueryContextMap := make(map[BenchQuery]*odoh.QueryContext, 0)

	odohTargetConfig := network.RetrieveODoHConfig(odohTargetHostname)

	for _, q := range queries {
		dnsQ := PrepareDNSQuery(q, dnsType, dnssec)
		benchQ := BenchQuery{
			Query:     dnsQ.Question[0].Name,
			QueryType: dnsQ.Question[0].Qtype,
		}
		packedDnsQuery, err := dnsQ.Pack()
		if err != nil {
			continue
		}
		odohQuery := odoh.CreateObliviousDNSQuery(packedDnsQuery, 0)
		encryptionStart := time.Now()
		odohMessageQuery, odohQueryContext, err := odohTargetConfig.Contents.EncryptQuery(odohQuery)
		if err != nil {
			continue
		}
		encryptionEnd := time.Now()
		benchQ.EncryptionTime = encryptionEnd.Sub(encryptionStart)
		packedDnsQuery = odohMessageQuery.Marshal()

		odohQueryContextMap[benchQ] = &odohQueryContext
		serializedQueryMap[benchQ] = packedDnsQuery
	}

	return bench("ODoH", serializedQueryMap, odohQueryContextMap, odohTargetHostname, requestRate, anchor, outputPath)
}
