package benchmark

import (
	"fmt"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
	"net"
	"strconv"
	"time"
)

func BenchmarkDo53WithDNSSEC(c *cli.Context) error {
	clientRecurse := c.Bool("trace")

	if clientRecurse {
		return BenchmarkDo53WithClientRecursion(c)
	}
	
	inputFile := c.String("input")
	outputDir := c.String("output")
	requestRate := c.Int("rate")
	dnsTypeString := c.String("type")
	resolverHostNameOrIP := c.String("resolver")
	resolverConnectionPort := c.Int("port")
	useUDP := c.Bool("udp")
	useTCP := c.Bool("tcp")
	dnssec := c.Bool("dnssec")

	if (useUDP == false && useTCP == false) || (useUDP == true && useTCP == true) {
		fmt.Println("Please provide at least one of --udp or --tcp. Exiting benchmarking.")
		return nil
	}

	protocolUsed := ""
	if useUDP {
		protocolUsed = "udp"
	}
	if useTCP {
		protocolUsed = "tcp"
	}

	outputPath := fmt.Sprintf("%v/results-%v-%v-DO-proof-%v-%v.csv", outputDir, "Do53", protocolUsed, dnssec, time.Now().UnixNano())

	anchor := bootstrap.CheckAndValidateDNSRootAnchors()
	dnsType := common.DnsQueryStringToType(dnsTypeString)
	CheckIfDirectoryExistsOrCreate(outputDir)
	queries := ReadInputQueryList(inputFile)

	connectToResolverAt := net.JoinHostPort(resolverHostNameOrIP, strconv.FormatInt(int64(resolverConnectionPort), 10))

	serializedQueryMap := make(map[BenchQuery]*dns.Msg, 0)

	for _, q := range queries {
		dnsQ := PrepareDNSQuery(q, dnsType, dnssec)
		benchQ := BenchQuery{
			Query:     dnsQ.Question[0].Name,
			QueryType: dnsQ.Question[0].Qtype,
		}
		serializedQueryMap[benchQ] = dnsQ
	}

	return benchDO53(protocolUsed, serializedQueryMap, connectToResolverAt, requestRate, anchor, outputPath)
}
