package benchmark

import (
	"context"
	"fmt"
	"github.com/allegro/bigcache/v3"
	"github.com/cloudflare/odoh-client-go/benchmark/resolver"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
	"golang.org/x/sync/semaphore"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func benchDo53ClientActions(connectionProtocolType string, serializedQueries map[BenchQuery]*dns.Msg, connectionString string, parallelism int, anchor bootstrap.TrustAnchor, outFile string) error {
	cache, err := bigcache.New(context.Background(), bigcache.DefaultConfig(24*time.Hour))
	resolverInUse := &resolver.Resolver{
		Timeout:    2500 * time.Second,
		Nameserver: connectionString,
		Cache:      cache,
	}

	// Prepare clients.
	clients := make([]*dns.Client, 0)
	for i := 0; i < parallelism; i++ {
		c := new(dns.Client)
		c.Net = connectionProtocolType
		c.UDPSize = 4096
		clients = append(clients, c)
	}

	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic("unable to open an output file for writing out results")
	}
	defer f.Close()

	if _, err := f.WriteString(strings.Join(TelemetryHeader(), ",") + "\n"); err != nil {
		log.Println("failed to write header to disk in output file.")
	}

	var sem = semaphore.NewWeighted(int64(parallelism))
	var wg sync.WaitGroup

	results := make([]Telemetry, 0)
	var counterIndex int64

	for query, serializedQuery := range serializedQueries {
		err := sem.Acquire(context.Background(), 1)
		if err != nil {
			log.Fatalf(fmt.Sprintf("failed to acquire semaphore. Query: %v\n", query))
		}
		wg.Add(1)

		atomic.AddInt64(&counterIndex, 1)

		go func(serializedQuery *dns.Msg, query BenchQuery, counter int64) {
			//c := clients[int(counter)%len(clients)]
			nwStart := time.Now()

			respBytes, queryBytesOnWire, respBytesOnWire, _ := resolver.ResolveQueryWithResolver(serializedQuery, resolverInUse)
			resp := new(dns.Msg)
			_ = resp.Unpack(respBytes)
			//resp, _, _ := c.Exchange(serializedQuery, connectionString)
			nwEnd := time.Now()

			t := Telemetry{
				Protocol:                fmt.Sprintf("do53-%v-client", connectionProtocolType),
				Query:                   query.Query,
				QueryType:               query.QueryType,
				VerificationStatus:      false,
				StartTime:               nwStart,
				EndTime:                 nwEnd,
				NetworkTime:             nwEnd.Sub(nwStart),
				VerificationTime:        0,
				QuerySizeBytesOnWire:    queryBytesOnWire,
				ResponseSizeBytesOnWire: respBytesOnWire,
				DNSResponseSizeBytes:    len(respBytes), // Effective result bytes.
				EncryptionTime:          0,
				DecryptionTime:          0,
			}

			if _, err := f.WriteString(strings.Join(t.Serialize(), ",") + "\n"); err != nil {
				log.Println("failed to write to disk")
			}

			results = append(results, t)
			sem.Release(1)
			wg.Done()
		}(serializedQuery, query, counterIndex)
	}

	wg.Wait()

	return nil

}

func BenchmarkDo53WithClientRecursion(c *cli.Context) error {
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

	outputPath := fmt.Sprintf("%v/results-%v-%v-DO-proof-%v-%v.csv", outputDir, "Do53-client", protocolUsed, dnssec, time.Now().UnixNano())

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

	return benchDo53ClientActions(protocolUsed, serializedQueryMap, connectToResolverAt, requestRate, anchor, outputPath)
}
