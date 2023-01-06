package benchmark

import (
	"context"
	"fmt"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/cloudflare/odoh-client-go/network"
	"github.com/cloudflare/odoh-client-go/verification"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func PrepareDNSQuery(hostname string, queryType uint16, dnssec bool) *dns.Msg {
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(dns.Fqdn(hostname), queryType)
	if dnssec {
		dnsQuery.SetEdns0(4096, true)
	}
	return dnsQuery
}

func bench(protocol string, serializedQueries map[BenchQuery][]byte, odohQueryContext map[BenchQuery]*odoh.QueryContext, resolverHostname string, parallelism int, anchor bootstrap.TrustAnchor, outFile string) error {

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

	for query, serializedQuery := range serializedQueries {
		err := sem.Acquire(context.Background(), 1)
		if err != nil {
			log.Fatalf(fmt.Sprintf("failed to acquire semaphore. Query: %v\n", query))
		}
		wg.Add(1)
		go func(serializedQuery []byte, query BenchQuery) {
			var queryContext *odoh.QueryContext
			queryContext = nil
			useODoH := false
			contentType := common.DOH_CONTENT_TYPE

			if odohQueryContext != nil {
				queryContext = odohQueryContext[query]
				useODoH = true
				contentType = common.ODOH_CONTENT_TYPE
			}
			resp, report, _ := network.QueryDNS(resolverHostname,
				serializedQuery,
				contentType,
				useODoH,
				queryContext)

			if resp == nil {
				resp = new(dns.Msg)
			}

			verificationStartTime := time.Now()

			validity, _ := verification.ValidateDNSSECSignature(resp, query.Query, &anchor)
			verificationEndTime := time.Now()

			t := Telemetry{
				Protocol:                protocol,
				Query:                   query.Query,
				QueryType:               query.QueryType,
				VerificationStatus:      validity,
				StartTime:               report.StartTime,
				EndTime:                 report.EndTime,
				NetworkTime:             report.NetworkTime,
				VerificationTime:        verificationEndTime.Sub(verificationStartTime),
				QuerySizeBytesOnWire:    report.QuerySizeBytesOnWire,
				ResponseSizeBytesOnWire: report.ResponseSizeBytesOnWire,
				DNSResponseSizeBytes:    report.ResponseSizeBytes,
				EncryptionTime:          query.EncryptionTime,
			}
			if report.DecryptionTime != nil {
				t.DecryptionTime = *report.DecryptionTime
			}

			if _, err := f.WriteString(strings.Join(t.Serialize(), ",") + "\n"); err != nil {
				log.Println("failed to write to disk")
			}

			results = append(results, t)

			sem.Release(1)
			wg.Done()
		}(serializedQuery, query)
	}

	wg.Wait()

	return nil
}

func benchDO53(connectionProtocolType string, serializedQueries map[BenchQuery]*dns.Msg, connectionString string, parallelism int, anchor bootstrap.TrustAnchor, outFile string) error {
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
			c := clients[int(counter)%len(clients)]
			nwStart := time.Now()
			resp, _, _ := c.Exchange(serializedQuery, connectionString)
			nwEnd := time.Now()

			if resp == nil {
				resp = new(dns.Msg)
			}

			vsStart := time.Now()
			validity, _ := verification.ValidateDNSSECSignature(resp, query.Query, &anchor)
			vsEnd := time.Now()

			t := Telemetry{
				Protocol:                fmt.Sprintf("do53-%v", connectionProtocolType),
				Query:                   query.Query,
				QueryType:               query.QueryType,
				VerificationStatus:      validity,
				StartTime:               nwStart,
				EndTime:                 nwEnd,
				NetworkTime:             nwEnd.Sub(nwStart),
				VerificationTime:        vsEnd.Sub(vsStart),
				QuerySizeBytesOnWire:    serializedQuery.Len(),
				ResponseSizeBytesOnWire: resp.Len(),
				DNSResponseSizeBytes:    resp.Len(),
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
