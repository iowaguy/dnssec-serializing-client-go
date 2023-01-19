package benchmark

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/cloudflare/odoh-client-go/network"
	"github.com/cloudflare/odoh-client-go/verification"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"golang.org/x/net/idna"
	"golang.org/x/sync/semaphore"
)

func PrepareDNSQuery(hostname string, queryType uint16, dnssec bool) *dns.Msg {
	domainName, err := idna.ToASCII(hostname)
	if err != nil {
		log.Printf("Unable to encode hostname %v to ASCII.", hostname)
	}
	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(dns.Fqdn(domainName), queryType)
	if dnssec {
		dnsQuery.SetEdns0(4096, true)
	}
	return dnsQuery
}

// iterate over zones and dnskeys in the zones and add the type to the results array
func collectKeyTypes(resp *dns.Msg) []string {
	keyAlgs := make([]string, 0)
	for _, rr := range resp.Extra {
		switch t := rr.(type) {
		case *dns.Chain:
			for _, zone := range t.Zones {
				for _, key := range zone.Keys {
					keyBytes, err := base64.StdEncoding.DecodeString(key.PublicKey)
					if err != nil {
						log.Println("DNSKEY could not be decoded.")
						continue
					}

					keyLength := "UNKNOWN"
					switch key.Algorithm {
					case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
						var exponentLength uint64
						exponentStart := 0
						// According to RFC 3110, "[the exponent] length in octets is represented
						// as one octet if it is in the range of 1 to 255 and by a zero octet
						// followed by a two octet unsigned length if it is longer than 255 bytes"
						if uint8(keyBytes[0]) == 0 {
							exponentLength = binary.BigEndian.Uint64(keyBytes[1:3])
							exponentStart = 3
						} else {
							exponentLength = uint64(keyBytes[0])
							exponentStart = 1
						}

						keyLengthL := len(keyBytes) - exponentStart - int(exponentLength)
						keyLength = strconv.FormatUint(uint64(keyLengthL*8), 10)
					case dns.DH:
						// can be determined as in https://www.rfc-editor.org/rfc/rfc2539
						keyLength = "UNKNOWN"
					case dns.DSA, dns.DSANSEC3SHA1:
						// can be determined as in https://www.rfc-editor.org/rfc/rfc2536#page-2
						keyLength = "UNKNOWN"
					case dns.ECDSAP256SHA256:
						keyLength = "UNKNOWN"
					case dns.ECDSAP384SHA384:
						keyLength = "UNKNOWN"
					case dns.ECCGOST:
						// not interesting, the key size MUST be 512 bits according
						// to https://www.rfc-editor.org/rfc/rfc5933#page-6
						keyLength = "512"
					case dns.ED25519:
						// keys have a fixed length of 256
						keyLength = "256"
					case dns.ED448:
						// keys have a fixed length
						keyLength = "456"
					default:
						keyLength = "UNKNOWN"
					}

					keyAlgs = append(keyAlgs, dns.AlgorithmToString[key.Algorithm]+"--"+keyLength)
				}
			}
		default:
			continue
		}
	}

	return keyAlgs
}

func bench(protocol string, serializedQueries map[BenchQuery][]byte, odohQueryContext map[BenchQuery]*odoh.QueryContext, resolverHostname string, parallelism int, anchor bootstrap.TrustAnchor, proxyURL *url.URL, isSocks5 bool, outFile string) error {

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
				queryContext,
				proxyURL,
				isSocks5)

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
				KeyTypes:                collectKeyTypes(resp),
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
				KeyTypes:                collectKeyTypes(resp),
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
