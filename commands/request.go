package commands

import (
	"bytes"
	"fmt"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func queryDNS(hostname string, serializedDnsQueryString []byte, contentType string, useODoH bool, odohQueryContext *odoh.QueryContext) (response *dns.Msg, err error) {
	client := http.Client{}
	queryUrl := common.BuildDohURL(hostname).String()
	log.Printf("Querying %v\n", queryUrl)
	req, err := http.NewRequest(http.MethodPost, queryUrl, bytes.NewBuffer(serializedDnsQueryString))
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Fatalf("Received non-2XX status code from %v: %v", hostname, string(bodyBytes))
	}

	// For ODoH do some pre-processing before passing it on
	if useODoH {
		// bodyBytes is encrypted response data which needs to be decrypted
		obliviousDNSResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)
		if err != nil {
			log.Fatal(err)
		}
		decryptedAnswerBytes, err := odohQueryContext.OpenAnswer(obliviousDNSResponse)
		if err != nil {
			log.Fatal(err)
		}
		bodyBytes = decryptedAnswerBytes
	}

	dnsBytes, err := common.ParseDnsResponse(bodyBytes)

	return dnsBytes, nil
}

func SerializedDNSSECQuery(c *cli.Context) error {
	domainName := dns.Fqdn(c.String("domain"))
	dnsTypeString := c.String("dnstype")
	dnsTargetServer := c.String("target")
	dnssec := c.Bool("dnssec")
	useODoH := c.Bool("odoh")
	dnsType := common.DnsQueryStringToType(dnsTypeString)

	anchor := CheckAndValidateDNSRootAnchors()

	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(domainName, dnsType)
	if dnssec {
		dnsQuery.SetEdns0(4096, true)
	}

	packedDnsQuery, err := dnsQuery.Pack()
	if err != nil {
		return err
	}

	contentType := common.DOH_CONTENT_TYPE
	var odohQueryContext odoh.QueryContext
	var odohMessageQuery odoh.ObliviousDNSMessage

	if useODoH {
		fmt.Printf("Retriveing ODoH Target configuration ...\n")
		odohTargetConfig := RetrieveODoHConfig(dnsTargetServer)
		odohQuery := odoh.CreateObliviousDNSQuery(packedDnsQuery, 0)
		odohMessageQuery, odohQueryContext, err = odohTargetConfig.Contents.EncryptQuery(odohQuery)
		if err != nil {
			return err
		}
		packedDnsQuery = odohMessageQuery.Marshal()
		contentType = common.ODOH_CONTENT_TYPE
	}
	start := time.Now()

	response, err := queryDNS(dnsTargetServer, packedDnsQuery, contentType, useODoH, &odohQueryContext)
	if err != nil {
		fmt.Println("Failed with a response here.")
		return err
	}

	end := time.Now()

	fmt.Printf("%v\n", response)

	vStart := time.Now()
	ok, err := ValidateDNSSECSignature(response, domainName, &anchor)
	if ok {
		fmt.Printf("%v Verified DNSSEC Chain successfully. %v\n", "\033[32m", "\033[0m")
	} else {
		if err != nil {
			fmt.Printf("%v Failed DNSSEC Verification. %v\n", "\033[31m", "\033[0m")
			fmt.Printf("Error: %v\n", err)
		} else {
			fmt.Printf("%v Domain is not DNSSEC Enabled. %v\n", "\033[33m", "\033[0m")
		}
	}
	vEnd := time.Now()
	fmt.Printf("Network Time: %v\n", end.Sub(start).String())
	fmt.Printf("Verification Time: %v\n", vEnd.Sub(vStart).String())

	return nil
}
