package commands

import (
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

func queryDNS(hostname string, serializedDnsQueryString []byte) (response *dns.Msg, err error) {
	client := http.Client{}
	queryUrl := buildDohURL(hostname).String()
	log.Printf("Querying %v\n", queryUrl)
	req, err := http.NewRequest(http.MethodGet, queryUrl, nil)
	if err != nil {
		log.Fatalln(err)
	}

	queries := req.URL.Query()
	encodedString := base64.RawURLEncoding.EncodeToString(serializedDnsQueryString)
	queries.Add("dns", encodedString)
	req.Header.Set("Content-Type", DOH_CONTENT_TYPE)
	req.URL.RawQuery = queries.Encode()

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
	dnsBytes, err := parseDnsResponse(bodyBytes)

	return dnsBytes, nil
}

func SerializedDNSSECQuery(c *cli.Context) error {
	domainName := dns.Fqdn(c.String("domain"))
	dnsTypeString := c.String("dnstype")
	dnsTargetServer := c.String("target")
	dnssec := c.Bool("dnssec")
	dnsType := dnsQueryStringToType(dnsTypeString)

	dnsQuery := new(dns.Msg)
	dnsQuery.SetQuestion(domainName, dnsType)
	if dnssec {
		dnsQuery.SetEdns0(4096, true)
	}
	packedDnsQuery, err := dnsQuery.Pack()
	if err != nil {
		return err
	}
	start := time.Now()

	response, err := queryDNS(dnsTargetServer, packedDnsQuery)
	if err != nil {
		fmt.Println("Failed with a response here.")
		return err
	}

	end := time.Now()

	fmt.Printf("%v\n", response)

	vStart := time.Now()
	ok, err := ValidateDNSSECSignature(response, domainName)
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
