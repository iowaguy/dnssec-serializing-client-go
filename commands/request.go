package commands

import (
	"fmt"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/cloudflare/odoh-client-go/network"
	"github.com/cloudflare/odoh-client-go/verification"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"github.com/urfave/cli/v2"
	"golang.org/x/net/idna"
	"net/url"
	"time"
)

func SerializedDNSSECQuery(c *cli.Context) error {
	domainNameString := dns.Fqdn(c.String("domain"))
	dnsTypeString := c.String("dnstype")
	dnsTargetServer := c.String("target")
	dnssec := c.Bool("dnssec")
	useODoH := c.Bool("odoh")
	proxyHostname := c.String("proxy")

	dnsType := common.DnsQueryStringToType(dnsTypeString)

	anchor := bootstrap.CheckAndValidateDNSRootAnchors()

	domainName, _ := idna.ToASCII(domainNameString)

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
	var proxyURL *url.URL

	if useODoH {
		fmt.Printf("Retriveing ODoH Target configuration ...\n")
		odohTargetConfig := network.RetrieveODoHConfig(dnsTargetServer)

		if proxyHostname != "" {
			// Make the query instead to a proxy
			proxyURL = common.BuildODoHURL(proxyHostname, dnsTargetServer)
		}

		odohQuery := odoh.CreateObliviousDNSQuery(packedDnsQuery, 0)
		odohMessageQuery, odohQueryContext, err = odohTargetConfig.Contents.EncryptQuery(odohQuery)
		if err != nil {
			return err
		}
		packedDnsQuery = odohMessageQuery.Marshal()
		contentType = common.ODOH_CONTENT_TYPE
	}
	start := time.Now()

	response, _, err := network.QueryDNS(dnsTargetServer, packedDnsQuery, contentType, useODoH, &odohQueryContext, proxyURL)
	if err != nil {
		fmt.Println("Failed with a response here.")
		return err
	}

	end := time.Now()

	fmt.Printf("%v\n", response)

	vStart := time.Now()
	ok, err := verification.ValidateDNSSECSignature(response, domainName, &anchor)
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
