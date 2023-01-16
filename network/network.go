package network

import (
	"bytes"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

func QueryDNS(hostname string, serializedDnsQueryString []byte, contentType string, useODoH bool, odohQueryContext *odoh.QueryContext, proxyHostname *url.URL) (response *dns.Msg, r *common.Reporting, err error) {

	report := common.Reporting{}

	client := http.Client{}
	var queryUrl string
	if useODoH && proxyHostname != nil {
		queryUrl = proxyHostname.String()
	} else {
		queryUrl = common.BuildDohURL(hostname).String()
	}

	report.QuerySizeBytesOnWire = len(serializedDnsQueryString)

	report.StartTime = time.Now()

	req, err := http.NewRequest(http.MethodPost, queryUrl, bytes.NewBuffer(serializedDnsQueryString))
	if err != nil {
		log.Fatalln(err)
	}

	req.Header.Set("Content-Type", contentType)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}

	report.EndTime = time.Now()
	report.NetworkTime = report.EndTime.Sub(report.StartTime)
	report.DecryptionTime = nil

	bodyBytes, err := ioutil.ReadAll(resp.Body)

	report.ResponseSizeBytesOnWire = len(bodyBytes)

	if err != nil {
		log.Fatal(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("Received non-2XX status code from %v: %v", hostname, string(bodyBytes))
	}

	// For ODoH do some pre-processing before passing it on
	if useODoH {
		decryptionStart := time.Now()
		// bodyBytes is encrypted response data which needs to be decrypted
		obliviousDNSResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)
		if err != nil {
			log.Fatal(err)
		}
		decryptedAnswerBytes, err := odohQueryContext.OpenAnswer(obliviousDNSResponse)
		if err != nil {
			log.Fatal(err)
		}
		decryptionEnd := time.Now()
		decryptionTime := decryptionEnd.Sub(decryptionStart)
		report.DecryptionTime = &decryptionTime

		bodyBytes = decryptedAnswerBytes
	}

	dnsBytes, err := common.ParseDnsResponse(bodyBytes)

	report.ResponseSizeBytes = dnsBytes.Len()

	return dnsBytes, &report, nil
}
