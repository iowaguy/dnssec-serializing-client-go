package common

import (
	"log"
	"net/url"
	"strings"

	"github.com/miekg/dns"
)

// Function for Converting CLI DNS Query Type to the uint16 Datatype
func DnsQueryStringToType(stringType string) uint16 {
	t, ok := dns.StringToType[strings.ToUpper(stringType)]
	if !ok {
		log.Fatalf("unknown query type: \"%v\"", stringType)
	}
	return t
}

func ParseDnsResponse(data []byte) (*dns.Msg, error) {
	msg := &dns.Msg{}
	err := msg.Unpack(data)
	return msg, err
}

func buildURL(s, defaultPath string) *url.URL {
	if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("failed to parse url: %v", err)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultPath
	}
	return u
}

func BuildDohURL(s string) *url.URL {
	return buildURL(s, DOH_DEFAULT_PATH)
}
