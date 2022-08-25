package commands

import (
	"github.com/urfave/cli"
)

var Commands = []cli.Command{
	{
		Name:   "query",
		Usage:  "An application/dns-message request",
		Action: SerializedDNSSECQuery,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "domain, d",
				Value: "www.cloudflare.com.",
			},
			cli.StringFlag{
				Name:  "dnstype, t",
				Value: "AAAA",
			},
			cli.StringFlag{
				Name:  "target",
				Value: "localhost:8080",
			},
			cli.BoolFlag{
				Name: "dnssec",
			},
		},
	},
}
