package commands

import (
	"github.com/cloudflare/odoh-client-go/benchmark"
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
			cli.BoolFlag{
				Name: "odoh",
			},
		},
	},
	{
		Name:  "bench",
		Usage: "Benchmark utility to run DNS queries using multiple protocols",
		Subcommands: []cli.Command{
			{
				Name:   "doh",
				Usage:  "Run benchmarks with DoH queries to the resolver",
				Action: benchmark.BenchmarkDoHWithDNSSEC,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:     "resolver",
						Required: false,
						Value:    "doh.cloudflare-dns.com",
					},
					cli.StringFlag{
						Name:     "input, i",
						Required: true,
					},
					cli.StringFlag{
						Name:     "output, o",
						Value:    "results",
						Required: false,
					},
					cli.StringFlag{
						Name:     "type, t",
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
					cli.IntFlag{
						Name:     "rate, r",
						Usage:    "The number of requests to send to the resolver",
						Required: false,
						Value:    10,
					},
					cli.BoolFlag{
						Name:     "transport-secure",
						Required: false,
					},
				},
			},
			{
				Name:   "do53",
				Usage:  "Run benchmark with Do53 queries to the resolver",
				Action: benchmark.BenchmarkDo53WithDNSSEC,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:     "input, i",
						Required: true,
					},
					cli.StringFlag{
						Name:     "output, o",
						Value:    "results",
						Required: false,
					},
					cli.IntFlag{
						Name:     "rate, r",
						Usage:    "The number of requests to send to the resolver",
						Required: false,
						Value:    10,
					},
					cli.StringFlag{
						Name:     "type, t",
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
				},
			},
			{
				Name:   "odoh",
				Usage:  "Run benchmarks with ODoH queries to the resolver",
				Action: benchmark.BenchmarkODoHWithDNSSEC,
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:     "input, i",
						Required: true,
					},
					cli.StringFlag{
						Name:     "output, o",
						Value:    "results",
						Required: false,
					},
					cli.IntFlag{
						Name:     "rate, r",
						Usage:    "The number of requests to send to the resolver",
						Required: false,
						Value:    10,
					},
					cli.StringFlag{
						Name:     "type, t",
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
					cli.BoolFlag{
						Name:     "transport-secure",
						Required: false,
					},
					cli.StringFlag{
						Name:     "target",
						Required: false,
						Value:    "odoh.cloudflare-dns.com",
					},
					cli.StringFlag{
						Name:     "proxy",
						Required: true,
						Usage:    "The hostname of the proxy to route the Oblivious DoH queries through",
					},
				},
			},
		},
	},
}
