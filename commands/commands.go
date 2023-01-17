package commands

import (
	"github.com/cloudflare/odoh-client-go/benchmark"
	"github.com/urfave/cli/v2"
)

var Commands = []*cli.Command{
	{
		Name:   "query",
		Usage:  "An application/dns-message request",
		Action: SerializedDNSSECQuery,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "domain",
				Aliases: []string{"d"},
				Value:   "www.cloudflare.com.",
			},
			&cli.StringFlag{
				Name:    "dnstype",
				Aliases: []string{"p"},
				Value:   "AAAA",
			},
			&cli.StringFlag{
				Name:    "target",
				Aliases: []string{"t"},
				Value:   "localhost:8080",
			},
			&cli.BoolFlag{
				Name: "dnssec",
			},
			&cli.BoolFlag{
				Name: "odoh",
			},
			&cli.StringFlag{
				Name:  "proxy",
				Usage: "Hostname of the proxy server to use to send the odoh query to",
			},
		},
	},
	{
		Name:  "bench",
		Usage: "Benchmark utility to run DNS queries using multiple protocols",
		Subcommands: []*cli.Command{
			{
				Name:   "doh",
				Usage:  "Run benchmarks with DoH queries to the resolver",
				Action: benchmark.BenchmarkDoHWithDNSSEC,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "resolver",
						Required: false,
						Value:    "doh.cloudflare-dns.com",
					},
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Value:    "results",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "type",
						Aliases:  []string{"t"},
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
					&cli.IntFlag{
						Name:     "rate",
						Aliases:  []string{"r"},
						Usage:    "The number of requests to send to the resolver in parallel in a batch",
						Required: false,
						Value:    10,
					},
					&cli.BoolFlag{
						Name: "dnssec",
					},
				},
			},
			{
				Name:   "do53",
				Usage:  "Run benchmark with Do53 queries to the resolver",
				Action: benchmark.BenchmarkDo53WithDNSSEC,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Value:    "results",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "rate",
						Aliases:  []string{"r"},
						Usage:    "The number of requests to send to the resolver",
						Required: false,
						Value:    10,
					},
					&cli.StringFlag{
						Name:     "type",
						Aliases:  []string{"t"},
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
					&cli.StringFlag{
						Name:     "resolver",
						Required: true,
						Usage:    "Enter the hostname or IP address of the resolver",
					},
					&cli.IntFlag{
						Name:     "port",
						Value:    53,
						Required: false,
						Usage:    "Enter the port number to connect to.",
					},
					&cli.BoolFlag{
						Name: "dnssec",
					},
					&cli.BoolFlag{
						Name: "udp",
					},
					&cli.BoolFlag{
						Name: "tcp",
					},
					&cli.BoolFlag{
						Name: "trace",
					},
				},
			},
			{
				Name:   "odoh",
				Usage:  "Run benchmarks with ODoH queries to the resolver",
				Action: benchmark.BenchmarkODoHWithDNSSEC,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Value:    "results",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "rate",
						Aliases:  []string{"r"},
						Usage:    "The number of requests to send to the resolver",
						Required: false,
						Value:    10,
					},
					&cli.StringFlag{
						Name:     "type",
						Aliases:  []string{"t"},
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
					&cli.StringFlag{
						Name:     "target",
						Required: false,
						Value:    "odoh.cloudflare-dns.com",
					},
					&cli.StringFlag{
						Name:     "proxy",
						Required: true,
						Usage:    "The hostname of the proxy to route the Oblivious DoH queries through",
					},
					&cli.BoolFlag{
						Name: "dnssec",
					},
				},
			},
			{
				Name:   "dohot",
				Usage:  "Run benchmarks with DoH queries over a Tor network",
				Action: benchmark.BenchmarkDoHoTWithDNSSEC,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "input",
						Aliases:  []string{"i"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "socks5",
						Value:    "localhost:9050",
						Required: false,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Value:    "results",
						Required: false,
					},
					&cli.IntFlag{
						Name:     "rate",
						Aliases:  []string{"r"},
						Usage:    "The number of requests to send to the resolver",
						Required: false,
						Value:    10,
					},
					&cli.StringFlag{
						Name:     "type",
						Aliases:  []string{"t"},
						Value:    "A",
						Required: false,
						Usage:    "DNS String Query Type (A|AAAA|MX|etc..,)",
					},
					&cli.StringFlag{
						Name:     "target",
						Required: false,
						Value:    "doh.cloudflare-dns.com",
					},
					&cli.BoolFlag{
						Name: "dnssec",
					},
				},
			},
		},
	},
}
