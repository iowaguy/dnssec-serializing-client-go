package benchmark

import (
	"fmt"
	"github.com/cloudflare/odoh-client-go/common"
	"github.com/urfave/cli"
)

func BenchmarkDoHWithDNSSEC(c *cli.Context) error {
	inputFile := c.String("input")
	outputDir := c.String("output")
	requestRate := c.Int("rate")
	dnsTypeString := c.String("type")
	resolverHostname := c.String("resolver")
	shouldUseHTTPS := c.Bool("transport-secure")

	dnsType := common.DnsQueryStringToType(dnsTypeString)

	fmt.Printf("%v\n", inputFile)
	fmt.Printf("%v\n", outputDir)
	fmt.Printf("%v\n", requestRate)
	fmt.Printf("%v\n", dnsType)
	fmt.Printf("%v\n", resolverHostname)
	fmt.Printf("%v\n", shouldUseHTTPS)

	CheckIfDirectoryExistsOrCreate(outputDir)
	queries := ReadInputQueryList(inputFile)
	fmt.Printf("Number of queries: %v\n", len(queries))
	fmt.Printf("Number of query request batches: %v @ %v q/exec\n", len(queries)/requestRate+1, requestRate)

	return nil
}

func BenchmarkDo53WithDNSSEC(c *cli.Context) error {
	return nil
}

func BenchmarkODoHWithDNSSEC(c *cli.Context) error {
	return nil
}
