package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"time"

	"github.com/cloudflare/odoh-client-go/commands"
)

var (
	Version = "0"
	Tag     = "0"
)

func main() {
	app := cli.App{
		Name:     "client",
		HelpName: "DNS Client with DNSSEC Serialized Responses Command Line Interface",
		Version:  fmt.Sprintf("%v - %v", Version, Tag),
		Commands: commands.Commands,
		Compiled: time.Time{},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
