package network

import (
	"fmt"
	"github.com/cloudflare/odoh-go"
	"io/ioutil"
	"log"
	"net/http"
)

const ConfigEndpoint = "/.well-known/odohconfigs"

func RetrieveODoHConfig(targetURI string) odoh.ObliviousDoHConfig {
	client := http.Client{}
	queryURL := fmt.Sprintf("%v%v", targetURI, ConfigEndpoint)
	req, err := http.NewRequest(http.MethodGet, queryURL, nil)
	if err != nil {
		log.Fatalf("failed to retrive configuration from the Oblivious Target")
	}
	resp, err := client.Do(req)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	config, err := odoh.UnmarshalObliviousDoHConfig(bodyBytes)
	if err != nil {
		log.Fatalf("failed to unmarshal configuration from the Oblivious Target")
	}
	return config
}
