package commands

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cloudflare/odoh-client-go/common"
	"go.mozilla.org/pkcs7"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"time"
)

func DownloadFile(urlLocation string, outputFilePath string) {
	client := http.Client{Timeout: 30 * time.Second}

	f, err := os.Create(outputFilePath)
	if err != nil {
		log.Fatalf("unable to create file %v\nError: %v\n", outputFilePath, err)
	}
	defer f.Close()

	fmt.Printf("Downloading: %v\n", urlLocation)
	resp, err := client.Get(urlLocation)
	if err != nil {
		log.Fatalf("unable to download the resource from IANA [%v]. %v\n", urlLocation, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("receive invalid response code from server during bootstrap. Try again. [HTTP %v]\n", resp.StatusCode)
	}

	_, err = io.Copy(f, resp.Body)
	if err != nil {
		log.Fatalf("unable to write output into the corresponding file: %v.Error %v\n", outputFilePath, err)
	}
}

func ReadCheckSum(filePath string) map[string]string {
	f, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("unable to read checksum file at %v.Error: %v\n", filePath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	res := make(map[string]string)

	for scanner.Scan() {
		line := scanner.Text()
		elements := strings.Split(line, common.ChecksumDelimiter)
		res[strings.TrimSpace(elements[1])] = strings.TrimSpace(elements[0])
	}

	return res
}

func CheckDownloadIntegrity(filePath string, providedCheckSumHex string) (string, error) {
	buffer, err := os.ReadFile(filePath)
	if err != nil {
		log.Fatalf("unable to open file %v to read. Error: %v\n", filePath, err)
	}

	checksum := sha256.Sum256(buffer)
	computedCheckSumHex := hex.EncodeToString(checksum[:])

	if computedCheckSumHex == providedCheckSumHex {
		return computedCheckSumHex, nil
	}
	return computedCheckSumHex, errors.New("mismatched checksum")
}

func CheckAndValidateDNSRootAnchors() TrustAnchor {
	directoryPath := common.RootAnchorsLocation

	// Create a directory for root anchors if it doesn't exist already.
	if _, err := os.Stat(directoryPath); errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(directoryPath, os.ModePerm)
		if err != nil {
			log.Fatalf("unable to create the directory to bootstrap root anchors: %v.\nError: %v\n", directoryPath, err)
		}
	}

	// Check for the filenames existence or fetch them as necessary.
	rootAnchorsAndLocations := common.ReturnRootAnchorFileAndLocationInformation()

	for fileName, fetchLocation := range rootAnchorsAndLocations {
		filePath := path.Join(directoryPath, fileName)
		if _, err := os.Stat(filePath); errors.Is(err, os.ErrNotExist) {
			DownloadFile(fetchLocation, filePath)
		}
	}

	// Proceed with verification, previous state mutated to local location information.
	_integrityTimerStart := time.Now()
	fileChecksums := ReadCheckSum(path.Join(directoryPath, common.ChecksumFile))

	for fileName, checkSumHexString := range fileChecksums {
		filePath := path.Join(directoryPath, fileName)
		computedChecksum, err := CheckDownloadIntegrity(filePath, checkSumHexString)
		if err != nil {
			log.Fatalf("unable to verify integrity of %v [%v != %v]\n", filePath, checkSumHexString, computedChecksum)
		}
	}
	_integrityTimerEnd := time.Now()
	log.Printf("\tTime to verify checksum integrity: %v\n", _integrityTimerEnd.Sub(_integrityTimerStart))

	// Downloaded files have the correct integrity, now proceed to verifying the signatures themselves in trust anchors.
	_signatureVerificationStart := time.Now()
	certPEMBytes, err := os.ReadFile(path.Join(directoryPath, common.ICANNBundleFile))
	if err != nil {
		log.Fatalf("unable to read %v file", common.ICANNBundleFile)
	}
	certDERBytesBlock, _ := pem.Decode(certPEMBytes)
	cert, err := x509.ParseCertificate(certDERBytesBlock.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	sigBytes, err := os.ReadFile(path.Join(directoryPath, common.RootAnchorSignatureFile))
	if err != nil {
		log.Fatalf("unable to read %v file", common.RootAnchorSignatureFile)
	}
	p7, err := pkcs7.Parse(sigBytes)

	// Retrieve the trust anchor and complete bootstrapping procedure
	anchorsBytes, err := os.ReadFile(path.Join(directoryPath, common.RootAnchorsFile))
	if err != nil {
		log.Fatalf("unable to read %v file", common.RootAnchorsFile)
	}

	p7.Content = anchorsBytes
	err = p7.VerifyWithChain(pool)
	if err != nil {
		log.Fatalf("signature verification of the message failed. Invalid root anchor signatures.")
	}
	_signatureVerificationEnd := time.Now()
	log.Printf("\tTime to verify root anchor signatures: %v\n", _signatureVerificationEnd.Sub(_signatureVerificationStart))

	anchor := ParseAsTrustAnchor(anchorsBytes)
	return anchor
}
