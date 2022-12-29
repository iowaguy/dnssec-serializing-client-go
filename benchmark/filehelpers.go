package benchmark

import (
	"bufio"
	"errors"
	"log"
	"os"
)

func CheckIfDirectoryExistsOrCreate(dirname string) {
	if _, err := os.Stat(dirname); errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(dirname, os.ModePerm)
		if err != nil {
			log.Fatalf("unable to create the necessary directory. %v\nError: %v\n", dirname, err)
		}
	}
}

func ReadInputQueryList(inputFilePath string) []string {
	// Returns a list of hostnames
	queries := make([]string, 0)
	f, err := os.Open(inputFilePath)
	if err != nil {
		log.Fatalf("unable to open the input file %v for reading.\nError: %v\n", inputFilePath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		query := scanner.Text()
		queries = append(queries, query)
	}

	return queries
}
