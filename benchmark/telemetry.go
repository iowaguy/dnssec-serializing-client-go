package benchmark

import (
	"golang.org/x/net/idna"
	"strconv"
	"time"
)

type BenchQuery struct {
	Query          string
	QueryType      uint16
	EncryptionTime time.Duration
}

type Telemetry struct {
	Protocol                string
	Query                   string
	QueryType               uint16
	VerificationStatus      bool
	StartTime               time.Time
	EndTime                 time.Time
	NetworkTime             time.Duration
	VerificationTime        time.Duration
	QuerySizeBytesOnWire    int
	ResponseSizeBytesOnWire int
	DNSResponseSizeBytes    int

	// For ODoH
	EncryptionTime time.Duration
	DecryptionTime time.Duration
}

func TelemetryHeader() []string {
	header := make([]string, 0)

	header = append(header, "Protocol")
	header = append(header, "Query")
	header = append(header, "QueryType")
	header = append(header, "VerificationStatus")
	header = append(header, "NetworkTime")
	header = append(header, "VerificationTime")
	header = append(header, "QuerySizeOnWire")
	header = append(header, "ResponseSizeOnWire")
	header = append(header, "ResponseSize")
	header = append(header, "EncryptionTime")
	header = append(header, "DecryptionTime")

	return header
}

func (t *Telemetry) Serialize() []string {
	res := make([]string, 0)

	queryUnicode, _ := idna.ToUnicode(t.Query)

	res = append(res, t.Protocol)
	res = append(res, queryUnicode)
	res = append(res, strconv.FormatUint(uint64(t.QueryType), 10))
	res = append(res, strconv.FormatBool(t.VerificationStatus))
	res = append(res, t.NetworkTime.String())
	res = append(res, t.VerificationTime.String())
	res = append(res, strconv.FormatInt(int64(t.QuerySizeBytesOnWire), 10))
	res = append(res, strconv.FormatInt(int64(t.ResponseSizeBytesOnWire), 10))
	res = append(res, strconv.FormatInt(int64(t.DNSResponseSizeBytes), 10))
	res = append(res, t.EncryptionTime.String())
	res = append(res, t.DecryptionTime.String())

	return res
}
