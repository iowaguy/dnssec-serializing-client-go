package dns

type ZonePair struct {
	Entry Entering
	Exit  Leaving
}

type DNSSECProof struct {
	Hdr             RR_Header
	Initial_key_tag uint16
	Num_zones       uint8
	Zones           []ZonePair
}

type ZoneRecType uint8

const (
	EnteringType ZoneRecType = 0
	LeavingType              = 1
)

type Signature struct {
	Length     uint16
	Algorithm  uint8
	Labels     uint8
	Ttl        uint32
	Expires    uint32
	Begins     uint32
	Key_tag    uint16
	SignerName string
	Signature  []byte
}

type Key struct {
	Length     uint16
	Flags      uint16
	Protocol   uint8
	Algorithm  uint8
	Public_key []byte
}

type Entering struct {
	Length          uint16
	ZType           ZoneRecType
	Entry_key_index uint8
	Key_sig         Signature
	Num_keys        uint8
	Keys            []Key
}

type SerialDS struct {
	Length      uint16
	Key_tag     uint16
	Algorithm   uint8
	Digest_type uint8
	Digest_len  uint16
	Digest      []byte
}

type RRType uint16

type LeavingRecordType uint8

const (
	LeavingUncommitted LeavingRecordType = 0
	LeavingCNAMEType                     = 1
	LeavingDNAMEType                     = 2
	LeavingDSType                        = 3
	LeavingOtherType                     = 4
)

type Leaving struct {
	Length      uint16
	ZType       ZoneRecType
	Next_name   Name
	Rrtype      RRType
	Rrsig       Signature
	LeavingType LeavingRecordType

	// Used in CNAME and DNAME only
	Name Name

	// Used in DS only
	Num_ds     uint8
	Ds_records []SerialDS

	// Used in "other" only
	Num_rrs uint8
	Rrs     []RR
}
