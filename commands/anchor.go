package commands

import (
	"encoding/xml"
	"errors"
	"github.com/miekg/dns"
	"log"
	"time"
)

type KeyDigest struct {
	ID         string     `xml:"id,attr"`
	ValidFrom  *time.Time `xml:"validFrom,attr"`
	ValidUntil *time.Time `xml:"validUntil,attr"`
	KeyTag     uint16     `xml:"KeyTag"`
	Algorithm  uint8      `xml:"Algorithm"`
	DigestType uint8      `xml:"DigestType"`
	Digest     string     `xml:"Digest"`
}

type TrustAnchor struct {
	Name    xml.Name    `xml:"TrustAnchor"`
	ID      string      `xml:"id,attr"`
	Source  string      `xml:"source,attr"`
	Zone    string      `xml:"Zone"`
	Digests []KeyDigest `xml:"KeyDigest"`
}

func (k *KeyDigest) Verify() error {
	now := time.Now()
	if now.Before(*k.ValidFrom) || k.ValidUntil != nil && now.After(*k.ValidUntil) {
		return errors.New("key digest is invalid due to validity expiry")
	}
	return nil
}

func (t *TrustAnchor) ToDS() []dns.DS {
	res := make([]dns.DS, 0)
	for _, digest := range t.Digests {
		err := digest.Verify()
		if err != nil {
			continue
		}
		dsRecord := dns.DS{
			Hdr: dns.RR_Header{
				Name:  t.Zone,
				Class: dns.ClassINET,
			},
			KeyTag:     digest.KeyTag,
			Algorithm:  digest.Algorithm,
			DigestType: digest.DigestType,
			Digest:     digest.Digest,
		}
		res = append(res, dsRecord)
	}
	return res
}

func ParseAsTrustAnchor(xmlBytes []byte) TrustAnchor {
	t := TrustAnchor{}
	err := xml.Unmarshal(xmlBytes, &t)
	if err != nil {
		log.Fatalf("unable to unmarshal root-anchors to TrustAnchor.Error: %v\n", err)
	}
	return t
}
