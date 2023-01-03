package verification

import (
	"errors"
	"fmt"
	"github.com/cloudflare/odoh-client-go/bootstrap"
	"github.com/miekg/dns"
	"strings"
)

func convertSignatureToRrsig(signature dns.Signature, signatureTypeCovered uint16, signerName string) dns.RRSIG {
	headerSignerName := signerName
	if signatureTypeCovered == dns.TypeDS {
		fqdnSegments := strings.Split(signerName, ".")
		signerName = dns.Fqdn(strings.Join(fqdnSegments[1:], "."))
	}
	r := dns.RRSIG{
		Hdr: dns.RR_Header{
			Rrtype:   dns.TypeRRSIG,
			Class:    dns.ClassINET,
			Ttl:      signature.Ttl,
			Rdlength: signature.Length,
			Name:     headerSignerName,
		},
		TypeCovered: signatureTypeCovered,
		Algorithm:   signature.Algorithm,
		Labels:      signature.Labels,
		OrigTtl:     signature.Ttl,
		Expiration:  signature.Expires,
		Inception:   signature.Begins,
		KeyTag:      signature.Key_tag,
		SignerName:  signerName,
		Signature:   string(signature.Signature),
	}
	//fmt.Printf("Signature: %v\n", r.String())
	return r
}

func DNSKEYsToRR(keys []dns.DNSKEY) []dns.RR {
	r := make([]dns.RR, 0)
	for _, k := range keys {
		rr, err := dns.NewRR(k.String())
		if err != nil {
			fmt.Println("Failed to create RR from DNSKEY.")
		}
		r = append(r, rr)
	}
	return r
}

func SerialDStoDSRR(dsRecords []dns.SerialDS, signerName string) []dns.RR {
	r := make([]dns.RR, 0)
	for _, dsRecord := range dsRecords {
		record := new(dns.DS)
		record.Algorithm = dsRecord.Algorithm
		record.KeyTag = dsRecord.Key_tag
		record.Digest = string(dsRecord.Digest)
		record.DigestType = dsRecord.Digest_type
		record.Hdr.Rrtype = dns.TypeDS
		record.Hdr.Class = dns.ClassINET
		record.Hdr.Name = signerName
		RRValue, err := dns.NewRR(record.String())
		if err != nil {
			fmt.Println("Failed to convert DS entry to RR")
		}
		r = append(r, RRValue)
	}
	return r
}

func verifyDNSSECProofChain(chain *dns.DNSSECProof, query string, anchor *bootstrap.TrustAnchor) (bool, error) {
	// Split query into segments
	segments := strings.Split(dns.Fqdn(query), ".")
	numSegments := len(segments)
	// Initial state
	initialKeyTag := chain.Initial_key_tag
	if initialKeyTag != 0 {
		// For v1. Use 0 for denoting Root KSK
		return false, errors.New(fmt.Sprintf("failed due to invalid initial_key_tag state."))
	}
	// Transition to the ENTERING state
	isParentTheSigner, parentSignerIndex := false, -1
	for i := 0; i < int(chain.Num_zones); i++ {
		zone := chain.Zones[i]
		segmentStart := numSegments - 1 - i
		if isParentTheSigner {
			segmentStart = numSegments - 1 - parentSignerIndex
		}
		zoneSignerNameBuffer := segments[segmentStart:numSegments]
		signerName := dns.Fqdn(strings.Join(zoneSignerNameBuffer, "."))
		zoneKeySignature := convertSignatureToRrsig(zone.Entry.Key_sig, dns.TypeDNSKEY, signerName)
		dnsKeys := make([]dns.DNSKEY, 0)
		keyLookupMap := make(map[uint16]*dns.DNSKEY)
		for _, key := range zone.Entry.Keys {
			dnsKey := new(dns.DNSKEY)

			dnsKey.Protocol = key.Protocol
			dnsKey.Algorithm = key.Algorithm
			dnsKey.PublicKey = string(key.Public_key) // Looks like the PK is []byte() type casted from String
			dnsKey.Flags = key.Flags
			dnsKey.Hdr.Rrtype = dns.TypeDNSKEY
			dnsKey.Hdr.Class = dns.ClassINET
			dnsKey.Hdr.Name = signerName
			dnsKeys = append(dnsKeys, *dnsKey)
			keyLookupMap[dnsKey.KeyTag()] = dnsKey
		}
		err := zoneKeySignature.Verify(keyLookupMap[zoneKeySignature.KeyTag], DNSKEYsToRR(dnsKeys))
		if err != nil {
			fmt.Printf("Verification err: %v\n", err)
			return false, err
		}
		if signerName == "." {
			// If this is the root, also verify the DS information of the keys from the DNSKEYs through Root Anchors
			expectedRootDSRecords := anchor.ToDS()
			foundRootDSRecords := make([]dns.DS, 0)
			for _, key := range dnsKeys {
				if key.Flags&(dns.SEP|dns.ZONE) != (dns.SEP | dns.ZONE) {
					continue
				}
				ds := key.ToDS(dns.SHA256)
				foundRootDSRecords = append(foundRootDSRecords, *ds)
			}
			if len(foundRootDSRecords) == len(expectedRootDSRecords) {
				res := make(map[string]bool)
				mismatch := false
				for _, ds := range expectedRootDSRecords {
					res[strings.ToLower(ds.Digest)] = true
				}
				for _, resolverReturnedDS := range foundRootDSRecords {
					if _, ok := res[strings.ToLower(resolverReturnedDS.Digest)]; !ok {
						mismatch = true
					}
				}
				if mismatch {
					fmt.Printf("Expected root values do not match root anchors.\n")
					return false, errors.New("expected root values do not match root anchors\n")
				}
			}
		}

		if zone.Exit.Num_ds > 0 {
			zoneSignerNameBuffer = segments[numSegments-i-2 : numSegments]
			signerName = dns.Fqdn(strings.Join(zoneSignerNameBuffer, "."))
			dsSignature := convertSignatureToRrsig(zone.Exit.Rrsig, uint16(zone.Exit.Rrtype), signerName)
			dsRR := SerialDStoDSRR(zone.Exit.Ds_records, signerName)
			err = dsSignature.Verify(keyLookupMap[dsSignature.KeyTag], dsRR)
			if err != nil {
				fmt.Printf("DS Verification err: %v\n", err)
				return false, err
			}
		} else {
			// This could be a final record. Check that it is.
			if i == int(chain.Num_zones)-1 {
				resolvedRecords := zone.Exit.Rrs
				rrType := zone.Exit.Rrtype
				resolvedRecordSignature := convertSignatureToRrsig(zone.Exit.Rrsig, uint16(rrType), query)
				if _, ok := keyLookupMap[resolvedRecordSignature.KeyTag]; ok {
					signingKey := keyLookupMap[resolvedRecordSignature.KeyTag]
					if isParentTheSigner {
						resolvedRecordSignature.SignerName = signerName
					}
					err := resolvedRecordSignature.Verify(signingKey, resolvedRecords)
					if err != nil {
						fmt.Printf("Failed to verify records\n")
						return false, err
					}
				} else {
					fmt.Printf("Key not found!\n")
					return false, err
				}
			}
			// If it is not a final record but contains only the information of the next child segment in the chain
			// It's likely that it is signed by the parent and needs to be verified.
			if !isParentTheSigner {
				isParentTheSigner = true
				parentSignerIndex = i
			}
		}
	}
	return true, nil
}

func ValidateDNSSECSignature(msg *dns.Msg, query string, anchor *bootstrap.TrustAnchor) (bool, error) {
	if len(msg.Extra) > 0 {
		for _, proof := range msg.Extra {
			r, ok := proof.(*dns.DNSSECProof)
			if ok {
				// Obtained a DNSSEC Serialized Proof for verification
				return verifyDNSSECProofChain(r, query, anchor)
			}
			// Fall through for glue records which have Additional Data but aren't DNSSEC proofs
		}
	}
	return false, nil
}
