package commands

import (
	"errors"
	"fmt"
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

func verifyDNSSECProofChain(chain *dns.DNSSECProof, query string) (bool, error) {
	// Split query into segements
	segments := strings.Split(dns.Fqdn(query), ".")
	numSegments := len(segments)
	// Initial state
	initialKeyTag := chain.Initial_key_tag
	if initialKeyTag != 0 {
		// For v1. Use 0 for denoting Root KSK
		return false, errors.New(fmt.Sprintf("failed due to invalid initial_key_tag state."))
	}
	// Transition to the ENTERING state
	fmt.Printf("Number of Zones: %v\n", int(chain.Num_zones))
	for i := 0; i < int(chain.Num_zones); i++ {
		zone := chain.Zones[i]
		zoneSignerNameBuffer := segments[numSegments-1-i : numSegments]
		signerName := dns.Fqdn(strings.Join(zoneSignerNameBuffer, "."))
		zoneKeySignature := convertSignatureToRrsig(zone.Entry.Key_sig, dns.TypeDNSKEY, signerName)
		dnsKeys := make([]dns.DNSKEY, 0)
		keyLookupMap := make(map[uint16]*dns.DNSKEY)
		for _, key := range zone.Entry.Keys {
			dnsKey := new(dns.DNSKEY)
			var dnsKeyBytes []byte
			_, _ = dns.PackRR(&key, dnsKeyBytes, 0, nil, false)

			dnsKey.Protocol = key.Protocol
			dnsKey.Algorithm = key.Algorithm
			dnsKey.PublicKey = string(key.Public_key) // Looks like the PK is []byte() type casted from String
			dnsKey.Flags = key.Flags
			dnsKey.Hdr.Rrtype = dns.TypeDNSKEY
			dnsKey.Hdr.Class = dns.ClassINET
			dnsKey.Hdr.Name = signerName
			dnsKeys = append(dnsKeys, *dnsKey)
			//fmt.Printf("\tInserting Key with ID %v\n", dnsKey.KeyTag())
			keyLookupMap[dnsKey.KeyTag()] = dnsKey
			//fmt.Printf("Zone Entry Key [%v] : %v\n", j, key.String())
			//fmt.Printf("\tKey [%v] PK: %v\n", j, hex.EncodeToString(key.Public_key))
			//fmt.Printf("\tKey [%v] Protocol: %v\n", j, key.Protocol)
			//fmt.Printf("\tKey [%v] Algorithm: %v\n", j, key.Algorithm)
			//fmt.Printf("\tKey [%v] Flags: %v\n", j, key.Flags)
			//fmt.Printf("\tKey [%v] Length: %v\n", j, key.Length)
			//fmt.Printf("\tKey [%v] KeyTag: %v\n", j, dnsKey.KeyTag())
		}
		fmt.Printf("Looking up key for %v\n", zoneKeySignature.KeyTag)
		//KSK := uint16(257)
		err := zoneKeySignature.Verify(keyLookupMap[zoneKeySignature.KeyTag], DNSKEYsToRR(dnsKeys))
		if err == nil {
			fmt.Printf("\tVerified DNSKEY Records at zone %v\n", i)
		} else {
			fmt.Printf("Verification err: %v\n", err)
			return false, err
		}

		if zone.Exit.Num_ds > 0 {
			zoneSignerNameBuffer = segments[numSegments-i-2 : numSegments]
			signerName = dns.Fqdn(strings.Join(zoneSignerNameBuffer, "."))
			dsSignature := convertSignatureToRrsig(zone.Exit.Rrsig, uint16(zone.Exit.Rrtype), signerName)
			dsRR := SerialDStoDSRR(zone.Exit.Ds_records, signerName)
			fmt.Printf("Looking up key for %v\n", dsSignature.KeyTag)
			err = dsSignature.Verify(keyLookupMap[dsSignature.KeyTag], dsRR)
			if err == nil {
				fmt.Printf("\tVerified DS Records delegated to %v\n", signerName)
			} else {
				fmt.Printf("DS Verification err: %v\n", err)
				return false, err
			}
		} else {
			// This could be a final record.
			resolvedRecords := zone.Exit.Rrs
			rrType := zone.Exit.Rrtype
			resolvedRecordSignature := convertSignatureToRrsig(zone.Exit.Rrsig, uint16(rrType), query)
			fmt.Printf("Looking up Key %v\n", resolvedRecordSignature.KeyTag)
			if _, ok := keyLookupMap[resolvedRecordSignature.KeyTag]; ok {
				err := resolvedRecordSignature.Verify(keyLookupMap[resolvedRecordSignature.KeyTag], resolvedRecords)
				if err == nil {
					fmt.Printf("\t Verified %v Records successfully\n", rrType)
				} else {
					fmt.Printf("Failed to verify records\n")
					return false, err
				}
			} else {
				fmt.Printf("Key not found!\n")
				return false, err
			}
		}
	}
	return true, nil
}

func ValidateDNSSECSignature(msg *dns.Msg, query string) (bool, error) {
	if len(msg.Extra) > 0 {
		for _, proof := range msg.Extra {
			r, ok := proof.(*dns.DNSSECProof)
			if ok {
				// Obtained a DNSSEC Serialized Proof for verification
				return verifyDNSSECProofChain(r, query)
			}
			// Fall through for glue records which have Additional Data but aren't DNSSEC proofs
		}
	}
	return false, nil
}
