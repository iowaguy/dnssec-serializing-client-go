package commands

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"log"
)

func convertSignatureToRrsig(signature dns.Signature, signatureTypeCovered uint16) dns.RRSIG {
	r := dns.RRSIG{
		Hdr: dns.RR_Header{
			Rrtype:   dns.TypeRRSIG,
			Class:    dns.ClassINET,
			Ttl:      signature.Header().Ttl,
			Rdlength: signature.Header().Rdlength,
		},
		TypeCovered: signatureTypeCovered,
		Algorithm:   signature.Algorithm,
		Labels:      signature.Labels,
		OrigTtl:     signature.Ttl,
		Expiration:  signature.Expires,
		Inception:   signature.Begins,
		KeyTag:      signature.Key_tag,
		Signature:   string(signature.Signature),
	}
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

func SerialDStoDSRR(dsRecords []dns.SerialDS) []dns.RR {
	r := make([]dns.RR, 0)
	for _, dsRecord := range dsRecords {
		record := new(dns.DS)
		record.Algorithm = dsRecord.Algorithm
		record.KeyTag = dsRecord.Key_tag
		record.Digest = string(dsRecord.Digest)
		record.DigestType = dsRecord.Digest_type
		record.Hdr.Rrtype = dns.TypeDS
		record.Hdr.Class = dns.ClassINET
		fmt.Println(record.String())
		RRValue, err := dns.NewRR(record.String())
		if err != nil {
			fmt.Println("Failed to convert DS entry to RR")
		}
		r = append(r, RRValue)
	}
	return r
}

func verifyDNSSECProofChain(chain *dns.DNSSECProof) (bool, error) {
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
		zoneKeySignature := convertSignatureToRrsig(zone.Entry.Key_sig, dns.TypeDNSKEY)
		dnsKeys := make([]dns.DNSKEY, 0)
		keyLookupMap := make(map[uint16]*dns.DNSKEY)
		for _, key := range zone.Entry.Keys {
			dnsKey := new(dns.DNSKEY)
			var dnsKeyBytes []byte
			_, _ = dns.PackRR(&key, dnsKeyBytes, 0, nil, false)
			fmt.Printf("Temp Key: %v\n", dnsKeyBytes)

			dnsKey.Protocol = key.Protocol
			dnsKey.Algorithm = key.Algorithm
			dnsKey.PublicKey = string(key.Public_key) // Looks like the PK is []byte() type casted from String
			dnsKey.Flags = key.Flags
			dnsKey.Hdr.Rrtype = dns.TypeDNSKEY
			dnsKey.Hdr.Class = dns.ClassINET
			dnsKeys = append(dnsKeys, *dnsKey)
			fmt.Printf("\tInserting Key with ID %v\n", dnsKey.KeyTag())
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
		}

		if zone.Exit.Num_ds > 0 {
			dsSignature := convertSignatureToRrsig(zone.Exit.Rrsig, zone.Exit.Rrsig.Header().Rrtype)
			fmt.Printf("Sig: %v\n", dsSignature.String())
			dsRR := SerialDStoDSRR(zone.Exit.Ds_records)
			fmt.Printf("Looking up key for %v\n", dsSignature.KeyTag)
			err = dsSignature.Verify(keyLookupMap[dsSignature.KeyTag], dsRR)
			if err == nil {
				fmt.Printf("\tVerified DS Records")
			} else {
				fmt.Printf("DS Verification err: %v\n", err)
			}
		} else {
			// This could be a final record.
			resolvedRecords := zone.Exit.Rrs
			rrType := zone.Exit.Rrtype
			resolvedRecordSignature := convertSignatureToRrsig(zone.Exit.Rrsig, rrType.Header().Rrtype)
			fmt.Printf("Looking up Key %v\n", resolvedRecordSignature.KeyTag)
			if _, ok := keyLookupMap[resolvedRecordSignature.KeyTag]; ok {
				err := resolvedRecordSignature.Verify(keyLookupMap[resolvedRecordSignature.KeyTag], resolvedRecords)
				if err == nil {
					fmt.Printf("\t Verified %v Records successfully", rrType)
				} else {
					fmt.Printf("Failed to verify records")
				}
			} else {
				fmt.Printf("Key not found!")
			}
		}

		//fmt.Printf("DS : %v\n", zone.Exit.Ds_records)
		//fmt.Printf("%v -->Next--> %v %v\n", i, nextName, zone.Exit)
	}
	return true, nil
}

func ValidateDNSSECSignature(msg *dns.Msg) (bool, error) {
	if len(msg.Extra) > 0 {
		log.Printf("Potentially contains %v DNSSEC Signatures", len(msg.Extra))
		for _, proof := range msg.Extra {
			r, ok := proof.(*dns.DNSSECProof)
			if ok {
				// Obtained a DNSSEC Serialized Proof for verification
				return verifyDNSSECProofChain(r)
			}
			// Fall through for glue records which have Additional Data but aren't DNSSEC proofs
		}
	}
	return false, nil
}
