package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

type zoneStack []dns.Zone

func (s zoneStack) isEmpty() bool {
	return len(s) == 0
}

func (s zoneStack) push(v dns.Zone) zoneStack {
	return append(s, v)
}

func (s zoneStack) pop() (zoneStack, dns.Zone) {
	if s.isEmpty() {
		return s, dns.Zone{}
	} else {
		l := len(s)
		return s[:l-1], s[l-1]
	}
}

func (s zoneStack) peek() dns.Zone {
	if s.isEmpty() {
		return dns.Zone{}
	} else {
		l := len(s)
		return s[l-1]
	}
}

func (s zoneStack) String() string {
	builder := strings.Builder{}

	for _, z := range s {
		builder.WriteString(z.String())
	}
	return builder.String()
}

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

// Assume that the zones are returned in order
func getRoot(chain *dns.Chain) (*dns.Zone, error) {
	if len(chain.Zones) == 0 {
		return nil, errors.New(fmt.Sprintf("no zones included in proof chain."))
	}

	return &chain.Zones[0], nil
}

func isRoot(zone *dns.Zone) bool {
	if zone == nil {
		return false
	}
	return zone.Name == "."
}

// Assumes the key argument is supposed to be the root key. If it is not the root key, it will
// fail the same way as if the root key was incorrect.
func areRootKeysTrusted(dnsKeys []*dns.DNSKEY, anchor *TrustAnchor) (bool, error) {
	// If this is the root, also verify the DS information of the keys from the DNSKEYs through Root Anchors
	return areKSKsTrusted(dnsKeys, anchor.ToDS())
}

func areKSKsTrusted(dnsKeys []*dns.DNSKEY, dsSet []dns.DS) (bool, error) {
	calculatedDSRecords := make([]dns.DS, 0, len(dnsKeys))
	for _, key := range dnsKeys {
		if !isKSK(key) {
			continue
		}
		ds := key.ToDS(dns.SHA256)
		calculatedDSRecords = append(calculatedDSRecords, *ds)
	}
	if len(calculatedDSRecords) == len(dsSet) {
		res := make(map[string]bool)
		mismatch := false
		for _, ds := range dsSet {
			res[strings.ToLower(ds.Digest)] = true
		}
		for _, resolverReturnedDS := range calculatedDSRecords {
			if _, ok := res[strings.ToLower(resolverReturnedDS.Digest)]; !ok {
				mismatch = true
			}
		}
		if mismatch {
			fmt.Printf("Expected root values do not match root anchors.\n")
			return false, errors.New("expected root values do not match root anchors\n")
		}
	}
	return true, nil
}

func isZSK(key *dns.DNSKEY) bool {
	return int(key.Flags)&dns.ZONE == dns.ZONE
}

// Check if the provided key is a key-signing key
func isKSK(key *dns.DNSKEY) bool {
	// is Secure Entry Point
	isSEP := int(key.Flags)&dns.SEP == dns.SEP

	return isZSK(key) && isSEP
}

func separateKeyTypes(keys []*dns.DNSKEY) (ksks []*dns.DNSKEY, zsks []*dns.DNSKEY) {
	// collect KSKs in zone
	ksks = make([]*dns.DNSKEY, 0)
	zsks = make([]*dns.DNSKEY, 0)
	for _, key := range keys {
		if isKSK(key) {
			ksks = append(ksks, key)
		} else if isZSK(key) {
			zsks = append(zsks, key)
		}
	}

	return ksks, zsks
}

// Check that for each signature on the RR set, it is verified by at least one key
func checkSigs(sigs []dns.RRSIG, keys []*dns.DNSKEY, rrs []dns.RR) bool {
	for _, sig := range sigs {
		sigVerified := false
		for _, key := range keys {
			if key.KeyTag() == sig.KeyTag {
				err := sig.Verify(key, rrs)
				if err == nil {
					sigVerified = true
					break
				}
			}
		}
		if !sigVerified {
			// this means none of the keys could verify this signature
			return false
		}
	}

	return true
}

func verifyDNSSECProofChain(chain *dns.Chain, target string, anchor *TrustAnchor) (bool, error) {
	trustedKeys := make(map[dns.Name][]*dns.DNSKEY)
	visited := zoneStack{}
	// Initial state
	if chain.InitialKeyTag != 0 {
		// For v1. Use 0 for denoting Root KSK
		return false, errors.New(fmt.Sprintf("failed due to invalid initial_key_tag state."))
	}

	if len(chain.Zones) == 0 {
		return false, errors.New(fmt.Sprintf("no zones included in proof chain."))
	}

	for _, currentZone := range chain.Zones {
		if visited.isEmpty() && !isRoot(&currentZone) {
			return false, errors.New(fmt.Sprintf("the first zone is not the root but it should be"))
		}

		// Check that current_zone.prev_name == visited.peek().name, or matches according to wildcard rules.
		// TODO need to check that the strings match according to the wildcard rules
		if !isRoot(&currentZone) && currentZone.PreviousName != visited.peek().Name {
			return false, errors.New(fmt.Sprintf("proof is incorrect, zones missing or are in the wrong order"))
		}

		keyRRs := make([]*dns.DNSKEY, 0, len(currentZone.Keys))
		for _, key := range currentZone.Keys {
			keyRRs = append(keyRRs, dns.Copy(&key).(*dns.DNSKEY))
		}
		ksks, zsks := separateKeyTypes(keyRRs)

		// check that the root keys are trusted
		if isRoot(&currentZone) {
			areTrusted, err := areRootKeysTrusted(ksks, anchor)
			if err != nil {
				return false, err
			}
			if areTrusted {
				trustedKeys[currentZone.Name] = ksks
			}
		}

		_, parentZSKs := separateKeyTypes(trustedKeys[currentZone.PreviousName])

		// This block is for handling the case where a child zone is signed by its parent's key.
		// We know that a zone did not use it's own keys if it has no DS records.
		if !isRoot(&currentZone) && len(currentZone.DSSet) == 0 {
			// If the current_zone has no delegations and is not the root, but has a
			// non-empty set of KSKs, fail.
			if len(ksks) != 0 {
				return false, errors.New(fmt.Sprintf("If there are keys, there should be delegations."))
			}

			// If the current zone does not have any keys or DSes then it must have leaves and leaf signatures.
			if len(currentZone.Leaves) == 0 || len(currentZone.LeavesSigs) == 0 {
				return false, errors.New(fmt.Sprintf("If there are no keys and no delegations, there should be leaves and leaves signatures."))
			}

			for _, leafSig := range currentZone.LeavesSigs {
				// If the current zone does not have it's own keys, we must have seen
				// the keys when we traversed SignerName already.
				if _, ok := trustedKeys[dns.Name(leafSig.SignerName)]; !ok {
					return false, errors.New(fmt.Sprintf("If there are no keys and no delegations, we should have seen the SignerName's (%s) key already.", leafSig.SignerName))
				}
			}

			// At this point we will have already failed if the current zone has no LeavesSigs
			trustedKeys[currentZone.Name] = trustedKeys[dns.Name(currentZone.LeavesSigs[0].SignerName)]
		} else {
			// convert slice of pointers to slice of structs
			dsRRs := make([]dns.RR, 0, len(currentZone.DSSet))
			for _, ds := range currentZone.DSSet {
				dsRRs = append(dsRRs, dns.Copy(&ds))
			}

			// Check that DSSig signatures verify
			sigVerified := checkSigs(currentZone.DSSigs, parentZSKs, dsRRs)

			// one of the parents' ZSKs should have been used to sign the current zone's DS
			if !sigVerified {
				return false, errors.New(fmt.Sprintf("the RRSIG DS for %s could not be verified", currentZone.Name))
			}

			// check if the KSKs are trusted (against the DSes)
			trusted, err := areKSKsTrusted(ksks, currentZone.DSSet)
			if err != nil {
				return false, err
			}

			if !trusted {
				return false, errors.New(fmt.Sprintf("the KSKs of the zone %s could not be verified against the DS records", currentZone.Name))
			}

			// add trusted KSKs to trust store for current zone---there should be no other
			// trusted keys for the current zone at this point
			trustedKeys[currentZone.Name] = ksks
		}

		// convert slice of pointers to slice of structs
		currentZoneKeys := make([]dns.RR, 0, len(currentZone.Keys))
		for _, key := range currentZone.Keys {
			currentZoneKeys = append(currentZoneKeys, dns.Copy(&key))
		}

		// check current zone's key signatures against the already trusted keys
		// for this zone. There must be exactly one key that verifies each signature
		sigVerified := checkSigs(currentZone.KeySigs, trustedKeys[currentZone.Name], currentZoneKeys)
		if !sigVerified {
			return false, errors.New(fmt.Sprintf("the signature of zone %s's keys could not be verified", currentZone.Name))
		} else {
			// add the ZSKs of the current zone to the trust store, the KSKs are already in there
			for _, zsk := range zsks {
				trustedKeys[currentZone.Name] = append(trustedKeys[currentZone.Name], zsk)
			}
		}

		if !isZSK(&currentZone.Keys[currentZone.ZSKIndex]) {
			return false, errors.New(fmt.Sprintf("ZSK index of zone %s does not point to a ZSK", currentZone.Name))
		}

		if len(currentZone.Leaves) > 0 {
			// convert slice of pointers to slice of structs
			currentZoneLeaves := make([]dns.RR, 0, len(currentZone.Leaves))
			for _, leaf := range currentZone.Leaves {
				currentZoneLeaves = append(currentZoneLeaves, leaf)
			}
			sigVerified := checkSigs(currentZone.LeavesSigs, trustedKeys[currentZone.Name], currentZoneLeaves)
			if !sigVerified {
				return false, errors.New(fmt.Sprintf("the signature of zone %s's leaves could not be verified", currentZone.Name))
			}

			hasCNAME := false
			for _, leaf := range currentZone.Leaves {
				switch l := leaf.(type) {
				case *dns.CNAME:
					hasCNAME = true
					if currentZone.Name.String() == target {
						target = l.Target
						for {
							if dns.IsSubDomain(visited.peek().Name.String(), target) {
								break
							}
							visited.pop()
						}
					} else {
						return false, errors.New(fmt.Sprintf("a non-leaf zone %s contains a CNAME", currentZone.Name))
					}
					visited = visited.push(currentZone)
					break
				case *dns.DNAME:
					// replace the portion of target matching current_zone.name with dname.target
					labelsInCommon := dns.CompareDomainName(currentZone.Name.String(), target)
					s := dns.SplitDomainName(target)
					oldSuffix := s[len(s)-labelsInCommon:]
					target = strings.Replace(target, dns.Fqdn(strings.Join(oldSuffix, ".")), l.Target, 1)

					// pop zones off of visited until the new target is within the topmost zone.
					for {
						if dns.IsSubDomain(visited.peek().Name.String(), target) {
							break
						}
						visited.pop()
					}
				case *dns.NSEC:
					return true, errors.New(fmt.Sprintf("found an NSEC"))
				case *dns.NSEC3:
					return true, errors.New(fmt.Sprintf("found an NSEC3"))
				}
			}

			if !hasCNAME && currentZone.Name.String() == target {
				return true, nil
			}
		} else {
			visited = visited.push(currentZone)
		}
	}
	return false, nil
}

func ValidateDNSSECSignature(msg *dns.Msg, query string, anchor *TrustAnchor) (bool, error) {
	if len(msg.Extra) > 0 {
		for _, proof := range msg.Extra {
			r, ok := proof.(*dns.Chain)
			if ok {
				// Obtained a DNSSEC Serialized Proof for verification
				return verifyDNSSECProofChain(r, query, anchor)
			}
			// Fall through for glue records which have Additional Data but aren't DNSSEC proofs
		}
	}
	return false, nil
}
