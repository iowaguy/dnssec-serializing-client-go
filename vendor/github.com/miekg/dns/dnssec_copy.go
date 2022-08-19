package dns

import "strings"

func (rr *ZonePair) copy() RR {
	return copyZonePair(rr)
}

func (rr *DNSSECProof) copy() RR {
	zonePairs := make([]ZonePair, len(rr.Zones))
	for i, z := range rr.Zones {
		zonePairs[i] = *copyZonePair(&z)
	}
	return &DNSSECProof{
		Hdr:             *rr.Header(),
		Initial_key_tag: rr.Initial_key_tag,
		Num_zones:       rr.Num_zones,
		Zones:           zonePairs,
	}
}

func (rr *Signature) copy() RR {
	return copySignature(rr)
}

func (rr *Entering) copy() RR {
	return copyEntering(rr)
}

func (rr *SerialDS) copy() RR {
	return copyDataSerialDS(rr)
}

func (rr *Leaving) copy() RR {
	return copyLeaving(rr)
}

func (rr *Key) copy() RR {
	return copyDataKey(rr)
}

func copyDataKey(rr *Key) *Key {
	newPubKey := make([]byte, len(rr.Public_key))
	copy(newPubKey, rr.Public_key)
	return &Key{
		rr.Length,
		rr.Flags,
		rr.Protocol,
		rr.Algorithm,
		newPubKey,
	}
}

func copyEntering(entry *Entering) *Entering {
	newKeys := entry.Keys
	return &Entering{
		entry.Length,
		entry.ZType,
		entry.Entry_key_index,
		*copySignature(&entry.Key_sig),
		entry.Num_keys,
		newKeys,
	}
}

func copyLeaving(exit *Leaving) *Leaving {
	dsRecords := make([]SerialDS, len(exit.Ds_records))
	for i, ds := range exit.Ds_records {
		dsRecords[i] = *copyDataSerialDS(&ds)
	}

	rrs := make([]RR, len(exit.Rrs))
	for i, r := range exit.Rrs {
		rrs[i] = r.copy()
	}

	return &Leaving{
		Length:      exit.Length,
		ZType:       exit.ZType,
		Next_name:   Name(strings.Clone(exit.Next_name.String())),
		Rrtype:      exit.Rrtype,
		Rrsig:       *copySignature(&exit.Rrsig),
		LeavingType: exit.LeavingType,
		Name:        exit.Name,
		Num_ds:      exit.Num_ds,
		Ds_records:  dsRecords,
		Num_rrs:     exit.Num_rrs,
		Rrs:         rrs,
	}
}

func copySignature(sig *Signature) *Signature {
	newSig := make([]byte, len(sig.Signature))
	copy(newSig, sig.Signature)
	return &Signature{
		sig.Length,
		sig.Algorithm,
		sig.Labels,
		sig.Ttl,
		sig.Expires,
		sig.Begins,
		sig.Key_tag,
		newSig,
	}
}

func copyZonePair(zp *ZonePair) *ZonePair {
	return &ZonePair{
		*copyEntering(&zp.Entry),
		*copyLeaving(&zp.Exit),
	}
}

func copyDataSerialDS(s *SerialDS) *SerialDS {
	newDigest := make([]byte, len(s.Digest))
	copy(newDigest, s.Digest)
	return &SerialDS{
		s.Length,
		s.Key_tag,
		s.Algorithm,
		s.Digest_type,
		s.Digest_len,
		newDigest,
	}
}
