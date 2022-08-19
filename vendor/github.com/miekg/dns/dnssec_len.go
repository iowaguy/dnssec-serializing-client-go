package dns

func (rr *ZonePair) len(off int, compression map[string]struct{}) int {
	l := rr.Entry.len(0, compression)
	l += rr.Exit.len(0, compression)
	return l
}

func (rr *DNSSECProof) len(off int, compression map[string]struct{}) int {
	l := rr.Hdr.len(off, compression)
	l += 2 // initial_key_tag
	l += 1 // num_zones

	for _, z := range rr.Zones {
		l += z.len(0, compression)
	}
	return l
}

func (rr *Signature) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 1 // algorithm
	l += 1 // labels
	l += 4 // ttl
	l += 4 // expires
	l += 4 // begins
	l += 2 // key_tag
	l += len(rr.Signature)
	return l
}

func (rr *Key) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 2 // flags
	l += 1 // protocol
	l += 1 // algorithm
	l += len(rr.Public_key)
	return l
}

func (rr *Entering) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 1 // zType
	l += 1 // entry_key_index
	l += rr.Key_sig.len(l, compression)
	l += 1 // num_keys

	for _, k := range rr.Keys {
		l += k.len(l, compression)
	}
	return l
}

func (rr *SerialDS) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 2 // key_tag
	l += 1 // algorithm
	l += 1 // digest_type
	l += 2 // digest_len
	l += len(rr.Digest)
	return l
}

func (rr *Leaving) len(off int, compression map[string]struct{}) int {
	l := 2 // length
	l += 1 // zType

	// need to add one for the first zone length
	l += len([]byte(rr.Next_name)) + 1
	l += 2 // rrtype
	l += rr.Rrsig.len(l, compression)
	l += 1 // leavingtype

	switch rr.LeavingType {
	case LeavingCNAMEType:
		fallthrough
	case LeavingDNAMEType:
		// need to add one for the first zone length
		l += len([]byte(rr.Name)) + 1
	case LeavingDSType:
		l += 1 // num_ds

		for _, ds := range rr.Ds_records {
			l += ds.len(0, compression)
		}
	case LeavingOtherType:
		l += 1 // num_rrs

		for _, r := range rr.Rrs {
			l += r.len(0, compression)
		}
	}
	return l
}
