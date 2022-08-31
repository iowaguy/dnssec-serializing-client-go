package dns

func (rr *Signature) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataSignature(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *SerialDS) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataSerialDS(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *Key) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataKey(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *Entering) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataEntering(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *Leaving) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *ZonePair) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	*rr, off, err = unpackDataZonePair(msg, off)
	if err != nil {
		return off, err
	}
	return off, nil
}

func (rr *DNSSECProof) unpack(msg []byte, off int) (off1 int, err error) {
	rdStart := off
	_ = rdStart

	rr.Initial_key_tag, off, err = unpackUint16(msg, off)
	if err != nil {
		return off, err
	}
	rr.Num_zones, off, err = unpackUint8(msg, off)
	if err != nil {
		return off, err
	}

	rr.Zones = make([]ZonePair, rr.Num_zones)
	for i := 0; i < int(rr.Num_zones); i++ {
		rr.Zones[i], off, err = unpackDataZonePair(msg, off)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func unpackDataSignature(msg []byte, off int) (sig Signature, off1 int, err error) {
	rdStart := off

	sig = Signature{}
	if off == len(msg) {
		return sig, off, nil
	}

	sig.Length, off, err = unpackUint16(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Algorithm, off, err = unpackUint8(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Labels, off, err = unpackUint8(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Ttl, off, err = unpackUint32(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Expires, off, err = unpackUint32(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Begins, off, err = unpackUint32(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Key_tag, off, err = unpackUint16(msg, off)
	if err != nil {
		return sig, off, err
	}
	sig.Signature, off, err = unpackByteArray(msg, off, int(sig.Length)-(off-rdStart))
	if err != nil {
		return sig, off, err
	}
	//signerName, off, err := unpackByteArray(msg, off, int(sig.Length)-(off-rdStart))
	//if err != nil {
	//	return sig, off, err
	//}
	//sig.SignerName = string(signerName)
	return sig, off, nil
}

func unpackByteArray(msg []byte, off int, length int) (b []byte, off1 int, err error) {
	// Error handling for cases where query resolutions do not have DNSSEC Enabled
	if length < 0 {
		return nil, off, err
	}
	if off+length > len(msg) {
		return nil, 0, err
	}
	b = make([]byte, length)
	copy(b, msg[off:off+length])
	return b, off + length, nil
}

func unpackDataKey(msg []byte, off int) (key Key, off1 int, err error) {
	rdStart := off

	key = Key{}
	if off == len(msg) {
		return key, off, nil
	}

	key.Length, off, err = unpackUint16(msg, off)
	if err != nil {
		return key, off, err
	}
	key.Flags, off, err = unpackUint16(msg, off)
	if err != nil {
		return key, off, err
	}
	key.Protocol, off, err = unpackUint8(msg, off)
	if err != nil {
		return key, off, err
	}
	key.Algorithm, off, err = unpackUint8(msg, off)
	if err != nil {
		return key, off, err
	}
	key.Public_key, off, err = unpackByteArray(msg, off, int(key.Length)-(off-rdStart))
	if err != nil {
		return key, off, err
	}

	return key, off, nil
}

func unpackDataSerialDS(msg []byte, off int) (ds SerialDS, off1 int, err error) {
	rdStart := off

	ds = SerialDS{}
	if off == len(msg) {
		return ds, off, nil
	}

	ds.Length, off, err = unpackUint16(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.Key_tag, off, err = unpackUint16(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.Algorithm, off, err = unpackUint8(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.Digest_type, off, err = unpackUint8(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.Digest_len, off, err = unpackUint16(msg, off)
	if err != nil {
		return ds, off, err
	}
	ds.Digest, off, err = unpackByteArray(msg, off, int(ds.Length)-(off-rdStart))
	if err != nil {
		return ds, off, err
	}

	return ds, off, nil
}

func unpackDataEntering(msg []byte, off int) (entry Entering, off1 int, err error) {
	entry = Entering{}
	if off == len(msg) {
		return entry, off, nil
	}
	entry.Length, off, err = unpackUint16(msg, off)
	if err != nil {
		return entry, off, err
	}
	zType, off, err := unpackUint8(msg, off)
	if err != nil {
		return entry, off, err
	}
	entry.ZType = ZoneRecType(zType)

	entry.Entry_key_index, off, err = unpackUint8(msg, off)
	if err != nil {
		return entry, off, err
	}
	entry.Key_sig, off, err = unpackDataSignature(msg, off)
	if err != nil {
		return entry, off, err
	}
	entry.Num_keys, off, err = unpackUint8(msg, off)
	if err != nil {
		return entry, off, err
	}

	entry.Keys = make([]Key, entry.Num_keys)
	for i := 0; i < int(entry.Num_keys); i++ {
		entry.Keys[i], off, err = unpackDataKey(msg, off)
		if err != nil {
			return entry, off, err
		}
	}

	return entry, off, nil
}

func unpackDataLeaving(msg []byte, off int) (l Leaving, off1 int, err error) {
	l = Leaving{}
	if off == len(msg) {
		return l, off, nil
	}
	l.Length, off, err = unpackUint16(msg, off)
	if err != nil {
		return l, off, err
	}
	zType, off, err := unpackUint8(msg, off)
	if err != nil {
		return l, off, err
	}
	l.ZType = ZoneRecType(zType)

	next_name, off, err := UnpackDomainName(msg, off)
	if err != nil {
		return l, off, err
	}
	l.Next_name = Name(next_name)

	rrtype, off, err := unpackUint16(msg, off)
	if err != nil {
		return l, off, err
	}
	l.Rrtype = RRType(rrtype)

	l.Rrsig, off, err = unpackDataSignature(msg, off)
	if err != nil {
		return l, off, err
	}
	leavingType, off, err := unpackUint8(msg, off)
	if err != nil {
		return l, off, err
	}
	l.LeavingType = LeavingRecordType(leavingType)

	switch l.LeavingType {
	case LeavingCNAMEType:
		fallthrough
	case LeavingDNAMEType:
		name, off, err := UnpackDomainName(msg, off)
		if err != nil {
			return l, off, err
		}
		l.Name = Name(name)
	case LeavingDSType:
		l.Num_ds, off, err = unpackUint8(msg, off)
		if err != nil {
			return l, off, err
		}

		l.Ds_records = make([]SerialDS, int(l.Num_ds))
		for i := 0; i < int(l.Num_ds); i++ {
			l.Ds_records[i], off, err = unpackDataSerialDS(msg, off)
			if err != nil {
				return l, off, err
			}
		}
	case LeavingOtherType:
		l.Num_rrs, off, err = unpackUint8(msg, off)
		if err != nil {
			return l, off, err
		}

		l.Rrs = make([]RR, int(l.Num_rrs))
		for i := 0; i < int(l.Num_rrs); i++ {
			l.Rrs[i], off, err = UnpackRR(msg, off)
			if err != nil {
				return l, off, err
			}
		}
	}

	return l, off, nil
}

func unpackDataZonePair(msg []byte, off int) (zp ZonePair, off1 int, err error) {
	zp = ZonePair{}
	if off == len(msg) {
		return zp, off, nil
	}

	zp.Entry, off, err = unpackDataEntering(msg, off)
	if err != nil {
		return zp, off, err
	}
	zp.Exit, off, err = unpackDataLeaving(msg, off)
	if err != nil {
		return zp, off, err
	}

	return zp, off, nil
}
