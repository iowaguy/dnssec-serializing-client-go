package dns

func (rr *ZonePair) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataZonePair(rr, msg, off, compression, compress)
}

func (rr *DNSSECProof) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(rr.Initial_key_tag, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(rr.Num_zones, msg, off)
	if err != nil {
		return off, err
	}

	for _, z := range rr.Zones {
		off, err = packDataZonePair(&z, msg, off, compression, compress)
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

func (rr *Signature) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataSignature(rr, msg, off, compression, compress)
}

func (rr *Key) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataKey(rr, msg, off, compression, compress)
}

func (rr *Entering) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataEntering(rr, msg, off, compression, compress)
}

func (rr *SerialDS) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataSerialDS(rr, msg, off, compression, compress)
}

func (rr *Leaving) pack(msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	return packDataLeaving(rr, msg, off, compression, compress)
}

func packDataSignature(sig *Signature, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(sig.Length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(sig.Algorithm, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(sig.Labels, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(sig.Ttl, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(sig.Expires, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint32(sig.Begins, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(sig.Key_tag, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(sig.Signature, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataZonePair(zp *ZonePair, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDataEntering(&zp.Entry, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	off, err = packDataLeaving(&zp.Exit, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataKey(key *Key, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(key.Length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(key.Flags, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(key.Protocol, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(key.Algorithm, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(key.Public_key, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packByteArray(b []byte, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	copy(msg[off:], b)
	return off + len(b), nil
}

func packDataEntering(entry *Entering, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(entry.Length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(uint8(entry.ZType), msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(entry.Entry_key_index, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDataSignature(&entry.Key_sig, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint8(entry.Num_keys, msg, off)
	if err != nil {
		return off, err
	}
	for _, k := range entry.Keys {
		off, err = packDataKey(&k, msg, off, compression, compress)
		if err != nil {
			return off, err
		}
	}

	return off, nil
}

func packDataSerialDS(ds *SerialDS, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(ds.Length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(ds.Key_tag, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(ds.Algorithm, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(ds.Digest_type, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint16(ds.Digest_len, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packByteArray(ds.Digest, msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}

func packDataLeaving(l *Leaving, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packUint16(l.Length, msg, off)
	if err != nil {
		return off, err
	}
	off, err = packUint8(uint8(l.ZType), msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDomainName(string(l.Next_name), msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint16(uint16(l.Rrtype), msg, off)
	if err != nil {
		return off, err
	}
	off, err = packDataSignature(&l.Rrsig, msg, off, compression, compress)
	if err != nil {
		return off, err
	}
	off, err = packUint8(uint8(l.LeavingType), msg, off)
	if err != nil {
		return off, err
	}

	switch l.LeavingType {
	case LeavingCNAMEType:
		fallthrough
	case LeavingDNAMEType:
		off, err = packDataLeavingCNAME(l, msg, off, compression, compress)
	case LeavingDSType:
		off, err = packUint8(l.Num_ds, msg, off)
		if err != nil {
			return off, err
		}
		for _, ds := range l.Ds_records {
			off, err = packDataSerialDS(&ds, msg, off, compression, compress)
			if err != nil {
				return off, err
			}
		}
	case LeavingOtherType:
		off, err = packUint8(l.Num_rrs, msg, off)
		if err != nil {
			return off, err
		}
		for _, r := range l.Rrs {
			off, err = PackRR(r, msg, off, compression.ext, compress)
			if err != nil {
				return off, err
			}
		}
	}

	return off, nil
}

func packDataLeavingCNAME(l *Leaving, msg []byte, off int, compression compressionMap, compress bool) (off1 int, err error) {
	off, err = packDomainName(string(l.Name), msg, off, compression, compress)
	if err != nil {
		return off, err
	}

	return off, nil
}
