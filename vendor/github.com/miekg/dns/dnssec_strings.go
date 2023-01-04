package dns

import (
	"bytes"
	"strconv"
)

func (rr *ZonePair) String() string {
	return rr.Entry.String() + " " + rr.Exit.String()
}

func (rr *DNSSECProof) String() string {
	var b bytes.Buffer
	for _, zone := range rr.Zones {
		b.WriteString(zone.String())
	}
	return strconv.Itoa(int(rr.Initial_key_tag)) + " " +
		strconv.Itoa(int(rr.Num_zones)) + " " + b.String()
}

func (rr *ZoneRecType) String() string {
	return strconv.Itoa(int(*rr))
}

func (rr *Signature) String() string {
	return strconv.Itoa(int(rr.Length)) + " " +
		strconv.Itoa(int(rr.Algorithm)) + " " +
		strconv.Itoa(int(rr.Labels)) + " " +
		strconv.Itoa(int(rr.Ttl)) + " " +
		strconv.Itoa(int(rr.Expires)) + " " +
		strconv.Itoa(int(rr.Begins)) + " " +
		strconv.Itoa(int(rr.Key_tag)) + " " +
		toBase64(rr.Signature)
}

func (rr *Key) String() string {
	return strconv.Itoa(int(rr.Length)) + " " +
		strconv.Itoa(int(rr.Flags)) + " " +
		strconv.Itoa(int(rr.Protocol)) + " " +
		strconv.Itoa(int(rr.Algorithm)) + " " +
		toBase64(rr.Public_key)
}

func (rr *Entering) String() string {
	var b bytes.Buffer
	for _, key := range rr.Keys {
		b.WriteString(key.String())
	}
	return strconv.Itoa(int(rr.Length)) + " " +
		rr.ZType.String() + " " +
		strconv.Itoa(int(rr.Entry_key_index)) + " " +
		rr.Key_sig.String() + " " +
		strconv.Itoa(int(rr.Num_keys)) + " " +
		b.String()
}

func (rr *SerialDS) String() string {
	return strconv.Itoa(int(rr.Length)) + " " +
		strconv.Itoa(int(rr.Key_tag)) + " " +
		strconv.Itoa(int(rr.Algorithm)) + " " +
		strconv.Itoa(int(rr.Digest_type)) + " " +
		strconv.Itoa(int(rr.Digest_len)) + " " +
		toBase64(rr.Digest)
}

func (rr *RRType) String() string {
	return strconv.Itoa(int(*rr))
}

func (rr *Leaving) String() string {
	s := strconv.Itoa(int(rr.Length)) + " " +
		rr.ZType.String() + " " +
		rr.Next_name.String() + " " +
		rr.Rrtype.String() + " " +
		rr.Rrsig.String() + " " +
		strconv.Itoa(int(rr.LeavingType))

	switch rr.LeavingType {
	case LeavingCNAMEType:
		fallthrough
	case LeavingDNAMEType:
		return s + " " + rr.Name.String()
	case LeavingDSType:
		var b bytes.Buffer
		for _, ds := range rr.Ds_records {
			b.WriteString(ds.String())
		}
		return s + " " + strconv.Itoa(int(rr.Num_ds)) +
			" " + b.String()
	case LeavingOtherType:
		var b bytes.Buffer
		for _, rrdata := range rr.Rrs {
			b.WriteString(rrdata.String())
		}
		return s + strconv.Itoa(int(rr.Num_rrs)) + " " + b.String()
	}

	return s
}

func (rr *Zone) String() string {
	var keysBuffer bytes.Buffer
	for _, key := range rr.Keys {
		keysBuffer.WriteString(key.String())
	}
	var keysSigsBuffer bytes.Buffer
	for _, keySig := range rr.KeySigs {
		keysSigsBuffer.WriteString(keySig.String())
	}

	var dsBuffer bytes.Buffer
	for _, ds := range rr.DSSet {
		dsBuffer.WriteString(ds.String())
	}
	var dsSigsBuffer bytes.Buffer
	for _, dsSig := range rr.DSSigs {
		dsSigsBuffer.WriteString(dsSig.String())
	}

	var leavesBuffer bytes.Buffer
	for _, leaf := range rr.Leaves {
		leavesBuffer.WriteString(leaf.String())
	}
	var leavesSigsBuffer bytes.Buffer
	for _, leavesSig := range rr.LeavesSigs {
		leavesSigsBuffer.WriteString(leavesSig.String())
	}

	return string(rr.Name) + " " +
		string(rr.PreviousName) + " " +
		strconv.Itoa(int(rr.ZSKIndex)) + " " +
		strconv.Itoa(int(rr.NumKeys)) + " " +
		keysBuffer.String() + " " +
		strconv.Itoa(int(rr.NumKeySigs)) + " " +
		keysSigsBuffer.String() + " " +
		strconv.Itoa(int(rr.NumDS)) + " " +
		dsBuffer.String() + " " +
		strconv.Itoa(int(rr.NumDSSigs)) + " " +
		dsSigsBuffer.String() + " " +
		strconv.Itoa(int(rr.NumLeaves)) + " " +
		leavesBuffer.String() + " " +
		strconv.Itoa(int(rr.NumLeavesSigs)) + " " +
		leavesSigsBuffer.String()
}

func (rr *Chain) String() string {
	var zonesBuffer bytes.Buffer
	for _, zone := range rr.Zones {
		zonesBuffer.WriteString(zone.String())
	}

	return strconv.Itoa(int(rr.Version)) + " " +
		strconv.Itoa(int(rr.InitialKeyTag)) + " " +
		strconv.Itoa(int(rr.NumZones)) + " " +
		zonesBuffer.String()
}
