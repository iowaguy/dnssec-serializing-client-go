package dns

func (rr *ZonePair) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *DNSSECProof) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Signature) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Key) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Entering) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *SerialDS) isDuplicate(_r2 RR) bool {
	return false
}

func (rr *Leaving) isDuplicate(_r2 RR) bool {
	return false
}

func (r1 *Zone) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*Zone)
	if !ok {
		return false
	}
	_ = r2
	if !isDuplicateName(string(r1.Name), string(r2.Name)) {
		return false
	}
	if !isDuplicateName(string(r1.PreviousName), string(r2.PreviousName)) {
		return false
	}
	if r1.ZSKIndex != r2.ZSKIndex {
		return false
	}
	if r1.NumKeys != r2.NumKeys {
		return false
	}
	if len(r1.Keys) != len(r2.Keys) {
		return false
	}
	for i := 0; i < len(r1.Keys); i++ {
		if r1.Keys[i] != r2.Keys[i] {
			return false
		}
	}
	if r1.NumKeySigs != r2.NumKeySigs {
		return false
	}
	if len(r1.KeySigs) != len(r2.KeySigs) {
		return false
	}
	for i := 0; i < len(r1.KeySigs); i++ {
		if r1.KeySigs[i] != r2.KeySigs[i] {
			return false
		}
	}
	if r1.NumDS != r2.NumDS {
		return false
	}
	if len(r1.DSSet) != len(r2.DSSet) {
		return false
	}
	for i := 0; i < len(r1.DSSet); i++ {
		if r1.DSSet[i] != r2.DSSet[i] {
			return false
		}
	}
	if r1.NumDSSigs != r2.NumDSSigs {
		return false
	}
	if len(r1.DSSigs) != len(r2.DSSigs) {
		return false
	}
	for i := 0; i < len(r1.DSSigs); i++ {
		if r1.DSSigs[i] != r2.DSSigs[i] {
			return false
		}
	}
	if r1.NumLeaves != r2.NumLeaves {
		return false
	}
	if len(r1.Leaves) != len(r2.Leaves) {
		return false
	}
	for i := 0; i < len(r1.Leaves); i++ {
		if r1.Leaves[i] != r2.Leaves[i] {
			return false
		}
	}
	if r1.NumLeavesSigs != r2.NumLeavesSigs {
		return false
	}
	if len(r1.LeavesSigs) != len(r2.LeavesSigs) {
		return false
	}
	for i := 0; i < len(r1.LeavesSigs); i++ {
		if r1.LeavesSigs[i] != r2.LeavesSigs[i] {
			return false
		}
	}
	return true
}

func (r1 *Chain) isDuplicate(_r2 RR) bool {
	r2, ok := _r2.(*Chain)
	if !ok {
		return false
	}
	_ = r2
	if r1.Version != r2.Version {
		return false
	}
	if r1.InitialKeyTag != r2.InitialKeyTag {
		return false
	}
	if r1.NumZones != r2.NumZones {
		return false
	}
	if len(r1.Zones) != len(r2.Zones) {
		return false
	}
	for i := 0; i < len(r1.Zones); i++ {
		if r1.Zones[i].isDuplicate(&r2.Zones[i]) {
			return false
		}
	}
	return true
}
