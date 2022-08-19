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
