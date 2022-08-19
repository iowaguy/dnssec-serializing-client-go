package dns

func (rr *ZonePair) Header() *RR_Header    { return &RR_Header{} }
func (rr *DNSSECProof) Header() *RR_Header { return &rr.Hdr }
func (rr *ZoneRecType) Header() *RR_Header { return &RR_Header{} }
func (rr *Signature) Header() *RR_Header   { return &RR_Header{} }
func (rr *Key) Header() *RR_Header         { return &RR_Header{} }
func (rr *Entering) Header() *RR_Header    { return &RR_Header{} }
func (rr *SerialDS) Header() *RR_Header    { return &RR_Header{} }
func (rr *RRType) Header() *RR_Header      { return &RR_Header{} }
func (rr *Leaving) Header() *RR_Header     { return &RR_Header{} }
