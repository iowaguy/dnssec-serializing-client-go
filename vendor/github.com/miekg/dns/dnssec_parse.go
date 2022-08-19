package dns

// NOTE This is for parsing from zone record format. We will
// not support this right now, but the methods need to be
// implemented for the DNSSEC serialization types to implement
// the RR interface.

func (rr *ZonePair) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}

func (rr *DNSSECProof) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}

func (rr *Signature) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}

func (rr *Key) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}

func (rr *Entering) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}

func (rr *SerialDS) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}

func (rr *Leaving) parse(c *zlexer, o string) *ParseError {
	return &ParseError{}
}
