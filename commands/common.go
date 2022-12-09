package commands

const (
	DOH_CONTENT_TYPE = "application/dns-message"
	DOH_DEFAULT_PATH = "/dns-query"
)

// IANA DNS Root Anchor Information
const (
	IANARootAnchors          = "https://data.iana.org/root-anchors/root-anchors.xml"
	IANAICANNPEMBundle       = "https://data.iana.org/root-anchors/icannbundle.pem"
	IANAChecksums            = "https://data.iana.org/root-anchors/checksums-sha256.txt"
	IANARootAnchorsSignature = "https://data.iana.org/root-anchors/root-anchors.p7s"
)

// Root Anchors Location Configuration
const (
	RootAnchorsLocation     = "root-anchors"
	RootAnchorsFile         = "root-anchors.xml"
	ICANNBundleFile         = "icannbundle.pem"
	ChecksumFile            = "checksums-sha256.txt"
	RootAnchorSignatureFile = "root-anchors.p7s"
	ChecksumDelimiter       = "  "
)

func ReturnRootAnchorFileAndLocationInformation() map[string]string {
	res := make(map[string]string)
	res[RootAnchorsFile] = IANARootAnchors
	res[ICANNBundleFile] = IANAICANNPEMBundle
	res[ChecksumFile] = IANAChecksums
	res[RootAnchorSignatureFile] = IANARootAnchorsSignature
	return res
}
