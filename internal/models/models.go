package models

type Classification string

const (
	Exposed         Classification = "EXPOSED"
	LikelyExposed   Classification = "LIKELY_EXPOSED"
	Protected       Classification = "PROTECTED"
	NotFound        Classification = "NOT_FOUND"
	Soft404         Classification = "SOFT_404"
	Redirect        Classification = "REDIRECT"
	DNSUnresolved   Classification = "DNS_UNRESOLVED"
	ConnectionError Classification = "CONNECTION_ERROR"
	Timeout         Classification = "TIMEOUT"
	Inconclusive    Classification = "INCONCLUSIVE"
)

type Finding struct {
	Host           string         `json:"host"`
	Scheme         string         `json:"scheme,omitempty"`
	Path           string         `json:"path,omitempty"`
	Detector       string         `json:"detector,omitempty"`
	Classification Classification `json:"classification"`
	Confidence     string         `json:"confidence"`
	Status         int            `json:"status,omitempty"`
	Evidence       string         `json:"evidence"`
}
