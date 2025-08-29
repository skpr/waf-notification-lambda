package waf

// Log represents the structure of a single WAF log entry stored in S3.
type Log struct {
	Action            string      `json:"action"`
	TerminatingRuleID string      `json:"terminatingRuleId"`
	HTTPSourceName    string      `json:"httpSourceName"`
	HTTPSourceId      string      `json:"httpSourceId"`
	HTTPRequest       HTTPRequest `json:"httpRequest"`
}

// HTTPRequest represents the structure of the HTTP request in the WAF log.
type HTTPRequest struct {
	ClientIP string `json:"clientIp"`
}
