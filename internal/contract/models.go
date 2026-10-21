// Package contract defines shared interfaces and validation for banner identification.
package contract

import "context"

type Record struct {
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	Banner         string `json:"banner"`
	BannerEncoding string `json:"banner_encoding"`
}

type Evidence struct {
	RuleID string `json:"rule_id"`
	Field  string `json:"field"`
	Value  string `json:"value"`
}

type Candidate struct {
	Protocol   string     `json:"protocol"`
	Product    string     `json:"product"`
	Version    string     `json:"version"`
	OSHint     string     `json:"os_hint"`
	Confidence float64    `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}

type Identification struct {
	Protocol   string      `json:"protocol"`
	Product    string      `json:"product"`
	Version    string      `json:"version"`
	OSHint     string      `json:"os_hint"`
	Confidence float64     `json:"confidence"`
	Evidence   []Evidence  `json:"evidence"`
	Candidates []Candidate `json:"candidates"`
}

type ItemError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Result struct {
	Index          int        `json:"index"`
	IP             string     `json:"ip"`
	Port           int        `json:"port"`
	Status         string     `json:"status"`
	Identification            // 匿名嵌入，识别字段在 JSON 顶层展开
	Error          *ItemError `json:"error"`
}

type IdentifyRequest struct {
	Records []Record `json:"records"`
}
type IdentifyResponse struct {
	Results []Result `json:"results"`
}
type ErrorResponse struct {
	Error ItemError `json:"error"`
}

type Recognizer interface {
	Identify(context.Context, Record) (Identification, error)
}
type BatchIdentifier interface {
	IdentifyBatch(context.Context, []Record) ([]Result, error)
}

const (
	StatusMatched = "matched"
	StatusUnknown = "unknown"
	StatusInvalid = "invalid"
	StatusFailed  = "failed"
)

// EmptyIdentification creates an unknown result with JSON arrays instead of null.
func EmptyIdentification() Identification {
	return Identification{Evidence: []Evidence{}, Candidates: []Candidate{}}
}
