// Package fingerprint contains the stateless banner recognition engine.
package fingerprint

import (
	"context"
	"encoding/base64"
	"sort"
	"strings"
	"unicode/utf8"

	"bannerfingerprint/internal/contract"
	ruledata "bannerfingerprint/rules"
)

const maxEvidenceValue = 256
const maxEvidencePerCandidate = 16
const maxCandidates = 16

// New constructs the immutable, concurrency-safe fingerprint recognizer.
func New() (contract.Recognizer, error) { return LoadRules(ruledata.Default) }

type match struct {
	protocol, product, version, osHint string
	confidence                         float64
	evidence                           contract.Evidence
}

func (e *engine) Identify(ctx context.Context, record contract.Record) (contract.Identification, error) {
	if err := ctx.Err(); err != nil {
		return contract.Identification{}, err
	}
	banner, err := contract.DecodeBanner(record, contract.MaxBannerBytes)
	if err != nil {
		return contract.Identification{}, err
	}
	if err := ctx.Err(); err != nil {
		return contract.Identification{}, err
	}

	matches := e.recognize(banner)
	if err := ctx.Err(); err != nil {
		return contract.Identification{}, err
	}
	return resolve(matches), nil
}

func (e *engine) recognize(b []byte) []match {
	var found []match
	text := string(b)
	if m, ok := e.sshMatch(text); ok {
		found = append(found, m)
	}
	found = append(found, e.httpMatches(text)...)
	if m, ok := e.mysqlMatch(b); ok {
		found = append(found, m)
	}
	found = append(found, e.redisMatches(text)...)
	found = append(found, e.ftpMatches(text)...)
	if m, ok := e.tlsMatch(b); ok {
		found = append(found, m)
	}
	for i := range found {
		d := e.definitions[found[i].evidence.RuleID]
		found[i].confidence = d.Confidence
		if d.Product != "" {
			found[i].product = d.Product
			if found[i].version == "" {
				found[i].confidence = d.Versionless
			}
		}
		if found[i].osHint != "" && d.OSConfidence > 0 {
			found[i].confidence = d.OSConfidence
		}
	}
	return found
}

func resolve(matches []match) contract.Identification {
	if len(matches) == 0 {
		return contract.EmptyIdentification()
	}
	grouped := make(map[key]contract.Candidate)
	for _, m := range matches {
		k := key{m.protocol, m.product, m.version, m.osHint}
		c, ok := grouped[k]
		if !ok {
			c = contract.Candidate{Protocol: m.protocol, Product: m.product, Version: m.version, OSHint: m.osHint, Confidence: m.confidence, Evidence: []contract.Evidence{}}
		}
		if m.confidence > c.Confidence {
			c.Confidence = m.confidence
		}
		c.Evidence = append(c.Evidence, m.evidence)
		grouped[k] = c
	}
	list := make([]contract.Candidate, 0, len(grouped))
	for _, c := range grouped {
		c.Evidence = uniqueEvidence(c.Evidence)
		if len(c.Evidence) > maxEvidencePerCandidate {
			c.Evidence = c.Evidence[:maxEvidencePerCandidate]
		}
		list = append(list, c)
	}
	// A product identification supersedes the protocol-only fallback for that protocol.
	products := map[string]bool{}
	for _, c := range list {
		if c.Product != "" {
			products[c.Protocol] = true
		}
	}
	filtered := list[:0]
	for _, c := range list {
		if c.Product == "" && products[c.Protocol] {
			continue
		}
		filtered = append(filtered, c)
	}
	list = filtered
	// A versionless duplicate adds no information when a versioned candidate exists,
	// unless it carries an additional OS hint.
	versioned := map[string]bool{}
	for _, c := range list {
		if c.Product != "" && c.Version != "" {
			versioned[c.Protocol+"\x00"+c.Product] = true
		}
	}
	filtered = list[:0]
	for _, c := range list {
		if c.Product != "" && c.Version == "" && c.OSHint == "" && versioned[c.Protocol+"\x00"+c.Product] {
			continue
		}
		filtered = append(filtered, c)
	}
	list = filtered
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Product != b.Product {
			return a.Product < b.Product
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.OSHint < b.OSHint
	})
	if len(list) > maxCandidates {
		list = list[:maxCandidates]
	}
	main := list[0]
	out := contract.Identification{Protocol: main.Protocol, Product: main.Product, Version: main.Version, OSHint: main.OSHint, Confidence: main.Confidence, Evidence: main.Evidence, Candidates: []contract.Candidate{}}
	if len(list) > 1 {
		out.Candidates = list
	}
	return out
}

type key struct{ protocol, product, version, osHint string }

func uniqueEvidence(in []contract.Evidence) []contract.Evidence {
	seen := make(map[contract.Evidence]struct{}, len(in))
	out := make([]contract.Evidence, 0, len(in))
	for _, e := range in {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Field != b.Field {
			return a.Field < b.Field
		}
		return a.Value < b.Value
	})
	return out
}

func evidence(rule, field string, b []byte) contract.Evidence {
	value := string(b)
	if !utf8.Valid(b) {
		value = "base64:" + base64.StdEncoding.EncodeToString(b)
	}
	value = truncateUTF8(value, maxEvidenceValue)
	return contract.Evidence{RuleID: rule, Field: field, Value: value}
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func binaryEvidence(rule string, b []byte) contract.Evidence {
	// Binary evidence is rendered from the precise matched bytes, never the full banner.
	return evidence(rule, "handshake", []byte("base64:"+base64.StdEncoding.EncodeToString(b)))
}

func printableHeaderEvidence(rule string, line string) contract.Evidence {
	return evidence(rule, "server", []byte(line))
}

func cleanLine(s string) string { return strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r") }
