package fingerprint

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"

	"bannerfingerprint/internal/contract"
)

type definition struct {
	ID           string  `json:"id"`
	Protocol     string  `json:"protocol"`
	Product      string  `json:"product"`
	Token        string  `json:"token"`
	Pattern      string  `json:"pattern"`
	Confidence   float64 `json:"confidence"`
	Versionless  float64 `json:"versionless"`
	OSConfidence float64 `json:"os_confidence"`
}

type engine struct {
	definitions  map[string]definition
	patterns     map[string]*regexp.Regexp
	httpToken    *regexp.Regexp
	httpProducts []serverFingerprint
	ftpProducts  []serverFingerprint
}

// NewFromFile loads and validates external rules once, before HTTP starts.
func NewFromFile(path string) (contract.Recognizer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rules: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1048577))
	if err != nil {
		return nil, err
	}
	return LoadRules(b)
}

// LoadRules compiles immutable rule data. Invalid configuration fails closed.
func LoadRules(data []byte) (contract.Recognizer, error) {
	fail := func() (contract.Recognizer, error) { return nil, fmt.Errorf("invalid fingerprint rules") }
	if len(data) > 1048576 {
		return fail()
	}
	var file struct {
		Rules []definition `json:"rules"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(&file) != nil || len(file.Rules) == 0 || len(file.Rules) > 128 {
		return fail()
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fail()
	}
	e := &engine{definitions: map[string]definition{}, patterns: map[string]*regexp.Regexp{}}
	var tokens []string
	tokenPattern := regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]*$`)
	for _, d := range file.Rules {
		if d.ID == "" {
			return fail()
		}
		if _, ok := e.definitions[d.ID]; ok {
			return fail()
		}
		for _, score := range []float64{d.Confidence, d.Versionless, d.OSConfidence} {
			if math.IsNaN(score) || score < 0 || score > 1 {
				return fail()
			}
		}
		if d.Pattern != "" {
			p, err := regexp.Compile(d.Pattern)
			if err != nil || len(d.Pattern) > 4096 {
				return fail()
			}
			e.patterns[d.ID] = p
		}
		if d.Token != "" {
			if !tokenPattern.MatchString(d.Token) || d.Product == "" {
				return fail()
			}
			p := serverFingerprint{name: strings.ToLower(d.Token), product: d.Product, rule: d.ID, score: d.Confidence, versionless: d.Versionless}
			switch d.Protocol {
			case "HTTP":
				e.httpProducts = append(e.httpProducts, p)
				tokens = append(tokens, regexp.QuoteMeta(d.Token))
			case "FTP":
				e.ftpProducts = append(e.ftpProducts, p)
			default:
				return fail()
			}
		}
		e.definitions[d.ID] = d
	}
	for _, id := range []string{"ssh.openssh", "mysql.handshake", "redis.command_error", "redis.pong", "redis.noauth", "protocol.ssh", "protocol.http", "protocol.ftp", "tls.record_prefix"} {
		if _, ok := e.definitions[id]; !ok {
			return fail()
		}
	}
	for _, id := range []string{"ssh.openssh", "redis.command_error", "redis.pong", "redis.noauth", "protocol.ftp"} {
		if e.patterns[id] == nil {
			return fail()
		}
	}
	if e.patterns["ssh.openssh"].NumSubexp() < 1 || len(tokens) == 0 {
		return fail()
	}
	sort.Slice(tokens, func(i, j int) bool { return len(tokens[i]) > len(tokens[j]) })
	e.httpToken = regexp.MustCompile("(?i)" + strings.Join(tokens, "|"))
	return e, nil
}
