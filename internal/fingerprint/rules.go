package fingerprint

import (
	"bytes"
	"regexp"
	"strings"
)

var (
	versionToken = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+(?:[A-Za-z_+-][A-Za-z0-9.+_-]*)?$`)
	distroMarker = regexp.MustCompile(`(?i)(?:^|[^a-z])(ubuntu|debian)(?:-[a-z0-9.]+)?(?:$|[^a-z])`)
)

func (e *engine) sshMatch(s string) (match, bool) {
	line := cleanLine(strings.SplitN(s, "\n", 2)[0])
	if !strings.HasPrefix(line, "SSH-") {
		return match{}, false
	}
	if !(strings.HasPrefix(line, "SSH-2.0-") || strings.HasPrefix(line, "SSH-1.99-")) {
		return match{}, false
	}
	parts := strings.SplitN(line, "-", 3)
	if len(parts) != 3 || (parts[1] != "2.0" && parts[1] != "1.99") {
		return match{}, false
	}
	software := strings.Fields(parts[2])
	if len(software) == 0 {
		return match{}, false
	}
	token := strings.SplitN(software[0], " ", 2)[0]
	ver := e.patterns["ssh.openssh"].FindStringSubmatch(token)
	if ver == nil {
		return match{protocol: "SSH", confidence: .60, evidence: evidence("protocol.ssh", "banner", []byte(line))}, true
	}
	os := ""
	comment := ""
	if len(software) > 1 {
		comment = strings.Join(software[1:], " ")
	}
	os = distroHint(comment)
	score := .90
	if os != "" {
		score = .95
	}
	return match{protocol: "SSH", product: "OpenSSH", version: ver[1], osHint: os, confidence: score, evidence: evidence("ssh.openssh", "banner", []byte(line))}, true
}

type serverFingerprint struct {
	name, product, rule string
	score, versionless  float64
}

func (e *engine) httpMatches(s string) []match {
	lines := strings.Split(s, "\n")
	if len(lines) == 0 {
		return nil
	}
	status := cleanLine(lines[0])
	fields := strings.Fields(status)
	if len(fields) < 2 || !validHTTPVersion(fields[0]) || !validHTTPStatusCode(fields[1]) {
		return nil
	}
	var found []match
	headerSeen := false
	for _, raw := range lines[1:] {
		line := cleanLine(raw)
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 || !validHeaderName(line[:colon]) {
			continue
		}
		headerSeen = true
		if !strings.EqualFold(strings.TrimSpace(line[:colon]), "Server") {
			continue
		}
		value := strings.TrimSpace(line[colon+1:])
		for _, loc := range e.httpToken.FindAllStringIndex(value, -1) {
			idx, end := loc[0], loc[1]
			if idx > 0 && value[idx-1] != ' ' && value[idx-1] != '\t' && value[idx-1] != '(' && value[idx-1] != ',' {
				continue
			}
			if end < len(value) && value[end] != '/' && value[end] != ' ' && value[end] != '\t' && value[end] != '(' && value[end] != ',' {
				continue
			}
			var product serverFingerprint
			for _, p := range e.httpProducts {
				if strings.EqualFold(value[idx:end], p.name) {
					product = p
					break
				}
			}
			version := ""
			tokenEnd := end
			if end < len(value) && value[end] == '/' {
				tokenEnd = end + 1
				for tokenEnd < len(value) && isVersionChar(value[tokenEnd]) {
					tokenEnd++
				}
				if candidate := value[end+1 : tokenEnd]; validDottedVersion(candidate) {
					version = candidate
				}
			}
			// Only comments immediately following this token belong to it.
			rest := strings.TrimSpace(value[tokenEnd:])
			os := ""
			if strings.HasPrefix(rest, "(") {
				if close := strings.IndexByte(rest, ')'); close >= 0 {
					os = distroHint(rest[1:close])
					if os != "" {
						tokenEnd = len(value) - len(rest) + close + 1
					}
				}
			}
			score := product.score
			if version == "" {
				score = product.versionless
			}
			found = append(found, match{protocol: "HTTP", product: product.product, version: version, osHint: os, confidence: score, evidence: printableHeaderEvidence(product.rule, value[idx:tokenEnd])})
		}
	}
	if !headerSeen {
		return nil
	}
	if len(found) == 0 {
		// Valid HTTP response structure is sufficient for protocol-only identification.
		return []match{{protocol: "HTTP", confidence: .60, evidence: evidence("protocol.http", "banner", []byte(status))}}
	}
	return found
}

func validHTTPVersion(s string) bool {
	switch s {
	case "HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0":
		return true
	default:
		return false
	}
}

func validHTTPStatusCode(s string) bool {
	return len(s) == 3 && s[0] >= '1' && s[0] <= '5' && s[1] >= '0' && s[1] <= '9' && s[2] >= '0' && s[2] <= '9'
}

func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))) {
			return false
		}
	}
	return true
}

func isVersionChar(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '.' || b == '+' || b == '_' || b == '-'
}
func validDottedVersion(s string) bool {
	if len(s) == 0 {
		return false
	}
	if !versionToken.MatchString(s) {
		return false
	}
	return strings.Contains(s, ".")
}

func distroHint(s string) string {
	loc := distroMarker.FindStringSubmatch(s)
	if len(loc) < 2 {
		return ""
	}
	if strings.EqualFold(loc[1], "ubuntu") {
		return "Ubuntu"
	}
	return "Debian"
}

func (e *engine) mysqlMatch(b []byte) (match, bool) {
	if len(b) < 8 || b[3] != 0 || b[4] != 0x0a {
		return match{}, false
	}
	declared := int(b[0]) | int(b[1])<<8 | int(b[2])<<16
	if declared < 4 || declared+4 < len(b) {
		return match{}, false
	}
	end := bytes.IndexByte(b[5:], 0)
	if end < 0 || end == 0 || end > 64 {
		return match{}, false
	}
	versionBytes := b[5 : 5+end]
	for _, c := range versionBytes {
		if c < 0x20 || c > 0x7e {
			return match{}, false
		}
	}
	version := string(versionBytes)
	if !validDottedVersion(version) || version[0] < '0' || version[0] > '9' {
		return match{}, false
	}
	return match{protocol: "MySQL", product: "MySQL", version: version, confidence: .90, evidence: binaryEvidence("mysql.handshake", b[:6+end])}, true
}

func (e *engine) redisMatches(s string) []match {
	for _, id := range []string{"redis.command_error", "redis.pong", "redis.noauth"} {
		if e.patterns[id].MatchString(s) {
			return []match{{protocol: "Redis", product: e.definitions[id].Product, confidence: .70, evidence: evidence(id, "banner", []byte(cleanLine(s)))}}
		}
	}
	return nil
}

func (e *engine) ftpMatches(s string) []match {
	line := cleanLine(strings.SplitN(s, "\n", 2)[0])
	if !(strings.HasPrefix(line, "220 ") || strings.HasPrefix(line, "220-")) {
		return nil
	}
	lower := asciiLower(line)
	for _, p := range e.ftpProducts {
		idx := strings.Index(lower, p.name)
		if idx < 0 {
			continue
		}
		if idx > 0 && line[idx-1] != ' ' && line[idx-1] != '\t' && line[idx-1] != '(' && line[idx-1] != '-' {
			continue
		}
		rest := line[idx+len(p.name):]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' && rest[0] != ')' && rest[0] != '-' && !(rest[0] >= '0' && rest[0] <= '9') {
			continue
		}
		version := ""
		if strings.HasPrefix(rest, " ") {
			rest = strings.TrimSpace(rest)
		} else if strings.HasPrefix(rest, "-") {
			rest = rest[1:]
		}
		if rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			token := strings.Fields(rest)[0]
			token = strings.TrimRight(token, ")],;:")
			if validDottedVersion(token) {
				version = token
			}
		}
		score := .90
		if p.product == "Pure-FTPd" {
			score = .80
		}
		if version == "" {
			score = .80
		}
		return []match{{protocol: "FTP", product: p.product, version: version, confidence: score, evidence: evidence(p.rule, "banner", []byte(line))}}
	}
	if e.patterns["protocol.ftp"].MatchString(line) {
		return []match{{protocol: "FTP", confidence: .60, evidence: evidence("protocol.ftp", "banner", []byte(line))}}
	}
	return nil
}

func (e *engine) tlsMatch(b []byte) (match, bool) {
	if len(b) < 9 || b[0] != 0x16 || b[1] != 0x03 || b[2] < 0x01 || b[2] > 0x04 {
		return match{}, false
	}
	recordLen := int(b[3])<<8 | int(b[4])
	payload := b[5:]
	if recordLen == 0 || recordLen <= len(payload) || len(payload) < 4 {
		return match{}, false
	}
	if payload[0] != 0x01 && payload[0] != 0x02 {
		return match{}, false
	}
	handshakeLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if handshakeLen <= len(payload)-4 {
		return match{}, false
	}
	return match{protocol: "TLS", confidence: .50, evidence: binaryEvidence("tls.record_prefix", b[:min(len(b), 9)])}, true
}

// ASCII-only folding preserves byte offsets into the original banner.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
