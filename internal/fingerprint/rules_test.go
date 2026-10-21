package fingerprint

import (
	"context"
	"encoding/base64"
	"testing"

	"bannerfingerprint/internal/contract"
)

func identify(t *testing.T, banner string, port int) contract.Identification {
	t.Helper()
	return identifyEncoding(t, banner, "utf8", port)
}

func identifyEncoding(t *testing.T, banner, encoding string, port int) contract.Identification {
	t.Helper()
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Identify(context.Background(), contract.Record{IP: "2001:db8::1", Port: port, Banner: banner, BannerEncoding: encoding})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestRuleVariantsAndWrongPorts(t *testing.T) {
	cases := []struct {
		name, banner, protocol, product, version, os string
		port                                         int
	}{
		{"ssh distro", "SSH-2.0-OpenSSH_9.8p1 Debian-2", "SSH", "OpenSSH", "9.8p1", "Debian", 443},
		{"ssh no inferred os", "SSH-2.0-OpenSSH_9.8", "SSH", "OpenSSH", "9.8", "", 80},
		{"ssh unsupported protocol", "SSH-2.0-OtherSSH_1.2", "SSH", "", "", "", 22},
		{"nginx wrong port", "HTTP/1.1 204 No Content\r\nServer: nginx/1.25.1\r\n", "HTTP", "nginx", "1.25.1", "", 22},
		{"nginx explicit os suffix", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n", "HTTP", "nginx", "1.24.0", "Ubuntu", 80},
		{"apache no version", "HTTP/1.1 200 OK\r\nServer: Apache\r\n", "HTTP", "Apache", "", "", 8080},
		{"jetty no version", "HTTP/1.1 200 OK\r\nServer: Jetty\r\n", "HTTP", "Jetty", "", "", 443},
		{"iis", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", "HTTP", "Microsoft-IIS", "10.0", "", 21},
		{"ftp vsftpd", "220 (vsFTPd 3.0.5)\r\n", "FTP", "vsFTPd", "3.0.5", "", 443},
		{"ftp pure", "220 Welcome to Pure-FTPd\r\n", "FTP", "Pure-FTPd", "", "", 80},
		{"redis pong", "+PONG\r\n", "Redis", "Redis", "", "", 22},
		{"redis noauth", "-NOAUTH Authentication required.\r\n", "Redis", "Redis", "", "", 21},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := identify(t, tc.banner, tc.port)
			if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version || got.OSHint != tc.os {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestHTTPServerTokenBoundariesAndOSAnnotationPosition(t *testing.T) {
	for _, banner := range []string{
		"HTTP/1.1 200 OK\r\nServer: notnginx/1.2\r\n",
		"HTTP/1.1 200 OK\r\nServer: nginx-proxy/1.2\r\n",
		"HTTP/1.1 200 OK\r\nServer: ApacheTomcat/9.0\r\n",
	} {
		got := identify(t, banner, 80)
		if got.Product != "" {
			t.Errorf("misidentified non-product token in %q as %q", banner, got.Product)
		}
	}
	// A parenthesized OS marker before the matched product is not product evidence.
	got := identify(t, "HTTP/1.1 200 OK\r\nServer: (Ubuntu) nginx/1.24.0\r\n", 80)
	if got.Product != "nginx" || got.Version != "1.24.0" || got.OSHint != "" {
		t.Fatalf("pre-product annotation should not become OS hint: %+v", got)
	}
	got = identify(t, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Debian-12)\r\n", 80)
	if got.Product != "nginx" || got.OSHint != "Debian" {
		t.Fatalf("post-product parenthesized distro should be recognized: %+v", got)
	}
}

func TestHTTPStatusLineVersionGrammar(t *testing.T) {
	for _, version := range []string{"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0"} {
		got := identify(t, version+" 200 OK\r\nServer: nginx/1.24.0\r\n", 80)
		if got.Protocol != "HTTP" || got.Product != "nginx" {
			t.Errorf("valid status version %q was rejected: %+v", version, got)
		}
	}
	for _, version := range []string{"HTTP/1.", "HTTP/1.10", "HTTP/1.2x", "HTTP/3", "HTTP/1.1x"} {
		got := identify(t, version+" 200 OK\r\nServer: nginx/1.24.0\r\n", 80)
		if got.Protocol != "" || got.Product != "" {
			t.Errorf("malformed or unsupported status version %q matched: %+v", version, got)
		}
	}
}

func TestHTTPDoesNotFingerprintStatusOrBodyAndSimilarProducts(t *testing.T) {
	for _, banner := range []string{
		"HTTP/1.1 200 nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nServer: Apache/2.4.57",
		"HTTP/1.1 200 OK\r\nServer: nginx-proxy/1.24.0\r\n",
		"HTTP/1.1 200 OK\r\nServer: vendor-nginx/1.24.0\r\n",
		"HTTP/1.1 200 OK\r\nServer: ApacheTomcat/9.0\r\n",
		"HTTP/1.x 200 OK\r\nServer: nginx/1.24.0\r\n",
		"HTTP/1.1 20 OK\r\nServer: nginx/1.24.0\r\n",
		"HTTP/1.1 200 OK\r\n",
		"HTTP/1.1 200 OK",
	} {
		got := identify(t, banner, 80)
		if got.Product != "" {
			t.Errorf("misidentified %q as %q", banner, got.Product)
		}
	}
	// Recognized HTTP structure still yields protocol-only identification.
	got := identify(t, "HTTP/1.1 503 Service Unavailable\r\nX-Test: yes\r\n\r\nnginx Apache", 8080)
	if got.Protocol != "HTTP" || got.Product != "" || got.Confidence != .60 {
		t.Fatalf("unexpected protocol fallback: %+v", got)
	}
}

func TestHTTPProductEvidenceOSAndCompleteHeaderBoundary(t *testing.T) {
	cases := []struct {
		name, banner, product, version, os, rule string
	}{
		{"server os hint", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 (Ubuntu)\r\n", "nginx", "1.24.0", "Ubuntu", "http.nginx"},
		{"earlier unrelated os comment", "HTTP/1.1 200 OK\r\nVia: (Ubuntu)\r\nServer: nginx/1.24.0\r\n", "nginx", "1.24.0", "", "http.nginx"},
		{"versionless product", "HTTP/1.1 200 OK\r\nServer: Apache\r\n", "Apache", "", "", "http.apache"},
		{"truncated after full server header", "HTTP/1.1 200 OK\r\nServer: Jetty/11.0.20", "Jetty", "11.0.20", "", "http.jetty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := identify(t, tc.banner, 8443)
			if got.Protocol != "HTTP" || got.Product != tc.product || got.Version != tc.version || got.OSHint != tc.os {
				t.Fatalf("got %+v", got)
			}
			if len(got.Evidence) != 1 || got.Evidence[0].RuleID != tc.rule || got.Evidence[0].Field != "server" {
				t.Fatalf("expected stable server evidence %q, got %+v", tc.rule, got.Evidence)
			}
		})
	}
}

func TestMultipleCandidatesAndStableOrdering(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nServer: Apache/2.4.57\r\n"
	first := identify(t, banner, 80)
	second := identify(t, banner, 443)
	if first.Product != "Apache" || len(first.Candidates) != 2 {
		t.Fatalf("expected score-tied lexical candidates, got %+v", first)
	}
	if first.Candidates[0].Product != "Apache" || first.Candidates[1].Product != "nginx" {
		t.Fatalf("unstable candidates: %+v", first.Candidates)
	}
	if first.Product != second.Product || first.Candidates[0].Product != second.Candidates[0].Product {
		t.Fatal("port affected candidate order")
	}
}

func TestSameProductVersionConflictKeepsEvidenceBackedCandidates(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nServer: nginx/1.25.3\r\nServer: nginx\r\n"
	got := identify(t, banner, 80)
	if got.Product != "nginx" || got.Version != "1.24.0" {
		t.Fatalf("expected deterministic lexical primary version, got %+v", got)
	}
	if len(got.Candidates) != 2 {
		t.Fatalf("expected both supported versions, with versionless duplicate removed: %+v", got.Candidates)
	}
	if got.Candidates[0].Version != "1.24.0" || got.Candidates[1].Version != "1.25.3" {
		t.Fatalf("version candidates are not stably ordered: %+v", got.Candidates)
	}
	for _, candidate := range got.Candidates {
		if len(candidate.Evidence) == 0 || candidate.Evidence[0].RuleID != "http.nginx" {
			t.Errorf("candidate lacks rule evidence: %+v", candidate)
		}
	}
}

func TestMalformedTruncatedMySQLAndTLS(t *testing.T) {
	mysql, err := base64.StdEncoding.DecodeString("SgAAAAo4LjAuMzIA")
	if err != nil {
		t.Fatal(err)
	}
	got := identifyEncoding(t, base64.StdEncoding.EncodeToString(mysql), "base64", 3306)
	if got.Product != "MySQL" || got.Version != "8.0.32" || len(got.Evidence) == 0 || got.Evidence[0].RuleID != "mysql.handshake" {
		t.Fatalf("truncated MySQL greeting not recognized: %+v", got)
	}
	for name, raw := range map[string][]byte{
		"wrong sequence":     {0x4a, 0, 0, 1, 0x0a, '8', '.', '0', '.', '3', '2', 0},
		"wrong protocol":     {0x4a, 0, 0, 0, 0x09, '8', '.', '0', '.', '3', '2', 0},
		"non version":        {0x4a, 0, 0, 0, 0x0a, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0},
		"missing terminator": {0x4a, 0, 0, 0, 0x0a, '8', '.', '0', '.', '3', '2'},
	} {
		t.Run(name, func(t *testing.T) {
			got := identifyEncoding(t, base64.StdEncoding.EncodeToString(raw), "base64", 3306)
			if got.Product != "" {
				t.Fatalf("unexpected MySQL match: %+v", got)
			}
		})
	}
	validTLS := []byte{0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1}
	got = identifyEncoding(t, base64.StdEncoding.EncodeToString(validTLS), "base64", 443)
	if got.Protocol != "TLS" || got.Product != "" || got.Version != "" || got.Confidence != .50 {
		t.Fatalf("TLS must be a limited partial identification: %+v", got)
	}
	if len(got.Evidence) == 0 || got.Evidence[0].Value[:7] != "base64:" {
		t.Fatalf("binary evidence should be base64: %+v", got.Evidence)
	}
	for _, raw := range [][]byte{{0x16, 0x03, 0x01, 0, 4, 0x01, 0, 0, 0}, {0x17, 0x03, 0x03, 0, 20, 0x01, 0, 0, 16}, {0x16, 0x04, 0x01, 0, 9, 0x01, 0, 0, 5}} {
		got := identifyEncoding(t, base64.StdEncoding.EncodeToString(raw), "base64", 443)
		if got.Protocol != "" {
			t.Errorf("invalid TLS fragment matched: %+v", got)
		}
	}
}

func TestUnknownAndFTPProtocolFallback(t *testing.T) {
	if got := identify(t, "QUIT\r\n", 21); got.Protocol != "" || got.Confidence != 0 || len(got.Evidence) != 0 {
		t.Fatalf("QUIT must remain unknown: %+v", got)
	}
	got := identify(t, "220 FTP service ready\r\n", 12345)
	if got.Protocol != "FTP" || got.Product != "" || got.Confidence != .60 {
		t.Fatalf("expected FTP protocol-only result: %+v", got)
	}
}

func TestFTPSimilarProductNamesDoNotMatch(t *testing.T) {
	for _, banner := range []string{"220 ProFTPDX 1.3.7\r\n", "220 NotProFTPD 1.3.7\r\n", "220 Pure-FTPdX\r\n", "220 vsFTPdPlus 3.0.5\r\n"} {
		got := identify(t, banner, 21)
		if got.Product != "" {
			t.Errorf("misidentified similar FTP product in %q as %q", banner, got.Product)
		}
	}
}

func TestReviewFTPFalsePositives(t *testing.T) {
	for _, banner := range []string{"220 mail.example ESMTP service ready\r\n", "220 service ready", "220 SFTP service ready", "220 notftp ready"} {
		if got := identify(t, banner, 21); got.Protocol != "" {
			t.Fatalf("%q misidentified: %+v", banner, got)
		}
	}
}

func TestReviewHTTPRepeatedTokensAndOSScope(t *testing.T) {
	got := identify(t, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 nginx/1.25.3 nginx/1.24.0", 80)
	if len(got.Candidates) != 2 || got.Candidates[0].Version != "1.24.0" || got.Candidates[1].Version != "1.25.3" {
		t.Fatalf("lost versions: %+v", got)
	}
	for _, prefix := range []string{"notnginx/0.1 ", "nginx-proxy/0.1 ", "İ代理 "} {
		got = identify(t, "HTTP/1.1 200 OK\r\nServer: "+prefix+"nginx/1.25.3", 80)
		if got.Product != "nginx" || got.Version != "1.25.3" {
			t.Fatalf("prefix %q: %+v", prefix, got)
		}
	}
	got = identify(t, "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0 Apache/2.4.57 (Ubuntu)", 80)
	if len(got.Candidates) != 2 {
		t.Fatalf("candidates: %+v", got)
	}
	for _, c := range got.Candidates {
		if c.Product == "nginx" && c.OSHint != "" {
			t.Fatal("OS leaked to nginx")
		}
		if c.Product == "Apache" && c.OSHint != "Ubuntu" {
			t.Fatal("Apache OS missing")
		}
	}
}

func TestMySQLDistributionSuffix(t *testing.T) {
	raw := append([]byte{0x4a, 0, 0, 0, 0x0a}, []byte("8.0.36-0ubuntu0.22.04.1\x00")...)
	got := identifyEncoding(t, base64.StdEncoding.EncodeToString(raw), "base64", 9999)
	if got.Product != "MySQL" || got.Version != "8.0.36-0ubuntu0.22.04.1" {
		t.Fatalf("lost server version: %+v", got)
	}
}
