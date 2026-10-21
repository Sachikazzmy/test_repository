package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"unicode/utf8"

	"bannerfingerprint/internal/contract"
	"bannerfingerprint/internal/fingerprint"
	"bannerfingerprint/internal/httpapi"
	"bannerfingerprint/internal/service"
)

func realHandler(t *testing.T, sc contract.ServiceConfig, hc contract.HTTPConfig) http.Handler {
	t.Helper()
	engine, err := fingerprint.New()
	if err != nil {
		t.Fatal(err)
	}
	batch, err := service.New(engine, sc)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := httpapi.New(batch, hc)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func readJSON(t *testing.T, path string, dest any) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, dest); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestServerAllSelftestFixtures(t *testing.T) {
	var input contract.IdentifyRequest
	body := readJSON(t, "../../testdata/selftest/input.json", &input)
	var expected contract.IdentifyResponse
	readJSON(t, "../../testdata/selftest/expected.json", &expected)
	if len(input.Records) != 20 || len(expected.Results) != 20 {
		t.Fatal("expected all 20 fixtures")
	}
	server := httptest.NewServer(realHandler(t, contract.DefaultServiceConfig(), contract.DefaultHTTPConfig()))
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/api/v1/identify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	if response.Header.Get("Content-Type") != "application/json" {
		t.Fatal("incorrect content type")
	}
	var got contract.IdentifyResponse
	if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != len(input.Records) {
		t.Fatalf("got %d results", len(got.Results))
	}
	for i, result := range got.Results {
		t.Run(input.Records[i].IP, func(t *testing.T) {
			want := expected.Results[i]
			record := input.Records[i]
			if result.Index != i || result.Index != want.Index || result.IP != record.IP || result.IP != want.IP || result.Port != record.Port || result.Port != want.Port {
				t.Fatalf("input/output correspondence: %+v", result)
			}
			if result.Status != want.Status || result.Protocol != want.Protocol || result.Product != want.Product || result.Version != want.Version || result.OSHint != want.OSHint || math.IsNaN(result.Confidence) || math.Abs(result.Confidence-want.Confidence) > 1e-9 {
				t.Fatalf("got %+v; want %+v", result, want)
			}
			if result.Error != nil || result.Evidence == nil || result.Candidates == nil {
				t.Fatalf("invalid response shape: %+v", result)
			}
			if want.Status == contract.StatusUnknown && len(result.Evidence) != 0 {
				t.Fatal("unknown has evidence")
			}
			if want.Status == contract.StatusMatched && len(result.Evidence) == 0 {
				t.Fatal("matched lacks evidence")
			}
			for _, e := range result.Evidence {
				if e.RuleID == "" || (e.Field != "banner" && e.Field != "server" && e.Field != "handshake") || len(e.Value) > 256 || !utf8.ValidString(e.Value) {
					t.Fatalf("invalid evidence: %+v", e)
				}
			}
		})
	}
}

func send(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestUnknownPartialInvalidAndDuplicateRecords(t *testing.T) {
	sc := contract.DefaultServiceConfig()
	sc.MaxBannerBytes = 32
	h := realHandler(t, sc, contract.DefaultHTTPConfig())
	records := []contract.Record{
		{IP: "2001:0db8::1", Port: 65535, Banner: "+PONG\r\n"},
		{IP: "192.0.2.2", Port: 80, Banner: ""},
		{IP: "not-an-ip", Port: 80, Banner: "+PONG"},
		{IP: "192.0.2.4", Port: 0, Banner: "+PONG"},
		{IP: "192.0.2.5", Port: 80, Banner: "%%%", BannerEncoding: "base64"},
		{IP: "192.0.2.6", Port: 80, Banner: strings.Repeat("x", 33)},
		{IP: "2001:0db8::1", Port: 65535, Banner: "+PONG\r\n"},
	}
	body, err := json.Marshal(contract.IdentifyRequest{Records: records})
	if err != nil {
		t.Fatal(err)
	}
	w := send(t, h, string(body))
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got contract.IdentifyResponse
	if err = json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != len(records) {
		t.Fatal("record count changed")
	}
	statuses := []string{"matched", "unknown", "invalid", "invalid", "invalid", "invalid", "matched"}
	codes := []string{"", "", contract.CodeInvalidIP, contract.CodeInvalidPort, contract.CodeInvalidEncoding, contract.CodeBannerTooLarge, ""}
	for i, r := range got.Results {
		if r.Index != i || r.IP != records[i].IP || r.Port != records[i].Port || r.Status != statuses[i] {
			t.Fatalf("item %d: %+v", i, r)
		}
		if codes[i] == "" {
			if r.Error != nil {
				t.Fatalf("item %d error: %+v", i, r.Error)
			}
		} else if r.Error == nil || r.Error.Code != codes[i] {
			t.Fatalf("item %d: %+v", i, r.Error)
		}
		if r.Status == "matched" {
			if r.Product != "Redis" {
				t.Fatalf("item %d: %+v", i, r)
			}
		} else if r.Protocol != "" || r.Product != "" || r.Version != "" || r.OSHint != "" || r.Confidence != 0 || len(r.Evidence) != 0 || len(r.Candidates) != 0 {
			t.Fatalf("item %d has unexpected identification", i)
		}
		if r.Evidence == nil || r.Candidates == nil {
			t.Fatal("null collection")
		}
	}
}

func TestRequestErrorsAndLimits(t *testing.T) {
	sc := contract.DefaultServiceConfig()
	sc.MaxBatchSize = 1
	hc := contract.DefaultHTTPConfig()
	hc.MaxBodyBytes = 512
	h := realHandler(t, sc, hc)
	valid := `{"ip":"192.0.2.1","port":80,"banner":""}`
	for _, tc := range []struct {
		name, body, code string
		status           int
	}{
		{"malformed", `{"records":[`, contract.CodeInvalidRequest, 400},
		{"missing banner", `{"records":[{"ip":"192.0.2.1","port":80}]}`, contract.CodeInvalidRequest, 400},
		{"wrong field type", `{"records":[{"ip":"192.0.2.1","port":"80","banner":""}]}`, contract.CodeInvalidRequest, 400},
		{"unknown field", `{"records":[],"extra":true}`, contract.CodeInvalidRequest, 400},
		{"null records", `{"records":null}`, contract.CodeInvalidRequest, 400},
		{"trailing value", `{"records":[]} {}`, contract.CodeInvalidRequest, 400},
		{"empty batch", `{"records":[]}`, contract.CodeInvalidBatch, 400},
		{"batch over limit", `{"records":[` + valid + `,` + valid + `]}`, contract.CodeInvalidBatch, 400},
		{"body over limit", strings.Repeat(" ", 513), contract.CodeBodyTooLarge, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := send(t, h, tc.body)
			var got contract.ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if w.Code != tc.status || got.Error.Code != tc.code || got.Error.Message == "" {
				t.Fatalf("status=%d response=%+v", w.Code, got)
			}
		})
	}
	// Exactly MaxBodyBytes, MaxBatchSize and MaxBannerBytes remain legal.
	sc.MaxBannerBytes = 4
	exact := `{"records":[{"ip":"192.0.2.1","port":80,"banner":"QUIT"}]}`
	hc.MaxBodyBytes = int64(len(exact))
	w := send(t, realHandler(t, sc, hc), exact)
	if w.Code != 200 {
		t.Fatalf("exact boundary rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestHealthRoutingAndCanceledRequest(t *testing.T) {
	h := realHandler(t, contract.DefaultServiceConfig(), contract.DefaultHTTPConfig())
	for _, tc := range []struct {
		method, path string
		status       int
	}{{"GET", "/healthz", 200}, {"POST", "/healthz", 405}, {"GET", "/missing", 404}, {"GET", "/api/v1/identify", 405}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.status {
			t.Fatalf("%s %s: %d", tc.method, tc.path, w.Code)
		}
		if tc.status == 200 && strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` {
			t.Fatal(w.Body.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/api/v1/identify", io.NopCloser(strings.NewReader(`{"records":[]}`))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Body.Len() != 0 {
		t.Fatalf("canceled request wrote response: %s", w.Body.String())
	}
}
