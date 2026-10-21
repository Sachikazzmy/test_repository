package httpapi

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bannerfingerprint/internal/contract"
)

// A real HTTP connection verifies the read deadline interrupts a stalled body;
// a recorder alone cannot prove this behavior.
func TestRequestTimeoutInterruptsBodyRead(t *testing.T) {
	batch := &fakeBatch{}
	cfg := contract.DefaultHTTPConfig()
	cfg.RequestTimeout = 50 * time.Millisecond
	srv := httptest.NewServer(testHandler(t, batch, cfg))
	defer srv.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(srv.URL, "http://"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Write([]byte("POST /api/v1/identify HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload contract.ErrorResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusGatewayTimeout || payload.Error.Code != contract.CodeRequestTimeout {
		t.Fatalf("status=%d payload=%+v", response.StatusCode, payload)
	}
}

func TestValidUnicodeAndOptionalEncoding(t *testing.T) {
	batch := &fakeBatch{identify: func(_ context.Context, records []contract.Record) ([]contract.Result, error) {
		if len(records) != 1 || records[0].Banner != "你好😀" || records[0].BannerEncoding != "utf8" {
			t.Fatalf("unexpected records: %+v", records)
		}
		return []contract.Result{}, nil
	}}
	h := testHandler(t, batch, contract.DefaultHTTPConfig())
	r := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(`{"records":[{"ip":"::1","port":22,"banner":"你好\ud83d\ude00","banner_encoding":"utf8"}]}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || batch.calls != 1 {
		t.Fatalf("status=%d calls=%d", w.Code, batch.calls)
	}
}

func TestHealthRoute(t *testing.T) {
	h := testHandler(t, &fakeBatch{}, contract.DefaultHTTPConfig())
	res := httptest.NewRecorder()
	h.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if res.Code != http.StatusOK || body.Status != "ok" || res.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d body=%#v headers=%v", res.Code, body, res.Header())
	}
}

func TestRoutesReturnStructured404And405(t *testing.T) {
	h := testHandler(t, &fakeBatch{}, contract.DefaultHTTPConfig())
	cases := []struct {
		method, path string
		status       int
		allow        string
		code         string
	}{
		{http.MethodGet, "/api/v1/identify", http.StatusMethodNotAllowed, http.MethodPost, contract.CodeMethodNotAllowed},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed, http.MethodGet, contract.CodeMethodNotAllowed},
		{http.MethodGet, "/missing", http.StatusNotFound, "", contract.CodeNotFound},
		{http.MethodGet, "/api/v1/identify/", http.StatusNotFound, "", contract.CodeNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.path+" "+tc.method, func(t *testing.T) {
			res := httptest.NewRecorder()
			h.ServeHTTP(res, httptest.NewRequest(tc.method, tc.path, nil))
			assertError(t, res, tc.status, tc.code)
			if got := res.Header().Get("Allow"); got != tc.allow {
				t.Fatalf("Allow=%q want=%q", got, tc.allow)
			}
		})
	}
}

func TestNewRejectsNilDependencyAndInvalidConfig(t *testing.T) {
	var typedNil *fakeBatch
	if _, err := New(typedNil, contract.DefaultHTTPConfig()); err == nil {
		t.Fatal("expected typed nil dependency error")
	}
	if _, err := New(nil, contract.DefaultHTTPConfig()); err == nil {
		t.Fatal("expected nil dependency error")
	}
	if _, err := New(&fakeBatch{}, contract.HTTPConfig{}); err == nil {
		t.Fatal("expected invalid config error")
	}
}

func TestContextCancellationPropagatesToBatchService(t *testing.T) {
	started := make(chan struct{})
	observed := make(chan error, 1)
	batch := &fakeBatch{identify: func(ctx context.Context, _ []contract.Record) ([]contract.Result, error) {
		close(started)
		<-ctx.Done()
		observed <- ctx.Err()
		return nil, ctx.Err()
	}}
	h := testHandler(t, batch, contract.DefaultHTTPConfig())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest())).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(res, req)
		close(done)
	}()
	<-started
	cancel()
	<-done
	if err := <-observed; err != context.Canceled {
		t.Fatalf("service context error=%v", err)
	}
	if res.Code == http.StatusInternalServerError {
		t.Fatalf("cancellation mapped to 500: %s", res.Body)
	}
}
