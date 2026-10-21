package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bannerfingerprint/internal/contract"
)

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
