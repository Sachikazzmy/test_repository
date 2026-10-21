package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bannerfingerprint/internal/contract"
)

type fakeBatch struct {
	identify func(context.Context, []contract.Record) ([]contract.Result, error)
	calls    int
}

func (f *fakeBatch) IdentifyBatch(ctx context.Context, records []contract.Record) ([]contract.Result, error) {
	f.calls++
	if f.identify != nil {
		return f.identify(ctx, records)
	}
	return []contract.Result{{Index: 0, IP: records[0].IP, Port: records[0].Port, Status: contract.StatusMatched, Identification: contract.Identification{Protocol: "SSH", Product: "OpenSSH", Version: "9.3", Evidence: []contract.Evidence{}, Candidates: []contract.Candidate{}}, Error: nil}}, nil
}

func testHandler(t *testing.T, batch contract.BatchIdentifier, cfg contract.HTTPConfig) http.Handler {
	t.Helper()
	h, err := New(batch, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func validRequest() string {
	return `{"records":[{"ip":"192.0.2.1","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}]}`
}

func TestIdentifySuccessAndContentTypeParameters(t *testing.T) {
	batch := &fakeBatch{}
	h := testHandler(t, batch, contract.DefaultHTTPConfig())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK || res.Header().Get("Content-Type") != "application/json" || batch.calls != 1 {
		t.Fatalf("status=%d content-type=%q calls=%d body=%s", res.Code, res.Header().Get("Content-Type"), batch.calls, res.Body)
	}
	var got contract.IdentifyResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Results) != 1 || got.Results[0].Protocol != "SSH" || got.Results[0].Product != "OpenSSH" {
		t.Fatalf("unexpected response: %#v", got)
	}
}

func TestIdentifyPartialFailureIsSuccessfulBatch(t *testing.T) {
	batch := &fakeBatch{identify: func(context.Context, []contract.Record) ([]contract.Result, error) {
		return []contract.Result{{Index: 0, Status: contract.StatusInvalid, Identification: contract.EmptyIdentification(), Error: &contract.ItemError{Code: contract.CodeInvalidIP, Message: "IP地址不合法"}}}, nil
	}}
	h := testHandler(t, batch, contract.DefaultHTTPConfig())
	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(res, req)
	var got contract.IdentifyResponse
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if res.Code != http.StatusOK || len(got.Results) != 1 || got.Results[0].Status != contract.StatusInvalid || got.Results[0].Error.Code != contract.CodeInvalidIP {
		t.Fatalf("status=%d response=%#v", res.Code, got)
	}
}

func TestIdentifyRejectsInvalidJSONShapes(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"syntax", `{"records":[}`},
		{"top case", `{"Records":[]}`},
		{"top case override", `{"records":[],"Records":[]}`},
		{"ip case", `{"records":[{"IP":"192.0.2.1","port":22,"banner":"x"}]}`},
		{"ip override", `{"records":[{"ip":"192.0.2.1","IP":"192.0.2.2","port":22,"banner":"x"}]}`},
		{"port override", `{"records":[{"ip":"192.0.2.1","port":22,"Port":80,"banner":"x"}]}`},
		{"banner override", `{"records":[{"ip":"192.0.2.1","port":22,"banner":"x","Banner":"y"}]}`},
		{"encoding case", `{"records":[{"ip":"192.0.2.1","port":22,"banner":"x","Banner_Encoding":"utf8"}]}`},
		{"escaped duplicate key", `{"records":[],"\u0072ecords":[]}`},
		{"deep nesting", `{"records":` + strings.Repeat("[", 1000) + `0` + strings.Repeat("]", 1000) + `}`},
		{"trailing value", validRequest() + ` {}`},
		{"unknown field", `{"records":[],"extra":true}`},
		{"nested unknown", `{"records":[{"ip":"192.0.2.1","port":22,"banner":"x","extra":1}]}`},
		{"duplicate key", `{"records":[],"records":[]}`},
		{"null records", `{"records":null}`},
		{"missing banner", `{"records":[{"ip":"192.0.2.1","port":22}]}`},
		{"null banner encoding", `{"records":[{"ip":"192.0.2.1","port":22,"banner":"x","banner_encoding":null}]}`},
		{"unpaired surrogate", `{"records":[{"ip":"192.0.2.1","port":22,"banner":"\ud800"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batch := &fakeBatch{}
			h := testHandler(t, batch, contract.DefaultHTTPConfig())
			res := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			h.ServeHTTP(res, req)
			assertError(t, res, http.StatusBadRequest, contract.CodeInvalidRequest)
			if batch.calls != 0 {
				t.Fatalf("service called for invalid request: %d", batch.calls)
			}
		})
	}
}

func TestIdentifyRejectsInvalidRawUTF8(t *testing.T) {
	batch := &fakeBatch{}
	h := testHandler(t, batch, contract.DefaultHTTPConfig())
	body := []byte(`{"records":[{"ip":"192.0.2.1","port":22,"banner":"` + string([]byte{0xff}) + `"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	assertError(t, res, http.StatusBadRequest, contract.CodeInvalidRequest)
}

func TestIdentifyRejectsContentTypeAndEncoding(t *testing.T) {
	cases := []struct{ contentType, contentEncoding string }{
		{"", ""}, {"text/json", ""}, {"application/json; bad parameter", ""}, {"application/json", "gzip"},
	}
	for _, tc := range cases {
		batch := &fakeBatch{}
		h := testHandler(t, batch, contract.DefaultHTTPConfig())
		req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
		req.Header.Set("Content-Type", tc.contentType)
		if tc.contentEncoding != "" {
			req.Header.Set("Content-Encoding", tc.contentEncoding)
		}
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		assertError(t, res, http.StatusUnsupportedMediaType, contract.CodeUnsupportedMediaType)
		if batch.calls != 0 {
			t.Fatal("service should not be called")
		}
	}
}

func TestIdentifyBodyLimit(t *testing.T) {
	batch := &fakeBatch{}
	cfg := contract.HTTPConfig{MaxBodyBytes: 16, RequestTimeout: time.Second}
	h := testHandler(t, batch, cfg)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	assertError(t, res, http.StatusRequestEntityTooLarge, contract.CodeBodyTooLarge)
	if batch.calls != 0 {
		t.Fatal("service should not be called for oversized body")
	}
}

func TestIdentifyBusinessAndInternalErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"invalid batch", &contract.Error{Code: contract.CodeInvalidBatch, Message: "批次为空"}, http.StatusBadRequest, contract.CodeInvalidBatch},
		{"internal", errors.New("secret stack trace with banner"), http.StatusInternalServerError, contract.CodeInternalError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			batch := &fakeBatch{identify: func(context.Context, []contract.Record) ([]contract.Result, error) { return nil, tc.err }}
			h := testHandler(t, batch, contract.DefaultHTTPConfig())
			req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
			req.Header.Set("Content-Type", "application/json")
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			assertError(t, res, tc.status, tc.code)
			if strings.Contains(res.Body.String(), "secret stack trace") || strings.Contains(res.Body.String(), "SSH-2.0") {
				t.Fatalf("leaked private data: %s", res.Body)
			}
		})
	}
}

func TestIdentifyTimeoutAndClientCancellation(t *testing.T) {
	batch := &fakeBatch{identify: func(ctx context.Context, _ []contract.Record) ([]contract.Result, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	cfg := contract.HTTPConfig{MaxBodyBytes: 1024, RequestTimeout: 20 * time.Millisecond}
	h := testHandler(t, batch, cfg)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	assertError(t, res, http.StatusGatewayTimeout, contract.CodeRequestTimeout)

	canceled := &fakeBatch{}
	h = testHandler(t, canceled, contract.DefaultHTTPConfig())
	req = httptest.NewRequest(http.MethodPost, "/api/v1/identify", strings.NewReader(validRequest()))
	req.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	res = httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code == http.StatusInternalServerError || canceled.calls != 0 {
		t.Fatalf("cancel mapped incorrectly: status=%d calls=%d body=%s", res.Code, canceled.calls, res.Body)
	}
}

func assertError(t *testing.T, res *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if res.Code != status {
		t.Fatalf("status=%d want=%d body=%s", res.Code, status, res.Body)
	}
	if got := res.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type=%q", got)
	}
	var payload contract.ErrorResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error.Code != code || payload.Error.Message == "" {
		t.Fatalf("error=%#v want code=%q", payload.Error, code)
	}
}
