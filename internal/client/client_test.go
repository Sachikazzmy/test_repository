package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRunArrayAndWrapper(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/fingerprint" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("bad request")
		}
		var rows []map[string]any
		if json.NewDecoder(r.Body).Decode(&rows) != nil || len(rows) != 1 {
			t.Error("bad records")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`[{"ip":"::1","port":22,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}]`))
	}))
	defer s.Close()
	for _, input := range []string{`[{"ip":"::1","port":22,"banner":"QUIT"}]`, `{"records":[{"ip":"::1","port":22,"banner":"QUIT"}]}`} {
		var out bytes.Buffer
		if err := Run(context.Background(), s.URL, strings.NewReader(input), &out, s.Client()); err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		if json.Unmarshal(out.Bytes(), &rows) != nil || rows[0]["protocol"] != "unknown" {
			t.Fatal(out.String())
		}
	}
}

func TestRunErrors(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "private", 500) }))
	defer s.Close()
	for _, input := range []string{`[]`, `oops`, `null`, `{}`} {
		if err := Run(context.Background(), s.URL, strings.NewReader(input), &bytes.Buffer{}, s.Client()); err == nil {
			t.Fatal("expected error")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, s.URL, strings.NewReader(`[]`), &bytes.Buffer{}, s.Client()); err == nil {
		t.Fatal("cancellation ignored")
	}
	if err := Run(context.Background(), "invalid", strings.NewReader(`[]`), &bytes.Buffer{}, &http.Client{Timeout: time.Second}); err == nil {
		t.Fatal("bad URL accepted")
	}
}
