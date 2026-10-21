package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"bannerfingerprint/internal/client"
	"bannerfingerprint/internal/contract"
)

func TestDeliveryClientServerAllFixtures(t *testing.T) {
	s := httptest.NewServer(realHandler(t, contract.DefaultServiceConfig(), contract.DefaultHTTPConfig()))
	defer s.Close()
	f, err := os.Open("../../testdata/selftest/input.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out bytes.Buffer
	if err := client.Run(context.Background(), s.URL, f, &out, s.Client()); err != nil {
		t.Fatal(err)
	}
	var got []contract.Result
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var want contract.IdentifyResponse
	readJSON(t, "../../testdata/selftest/expected.json", &want)
	if len(got) != 20 {
		t.Fatal("incomplete results")
	}
	for i, r := range got {
		w := want.Results[i]
		if w.Protocol == "" {
			w.Protocol = "unknown"
		}
		if r.IP != w.IP || r.Port != w.Port || r.Protocol != w.Protocol || r.Product != w.Product || r.Version != w.Version || r.OSHint != w.OSHint || r.Confidence != w.Confidence {
			t.Fatalf("row %d got %+v want %+v", i, r, w)
		}
	}
	response, err := s.Client().Get(s.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("health failed")
	}
}
