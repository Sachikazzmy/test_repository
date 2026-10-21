package contract_test

import (
	"bannerfingerprint/internal/contract"
	"encoding/json"
	"os"
	"testing"
)

func TestSelftestFixtures(t *testing.T) {
	read := func(name string, v any) {
		t.Helper()
		b, err := os.ReadFile("../../testdata/selftest/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	var input contract.IdentifyRequest
	var expected contract.IdentifyResponse
	var manifest struct {
		Purpose string `json:"purpose"`
		Cases   []struct {
			Index  int    `json:"index"`
			IP     string `json:"ip"`
			Source string `json:"expected_source"`
		} `json:"cases"`
	}
	read("input", &input)
	read("expected", &expected)
	read("manifest", &manifest)
	if len(input.Records) != 20 || len(expected.Results) != 20 || len(manifest.Cases) != 20 || manifest.Purpose != "selftest_not_final_acceptance" {
		t.Fatal("incomplete fixtures")
	}
	for i, r := range input.Records {
		if err := contract.ValidateRecord(r, contract.DefaultServiceConfig().MaxBannerBytes); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		e := expected.Results[i]
		m := manifest.Cases[i]
		if e.Index != i || e.IP != r.IP || e.Port != r.Port || m.Index != i || m.IP != r.IP {
			t.Fatalf("alignment at %d", i)
		}
		source := "contract_inferred"
		if i < 7 {
			source = "user"
		}
		if m.Source != source {
			t.Fatalf("source at %d", i)
		}
	}
	for _, i := range []int{3, 10, 15} {
		if input.Records[i].BannerEncoding != "base64" {
			t.Fatal("binary encoding missing")
		}
	}
	got, _ := contract.DecodeBanner(input.Records[3], 1024)
	if string(got) != "J\x00\x00\x00\x0a8.0.32\x00" {
		t.Fatal("MySQL bytes corrupted")
	}
	got, _ = contract.DecodeBanner(input.Records[15], 1024)
	if string(got) != "\x16\x03\x01\x00\xa5\x01\x00\x00\xa1" {
		t.Fatal("TLS bytes corrupted")
	}
}

func TestResultJSONShape(t *testing.T) {
	r := contract.Result{Index: 3, IP: "::1", Port: 22, Status: contract.StatusUnknown, Identification: contract.EmptyIdentification()}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"index", "ip", "port", "status", "protocol", "product", "version", "os_hint", "confidence", "evidence", "candidates", "error"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("missing %s", key)
		}
	}
	if string(m["evidence"]) != "[]" || string(m["candidates"]) != "[]" || string(m["error"]) != "null" {
		t.Fatal(string(b))
	}
}
