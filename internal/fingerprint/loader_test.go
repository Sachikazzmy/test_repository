package fingerprint

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"bannerfingerprint/internal/contract"
	ruledata "bannerfingerprint/rules"
)

func TestExternalRulesChangeRecognitionWithoutCodeChange(t *testing.T) {
	var file struct {
		Rules []definition `json:"rules"`
	}
	if err := json.Unmarshal(ruledata.Default, &file); err != nil {
		t.Fatal(err)
	}
	file.Rules = append(file.Rules, definition{ID: "http.custom", Protocol: "HTTP", Product: "ExampleServer", Token: "example-server", Confidence: .88, Versionless: .6})
	b, _ := json.Marshal(file)
	path := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	e, err := NewFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.Identify(context.Background(), contract.Record{Banner: "HTTP/1.1 200 OK\r\nServer: example-server/3.2.1"})
	if err != nil || got.Product != "ExampleServer" || got.Version != "3.2.1" || got.Confidence != .88 {
		t.Fatalf("got %+v err %v", got, err)
	}
}

func TestInvalidRuleFiles(t *testing.T) {
	for _, data := range [][]byte{nil, []byte(`{"rules":[]}`), []byte(`{"extra":true}`), append(append([]byte{}, ruledata.Default...), []byte(` {}`)...)} {
		if _, err := LoadRules(data); err == nil {
			t.Fatal("invalid rules accepted")
		}
	}
	if _, err := NewFromFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing rule file accepted")
	}
	var file struct {
		Rules []definition `json:"rules"`
	}
	json.Unmarshal(ruledata.Default, &file)
	file.Rules[0].Pattern = "["
	b, _ := json.Marshal(file)
	if _, err := LoadRules(b); err == nil {
		t.Fatal("invalid regex accepted")
	}
}
