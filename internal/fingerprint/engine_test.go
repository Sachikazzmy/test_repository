package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"

	"bannerfingerprint/internal/contract"
)

func TestSelftestFixtures(t *testing.T) {
	inputBytes, err := os.ReadFile("testdata/selftest-input.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes, err := os.ReadFile("testdata/selftest-expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var input contract.IdentifyRequest
	var expected contract.IdentifyResponse
	if err = json.Unmarshal(inputBytes, &input); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(expectedBytes, &expected); err != nil {
		t.Fatal(err)
	}
	if len(input.Records) != 20 || len(expected.Results) != 20 {
		t.Fatalf("fixture count records=%d expected=%d", len(input.Records), len(expected.Results))
	}
	recognizer, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for i, record := range input.Records {
		t.Run(record.IP, func(t *testing.T) {
			got, err := recognizer.Identify(context.Background(), record)
			if err != nil {
				t.Fatal(err)
			}
			want := expected.Results[i]
			if got.Protocol != want.Protocol || got.Product != want.Product || got.Version != want.Version || got.OSHint != want.OSHint || got.Confidence != want.Confidence {
				t.Errorf("got %+v; want protocol=%q product=%q version=%q os=%q score=%v", got, want.Protocol, want.Product, want.Version, want.OSHint, want.Confidence)
			}
			if want.Status == contract.StatusUnknown && len(got.Evidence) != 0 {
				t.Errorf("unknown result has evidence: %+v", got.Evidence)
			}
			if want.Status == contract.StatusMatched && len(got.Evidence) == 0 {
				t.Error("matched result has no evidence")
			}
		})
	}
}

func TestIdentifyCancellationAndInvalidEncoding(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = r.Identify(ctx, contract.Record{Banner: "SSH-2.0-OpenSSH_9.3"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	_, err = r.Identify(context.Background(), contract.Record{Banner: "%%%", BannerEncoding: "base64"})
	var ce *contract.Error
	if !errors.As(err, &ce) || ce.Code != contract.CodeInvalidEncoding {
		t.Fatalf("got %v, want invalid_encoding", err)
	}
}

func TestConcurrentIdentify(t *testing.T) {
	r, err := New()
	if err != nil {
		t.Fatal(err)
	}
	record := contract.Record{Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"}
	const callers = 64
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			got, err := r.Identify(context.Background(), record)
			if err != nil || got.Product != "nginx" || got.Version != "1.24.0" {
				t.Errorf("got=%+v err=%v", got, err)
			}
		}()
	}
	wg.Wait()
}
