package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"bannerfingerprint/internal/contract"
)

type identifyFunc func(context.Context, contract.Record) (contract.Identification, error)

func (f identifyFunc) Identify(ctx context.Context, record contract.Record) (contract.Identification, error) {
	return f(ctx, record)
}

func testConfig() contract.ServiceConfig {
	return contract.ServiceConfig{MaxBatchSize: 8, MaxBannerBytes: 32, Workers: 3}
}

func validRecord(lastOctet int, banner string) contract.Record {
	return contract.Record{IP: "192.0.2." + itoa(lastOctet), Port: 80, Banner: banner}
}

func TestIdentifyBatchOutcomesValidationAndDuplicates(t *testing.T) {
	var mu sync.Mutex
	calls := make(map[string]int)
	recognizer := identifyFunc(func(_ context.Context, record contract.Record) (contract.Identification, error) {
		mu.Lock()
		calls[record.Banner]++
		mu.Unlock()
		switch record.Banner {
		case "matched":
			id := contract.EmptyIdentification()
			id.Protocol = "HTTP"
			id.Evidence = append(id.Evidence, contract.Evidence{RuleID: "test.rule", Field: "banner", Value: "matched"})
			return id, nil
		case "failure-secret-banner":
			return contract.Identification{}, errors.New("failure-secret-banner: internal details")
		default:
			return contract.Identification{}, nil
		}
	})
	service, err := New(recognizer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	records := []contract.Record{
		validRecord(1, "matched"),
		validRecord(2, "unknown"),
		validRecord(3, "failure-secret-banner"),
		validRecord(4, "matched"), // duplicate payloads remain separate results
		{IP: "not-an-ip", Port: 80, Banner: "invalid"},
	}
	results, err := service.IdentifyBatch(context.Background(), records)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != len(records) {
		t.Fatalf("got %d results, want %d", len(results), len(records))
	}
	wantStatus := []string{contract.StatusMatched, contract.StatusUnknown, contract.StatusFailed, contract.StatusMatched, contract.StatusInvalid}
	for i, result := range results {
		if result.Index != i || result.IP != records[i].IP || result.Port != records[i].Port {
			t.Errorf("result[%d] identity = (%d, %q, %d), want (%d, %q, %d)", i, result.Index, result.IP, result.Port, i, records[i].IP, records[i].Port)
		}
		if result.Status != wantStatus[i] {
			t.Errorf("result[%d].Status = %q, want %q", i, result.Status, wantStatus[i])
		}
		if result.Identification.Evidence == nil || result.Identification.Candidates == nil {
			t.Errorf("result[%d] has nil identification collections", i)
		}
	}
	if results[2].Error == nil || results[2].Error.Code != contract.CodeIdentificationFailed {
		t.Fatalf("failed item error = %#v", results[2].Error)
	}
	if strings.Contains(results[2].Error.Message, "failure-secret-banner") || strings.Contains(results[2].Error.Message, "internal details") {
		t.Fatalf("internal error leaked: %q", results[2].Error.Message)
	}
	if results[4].Error == nil || results[4].Error.Code != contract.CodeInvalidIP {
		t.Fatalf("invalid item error = %#v", results[4].Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["matched"] != 2 || calls["unknown"] != 1 || calls["failure-secret-banner"] != 1 || calls["invalid"] != 0 {
		t.Fatalf("recognizer calls = %#v", calls)
	}
}

func TestNewAndBatchBoundaries(t *testing.T) {
	validRecognizer := identifyFunc(func(context.Context, contract.Record) (contract.Identification, error) {
		return contract.EmptyIdentification(), nil
	})
	if _, err := New(nil, testConfig()); err == nil {
		t.Fatal("New(nil, ...) succeeded")
	}
	var typedNil *nilRecognizer
	if _, err := New(typedNil, testConfig()); err == nil {
		t.Fatal("New(typed nil, ...) succeeded")
	}
	badConfig := testConfig()
	badConfig.Workers = 0
	if _, err := New(validRecognizer, badConfig); err == nil {
		t.Fatal("New accepted invalid config")
	}

	service, err := New(validRecognizer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, records := range [][]contract.Record{nil, {}} {
		if results, err := service.IdentifyBatch(context.Background(), records); err == nil || results != nil {
			t.Fatalf("empty batch = (%#v, %v), want nil and error", results, err)
		} else {
			var publicErr *contract.Error
			if !errors.As(err, &publicErr) || publicErr.Code != contract.CodeInvalidBatch {
				t.Fatalf("empty batch error = %v", err)
			}
		}
	}
	tooMany := make([]contract.Record, testConfig().MaxBatchSize+1)
	for i := range tooMany {
		tooMany[i] = validRecord(i%250+1, "ok")
	}
	if _, err := service.IdentifyBatch(context.Background(), tooMany); err == nil {
		t.Fatal("oversized batch succeeded")
	}
}

func TestBannerLengthBoundaryAndInvalidEncodingDoNotCallRecognizer(t *testing.T) {
	calls := 0
	service, err := New(identifyFunc(func(context.Context, contract.Record) (contract.Identification, error) {
		calls++
		return contract.EmptyIdentification(), nil
	}), testConfig())
	if err != nil {
		t.Fatal(err)
	}
	results, err := service.IdentifyBatch(context.Background(), []contract.Record{
		validRecord(1, strings.Repeat("x", 32)), // exact byte boundary
		validRecord(2, strings.Repeat("x", 33)),
		{IP: "192.0.2.3", Port: 1, Banner: "%%%", BannerEncoding: "base64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Status != contract.StatusUnknown {
		t.Errorf("boundary status = %q, want unknown", results[0].Status)
	}
	if results[1].Status != contract.StatusInvalid || results[1].Error.Code != contract.CodeBannerTooLarge {
		t.Errorf("oversized banner result = %#v", results[1])
	}
	if results[2].Status != contract.StatusInvalid || results[2].Error.Code != contract.CodeInvalidEncoding {
		t.Errorf("invalid encoding result = %#v", results[2])
	}
	if calls != 1 {
		t.Fatalf("recognizer calls = %d, want 1", calls)
	}
}

func TestIdentifyBatchExpiredDeadlineReturnsNoPartialResults(t *testing.T) {
	calls := 0
	service, err := New(identifyFunc(func(context.Context, contract.Record) (contract.Identification, error) {
		calls++
		return contract.EmptyIdentification(), nil
	}), testConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	results, err := service.IdentifyBatch(ctx, []contract.Record{validRecord(1, "valid")})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("IdentifyBatch error = %v, want context.DeadlineExceeded", err)
	}
	if results != nil {
		t.Fatalf("deadline returned results: %#v", results)
	}
	if calls != 0 {
		t.Fatalf("recognizer calls = %d, want 0", calls)
	}
}

type nilRecognizer struct{}

func (*nilRecognizer) Identify(context.Context, contract.Record) (contract.Identification, error) {
	return contract.Identification{}, nil
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	return string(buf[i:])
}
