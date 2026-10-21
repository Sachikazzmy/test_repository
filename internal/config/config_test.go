package config

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"bannerfingerprint/internal/contract"
)

func loadMap(values map[string]string) (Config, error) {
	return LoadFrom(func(name string) (string, bool) { v, ok := values[name]; return v, ok })
}

func TestDefaultsReuseContract(t *testing.T) {
	got, err := loadMap(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, Default()) || got.Service != contract.DefaultServiceConfig() || got.HTTP != contract.DefaultHTTPConfig() {
		t.Fatalf("defaults drifted: %+v", got)
	}
}

func TestAllEnvironmentOverrides(t *testing.T) {
	got, err := loadMap(map[string]string{
		"BANNER_LISTEN_ADDR": "[::1]:0", "BANNER_MAX_BATCH_SIZE": "25", "BANNER_MAX_BANNER_BYTES": "2048",
		"BANNER_WORKERS": "3", "BANNER_MAX_BODY_BYTES": "16384", "BANNER_REQUEST_TIMEOUT": "20s",
		"BANNER_READ_HEADER_TIMEOUT": "2s", "BANNER_WRITE_TIMEOUT": "21s", "BANNER_IDLE_TIMEOUT": "30s", "BANNER_SHUTDOWN_TIMEOUT": "3s",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{ListenAddr: "[::1]:0", Service: contract.ServiceConfig{MaxBatchSize: 25, MaxBannerBytes: 2048, Workers: 3}, HTTP: contract.HTTPConfig{MaxBodyBytes: 16384, RequestTimeout: 20 * time.Second}, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 21 * time.Second, IdleTimeout: 30 * time.Second, ShutdownTimeout: 3 * time.Second}
	if got != want {
		t.Fatalf("got %+v; want %+v", got, want)
	}
}

func TestInvalidEnvironment(t *testing.T) {
	cases := map[string][]string{
		"BANNER_LISTEN_ADDR":      {"", "localhost", "127.0.0.1:-1", ":65536", ":http", " :8080"},
		"BANNER_MAX_BATCH_SIZE":   {"", "0", "10001", "1.5", "999999999999999999999999"},
		"BANNER_MAX_BANNER_BYTES": {"", "0", "1048577"}, "BANNER_WORKERS": {"", "0", "257"},
		"BANNER_MAX_BODY_BYTES":      {"", "0", "67108865", "99999999999999999999999"},
		"BANNER_REQUEST_TIMEOUT":     {"", "0", "-1s", "301s", "5", "bogus"},
		"BANNER_READ_HEADER_TIMEOUT": {"", "0", "61s"}, "BANNER_WRITE_TIMEOUT": {"", "0", "10s", "601s"},
		"BANNER_IDLE_TIMEOUT": {"", "0", "601s"}, "BANNER_SHUTDOWN_TIMEOUT": {"", "0", "61s"},
	}
	for name, values := range cases {
		for _, value := range values {
			t.Run(name+"/"+value, func(t *testing.T) {
				_, err := loadMap(map[string]string{name: value})
				var public *contract.Error
				if !errors.As(err, &public) || public.Code != contract.CodeInvalidConfig {
					t.Fatalf("got %v", err)
				}
			})
		}
	}
	if _, err := LoadFrom(nil); err == nil {
		t.Fatal("nil lookup accepted")
	}
}

func TestBoundsAndTimeoutRelationship(t *testing.T) {
	for _, values := range []map[string]string{
		{"BANNER_MAX_BATCH_SIZE": "1", "BANNER_MAX_BANNER_BYTES": "1", "BANNER_WORKERS": "1", "BANNER_MAX_BODY_BYTES": "1", "BANNER_REQUEST_TIMEOUT": "1ns", "BANNER_WRITE_TIMEOUT": "2ns"},
		{"BANNER_MAX_BATCH_SIZE": "10000", "BANNER_MAX_BANNER_BYTES": "1048576", "BANNER_WORKERS": "256", "BANNER_MAX_BODY_BYTES": "67108864", "BANNER_REQUEST_TIMEOUT": "5m", "BANNER_WRITE_TIMEOUT": "10m", "BANNER_READ_HEADER_TIMEOUT": "1m", "BANNER_IDLE_TIMEOUT": "10m", "BANNER_SHUTDOWN_TIMEOUT": "1m"},
	} {
		if _, err := loadMap(values); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadMap(map[string]string{"BANNER_REQUEST_TIMEOUT": "15s"}); err == nil {
		t.Fatal("write timeout equal to request timeout accepted")
	}
	c := Default()
	c.ReadHeaderTimeout = -time.Second
	if err := Validate(c); err == nil {
		t.Fatal("invalid programmatic config accepted")
	}
}

func TestLoadUsesProcessEnvironmentAndDoesNotEchoInvalidValue(t *testing.T) {
	values := map[string]string{
		"BANNER_LISTEN_ADDR": "127.0.0.1:0", "BANNER_MAX_BATCH_SIZE": "100", "BANNER_MAX_BANNER_BYTES": "1024",
		"BANNER_WORKERS": "3", "BANNER_MAX_BODY_BYTES": "8192", "BANNER_REQUEST_TIMEOUT": "1s",
		"BANNER_READ_HEADER_TIMEOUT": "1s", "BANNER_WRITE_TIMEOUT": "2s", "BANNER_IDLE_TIMEOUT": "3s", "BANNER_SHUTDOWN_TIMEOUT": "1s",
	}
	for name, value := range values {
		t.Setenv(name, value)
	}
	got, err := Load()
	if err != nil || got.Service.Workers != 3 {
		t.Fatalf("Load: %+v, %v", got, err)
	}
	t.Setenv("BANNER_WORKERS", "private-invalid-value")
	_, err = Load()
	if err == nil || !strings.Contains(err.Error(), "BANNER_WORKERS") || strings.Contains(err.Error(), "private-invalid-value") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestExternalRulePath(t *testing.T) {
	got, err := loadMap(map[string]string{"BANNER_RULES_PATH": "/app/rules/rules.json"})
	if err != nil || got.RulesPath != "/app/rules/rules.json" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := loadMap(map[string]string{"BANNER_RULES_PATH": ""}); err == nil {
		t.Fatal("explicit empty path accepted")
	}
}
