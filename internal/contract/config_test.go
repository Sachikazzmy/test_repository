package contract_test

import (
	"bannerfingerprint/internal/contract"
	"testing"
	"time"
)

func TestConfigBounds(t *testing.T) {
	assertCode(t, contract.ValidateServiceConfig(contract.DefaultServiceConfig()), "")
	assertCode(t, contract.ValidateHTTPConfig(contract.DefaultHTTPConfig()), "")
	for _, c := range []contract.ServiceConfig{{1, 1, 1}, {10000, 1048576, 256}} {
		assertCode(t, contract.ValidateServiceConfig(c), "")
	}
	for _, c := range []contract.ServiceConfig{{0, 1, 1}, {10001, 1, 1}, {1, 0, 1}, {1, 1048577, 1}, {1, 1, 0}, {1, 1, 257}} {
		assertCode(t, contract.ValidateServiceConfig(c), contract.CodeInvalidConfig)
	}
	for _, c := range []contract.HTTPConfig{{1, time.Nanosecond}, {67108864, 5 * time.Minute}} {
		assertCode(t, contract.ValidateHTTPConfig(c), "")
	}
	for _, c := range []contract.HTTPConfig{{0, time.Second}, {67108865, time.Second}, {1, 0}, {1, 5*time.Minute + 1}} {
		assertCode(t, contract.ValidateHTTPConfig(c), contract.CodeInvalidConfig)
	}
}
