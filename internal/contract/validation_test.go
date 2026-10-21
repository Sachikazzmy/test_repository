package contract_test

import (
	"bannerfingerprint/internal/contract"
	"errors"
	"testing"
)

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var target *contract.Error
	if !errors.As(err, &target) || target.Code != code {
		t.Fatalf("got %v, want code %s", err, code)
	}
}

func TestValidateRecord(t *testing.T) {
	for _, tc := range []struct {
		ip   string
		port int
		code string
	}{
		{"1.2.3.4", 1, ""}, {"::1", 65535, ""}, {"::ffff:192.0.2.1", 22, ""},
		{"localhost", 22, contract.CodeInvalidIP}, {" 1.2.3.4", 22, contract.CodeInvalidIP},
		{"1.2.3.4:22", 22, contract.CodeInvalidIP}, {"fe80::1%en0", 22, contract.CodeInvalidIP},
		{"1.2.3.4", 0, contract.CodeInvalidPort}, {"1.2.3.4", 65536, contract.CodeInvalidPort},
	} {
		t.Run(tc.ip, func(t *testing.T) {
			assertCode(t, contract.ValidateRecord(contract.Record{IP: tc.ip, Port: tc.port}, 16), tc.code)
		})
	}
	r := contract.Record{IP: "bad", Port: 0, BannerEncoding: "bad"}
	assertCode(t, contract.ValidateRecord(r, 16), contract.CodeInvalidIP)
	r.IP = "::1"
	assertCode(t, contract.ValidateRecord(r, 16), contract.CodeInvalidPort)
}

func TestErrorSafeWrapping(t *testing.T) {
	cause := errors.New("private banner")
	err := &contract.Error{Code: contract.CodeInternalError, Message: "safe", Cause: cause}
	if err.Error() != "internal_error: safe" || !errors.Is(err, cause) {
		t.Fatal("unsafe error or broken unwrap")
	}
}
