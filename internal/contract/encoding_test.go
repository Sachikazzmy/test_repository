package contract_test

import (
	"bannerfingerprint/internal/contract"
	"testing"
)

func TestDecodeBanner(t *testing.T) {
	for _, tc := range []struct {
		name, encoding, input, want, code string
		limit                             int
	}{
		{"empty", "", "", "", "", 1},
		{"binary", "base64", "AP8=", "\x00\xff", "", 4},
		{"literal escapes", "utf8", `\r\n`, `\r\n`, "", 4},
		{"nul", "utf8", "\x00\r\n", "\x00\r\n", "", 3},
		{"unicode boundary", "utf8", "中", "中", "", 3},
		{"unicode over", "utf8", "中", "", contract.CodeBannerTooLarge, 2},
		{"invalid utf8", "utf8", "\xff", "", contract.CodeInvalidEncoding, 4},
		{"whitespace", "base64", "YQ==\n", "", contract.CodeInvalidEncoding, 8},
		{"url alphabet", "base64", "__8=", "", contract.CodeInvalidEncoding, 4},
		{"no padding", "base64", "YQ", "", contract.CodeInvalidEncoding, 4},
		{"noncanonical bits", "base64", "YR==", "", contract.CodeInvalidEncoding, 4},
		{"encoded limit", "base64", "YQ==", "", contract.CodeBannerTooLarge, 3},
		{"encoding precedence", "unknown", "long", "", contract.CodeInvalidEncoding, 1},
		{"zero limit", "", "", "", contract.CodeInvalidConfig, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := contract.Record{Banner: tc.input, BannerEncoding: tc.encoding}
			got, err := contract.DecodeBanner(r, tc.limit)
			assertCode(t, err, tc.code)
			if err == nil && string(got) != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if r.Banner != tc.input {
				t.Fatal("mutated input")
			}
		})
	}
}
