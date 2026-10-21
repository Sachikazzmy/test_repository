package contract

import (
	"encoding/base64"
	"net/netip"
	"unicode/utf8"
)

// DecodeBanner validates encoding and limits before allocating decoded bytes.
// It does not unescape text or validate the record's address and port.
func DecodeBanner(record Record, maxBytes int) ([]byte, error) {
	if maxBytes < 1 || maxBytes > MaxBannerBytes {
		return nil, &Error{Code: CodeInvalidConfig, Message: "Banner长度配置超出允许范围"}
	}
	encoding := record.BannerEncoding
	if encoding != "" && encoding != "utf8" && encoding != "base64" {
		return nil, &Error{Code: CodeInvalidEncoding, Message: "不支持的Banner编码"}
	}
	if len(record.Banner) > maxBytes {
		return nil, &Error{Code: CodeBannerTooLarge, Message: "Banner超过字节上限"}
	}
	if encoding != "base64" {
		if !utf8.ValidString(record.Banner) {
			return nil, &Error{Code: CodeInvalidEncoding, Message: "Banner不是有效UTF-8"}
		}
		return []byte(record.Banner), nil
	}
	// DecodeString ignores CR/LF even in Strict mode, so validate alphabet first.
	for i := 0; i < len(record.Banner); i++ {
		b := record.Banner[i]
		if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=') {
			return nil, &Error{Code: CodeInvalidEncoding, Message: "Banner不是规范base64"}
		}
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(record.Banner)
	if err != nil {
		return nil, &Error{Code: CodeInvalidEncoding, Message: "Banner不是规范base64"}
	}
	if len(decoded) > maxBytes {
		return nil, &Error{Code: CodeBannerTooLarge, Message: "Banner超过字节上限"}
	}
	return decoded, nil
}

func ValidateRecord(record Record, maxBytes int) error {
	addr, err := netip.ParseAddr(record.IP)
	if err != nil || addr.Zone() != "" {
		return &Error{Code: CodeInvalidIP, Message: "IP地址不合法"}
	}
	if record.Port < 1 || record.Port > 65535 {
		return &Error{Code: CodeInvalidPort, Message: "端口不合法"}
	}
	_, err = DecodeBanner(record, maxBytes)
	return err
}
