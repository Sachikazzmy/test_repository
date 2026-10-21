package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (a *api) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.URL.Path != "/api/v1/identify" && r.URL.Path != "/fingerprint") || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		deadline := time.Now().Add(a.config.RequestTimeout)
		controller := http.NewResponseController(w)
		// Supported by net/http server writers; unsupported writers still get context timeout.
		_ = controller.SetReadDeadline(deadline)
		defer func() { _ = controller.SetReadDeadline(time.Time{}) }()

		ctx, cancel := context.WithDeadline(r.Context(), deadline)
		defer cancel()
		r = r.WithContext(ctx)
		r.Body = http.MaxBytesReader(w, r.Body, a.config.MaxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, context.DeadlineExceeded)
}

// validateStrictJSON rejects malformed Unicode, duplicate object keys, trailing
// top-level values, and request shapes that Go's struct decoder would otherwise
// silently accept as zero values.
func validateStrictJSON(data []byte) error {
	if !validJSONUnicode(data) {
		return errors.New("invalid unicode")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("top-level value must be object")
	}
	if err := walkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return validateRequiredFields(data)
}

func walkValue(dec *json.Decoder, depth int) error {
	if depth > 4 {
		return errors.New("JSON nesting exceeds request shape")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		return walkObject(dec, depth)
	case '[':
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("malformed array")
		}
		return nil
	default:
		return errors.New("unexpected delimiter")
	}
}

func walkObject(dec *json.Decoder, depth int) error {
	seen := make(map[string]struct{})
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return errors.New("object key is not string")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate object key")
		}
		seen[key] = struct{}{}
		if err := walkValue(dec, depth+1); err != nil {
			return err
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("malformed object")
	}
	return nil
}

func validateRequiredFields(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return errors.New("top-level object required")
	}
	for key := range top {
		if key != "records" {
			return errors.New("unknown top-level field")
		}
	}
	rawRecords, ok := top["records"]
	if !ok || isJSONNull(rawRecords) {
		return errors.New("records required")
	}
	var records []json.RawMessage
	if err := json.Unmarshal(rawRecords, &records); err != nil || records == nil {
		return errors.New("records array required")
	}
	for _, raw := range records {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return errors.New("record object required")
		}
		for key := range fields {
			switch key {
			case "ip", "port", "banner", "banner_encoding":
			default:
				return errors.New("unknown record field")
			}
		}
		for _, name := range []string{"ip", "port", "banner"} {
			value, exists := fields[name]
			if !exists || isJSONNull(value) {
				return errors.New("required record field missing")
			}
		}
		if value, exists := fields["banner_encoding"]; exists && isJSONNull(value) {
			return errors.New("banner_encoding cannot be null")
		}
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool { return strings.TrimSpace(string(raw)) == "null" }

func validJSONUnicode(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	for i := 0; i < len(data); {
		if data[i] != '"' {
			i++
			continue
		}
		i++
		for i < len(data) && data[i] != '"' {
			if data[i] != '\\' {
				i++
				continue
			}
			i++
			if i >= len(data) {
				return false
			}
			if data[i] != 'u' {
				i++
				continue
			}
			value, ok := unicodeEscape(data, i)
			if !ok {
				return false
			}
			i += 5
			if value >= 0xD800 && value <= 0xDBFF {
				if i+6 > len(data) || data[i] != '\\' || data[i+1] != 'u' {
					return false
				}
				low, ok := unicodeEscape(data, i+1)
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return false
				}
				i += 6
			} else if value >= 0xDC00 && value <= 0xDFFF {
				return false
			}
		}
		if i >= len(data) {
			return false
		}
		i++
	}
	return true
}

func unicodeEscape(data []byte, u int) (uint16, bool) {
	// u points to the 'u' in a \uXXXX sequence.
	if u+5 >= len(data) {
		return 0, false
	}
	var value uint16
	for _, b := range data[u+1 : u+5] {
		value <<= 4
		switch {
		case b >= '0' && b <= '9':
			value |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			value |= uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			value |= uint16(b-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}
