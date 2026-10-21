// Package client sends local scan data to a fingerprint server.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Run accepts a JSON array or the legacy records wrapper, and prints the server's array.
func Run(ctx context.Context, server string, input io.Reader, output io.Writer, transport *http.Client) error {
	u, err := url.Parse(server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("invalid server URL")
	}
	data, err := io.ReadAll(io.LimitReader(input, 8388609))
	if err != nil {
		return err
	}
	if len(data) > 8388608 {
		return fmt.Errorf("input exceeds 8 MiB")
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '{' {
		var wrapper struct {
			Records json.RawMessage `json:"records"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return fmt.Errorf("invalid input JSON")
		}
		data = wrapper.Records
	}
	if !json.Valid(data) || len(data) == 0 || data[0] != '[' {
		return fmt.Errorf("input must be a JSON array or records wrapper")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/fingerprint", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := transport.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer response.Body.Close()
	b, err := io.ReadAll(io.LimitReader(response.Body, 16777217))
	if err != nil {
		return err
	}
	if len(b) > 16777216 {
		return fmt.Errorf("response too large")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned HTTP %d", response.StatusCode)
	}
	var values []json.RawMessage
	if err := json.Unmarshal(b, &values); err != nil || values == nil {
		return fmt.Errorf("invalid server result array")
	}
	enc := json.NewEncoder(output)
	enc.SetIndent("", "  ")
	return enc.Encode(values)
}
