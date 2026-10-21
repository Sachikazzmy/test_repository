// Package config loads and validates server configuration from the environment.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"bannerfingerprint/internal/contract"
)

type Config struct {
	RulesPath         string
	ListenAddr        string
	Service           contract.ServiceConfig
	HTTP              contract.HTTPConfig
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

// Default reuses the shared business and HTTP defaults.
func Default() Config {
	return Config{
		ListenAddr: ":8080", Service: contract.DefaultServiceConfig(), HTTP: contract.DefaultHTTPConfig(),
		ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 60 * time.Second, ShutdownTimeout: 10 * time.Second,
	}
}

func Load() (Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom distinguishes an unset variable from an explicitly empty value.
func LoadFrom(lookup func(string) (string, bool)) (Config, error) {
	c := Default()
	if value, ok := lookupRulePath(lookup); ok {
		if value == "" {
			return Config{}, invalid("BANNER_RULES_PATH")
		}
		c.RulesPath = value
	}
	if lookup == nil {
		return Config{}, invalid("环境变量读取器")
	}
	if value, ok := lookup("BANNER_LISTEN_ADDR"); ok {
		c.ListenAddr = value
	}
	for _, entry := range []struct {
		name string
		dest *int
	}{
		{"BANNER_MAX_BATCH_SIZE", &c.Service.MaxBatchSize},
		{"BANNER_MAX_BANNER_BYTES", &c.Service.MaxBannerBytes},
		{"BANNER_WORKERS", &c.Service.Workers},
	} {
		if value, ok := lookup(entry.name); ok {
			n, err := strconv.Atoi(value)
			if err != nil {
				return Config{}, invalid(entry.name)
			}
			*entry.dest = n
		}
	}
	if value, ok := lookup("BANNER_MAX_BODY_BYTES"); ok {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return Config{}, invalid("BANNER_MAX_BODY_BYTES")
		}
		c.HTTP.MaxBodyBytes = n
	}
	for _, entry := range []struct {
		name string
		dest *time.Duration
	}{
		{"BANNER_REQUEST_TIMEOUT", &c.HTTP.RequestTimeout},
		{"BANNER_READ_HEADER_TIMEOUT", &c.ReadHeaderTimeout},
		{"BANNER_WRITE_TIMEOUT", &c.WriteTimeout},
		{"BANNER_IDLE_TIMEOUT", &c.IdleTimeout},
		{"BANNER_SHUTDOWN_TIMEOUT", &c.ShutdownTimeout},
	} {
		if value, ok := lookup(entry.name); ok {
			n, err := time.ParseDuration(value)
			if err != nil {
				return Config{}, invalid(entry.name)
			}
			*entry.dest = n
		}
	}
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

func Validate(c Config) error {
	if err := contract.ValidateServiceConfig(c.Service); err != nil {
		return err
	}
	if err := contract.ValidateHTTPConfig(c.HTTP); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(c.ListenAddr)
	if err != nil || strings.TrimSpace(c.ListenAddr) != c.ListenAddr || strings.ContainsAny(host, " \t\r\n") {
		return invalid("BANNER_LISTEN_ADDR")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return invalid("BANNER_LISTEN_ADDR")
	}
	for _, entry := range []struct {
		name       string
		value, max time.Duration
	}{
		{"BANNER_READ_HEADER_TIMEOUT", c.ReadHeaderTimeout, time.Minute},
		{"BANNER_IDLE_TIMEOUT", c.IdleTimeout, 10 * time.Minute},
		{"BANNER_SHUTDOWN_TIMEOUT", c.ShutdownTimeout, time.Minute},
	} {
		if entry.value <= 0 || entry.value > entry.max {
			return invalid(entry.name)
		}
	}
	if c.WriteTimeout <= c.HTTP.RequestTimeout || c.WriteTimeout > 10*time.Minute {
		return invalid("BANNER_WRITE_TIMEOUT（须大于请求超时且不超过10m）")
	}
	return nil
}

func invalid(name string) error {
	return &contract.Error{Code: contract.CodeInvalidConfig, Message: fmt.Sprintf("%s 配置不合法", name)}
}

func lookupRulePath(lookup func(string) (string, bool)) (string, bool) {
	if lookup == nil {
		return "", false
	}
	return lookup("BANNER_RULES_PATH")
}
