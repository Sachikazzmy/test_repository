package contract

import "time"

const (
	MaxBannerBytes          = 1048576
	MaxBatchSize            = 10000
	MaxWorkers              = 256
	MaxBodyBytes      int64 = 67108864
	MaxRequestTimeout       = 5 * time.Minute
)

type ServiceConfig struct {
	MaxBatchSize   int
	MaxBannerBytes int
	Workers        int
}

type HTTPConfig struct {
	MaxBodyBytes   int64
	RequestTimeout time.Duration
}

func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{MaxBatchSize: 1000, MaxBannerBytes: 65536, Workers: 8}
}

func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{MaxBodyBytes: 8388608, RequestTimeout: 10 * time.Second}
}

func ValidateServiceConfig(c ServiceConfig) error {
	if c.MaxBatchSize < 1 || c.MaxBatchSize > MaxBatchSize || c.MaxBannerBytes < 1 || c.MaxBannerBytes > MaxBannerBytes || c.Workers < 1 || c.Workers > MaxWorkers {
		return &Error{Code: CodeInvalidConfig, Message: "业务配置超出允许范围"}
	}
	return nil
}

func ValidateHTTPConfig(c HTTPConfig) error {
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > MaxBodyBytes || c.RequestTimeout <= 0 || c.RequestTimeout > MaxRequestTimeout {
		return &Error{Code: CodeInvalidConfig, Message: "HTTP配置超出允许范围"}
	}
	return nil
}
