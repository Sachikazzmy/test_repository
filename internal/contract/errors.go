package contract

const (
	CodeInvalidRequest       = "invalid_request"
	CodeInvalidBatch         = "invalid_batch"
	CodeInvalidIP            = "invalid_ip"
	CodeInvalidPort          = "invalid_port"
	CodeInvalidEncoding      = "invalid_encoding"
	CodeBannerTooLarge       = "banner_too_large"
	CodeIdentificationFailed = "identification_failed"
	CodeBodyTooLarge         = "body_too_large"
	CodeUnsupportedMediaType = "unsupported_media_type"
	CodeRequestTimeout       = "request_timeout"
	CodeInternalError        = "internal_error"
	CodeNotFound             = "not_found"
	CodeMethodNotAllowed     = "method_not_allowed"
	CodeInvalidConfig        = "invalid_config"
)

// Error holds a safe public message and an optional private cause.
type Error struct {
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func (e *Error) Unwrap() error { return e.Cause }
