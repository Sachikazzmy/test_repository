package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"bannerfingerprint/internal/contract"
)

type api struct {
	batch  contract.BatchIdentifier
	config contract.HTTPConfig
}

// New creates the HTTP API handler using the frozen shared contract.
func New(batch contract.BatchIdentifier, config contract.HTTPConfig) (http.Handler, error) {
	if batch == nil {
		return nil, &contract.Error{Code: contract.CodeInvalidConfig, Message: "批量识别服务不能为空"}
	}
	if err := contract.ValidateHTTPConfig(config); err != nil {
		return nil, err
	}
	a := &api{batch: batch, config: config}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/identify", a.identify)
	mux.HandleFunc("/healthz", a.health)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		a.writeError(w, http.StatusNotFound, contract.CodeNotFound, "请求路径不存在")
	})
	return a.middleware(mux), nil
}

func (a *api) health(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/healthz" {
		a.writeError(w, http.StatusNotFound, contract.CodeNotFound, "请求路径不存在")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		a.writeError(w, http.StatusMethodNotAllowed, contract.CodeMethodNotAllowed, "请求方法不允许")
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func (a *api) identify(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/identify" {
		a.writeError(w, http.StatusNotFound, contract.CodeNotFound, "请求路径不存在")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		a.writeError(w, http.StatusMethodNotAllowed, contract.CodeMethodNotAllowed, "请求方法不允许")
		return
	}
	if !validContentType(r.Header.Get("Content-Type")) || !validContentEncoding(r.Header.Get("Content-Encoding")) {
		a.writeError(w, http.StatusUnsupportedMediaType, contract.CodeUnsupportedMediaType, "仅支持未压缩的JSON请求")
		return
	}
	if r.Context().Err() != nil {
		a.handleContextEnd(w, r)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if r.Context().Err() != nil {
			a.handleContextEnd(w, r)
			return
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			a.writeError(w, http.StatusRequestEntityTooLarge, contract.CodeBodyTooLarge, "请求体超过大小限制")
			return
		}
		if isTimeout(err) {
			a.writeError(w, http.StatusGatewayTimeout, contract.CodeRequestTimeout, "请求处理超时")
			return
		}
		a.writeError(w, http.StatusBadRequest, contract.CodeInvalidRequest, "请求体无法读取")
		return
	}
	if err := validateStrictJSON(body); err != nil {
		a.writeError(w, http.StatusBadRequest, contract.CodeInvalidRequest, "请求格式不合法")
		return
	}
	var request contract.IdentifyRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil || request.Records == nil {
		a.writeError(w, http.StatusBadRequest, contract.CodeInvalidRequest, "请求格式不合法")
		return
	}
	if r.Context().Err() != nil {
		a.handleContextEnd(w, r)
		return
	}
	results, err := a.batch.IdentifyBatch(r.Context(), request.Records)
	if err != nil {
		a.handleBatchError(w, r, err)
		return
	}
	if r.Context().Err() != nil {
		a.handleContextEnd(w, r)
		return
	}
	writeJSON(w, http.StatusOK, contract.IdentifyResponse{Results: results})
}

func (a *api) handleBatchError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(r.Context().Err(), context.Canceled) {
		return
	}
	if errors.Is(r.Context().Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		a.writeError(w, http.StatusGatewayTimeout, contract.CodeRequestTimeout, "请求处理超时")
		return
	}
	if r.Context().Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	var apiErr *contract.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case contract.CodeInvalidBatch:
			a.writeError(w, http.StatusBadRequest, apiErr.Code, apiErr.Message)
			return
		case contract.CodeInvalidRequest:
			a.writeError(w, http.StatusBadRequest, apiErr.Code, apiErr.Message)
			return
		}
	}
	a.writeError(w, http.StatusInternalServerError, contract.CodeInternalError, "服务内部错误")
}

func (a *api) handleContextEnd(w http.ResponseWriter, r *http.Request) {
	if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
		a.writeError(w, http.StatusGatewayTimeout, contract.CodeRequestTimeout, "请求处理超时")
	}
}

func (a *api) writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, contract.ErrorResponse{Error: contract.ItemError{Code: code, Message: message}})
}

func validContentType(value string) bool {
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func validContentEncoding(value string) bool {
	return value == "" || strings.EqualFold(strings.TrimSpace(value), "identity")
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
