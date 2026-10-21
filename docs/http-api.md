# HTTP API

The HTTP transport is implemented by `internal/httpapi` and exposes a synchronous
batch identification endpoint. It receives only user supplied scan records; it
does not connect to the listed hosts.

## Endpoints

### `POST /api/v1/identify`

Send one JSON object with a `records` array. Each record has:

| Field | Type | Required | Meaning |
|---|---|---:|---|
| `ip` | string | yes | IPv4 or IPv6 address. Value validation is performed by the service. |
| `port` | integer | yes | Port number. Value validation is performed by the service. |
| `banner` | string | yes | Original banner text or encoded bytes; an empty string is allowed. |
| `banner_encoding` | string | no | `utf8` (default) or padded RFC 4648 `base64`. |

The request must use `Content-Type: application/json`; legal media type
parameters such as `charset=utf-8` are accepted. A missing or different media
type is rejected. Compressed request bodies are not supported; an absent or
`identity` `Content-Encoding` is accepted.

The parser rejects unknown fields, duplicate JSON keys, malformed UTF-8 or
unpaired Unicode surrogates, missing/null required fields, `records: null`, and
trailing JSON values. It does not reinterpret literal `\\r` or `\\n` sequences.
The whole JSON document is parsed and checked before the batch service is
called. Per-record IP, port, banner encoding, and banner size validation belongs
to the service.

Successful processing, including unknown and per-record invalid/failed results,
returns HTTP 200:

```json
{
  "results": [
    {
      "index": 0,
      "ip": "192.0.2.1",
      "port": 22,
      "status": "matched",
      "protocol": "SSH",
      "product": "OpenSSH",
      "version": "9.3",
      "os_hint": "",
      "confidence": 0.9,
      "evidence": [],
      "candidates": [],
      "error": null
    }
  ]
}
```

Request-level errors use this JSON shape:

```json
{"error":{"code":"invalid_request","message":"请求格式不合法"}}
```

| HTTP status | Error code | Meaning |
|---:|---|---|
| 400 | `invalid_request` | Invalid JSON, required fields, types, unknown/duplicate fields, or trailing value. |
| 400 | `invalid_batch` | Batch service rejected the batch. |
| 413 | `body_too_large` | Request body exceeded the configured byte limit. |
| 415 | `unsupported_media_type` | Content-Type or Content-Encoding is unsupported. |
| 504 | `request_timeout` | The configured request deadline expired. |
| 500 | `internal_error` | An unexpected service failure occurred. Internal details are not returned. |
| 404 | `not_found` | No endpoint exists at this path. |
| 405 | `method_not_allowed` | The path exists but the method is unsupported; `Allow` lists supported methods. |

A disconnected/cancelled client is not converted into an internal server error;
the handler stops processing and does not attempt to write an error response.
Request size and timeout are set with `contract.HTTPConfig`; use
`contract.DefaultHTTPConfig()` for the documented defaults (8 MiB body and 10
seconds). The API does not log request bodies or banners.

Example request:

```sh
curl --fail-with-body \
  -H 'Content-Type: application/json; charset=utf-8' \
  --data '{"records":[{"ip":"192.0.2.1","port":22,"banner":"SSH-2.0-OpenSSH_9.3"}]}' \
  http://127.0.0.1:8080/api/v1/identify
```

Example invalid request:

```sh
curl --include \
  -H 'Content-Type: application/json' \
  --data '{"records":null}' \
  http://127.0.0.1:8080/api/v1/identify
```

### `GET /healthz`

Returns `200 OK` and `{"status":"ok"}` when the HTTP handler is responsive.
This endpoint does not check scan targets or perform fingerprinting.

```sh
curl --fail http://127.0.0.1:8080/healthz
```
