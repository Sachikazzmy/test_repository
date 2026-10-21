# HTTP API

## 本轮契约检查与使用边界

HTTP层只依赖 `internal/contract`，通过 `New(contract.BatchIdentifier, contract.HTTPConfig) (http.Handler, error)` 注入业务能力。构造时拒绝nil、typed-nil依赖及非法配置。当前文档对应模块C；D阶段的运行入口、环境配置和集成测试未完成前，不视为可运行server的交付，也不生成Compose。

请求字段严格区分大小写，只接受 `records`、`ip`、`port`、`banner`、`banner_encoding`。例如同时提交 `ip` 和 `IP` 会返回400 / invalid_request，且不会调用业务服务。转义后相同的重复键也拒绝。JSON遍历深度最多4层（包含标量访问层），超出后立即拒绝；契约合法请求不受影响。

默认请求上限8 MiB、处理期限10秒。读取请求体通过net/http ResponseController设置读取期限，业务处理通过context传播期限；服务端Writer必须支持读取期限才能中断阻塞读取（标准net/http支持）。自定义ResponseWriter包装器应通过Unwrap暴露底层Writer。业务实现须遵守context，HTTP层不会遗弃后台任务来模拟超时。

请求体读取失败时关闭该连接，避免恢复读取期限后net/http继续等待不完整的body；读取超时本身优先映射为504，即使net/http同时取消了请求context。单纯客户端取消仍不映射为500，也不强制输出错误正文。

### 响应字段说明

| 字段 | 含义 |
|---|---|
| results | 与输入等长、顺序一致的结果数组 |
| index / ip / port | 从0开始的输入索引及原始地址、端口 |
| status | matched、unknown、invalid、failed |
| protocol / product / version / os_hint | 识别出的协议、产品、版本、明确OS提示；未知为空字符串 |
| confidence | 冻结规则定义的证据强度，非统计概率 |
| evidence | rule_id、field、value组成的匹配证据数组 |
| candidates | 多候选数组，元素包含识别字段和evidence；无多候选时为空数组 |
| error | 单条错误code/message；正常结果为null |

单条IP、端口、编码或Banner长度错误由service处理并放入结果，HTTP仍返回200。JSON语法、字段类型、缺失/null及字段名错误导致整批400。请求级错误不返回部分results。

### 测试

`handler_test.go` 使用fake BatchIdentifier验证结构化响应、部分失败、严格解析、大小写变体、重复键、大小限制、媒体类型、错误映射和超时。`middleware_test.go` 验证路由、健康检查、构造校验、取消传播、有效Unicode，以及本机临时端口上的真实慢请求体读取超时。测试不连接扫描目标。运行：`go test -race ./internal/httpapi`。

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
