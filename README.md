# Banner 指纹识别后端

Go 后端接收已有扫描数据，识别协议、软件、版本及明确的 OS 提示。当前提供同步 HTTP API、健康检查、批量处理、环境变量配置和有界优雅退出。仅处理提交的数据，不主动连接扫描目标。

## 启动

需要 Go 1.26.0 或更高版本，无第三方依赖。

```sh
go run ./cmd/server
```

默认监听 `:8080`。只监听本机或指定其他地址：

```sh
BANNER_LISTEN_ADDR=127.0.0.1:8080 go run ./cmd/server
```

构建独立程序：

```sh
go build -o /tmp/banner-server ./cmd/server
/tmp/banner-server
```

`Ctrl+C` / SIGINT 或 SIGTERM 会停止接受新连接，等待在途请求；达到退出期限后强制关闭连接并取消请求。配置、绑定或服务运行失败以非零状态退出；正常信号退出状态为零，退出超时会报告错误并以非零状态退出。日志记录监听地址、生命周期和启动错误，默认不记录请求正文、Banner 或证据正文。

## 配置

未设置的变量使用默认值；显式空值、解析失败或超出范围均导致启动失败。业务和接口默认值直接来自 `contract.DefaultServiceConfig()` 与 `contract.DefaultHTTPConfig()`，统一配置入口位于 `internal/config`。

| 环境变量 | 默认值 | 范围与说明 |
|---|---|---|
| `BANNER_LISTEN_ADDR` | `:8080` | TCP host:port，IPv6 使用方括号；启动时实际绑定；端口 0 可用于临时监听 |
| `BANNER_MAX_BATCH_SIZE` | `1000` | 1–10000 条 |
| `BANNER_MAX_BANNER_BYTES` | `65536` | 1–1048576 字节，同时约束编码前和解码后大小 |
| `BANNER_WORKERS` | `8` | 每批 1–256 个 worker，且不超过有效记录数 |
| `BANNER_MAX_BODY_BYTES` | `8388608` | 1–67108864 字节，包含 JSON 与转义开销 |
| `BANNER_REQUEST_TIMEOUT` | `10s` | >0 且 ≤5m；覆盖请求体读取、解析与识别 |
| `BANNER_READ_HEADER_TIMEOUT` | `5s` | >0 且 ≤1m |
| `BANNER_WRITE_TIMEOUT` | `15s` | 必须大于请求超时，且 ≤10m |
| `BANNER_IDLE_TIMEOUT` | `60s` | >0 且 ≤10m |
| `BANNER_SHUTDOWN_TIMEOUT` | `10s` | >0 且 ≤1m |

时间使用 Go duration 格式，例如 `500ms`、`20s`、`1m`。提高请求超时时需同步设置更大的写超时。请求读取由 HTTP 模块设置实际 read deadline；响应写入受 server WriteTimeout 约束。退出使用独立的 shutdown context，正常退出期间不提前取消在途请求。

## API

健康检查不执行识别：

```sh
curl --fail http://127.0.0.1:8080/healthz
```

返回 `{"status":"ok"}`。

批量识别：

```sh
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  --data '{"records":[{"ip":"192.0.2.1","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]}' \
  http://127.0.0.1:8080/api/v1/identify
```

```json
{
  "results": [{
    "index": 0,
    "ip": "192.0.2.1",
    "port": 22,
    "status": "matched",
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95,
    "evidence": [{
      "rule_id": "ssh.openssh",
      "field": "banner",
      "value": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
    }],
    "candidates": [],
    "error": null
  }]
}
```

每条必须包含字符串 `ip`、整数 `port`、字符串 `banner`；空 Banner 合法。`banner_encoding` 可省略或为 `utf8`，二进制使用标准带填充的 `base64`。JSON 转义只处理一次，不解释字面量 `\\r`、`\\n` 或 `\\xNN`。IP 接受 IPv4/IPv6，端口为 1–65535。

响应与输入逐条、按序对应，重复条目分别返回，IP 与端口原样回显。`matched` 表示有协议或产品证据，`unknown` 表示合法但无匹配，`invalid` 表示单条字段值或编码非法，`failed` 表示单条识别器错误。单条错误被隔离，整个请求正常处理时仍返回 200。未知版本与 OS 为空字符串，集合为空数组，无错误时 `error` 为 null。多个候选按契约稳定排序，主结果为第一项。

请求级错误格式：

```json
{"error":{"code":"invalid_request","message":"请求格式不合法"}}
```

| HTTP 状态 | 场景 |
|---|---|
| 400 | JSON、必填字段、类型、未知或重复字段、空批次或批量超限 |
| 413 | 请求体超限 |
| 415 | Content-Type 缺失/不支持，或使用压缩编码 |
| 504 | 请求超时；连接不可写时不保证错误正文送达 |
| 500 | 内部错误，响应不含内部详情 |
| 404 / 405 | 未知路径 / 方法不支持（含 Allow） |

单条 IP、端口、编码和 Banner 长度校验失败以 200 响应中的 `invalid` 表达。取消请求不返回部分成功结果。详细字段、错误码与排序语义见 [公共契约](docs/server-contract.md) 和 [HTTP 文档](docs/http-api.md)。

使用全部自测数据发起请求：

```sh
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  --data-binary @testdata/selftest/input.json \
  http://127.0.0.1:8080/api/v1/identify
```

## 测试

在仓库根目录执行：

```sh
gofmt -l cmd/server internal tests/integration
go test ./...
go test -race ./...
go vet ./...
go build ./...
```

`gofmt -l` 应无输出。`go build ./...` 检查全部包；生成独立程序使用前述 `go build -o` 命令。

集成测试使用真实 engine/service/handler，加载 `testdata/selftest` 的全部 20 条输入和预期结果，逐项比较输入输出对应关系、状态、协议、产品、版本、OS 提示与置信度，并检查证据结构。另覆盖 unknown、重复记录、单条非法/超限与部分失败、请求格式错误、批次数量与请求体边界、取消和健康检查。生命周期测试通过本机临时 listener 验证启动失败、正常退出等待请求、退出超时取消请求与监听资源释放；不依赖外部服务。运行这些测试的环境需允许绑定本机临时端口。

## 规则覆盖与限制

当前覆盖 SSH/OpenSSH；HTTP Server 头中的 nginx、Apache、Jetty、Microsoft-IIS；MySQL greeting 前缀；Redis PONG、NOAUTH 与命令参数错误；FTP 的 ProFTPD、vsFTPd、Pure-FTPd 及协议兜底；截断 TLS 握手记录前缀。详细规则 ID、评分及正反例边界见 [规则说明](docs/fingerprint-rules.md)。端口不能单独构成识别依据，confidence 表示规则证据强度，未经概率校准。

20 条数据属于自测，前 7 条预期由用户提供，后 13 条根据契约推导；通过自测不能宣称达到最终验收深度。MySQL/TLS 截断前缀不能证明完整握手，TLS 不等同于 HTTPS。当前为内存同步处理，worker 上限按每批生效，多个请求的 worker 数量会叠加。

审查发现的FTP通用欢迎语误识别、HTTP同一Server行多版本遗漏、OS注释跨产品关联、JSON大小写变体覆盖及慢请求体超时问题已修复，并提供回归测试。审查范围与实际验证见 [审查记录](docs/CODE_REVIEW.md)。

## Docker Compose

需要Docker及Compose插件。启动后端：

```sh
docker compose up --build -d --wait
curl --fail http://127.0.0.1:8080/healthz
```

提交自测数据可使用上面的curl命令。默认仅发布到本机8080；端口冲突时可执行 `BANNER_HOST_PORT=18080 docker compose up --build -d --wait`。如需更改容器业务配置，在shell或根目录.env中设置配置表中的变量。容器内监听固定为:8080；宿主绑定通过BANNER_BIND_HOST和BANNER_HOST_PORT配置。

```sh
docker compose logs --tail=100 server
docker compose down
```

镜像采用非root、只读文件系统，健康检查访问/healthz。停止期限65秒，覆盖最大60秒的应用退出等待时间。详细方案见 [Compose规划](docs/compose-plan.md)。首次构建需要拉取Go和Alpine基础镜像。

当前Compose交付server后端；client尚未实现，完整client+server系统与最终验收仍属于后续阶段。
