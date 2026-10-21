# Server 契约

## 最小交付公开契约（优先于下文旧接口）

新增 `POST /fingerprint`：请求为Record数组，响应为七字段数组（ip、port、protocol、product、version、os_hint、confidence），无识别或单条非法时protocol为`unknown`、评分0。其他未知字符串为空。新增 `GET /health`，只在规则加载成功并启动后可用。独立client读取数组或旧records包装文件，统一调用/fingerprint并输出数组。旧路径和下文详细内部模型保留兼容，不作为题目公开响应格式。新增BANNER_RULES_PATH选择外部规则文件，Compose默认只读挂载rules/rules.json。

## 原内部契约 v1

本文固定首版后端公共接口，供模块独立实现和测试。用户已提供 20 条自测输入、前 7 条预期输出；这些不是最终验收数据。后续最终验收可能扩展规则覆盖范围。公共实现已补齐至 `go.mod`、`internal/contract/**` 和 `testdata/selftest/**`；不包含识别引擎、client 或 Compose，也不自动启动 subagents。

本文优先于 `docs/SUBAGENT_TASKS.md` 中早期候选契约，尤其是扁平识别字段、OS 提示和评分定义。开发 agent 不得自行修改公共契约；变更应先更新本文并协调所有消费者。

## 1. 工程边界

- module：`bannerfingerprint`；首版 `go.mod` 使用 `go 1.26.0`，不指定 toolchain 下载。实现应使用 Go 1.26 标准库支持的能力。
- `internal/contract`：公共模型、接口、错误、配置默认值和校验/解码工具。
- `internal/fingerprint`：无状态、可并发调用的规则引擎。
- `internal/service`：输入校验、有界批量调度、结果组装。
- `internal/httpapi`：HTTP 解析、请求限制、错误映射。
- `internal/config`：环境变量解析；`cmd/server`：依赖组装和生命周期。
- fingerprint、service、httpapi 仅依赖 contract，互不导入。cmd/server 负责组装。单元测试使用注入 fake，集成测试使用真实模块。
- 首版同步处理，无数据库、消息队列、规则热更新或主动网络探测。

## 2. 公共 Go 模型

以下定义属于 `internal/contract`。所有列出的 JSON 字段始终输出，不使用 omitempty；空集合输出 `[]`，无错误输出 `null`。

```go
type Record struct {
    IP             string `json:"ip"`
    Port           int    `json:"port"`
    Banner         string `json:"banner"`
    BannerEncoding string `json:"banner_encoding"`
}

type Evidence struct {
    RuleID string `json:"rule_id"`
    Field  string `json:"field"`
    Value  string `json:"value"`
}

type Candidate struct {
    Protocol   string     `json:"protocol"`
    Product    string     `json:"product"`
    Version    string     `json:"version"`
    OSHint     string     `json:"os_hint"`
    Confidence float64    `json:"confidence"`
    Evidence   []Evidence `json:"evidence"`
}

type Identification struct {
    Protocol   string      `json:"protocol"`
    Product    string      `json:"product"`
    Version    string      `json:"version"`
    OSHint     string      `json:"os_hint"`
    Confidence float64     `json:"confidence"`
    Evidence   []Evidence  `json:"evidence"`
    Candidates []Candidate `json:"candidates"`
}

type ItemError struct {
    Code    string `json:"code"`
    Message string `json:"message"`
}

type Result struct {
    Index int    `json:"index"`
    IP    string `json:"ip"`
    Port  int    `json:"port"`
    Status string `json:"status"`
    Identification // 匿名嵌入，识别字段在 JSON 顶层展开
    Error *ItemError `json:"error"`
}

type IdentifyRequest struct { Records []Record `json:"records"` }
type IdentifyResponse struct { Results []Result `json:"results"` }
type ErrorResponse struct { Error ItemError `json:"error"` }

type Recognizer interface {
    Identify(context.Context, Record) (Identification, error)
}
type BatchIdentifier interface {
    IdentifyBatch(context.Context, []Record) ([]Result, error)
}
```

公共模型首版不实现自定义 JSON MarshalJSON，避免匿名嵌入吞掉其他字段。HTTP 解析层必须检查必填字段是否存在，不能只依赖 Go 零值；字段显式为 null 也视为请求格式错误。允许 banner 为空字符串，不允许缺失 banner。banner_encoding 可省略，但不能为 null。

### 2.1 状态与结果对应关系

| status | 含义 | 识别字段 | error |
|---|---|---|---|
| matched | 至少识别协议或产品 | 已知部分填值，其余为空 | null |
| unknown | 输入合法但没有规则匹配 | 字符串空、评分0、集合空 | null |
| invalid | 单条字段值或编码非法 | 同 unknown | 具体校验错误 |
| failed | 引擎返回非 context 错误 | 同 unknown | identification_failed |

输出条数与输入一致，顺序一致，index 从 0 开始。重复记录不合并。IP 和 port 原样回显，不做地址规范化替换。unknown 是正常业务结果。

### 2.2 多候选

引擎先按 `(protocol, product, version, os_hint)` 去重，合并证据，同组评分取最大值而非相加。候选按评分降序，再按上述四字段字节序升序排列；主结果取第一项。存在两个及以上不同候选时 candidates 包含全部候选（含主候选），仅一个候选时为 `[]`。不把一个候选的软件与另一个候选的版本拼接。证据按 `(rule_id, field, value)` 去重并升序排列。

同一协议/产品若已有明确版本候选，删除无版本且无额外 OS 信息的冗余候选；有不同版本的候选均保留。不得使用候选顺序表达未定义的人工优先级。

## 3. 编码、校验及公共工具

- `utf8`（默认）表示 JSON 解码一次后的有效 UTF-8 字节。允许 NUL 和 CRLF；非法 UTF-8 和非法 Unicode 代理项必须拒绝，不能依赖 encoding/json 的替换字符容错。
- `base64` 使用标准带填充 RFC 4648 编码，严格拒绝空白、URL-safe 字符及非规范编码；空字符串可解码为空字节。
- 输入样例的重复引号是粘贴格式问题；`\xNN` 不是合法 JSON 转义。只在制作 fixture 时还原，API 不自动修复，不二次解释字面量 `\\r\\n`。
- IP 使用 net/netip.ParseAddr，拒绝域名、地址加端口、zone ID 和前后空白；接受 IPv4/IPv6。port 范围 1–65535。
- MaxBannerBytes 同时限制 JSON 解码后的 Banner 字符串字节数和 base64 解码后的字节数。先检查编码长度再分配解码缓冲。传输中的转义膨胀由 MaxBodyBytes 单独限制。
- 校验顺序：IP、port、encoding、编码前长度、解码合法性/UTF-8、解码后长度。单条只返回第一个错误。

contract 提供以下函数，避免实现漂移：

```go
func DecodeBanner(record Record, maxBytes int) ([]byte, error)
func ValidateRecord(record Record, maxBytes int) error
func ValidateServiceConfig(ServiceConfig) error
func ValidateHTTPConfig(HTTPConfig) error
func DefaultServiceConfig() ServiceConfig
func DefaultHTTPConfig() HTTPConfig
```

DecodeBanner 只处理 encoding、字节上限及文本合法性；ValidateRecord 另外检查 IP/port 并调用 DecodeBanner。service 校验，engine 通过同一工具解码（使用公共硬上限），不改写 Record。错误用下节类型表达。

实现导出硬上限 `MaxBannerBytes`（1048576）、`MaxBatchSize`（10000）、`MaxWorkers`（256）、`MaxBodyBytes`（67108864，int64）、`MaxRequestTimeout`（5*time.Minute）。状态常量为 `StatusMatched`、`StatusUnknown`、`StatusInvalid`、`StatusFailed`。`EmptyIdentification() Identification` 初始化空集合；消费者必须使用该函数或显式初始化集合，结构体零值本身仍会序列化为null。JSON原始字节/代理项/必填字段的严格校验属于HTTP层，DecodeBanner不能恢复JSON解析器已经丢弃的信息。

## 4. 错误契约

```go
type Error struct {
    Code string
    Message string // 可安全对外展示的固定文案，不插入原始输入或底层错误
    Cause error
}
func (*Error) Error() string
func (*Error) Unwrap() error
```

使用 errors.As 获取 `*contract.Error`，禁止匹配错误文本。Code 常量采用 `CodeInvalidIP` 等名称，与下表 snake_case 一一对应；Message 的具体中文文案不参与程序分支。Error() 返回 Code 与 Message，不拼接 Cause。构造函数配置错误返回 `invalid_config`，仅用于启动诊断。

| 场景 | code | 作用范围/HTTP |
|---|---|---|
| JSON、必填字段、类型、未知字段、多个顶层值错误 | invalid_request | 请求/400 |
| records为null/缺失 | invalid_request | 请求/400 |
| records为空数组；超过 MaxBatchSize | invalid_batch | 请求/400 |
| IP/port非法 | invalid_ip / invalid_port | 单条/200 |
| encoding不支持、base64或UTF-8非法 | invalid_encoding | 单条/200；JSON层非法UTF-8归 invalid_request |
| Banner超限 | banner_too_large | 单条/200 |
| 引擎内部错误 | identification_failed | 单条/200 |
| 请求体超限 | body_too_large | 请求/413 |
| Content-Type非JSON或缺失 | unsupported_media_type | 请求/415 |
| 请求期限耗尽 | request_timeout | 请求/504 |
| 未知服务错误 | internal_error | 请求/500 |
| 路径/方法错误 | not_found / method_not_allowed | 请求/404、405 |

service 返回的顶层错误仅包括 invalid_batch、context取消/超时及不可恢复的服务错误；普通引擎错误隔离为 failed。context 错误必须可通过 errors.Is 判断。取消时不交付部分成功数组。客户端已断开时停止处理，不强制写状态；健康连接上发生非截止时间的 context.Canceled 时同样终止 handler，不转换为500或伪造成功响应。

直接调用IdentifyBatch时nil切片等同空批次，返回invalid_batch；HTTP能区分字段缺失/null，因此在进入service前按上表拒绝。非法JSON语法或字段类型使整批失败，只有语法和类型合法的条目才适用单条invalid隔离。

公共构造函数固定为：

```go
// internal/fingerprint
func New() (contract.Recognizer, error)
// internal/service
func New(contract.Recognizer, contract.ServiceConfig) (contract.BatchIdentifier, error)
// internal/httpapi
func New(contract.BatchIdentifier, contract.HTTPConfig) (http.Handler, error)
```

nil依赖、非法配置和规则编译失败必须在构造时返回错误，不延迟到请求时panic。Recognizer直接调用对非法编码返回公共错误，对无匹配返回空Identification及nil；输入合法性由service负责，引擎不依据非法IP/port匹配。所有实现接收已取消context时应及时返回对应context错误。

## 5. HTTP API

### POST /api/v1/identify

Content-Type 必须为 application/json，接受 charset=utf-8 等参数。首版不支持 Content-Encoding 压缩，非空且非 identity 时返回415。整个请求完成解析和大小检查后才能调用业务服务；未知字段在各层均拒绝，重复 JSON 键拒绝。只接受一个对象，不接受裸数组。

```json
{"records":[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]}
```

```json
{
  "results": [{
    "index": 0,
    "ip": "1.2.3.4",
    "port": 22,
    "status": "matched",
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95,
    "evidence": [{"rule_id":"ssh.openssh","field":"banner","value":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}],
    "candidates": [],
    "error": null
  }]
}
```

响应200包括全unknown、全invalid或部分失败。请求级错误格式：

```json
{"error":{"code":"invalid_request","message":"请求格式不合法"}}
```

响应 Content-Type 为 application/json。request timeout 从进入识别 handler 开始，覆盖读取、解析和业务处理；读取超时需通过请求级 read deadline 实际中断 body.Read，单纯设置 context 不足以实现。写响应受 server WriteTimeout 限制；WriteTimeout 必须大于 RequestTimeout。连接已不可写时不保证发送错误正文。

### GET /healthz

返回200、`{"status":"ok"}`，表示服务可响应，不执行扫描或指纹识别。其他路径404，已知路径错误方法405并带 Allow（识别为 POST，健康检查为 GET）。首版不隐式提供 HEAD。错误优先级：路由/方法、媒体类型、读取体积/超时、JSON格式、批次校验、单条处理。

## 6. 识别规则与评分

confidence 表示规则证据强度，不是校准概率。不得按 IP、数组索引或端口硬编码结果。端口不提高评分，也不单独构成匹配。protocol 使用 SSH、HTTP、MySQL、Redis、FTP、TLS 这些大小写；TLS 不等于 HTTPS。

| 稳定 rule_id | 内容依据 | 评分 |
|---|---|---|
| ssh.openssh | 合法SSH identification前缀及OpenSSH版本 | 0.90；同一行有明确Ubuntu/Debian发行标识为0.95 |
| http.nginx | HTTP响应头Server中的nginx及版本 | 0.90 |
| http.apache | HTTP响应头Server中的Apache及版本 | 0.90 |
| http.jetty | HTTP响应头Server中的Jetty及版本 | 0.85 |
| http.iis | HTTP响应头Server中的Microsoft-IIS及版本 | 0.90 |
| mysql.handshake | 4字节包头、序号0、协议字节0x0a及NUL结尾版本字段 | 0.90 |
| redis.command_error | RESP错误前缀及样例中的Redis命令错误结构 | 0.70 |
| redis.pong | 独立RESP简单字符串+PONG，可有末尾CRLF | 0.70 |
| redis.noauth | RESP -NOAUTH Authentication required.，可有末尾CRLF | 0.70 |
| ftp.proftpd | 220欢迎行中ProFTPD及版本 | 0.90 |
| ftp.vsftpd | 220欢迎行中vsFTPd及版本 | 0.90 |
| ftp.pureftpd | 220欢迎行中Pure-FTPd | 0.80 |
| tls.record_prefix | 合理TLS记录头及可用的握手头结构，但记录被截断 | 0.50，仅TLS，不报产品、版本 |
| protocol.ssh / protocol.http | 可确认协议结构，但未识别产品 | 0.60 |
| protocol.ftp | 有220响应与明确FTP语义，未识别产品 | 0.60 |

HTTP产品规则缺少版本但产品明确时评分0.80（Jetty为0.75）；SSH/FTP产品明确但缺版本时0.80。产品规则命中时不额外输出同段协议兜底候选。无表内规则匹配则unknown；新增规则需补充文档和正反例测试。

HTTP头名大小写不敏感，只解析首个完整响应头区，允许样例在完整header行后截断而无空行。不在正文搜索Server。OS提示只从对应SSH发行标识或HTTP Server产品后明确的Ubuntu/Debian注释提取；产品名本身不推断操作系统。保留展示版本字符串（如8.9p1），不截断有效补丁后缀。

MySQL样例包长度声称0x4a，但只提供开头字段，因此允许截断payload；必须存在有效包头、协议号和受限ASCII版本字段（以数字起始、包含点分数字），不能仅从任意文本提取版本。截断匹配只证明Banner特征，不能证明完整握手有效。TLS样例也不证明完整TLS会话或目标角色。

每条证据包括rule_id、字段名和匹配片段。字段名首版限定 banner、server、handshake；可打印证据最长256 UTF-8字节，过长按字符边界截断；二进制证据使用 `base64:` 加匹配字节编码后再限制长度。不输出完整原始Banner。每个候选最多16条证据，最多16个候选，超出时按上述确定性排序保留前16项。

## 7. 自测预期

以下仅是自测；前7行来自用户输出，后13行为当前契约推导。评分用数值比较，测试容差1e-9。用户样例的空OS和版本必须保持为空，不能补猜。

| IP末段 | protocol | product | version | os_hint | confidence | 来源 |
|---|---|---|---|---|---|---|
| 4 | SSH | OpenSSH | 8.9p1 | Ubuntu | 0.95 | 用户 |
| 5 | HTTP | nginx | 1.24.0 | 空 | 0.90 | 用户 |
| 6 | HTTP | Apache | 2.4.57 | 空 | 0.90 | 用户 |
| 7 | MySQL | MySQL | 8.0.32 | 空 | 0.90 | 用户 |
| 8 | Redis | Redis | 空 | 空 | 0.70 | 用户 |
| 9 | FTP | ProFTPD | 1.3.7 | 空 | 0.90 | 用户 |
| 10 | HTTP | Jetty | 9.4.51 | 空 | 0.85 | 用户 |
| 11 | SSH | OpenSSH | 9.3 | Debian | 0.95 | 推导 |
| 12 | HTTP | nginx | 1.18.0 | Ubuntu | 0.90 | 推导 |
| 13 | HTTP | Apache | 2.4.41 | Ubuntu | 0.90 | 推导 |
| 14 | MySQL | MySQL | 5.7.42 | 空 | 0.90 | 推导 |
| 15 | Redis | Redis | 空 | 空 | 0.70 | 推导 |
| 16 | FTP | vsFTPd | 3.0.5 | 空 | 0.90 | 推导 |
| 17 | HTTP | nginx | 1.25.3 | 空 | 0.90 | 推导 |
| 18 | SSH | OpenSSH | 4.3 | 空 | 0.90 | 推导 |
| 19 | TLS | 空 | 空 | 空 | 0.50 | 推导，弱识别 |
| 20 | HTTP | Microsoft-IIS | 10.0 | 空 | 0.90 | 推导 |
| 21 | Redis | Redis | 空 | 空 | 0.70 | 推导 |
| 22 | FTP | Pure-FTPd | 空 | 空 | 0.80 | 推导 |
| 23 | 空 | 空 | 空 | 空 | 0 | 推导，unknown |

fixture 放置 `testdata/selftest/input.json`（records包装）、`expected.json`（预期语义字段）和 `manifest.json`（每行来源）。二进制Banner以base64存储。测试比较固定业务字段及状态；证据验证rule_id、来源和长度，不依赖易变文案。

## 8. 配置与生命周期

```go
type ServiceConfig struct {
    MaxBatchSize int
    MaxBannerBytes int
    Workers int
}
type HTTPConfig struct {
    MaxBodyBytes int64
    RequestTimeout time.Duration
}
```

| 环境变量 | 默认值 | 合法范围 |
|---|---|---|
| BANNER_LISTEN_ADDR | :8080 | 非空，启动时校验并绑定 |
| BANNER_MAX_BATCH_SIZE | 1000 | 1–10000 |
| BANNER_MAX_BANNER_BYTES | 65536 | 1–1048576（公共硬上限） |
| BANNER_WORKERS | 8 | 1–256 |
| BANNER_MAX_BODY_BYTES | 8388608 | 1–67108864 |
| BANNER_REQUEST_TIMEOUT | 10s | >0且≤5m |
| BANNER_READ_HEADER_TIMEOUT | 5s | >0且≤1m |
| BANNER_WRITE_TIMEOUT | 15s | >RequestTimeout且≤10m |
| BANNER_IDLE_TIMEOUT | 60s | >0且≤10m |
| BANNER_SHUTDOWN_TIMEOUT | 10s | >0且≤1m |

环境变量未设置用默认值，显式空值/非法值启动失败。构造函数不把零值当默认值，必须调用Default函数获得默认配置。服务配置与HTTP配置分开校验。合法单条或批次数量不保证整个请求不超过传输大小限制。

service使用不超过Workers个worker；每批结果独立，不共享可变状态。引擎不得启动遗弃任务来模拟取消。收到退出信号先停止接受新请求，使用独立context执行Shutdown，超时后Close；不得复用已取消的信号context执行Shutdown。日志默认不含Banner、完整请求或证据正文。

## 9. 测试与审查门禁

实现时同步提供测试代码，当前公共契约与fixture测试已提供，其余模块测试在相应模块实现时提供：

- contract：validation_test.go、encoding_test.go、config_test.go。
- fingerprint：engine_test.go、rules_test.go，真实规则、全部自测、反例、并发与取消。
- service：service_test.go、concurrency_test.go，fake引擎、保序、隔离、并发上限与资源释放。
- httpapi：handler_test.go、middleware_test.go，fake服务、严格解析、限制、错误及取消。
- config/入口：配置边界和启动/优雅退出；integration：真实模块和全部自测fixture。

各模块完成后由主 agent 执行 code review，重点检查契约一致性、误识别、版本/OS推断、编码、错误映射、资源上限、取消和竞态。修复后执行格式检查、`go test ./...`、`go test -race ./...`、`go vet ./...`、`go build ./...`，报告实际结果及未解决问题。不得以通过这些自测宣称最终验收完成。
