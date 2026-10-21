# Server 分段开发提示词

> 当前状态：公共基线已实现于 `go.mod`、`internal/contract/**`，20条自测位于 `testdata/selftest/**`。任务0无需重做；下文早期候选设计与 `docs/server-contract.md` 不一致时，以后者和对应公共实现为准（包括扁平输出、OS提示、评分及错误码）。用户要求只提供提示词，不自动启动subagents。

> 2026-10-21 最终状态：0/A/B/C/D后端模块已完成，审查问题已修复并通过自测，server Compose已实际构建启动验证。审查结果见 `docs/CODE_REVIEW.md`。下文保留原分段开发任务作为历史参考，不应重新执行；启动subagents仍需用户明确授权。

## 使用时机与并行方式

本文是可直接分发的开发任务书。现已收到 20 条自测输入和前 7 条预期输出；以下统一契约保留早期候选设计供参考，执行时以 `docs/server-contract.md` 及公共实现为准。自测数据不等于最终验收数据，后续示例要求仍优先于候选字段。

先执行任务 0，完成公共类型与验收数据，再并行执行 A、B、C。当前最多三个子 agent 并发；三项结束后执行集成任务 D，最后由主 agent 做 code review。模块独立使用 fake 测试，无需等待其他模块实现。client 和 Docker Compose 不在本轮范围。

## 统一契约（任务 0 冻结）

- module 路径、Go 版本由任务 0 写入 `go.mod`，所有任务从该文件读取，不自行替换。
- 依赖方向：`httpapi -> contract`、`service -> contract`、`fingerprint -> contract`；`cmd/server` 负责组装。三个实现包禁止互相导入。标准库优先。
- `internal/contract` 统一持有公共类型、接口、配置结构、默认配置与错误类别。各模块不得重复声明或修改公共类型。
- 公共接口：`Recognizer.Identify(context.Context, Record) (Identification, error)`；`BatchIdentifier.IdentifyBatch(context.Context, []Record) ([]Result, error)`。
- 构造入口：`fingerprint.New() (contract.Recognizer, error)`；`service.New(contract.Recognizer, contract.ServiceConfig) (contract.BatchIdentifier, error)`；`httpapi.New(contract.BatchIdentifier, contract.HTTPConfig) (http.Handler, error)`。规则在构造时校验，配置错误在构造时返回。
- `Record`：`IP string`、`Port int`、`Banner string`、`BannerEncoding string`；JSON 为 snake_case。编码只允许 `utf8` 和 `base64`，空值表示 `utf8`。JSON 字符串正常反转义一次，不二次解释 `\\r`、`\\n`。原始输入不改写。
- `Identification`：`Protocols []string`、`Products []Product`、`Evidence []Evidence`。`Product` 含 `Name`、`Version`、`RuleID`；`Evidence` 含 `RuleID`、`Field`、`Value`。所有字段冻结时补齐 JSON 标签；未知版本为空字符串，集合为空数组。证据值有长度上限，响应不回显完整 Banner。
- `Result`：`Index int`、`IP string`、`Port int`、`Status string`、`Identification Identification`、`Error *ItemError`。状态为 `matched`、`unknown`、`invalid`、`failed`；`ItemError` 含稳定 `Code` 和安全的 `Message`，无错误时为 null。
- `Identify` 对有效但无匹配的数据返回空识别结果和 nil；对取消/超时保留标准 context 错误语义。输入校验、base64 校验由 service 负责；引擎依据编码解码匹配，不改写 Record。校验/解码工具由 contract 提供，避免两套规则。
- service 保证输出长度和顺序对应输入，重复记录不合并，`Index` 从 0 开始。IP 使用 `net/netip` 校验，port 为 1–65535，空 Banner 为合法未知结果。单条非法或识别错误隔离到结果；请求取消/超时返回顶层错误，不返回不完整成功批次。
- `ServiceConfig`：`MaxBatchSize`、`MaxBannerBytes`、`Workers`；`HTTPConfig`：`MaxBodyBytes`、`RequestTimeout`。冻结时明确 Go 类型及默认值。Banner 长度限制同时检查编码前和解码后字节数；顶层空批次或超出批量上限属于请求错误。
- HTTP：`POST /api/v1/identify`，请求 `{"records":[...]}`，成功 `{"results":[...]}`；包含单条失败也返回 200。`GET /healthz` 返回 200 与 `{"status":"ok"}`。请求级错误为 `{"error":{"code":"...","message":"..."}}`。
- HTTP 状态映射：非法 JSON/字段或批次错误 400；请求体超限 413；不支持的 Content-Type 415；服务端请求期限耗尽 504；内部失败 500。未知路径 404、方法错误 405（包含 Allow）。客户端取消不得转为 500；连接已断开时不强制写响应。
- JSON 拒绝未知字段和多个顶层值；Content-Type 接受带参数的 `application/json`。规则稳定排序去重，同一产品出现冲突版本时保留有证据的候选，不任意选一个版本。具体优先级依据样例冻结。
- contract 提供可映射的请求错误类别；HTTP 不解析错误字符串判断类别。规则证据不能仅由端口触发。暂不使用置信度、持久化和异步任务。

## 所有 subagents 的公共前置提示词

> 阅读根目录 AGENTS.md、本文及任务 0 生成的 docs/server-contract.md。遵守已冻结契约，限于分配目录修改，公共接口问题报给主 agent，禁止自行扩展契约。不要创建 Compose 或 client，不执行目标网络连接，不覆盖他人改动，不提交 git commit。实现代码时同批提供真实可运行的 `*_test.go` 和必要 `testdata`；禁止只交测试计划、空测试或仅验证 mock 本身。模块测试使用本地 fake 隔离外部实现。完成后报告文件清单、实际测试命令与结果、假设和遗留问题。没有运行的检查不得写成通过。

## 任务 0：公共契约与工程基线（先执行）

> 负责 `go.mod`、`internal/contract/**`、`docs/server-contract.md`、`testdata/acceptance/**`。先阅读用户样例，明确全部输入/输出字段与识别层级，按上方候选契约调整并冻结所有类型、方法、配置默认值、错误类别、排序语义和 HTTP 映射。公共实现仅包含模型、错误、校验/解码及配置校验，不写引擎、批量调度或 HTTP handler。将用户样例保存为输入/预期输出文件，并在 manifest 中标明来源及比较方式；未知字段不得静默丢弃。不得伪造尚未收到的用户示例。向主 agent 提交准确的构造签名与依赖清单，供 A/B/C 使用。
>
> 同时交付 `internal/contract/validation_test.go`、`encoding_test.go`，覆盖 IPv4/IPv6、端口边界、空 Banner、非法 base64、字节上限、多字节文本和配置边界。验收数据须能由 D 直接加载。

## 任务 A：识别引擎与规则

> 负责 `internal/fingerprint/**` 和 `docs/fingerprint-rules.md`。实现冻结的 Recognizer 和构造入口，使用只读规则支持并发调用。匹配时保留协议、产品及版本证据，支持多个候选、稳定排序去重和冲突处理；空 Banner 返回未知，端口不单独构成识别依据。规则必须有稳定 ID 和适用范围，版本不得超出实际捕获内容推断。解码使用公共工具，循环与规则执行检查 context，限制处理资源。首批规则覆盖全部用户样例，并泛化到同类 Banner；文档说明覆盖范围和局限。不依赖 service 或 httpapi。
>
> 同时交付 `engine_test.go`、`rules_test.go` 及模块内 `testdata`，覆盖真实规则提取、未知输入、相近产品反例、伪造端口、多产品、多版本冲突、二进制编码、重复证据和取消。加入并发调用测试，确保竞态检测可执行。测试直接调用真实引擎，不用 fake 引擎验证自身。

## 任务 B：批量业务服务

> 负责 `internal/service/**` 和 `docs/batch-service.md`。仅依赖 contract，通过注入 Recognizer 实现批量识别。实现批次/单条校验、有界 worker 并发、顺序恢复、错误隔离与取消；禁止每条记录无限创建 goroutine。保持原始 IP 与条目索引，重复输入独立输出。顶层取消时停止投递并回收自己管理的 worker；引擎须遵循 context，禁止通过遗弃后台调用伪造及时取消。业务层不引用 HTTP 状态码，也不导入真实 fingerprint 包。
>
> 同时交付 `service_test.go` 和 `concurrency_test.go`。使用可控 fake Recognizer 覆盖乱序完成仍保序、重复输入、非法项不调用引擎、局部引擎错误、未知结果、批次上限及 Banner 长度边界。用通道同步验证最大同时执行数量和取消后全部调用退出，不依赖任意 sleep 或运行时 goroutine 总数做断言。

## 任务 C：HTTP 传输层

> 负责 `internal/httpapi/**` 和 `docs/http-api.md`。仅依赖 contract，注入 BatchIdentifier，实现路由、严格 JSON 解析、请求体限制、Content-Type 校验、请求期限、统一错误映射与健康检查。HTTP 层不做指纹匹配或重复实现单条业务校验，不导入 service/fingerprint，不引入全局可变依赖。错误和日志不得泄露 Banner 或内部错误详情。记录全部请求响应字段及可执行 curl 示例。
>
> 同时交付 `handler_test.go`、`middleware_test.go`，使用 httptest 和 fake BatchIdentifier，覆盖成功、单条部分失败、非法 JSON、尾随 JSON、未知字段、错误 Content-Type、体积超限、顶层业务错误、内部错误、404/405、healthz、超时和 context 取消传播。断言状态码、响应结构及错误类别；不要只比较一段响应字符串。

## 任务 D：运行入口与整体验收（A/B/C 完成后）

> 负责 `cmd/server/**`、`internal/config/**`、`tests/integration/**` 和根目录 README.md。按公共构造入口组装真实模块，提供环境变量配置、启动失败提示、HTTP server 超时、信号处理和有界优雅退出。禁止改变其他模块契约；集成冲突报给主 agent 协调。文档给出本地启动、配置、请求示例和测试方式；不写 Compose，不提前实现 client。
>
> 同时交付 `internal/config/config_test.go`、`tests/integration/server_test.go` 以及可测试入口逻辑所需的 `cmd/server/*_test.go`。整体验收使用真实 engine/service/handler 和 httptest，加载用户全部验收样例，核对所有预期语义字段，并验证 unknown、部分失败和超限路径。运行生命周期测试使用本机临时端口或可注入 listener，验证启动失败与退出时资源释放；不依赖外部网络。性能测试仅在有明确目标时添加。

## 主 agent 最终 code review 与交付门禁

所有 subagents 结束后，主 agent 必须亲自阅读完整变更和测试，不能只采信完成报告：

1. 检查包依赖方向、公共契约一致性、目录所有权，以及是否覆盖用户样例要求的识别深度。
2. 审查误识别、版本猜测、多候选排序、编码和边界校验、超时取消、worker 退出、数据竞争及敏感信息泄露。
3. 检查测试是否验证真实行为，是否遗漏反例，是否用 fake 掩盖模块集成问题。
4. 按严重程度列出问题，附文件与行号、触发条件、影响及修复建议；委派原模块 agent 修复并重新审查。未解决问题明确列出，不能宣称全部完成。
5. 集成后运行格式检查、`go test ./...`、`go test -race ./...`、`go vet ./...`、`go build ./...`。检查失败必须定位处理；环境限制单独报告。仅在代码变化或发现问题后重复相关检查。
6. 最终向用户报告实现范围、code review 结论、实际测试结果与剩余限制。client 和 Compose 保持后续阶段。
