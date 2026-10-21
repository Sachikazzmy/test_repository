# 后端 Code Review 与验证记录

审查日期：2026-10-21。主agent检查0/A/B/C/D的公共契约、规则、批量服务、HTTP、配置、运行入口和测试，未启动subagents。当前后端满足已定义的最小要求；用户自测不是最终验收，完整client+server交付尚未完成。

## 发现与修复

| 优先级 | 位置 | 问题与修复 | 回归验证 |
|---|---|---|---|
| P2 | internal/httpapi/middleware.go | JSON结构体解码接受IP等大小写变体，覆盖合法字段；新增精确字段白名单，未知字段整批400且不调用service；遍历深度限制4 | 顶层、条目、可选字段变体，转义重复键，深嵌套 |
| P2 | internal/httpapi/handler.go | 读取超时后恢复deadline可能让net/http继续等待未完成body；读取错误关闭连接，实际读取超时优先于派生context取消映射504 | 真实本机连接发送部分body后停止，断言504和错误JSON |
| P2 | internal/fingerprint/rules.go | SMTP及通用service ready被误识别为FTP；兜底改为独立FTP语义 | SMTP/ESMTP、通用220、SFTP、相似词反例和FTP正例 |
| P2 | internal/fingerprint/rules.go | 同一Server值仅搜索首次产品，遗漏多版本；改为遍历原字符串全部合法token位置 | 同行多版本、重复去重、错误首次子串及Unicode前缀 |
| P2 | internal/fingerprint/rules.go | OS注释跨越后续产品关联到前一个产品；只读取紧跟当前产品/版本的括号注释 | nginx无OS、Apache带Ubuntu的同一行多候选 |
| P2 | internal/httpapi/handler.go | typed-nil业务依赖可通过构造后panic；构造时拒绝 | typed-nil构造测试 |

以上问题均已修复。规则证据保留实际产品片段及适用OS注释；没有改变公共Go接口、评分和20条自测预期。

## 最小要求检查

| 要求 | 证据与结论 |
|---|---|
| Go后端及可运行入口 | cmd/server、internal/config已具备启动校验、HTTP超时、信号退出及独立shutdown context |
| 输入ip/port/banner批量识别 | contract与service验证合法输入，保序、重复独立、单条失败隔离 |
| 协议/产品/版本/OS/评分 | 全部20条fixture经真实模块及容器HTTP接口匹配；前7条预期来自用户，其余来自契约推导 |
| 解耦与统一契约 | fingerprint/service/httpapi仅依赖contract，通过构造函数注入；cmd组装 |
| HTTP与资源控制 | 严格JSON、编码、请求体上限、批次/单条限制、worker边界、context和读取期限 |
| 测试 | 单元fake、真实引擎、真实模块集成、进程信号/生命周期以及竞态检查 |
| Compose | compose.yml、Dockerfile、.dockerignore及compose-plan.md；实际构建启动并验证健康 |

## 实际执行结果

本机Go 1.27.1 darwin/arm64：

- gofmt检查：无输出。
- go test -race ./...：全部7个包通过（含20条真实模块集成数据、SIGINT/SIGTERM及退出超时测试）。
- go vet ./...、go build ./...：通过。

Docker Desktop Linux/arm64：

- docker compose config --quiet：通过。
- 使用Go 1.26系列Alpine构建阶段编译最终代码，构建成功；不代表已在Go 1.26执行整套单元测试。
- 以独立项目banner-review、宿主127.0.0.1:18080启动最终镜像，Compose等待健康成功。
- HTTP提交testdata/selftest/input.json，逐字段对照expected.json，20/20通过。
- 验证后移除该项目容器与网络；保留镜像供后续使用。

## 剩余限制

- client尚未实现，Compose当前只启动server，无占位client。完整系统及最终验收不能宣称完成。
- 规则覆盖限于文档范围；confidence是规则证据强度，不是概率。TLS/MySQL片段匹配不能证明完整握手。
- worker按每批限制，多请求没有全局并发准入限制。默认绑定本机，公开部署需按容量限制入口并发并提供访问控制。
- 未做负载基准、跨架构运行或最终验收数据测试。本轮范围内无已知未修复的阻断性问题。
