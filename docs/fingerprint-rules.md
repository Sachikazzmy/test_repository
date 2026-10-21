# Banner 指纹规则

当前产品token、产品名称、SSH/Redis匹配正则与评分已迁入根目录`rules/rules.json`。`LoadRules`与`NewFromFile`启动校验规则并编译正则；默认New嵌入同一文件快照。Compose通过BANNER_RULES_PATH加载只读挂载文件，修改后重启生效。通用Go代码保留协议结构解析、字段提取、去重排序和证据限制。新增HTTP/FTP产品通过token规则扩展，其他协议的新结构解析仍需代码支持。

`internal/fingerprint` 实现冻结契约 v1 的无状态识别器。规则只检查提交的 Banner 字节；端口不参与匹配、加分或候选排序。`New` 返回可并发调用的 `contract.Recognizer`。识别器使用 `contract.DecodeBanner` 解码，不改写输入记录；非法编码返回 contract 错误，未知 Banner 返回空识别和 nil 错误。调用开始、解码后及识别后检查 context 取消。

## 规则

| 稳定 ID | 识别条件 | 输出 | 置信度 |
|---|---|---|---:|
| `ssh.openssh` | 第一行是 SSH-2.0 或 SSH-1.99 identification，软件 token 为 `OpenSSH_<version>` | SSH / OpenSSH / 原样版本；同一行版本后明确出现 Ubuntu 或 Debian 标识时附加 OS 提示 | 0.90；带发行标识 0.95 |
| `protocol.ssh` | SSH identification 合法，但没有 OpenSSH 产品证据 | SSH | 0.60 |
| `http.nginx` | 合法 HTTP 状态行及至少一个完整头行；首个头部区的 `Server` 值中存在边界完整的 nginx token | HTTP / nginx / 可选版本 | 有版本 0.90，无版本 0.80 |
| `http.apache` | 同上，产品 token 为 Apache | HTTP / Apache / 可选版本 | 有版本 0.90，无版本 0.80 |
| `http.jetty` | 同上，产品 token 为 Jetty | HTTP / Jetty / 可选版本 | 有版本 0.85，无版本 0.75 |
| `http.iis` | 同上，产品 token 为 Microsoft-IIS | HTTP / Microsoft-IIS / 可选版本 | 有版本 0.90，无版本 0.80 |
| `protocol.http` | HTTP 状态行和至少一个完整头行成立，但无已支持的 Server 产品 | HTTP | 0.60 |
| `mysql.handshake` | 四字节包头、序号 0、协议字节 `0x0a`、NUL 结尾且符合受限 ASCII 点分版本格式的版本字段 | MySQL / MySQL / 版本 | 0.90 |
| `redis.command_error` | RESP 错误行符合已知命令参数错误结构 | Redis / Redis | 0.70 |
| `redis.pong` | 独立 RESP `+PONG`，可带行结束符 | Redis / Redis | 0.70 |
| `redis.noauth` | 独立 `-NOAUTH Authentication required.` 行，可带行结束符 | Redis / Redis | 0.70 |
| `ftp.proftpd` | 220 欢迎行中边界完整的 ProFTPD token | FTP / ProFTPD / 可选版本 | 有版本 0.90，无版本 0.80 |
| `ftp.vsftpd` | 220 欢迎行中边界完整的 vsFTPd token | FTP / vsFTPd / 可选版本 | 有版本 0.90，无版本 0.80 |
| `ftp.pureftpd` | 220 欢迎行中边界完整的 Pure-FTPd token | FTP / Pure-FTPd / 可选版本 | 0.80 |
| `protocol.ftp` | 220 行提供明确 FTP 语义，但没有支持的产品 | FTP | 0.60 |
| `tls.record_prefix` | 合理 TLS record header 和 ClientHello/ServerHello 握手头可用，但记录或握手被截断 | 仅 TLS，不输出产品或版本 | 0.50 |

版本仅在 Banner 中有格式有效的明确信息时输出；缺失或无效版本为空。OS 提示只从 SSH 产品版本后的同一行发行标识，或 HTTP Server 产品 token 后的括号发行注释读取。产品名不会推断 OS。

HTTP 仅接受 `HTTP/1.0`、`HTTP/1.1`、`HTTP/2` 和 `HTTP/2.0` 状态行，状态码必须是三位 1xx–5xx。必须至少有一个语法完整的头行；允许在完整头行后截断而没有空行。解析在空行处停止，正文和状态文本中的软件名不作为 Server 证据。Server 名称大小写不敏感，但 token 前后必须有约定边界，因此 `nginx-proxy`、`vendor-nginx`、`ApacheTomcat` 等相似名称不匹配。

MySQL 可识别契约中的截断 greeting 前缀；这说明 Banner 中存在该结构，不代表完整握手。TLS 规则仅给出有限协议识别，不表示 HTTPS，也不推断服务端角色、TLS 版本、产品或证书信息。

## 冲突、证据与限制

候选按 `(protocol, product, version, os_hint)` 去重，证据合并去重，组内评分取最高值而不累加。产品命中会移除同协议的 protocol-only 候选；同一产品的无版本候选在存在版本候选且没有额外 OS 提示时移除。剩余候选按评分降序，再按四个键的字节序升序，主识别取首项。多个不同候选时输出最多 16 个候选（包含主候选）；单候选时 `candidates` 为空数组。每候选最多 16 条证据，按 rule ID、字段、值排序。

证据字段限于 `banner`、`server`、`handshake`，包含 rule ID 和实际匹配片段。可打印证据最多 256 UTF-8 字节；二进制匹配片段以 `base64:` 表示后截断。不会输出完整 Banner。评分表示规则证据强度，不是概率。输入范围受公共 Banner 上限限制，规则不执行 Banner 中内容，也不加载动态或网络规则。

自测输入、预期结果及其来源说明保存在本模块的 `testdata`，并由真实引擎测试读取。它们是当前回归样例，不构成最终覆盖范围承诺。

## 审查修复

HTTP逐个解析同一Server值中的全部合法产品token，保留不同版本，重复候选合并。通过正则返回原始字节位置，不对Unicode大小写转换后的字符串复用偏移；无效的首次同名子串不会掩盖后续有效token。OS只来自紧接当前产品/版本的括号注释，不跨越其他产品。FTP兜底必须出现独立FTP语义，SMTP/ESMTP、通用service ready和SFTP不触发。以上行为有真实引擎正反例回归测试。
