# Banner 指纹识别系统

Go实现的独立client + server。接收已有扫描记录，不主动探测目标。支持SSH/OpenSSH、HTTP（nginx/Apache/Jetty/IIS）、MySQL、Redis、FTP及有限TLS片段识别。软件和版本来自Banner证据；未识别统一返回`protocol: "unknown"`。confidence为0–1规则证据评分，不是统计概率。

## 一键运行

需要Docker Engine及Docker Compose插件，首次构建需要联网拉取基础镜像：

```sh
docker compose up --build
```

server通过真实`GET /health`健康检查后，独立client容器读取`examples/input.json`的20条数据，通过`http://server:8080/fingerprint`提交并在日志打印JSON数组。client执行成功后以0退出，server持续运行；这符合批处理命令行程序的生命周期。按Ctrl+C停止，或另一个终端执行`docker compose down`。

后台运行、重复提交和清理：

```sh
docker compose up --build -d
docker compose logs client
docker compose run --rm client
docker compose down
```

使用自己的JSON文件（路径需要可读）：

```sh
BANNER_INPUT_FILE=./my-input.json docker compose up --build
```

重复运行自定义数据：`BANNER_INPUT_FILE=./my-input.json docker compose run --rm client`。默认只向宿主机127.0.0.1:8080发布server端口；冲突时设置`BANNER_HOST_PORT=18080`。容器之间始终使用server服务名，不使用宿主地址或localhost。client通过单独的internal网络访问server，client没有发布端口。server另接ingress网络以支持宿主机端口访问。

## 本地Go运行

需要Go 1.26或更高，无第三方依赖：

```sh
go run ./cmd/server
# 另一个终端
go run ./cmd/client --input examples/input.json --server http://127.0.0.1:8080
```

client的`--timeout`默认15s，失败输出stderr并非零退出；默认输出完整JSON数组。也可使用`go build -o /tmp/banner-client ./cmd/client`生成独立程序。

## 对外API

### GET /health

规则加载并校验成功后才启动HTTP。正常返回200与`{"status":"ok"}`。

### POST /fingerprint

Content-Type为application/json，请求为JSON数组：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
]
```

成功响应为等长、同序数组：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.23","port":12345,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}
]
```

```sh
curl --fail http://127.0.0.1:8080/health
curl --fail-with-body -H 'Content-Type: application/json' \
  --data-binary @examples/input.json http://127.0.0.1:8080/fingerprint
```

IP支持IPv4/IPv6；端口1–65535。单条内容非法或不识别不影响其他条目，公开接口该条返回unknown。空Banner合法。版本或OS没有明确证据时为空字符串，不能从端口或软件名猜测。

二进制Banner增加`banner_encoding: "base64"`，使用标准带填充base64。普通文本可省略该字段。JSON中的CRLF使用`\r\n`；`\xNN`不是合法JSON。题目粘贴中的重复引号和二进制转义已整理为合法样例，不对API输入做隐式二次解码。

整个请求格式错误返回400，体积超限413，媒体类型不支持415，超时504，内部错误500；统一错误正文为`{"error":{"code":"...","message":"..."}}`。不认识不属于请求错误。错误/日志不回显完整Banner或内部堆栈。

保留兼容接口`POST /api/v1/identify`和`GET /healthz`；前者使用`{"records":[...]}`包装并返回包含status/evidence/candidates的详细结果，内部未知协议仍为空字符串。题目验收和client使用上面的公开数组接口。client也允许从旧records包装文件读取并转换为数组。

## 规则与程序解耦

`rules/rules.json`为单一规则来源：包含产品token、匹配正则、产品名称及版本/OS评分。Go负责协议结构解析、执行正则和稳定冲突排序。Compose将规则文件只读挂载到server；修改规则后`docker compose restart server`重新加载，无需编译。非法正则、重复ID、缺失必需规则或非法评分会使启动失败，健康检查不会假成功。

本地运行默认使用同一JSON文件的嵌入快照，独立二进制无需额外文件；使用`BANNER_RULES_PATH=./rules/rules.json go run ./cmd/server`从外部文件加载。外置规则扩展测试证明添加HTTP产品无需修改Go程序。说明和评分见`docs/fingerprint-rules.md`。

## 部署与限制

- 多阶段编译静态server/client程序，运行镜像不含Go工具链；65532非root、只读文件系统、删除全部capabilities、禁止提权。
- client依赖server健康，不靠固定sleep；输入及规则只读挂载，不需要数据库或持久卷。
- 默认业务限制：每批1000条、每条编码前/解码后65536字节、8个worker、请求体8MiB、请求超时10s。支持BANNER_MAX_BATCH_SIZE、BANNER_MAX_BANNER_BYTES、BANNER_WORKERS、BANNER_MAX_BODY_BYTES、BANNER_REQUEST_TIMEOUT覆盖。
- BANNER_WRITE_TIMEOUT默认15s，必须大于请求超时。其他超时和上限见docs/server-contract.md。环境变量显式空值或越界导致启动失败。
- SIGINT/SIGTERM有界优雅退出；BANNER_SHUTDOWN_TIMEOUT默认10s、最高60s，Compose等待65s后强制停止。日志轮转限制大小。
- 无认证，默认绑定本机；开放网络前应提供网关访问控制。并发worker按批限制，无全局请求准入，尚未进行负载基准测试。
- 截断TLS/MySQL只是特征识别，不能证明完整握手。TLS不等于HTTPS。规则不保证识别所有软件，不能识别就返回unknown。

## 测试与交付验证

```sh
gofmt -l cmd internal rules tests
go test -race ./...
go vet ./...
go build ./...
docker compose config --quiet
```

测试包含真实规则与反例、规则外置扩展/校验、client fake HTTP、真实client→server→engine的20条数据、边界、超时、取消和进程退出。部分测试需要本机临时端口权限。

20条输入是自测，前7条预期来自题目，其余根据规则推导，不代表隐藏验收已通过。审查及实际执行记录见docs/CODE_REVIEW.md。
