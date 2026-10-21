# 批量识别服务

`internal/service` 实现公共 `contract.BatchIdentifier`，只依赖 `internal/contract`，通过注入的 `contract.Recognizer` 执行单条识别。服务不做 HTTP 状态码映射，也不直接依赖规则引擎。

## 构造

```go
identifier, err := service.New(recognizer, contract.DefaultServiceConfig())
```

`recognizer` 必须非 nil；配置不会自动补默认值，调用方应先使用 `contract.DefaultServiceConfig()`。配置范围由 `contract.ValidateServiceConfig` 校验：批次 1–10000 条、Banner 1–1048576 字节、worker 1–256。无效依赖或配置在构造时返回 `contract.Error`（`invalid_config`）。

## 批量行为

- `IdentifyBatch` 拒绝空批次和超过 `MaxBatchSize` 的批次，返回 `invalid_batch`；nil 切片按空批次处理。
- 每条输入按 contract 规则校验 IP、端口、编码和 Banner 字节上限。非法条目输出 `invalid` 及其稳定错误码，不调用识别器；其他条目继续处理。
- 最多启动 `Workers` 个 worker，且 worker 数不超过有效条目数。使用无缓冲任务队列，不会为每条输入单独创建 goroutine。
- 每条输入产生一个结果，结果按输入顺序排列，`index` 从 0 开始；重复记录仍分别校验、识别和返回。
- 识别器普通错误只影响该条，状态为 `failed`，错误码固定为 `identification_failed`，对外消息为固定安全文案，不包含 Banner 或底层错误。
- 成功识别至少有 `protocol` 或 `product` 时状态为 `matched`；二者皆空时为 `unknown`。空 evidence 和 candidates 输出为空数组。
- 调用取消或期限耗尽时，停止投递新任务、取消 worker 所用 context、等待 worker 退出，并返回可由 `errors.Is` 判断的 context 错误；不返回部分结果。识别器必须遵守传入 context，服务不会遗弃仍在运行的识别调用。

## 使用示例

```go
identifier, err := service.New(recognizer, contract.DefaultServiceConfig())
if err != nil {

	return err
}

results, err := identifier.IdentifyBatch(ctx, []contract.Record{{
	IP: "192.0.2.10", Port: 22, Banner: "SSH-2.0-example",
}})
if err != nil {
	// 请求级错误：无效批次、取消或超时。
	return err
}
// results[0] 是该输入对应的 matched、unknown、invalid 或 failed 结果。
```

这里使用文档示例输入说明调用结构，不代表该 Banner 一定会被当前规则识别。

## 验证

在仓库根目录运行：

```sh
go test ./internal/service
```

测试使用注入的本地 fake Recognizer，不建立网络连接。
