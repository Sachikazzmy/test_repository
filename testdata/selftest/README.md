# 自测数据（非最终验收）

- `input.json`：完整20条输入，作为 `contract.IdentifyRequest` 读取。
- `expected.json`：作为 `contract.IdentifyResponse` 读取；只包含预期语义字段，不是完整HTTP响应快照。
- `manifest.json`：标记前7条输出来自用户，其余13条来自契约推导。输入均来自用户样例。

二进制MySQL和TLS样例以base64保存；其余文本保留CRLF及原始内容。重复引号已按粘贴格式修正，没有添加原始样例缺失的包内容。

引擎测试应比较index、ip、port、status、protocol、product、version、os_hint以及confidence（容差1e-9），证据另按规则ID和内容验证。当前contract测试只验证数据结构、输入合法性、来源对应关系及关键二进制字节，不验证识别能力。
