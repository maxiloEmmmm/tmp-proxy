daemon 的 discovery 上报目前固定为 3 秒一次 POST 到局域网 center。改造为可配置后端，
由 `~/.config/cfp/config.yaml` 驱动（`CFP_CONFIG` 环境变量可覆盖路径，启动时读一次）。

## [x] reporter 支持可配置后端 cf_kv / custom_center

- 配置 `reporter.type` 选 `cf_kv` 或 `custom_center`
- `custom_center`：维持 3 秒 POST 上报；CLI `-discover-host` 保留为覆盖项（出现即强制
  custom_center，现有 systemd unit 不用改），无 flag 时读配置文件，两者都无则不上报
- `cf_kv`（写 Cloudflare Workers KV，REST API）：
  - `token` / `token_env` 二选一（互斥）
  - `namespace` 填 title 或 namespace id，首次上报时解析并缓存
  - `prefix` 必填且非空，最终 KV key = `{prefix}/{key}`，key 为 daemon 的 `-key` 值
  - value 复用现有 `Report` JSON（discovery/mod.rs）
  - 每 1 小时上报一次 + 变更即写：UUID 轮换（24h）或隧道刷新换域名时立即上报，
    不等下个周期
  - 记录带固定 expiration_ttl = 3h；不提供周期和 TTL 配置项
  - `account_id` 填 Cloudflare 账号 ID，KV 请求使用该账号
  - KV 网络错误、超时、HTTP 429 或 5xx 每 1 分钟重试，直到成功后恢复每小时上报
  - 其他 4xx 或配置错误只记录错误并等待下一次正常上报，不退出 daemon
- 默认配置文件缺失则不上报；`CFP_CONFIG` 指向的文件缺失或已读取文件无效时启动报错；
  `-discover-host` 出现时跳过配置文件
- 配置示例：

  ```yaml
  reporter:
    type: cf_kv
    account_id: "<cloudflare-account-id>"
    token_env: CF_TOKEN
    namespace: proxy
    prefix: cfp
  ```

  `custom_center` 使用 `type: custom_center` 和 `host: 127.0.0.1:9000`。
- 验收：cargo build 通过；两种后端各跑通一次上报；KV 模式写入-读回-清理无残留
