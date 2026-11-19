# tmp-proxy

用 Rust 将本地服务接入 Cloudflare Quick Tunnel。连接端可以通过一条 WebSocket 同时转发多条 TCP 连接和 UDP 会话，并通过 Workers KV 跟随隧道地址和访问码的更新。

```text
应用 → tmp-proxy -yy / singbox-x → WSS → Cloudflare → tmp-proxy daemon → 目标服务
```

## 快速开始

在仓库根目录安装。构建需要 Rust 工具链和 PATH 中的 `capnp` 编译器。

```bash
cargo install --path . --locked --bin tmp-proxy
```

在两端准备一份 CFP 配置。命令行默认读取 `~/.config/cfp/config.yaml`，也可用 `CFP_CONFIG` 指定路径。

```yaml
reporter:
  type: cf_kv
  account_id: "<Cloudflare 账号 ID>"
  token_env: CF_TOKEN
  namespace: "<Workers KV namespace 名称或 ID>"
  prefix: cfp
```

在各自进程的环境里设置 `CF_TOKEN`。daemon 需要目标 namespace 的写入权限，连接端需要读取权限。两端使用同一个账号和 namespace，KV Key 由 daemon 的 `prefix` 和 `-key` 拼成完整的 `prefix/key`。

在服务所在机器启动 daemon。以下示例的 HTTP 服务监听 `127.0.0.1:8080`，发布的 KV Key 是 `cfp/demo`。

```bash
tmp-proxy -daemon -key demo -ip 127.0.0.1 -port 8080 -const
```

在另一台机器启动转发，再访问本地端口。

```bash
tmp-proxy -yy -kvk cfp/demo 127.0.0.1:18080
```

```bash
curl http://127.0.0.1:18080/
```

`-yy` 也可以直接接收 daemon 输出的 WSS URL。这个 URL 包含隧道访问码。使用 KV 时，连接端会在后台刷新地址，并在连接失败时重新查询。daemon 的 `-const` 关闭空闲触发的隧道重建，访问码仍定期轮换。

## 接入 singbox-x

把同一个 `cfp/demo` 填进 `singbox-x` 的 CF outbound，即可按目标地址转发 TCP 和 UDP。使用 sboxctl 时，在面板里添加一个 `cf` 静态节点，填写 KV Key，再把目标网段指向这个节点。[singbox-x CF 配置](https://github.com/maxiloEmmmm/singbox-x#cf-mux) · [sboxctl](https://github.com/maxiloEmmmm/singbox-mini-panel)

## 其他用法

- 临时分享端口时，直接运行 `tmp-proxy` 打开图形界面，也可以用 `tmp-proxy xx 127.0.0.1:22 user` 获取连接命令。
- daemon 指向 SSH 服务时，可用 `tmp-proxy zz -kvk cfp/demo -- ssh -p '{PORT}' user@127.0.0.1`。它分配一个临时本地端口，替换 `{PORT}`，并跟随 SSH 进程退出。
- `-center` 提供局域网发现服务。daemon 用 `-discover-host` 向 center 上报，可从 `/list` 读取记录。
- Linux 常驻部署可参考仓库中的 service 和 CFP 模板。示例通过 `CFP_CONFIG=/etc/cfp/config.yaml` 加载配置。[systemd 示例](deploy/systemd)
