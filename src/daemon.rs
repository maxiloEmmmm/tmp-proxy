use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Notify, RwLock};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::access_uuid::AccessUuid;
use crate::cf_lib::{self, SessionEvent};
use crate::connection_activity::ConnectionActivity;
use crate::discovery::config::{self, BackendConfig};
use crate::discovery::kv::KvBackend;
use crate::discovery::reporter::Reporter;
use crate::target_proxy;

const DEFAULT_TARGET_PORT: u16 = 22;
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UUID_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);
const CF_IDLE_LIFETIME: Duration = Duration::from_secs(6 * 60 * 60);

/// CLI configuration for non-GUI daemon mode.
///
/// Example: `-key nas-01 -ip 192.168.1.2` proxies to port 22.
pub(crate) struct Config {
    /// Stable identity used by the discovery center.
    pub(crate) key: String,
    /// Target IP reachable from this machine.
    pub(crate) target_ip: IpAddr,
    /// Target TCP port, defaulting to 22.
    pub(crate) target_port: u16,
    /// Optional validated discovery backend, with CLI center precedence.
    pub(crate) reporter: Option<BackendConfig>,
    /// Keep the Quick Tunnel hostname while access UUIDs continue rotating.
    pub(crate) constant_url: bool,
}

/// Reporter destination prepared once for all tunnel epochs.
enum ActiveReporter {
    /// Existing center socket address.
    CustomCenter(SocketAddr),
    /// KV backend whose resolved namespace survives tunnel refreshes.
    CfKv(Arc<KvBackend>),
}

impl Config {
    /// Parses daemon flags and enforces required `-key` and `-ip` values.
    ///
    /// Example: `-key nas -ip 10.0.0.2 -const` -> constant-URL daemon config.
    pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
        let mut key = None;
        let mut target_ip = None;
        let mut target_port = DEFAULT_TARGET_PORT;
        let mut discover_host = None;
        let mut port_seen = false;
        let mut constant_url = false;
        let mut index = 0;
        while index < args.len() {
            if args[index] == "-const" {
                if constant_url {
                    return Err(daemon_usage());
                }
                constant_url = true;
                index += 1;
                continue;
            }
            let value = args.get(index + 1).ok_or_else(daemon_usage)?;
            match args[index].as_str() {
                "-key" if key.is_none() => {
                    let value = value.trim();
                    if value.is_empty() {
                        return Err("daemon -key must not be empty".to_string());
                    }
                    key = Some(value.to_string());
                }
                "-ip" if target_ip.is_none() => {
                    target_ip = Some(
                        value
                            .parse()
                            .map_err(|error| format!("invalid daemon -ip: {error}"))?,
                    );
                }
                "-port" if !port_seen => {
                    target_port = parse_port(value, "daemon -port")?;
                    port_seen = true;
                }
                "-discover-host" if discover_host.is_none() => {
                    discover_host = Some(value.parse().map_err(|error| {
                        format!("invalid daemon -discover-host, expected ip:port: {error}")
                    })?);
                }
                _ => return Err(daemon_usage()),
            }
            index += 2;
        }
        let reporter = config::load(discover_host)?;
        Ok(Self {
            key: key.ok_or_else(daemon_usage)?,
            target_ip: target_ip.ok_or_else(daemon_usage)?,
            target_port,
            reporter,
            constant_url,
        })
    }

    /// Returns the target socket address used by request handlers.
    ///
    /// Example: target IP plus default port -> `192.168.1.2:22`.
    fn target_addr(&self) -> SocketAddr {
        SocketAddr::new(self.target_ip, self.target_port)
    }
}

/// Runs a non-GUI tunnel with rotating access UUIDs and optional reporting.
///
/// Example: `tmp-proxy -daemon ...` remains active across CF reconnects.
pub(crate) async fn run(config: Config) -> Result<(), String> {
    let target = config.target_addr();
    check_target(target).await?;
    let reporter_backend = match config.reporter {
        Some(BackendConfig::CustomCenter(center)) => Some(ActiveReporter::CustomCenter(center)),
        Some(BackendConfig::CfKv(kv_config)) => {
            let kv = Arc::new(KvBackend::new(kv_config, &config.key)?);
            if let Err(error) = kv.prepare().await {
                // 触发条件: 启动时 Cloudflare namespace 暂时无法解析。
                // 不能让 daemon 退出或立刻重试: 上报失败只记日志，等下一次正常上报。
                // 防止副作用: discovery 故障不影响 tunnel 启动。
                eprintln!("discovery report failed: {error}");
            }
            Some(ActiveReporter::CfKv(kv))
        }
        None => None,
    };
    let access_uuid = Arc::new(RwLock::new(AccessUuid::generate()));
    let uuid_rotation = time::sleep(UUID_LIFETIME);
    tokio::pin!(uuid_rotation);

    loop {
        let quick_tunnel = cf_lib::create_quick_tunnel()
            .await
            .map_err(|error| format!("create tunnel failed: {error}"))?;
        let cf_hostname = quick_tunnel.hostname;
        let session = quick_tunnel.session;
        let mut events = session.events();
        // 触发条件: -const 禁用空闲刷新，连接活跃度不再影响 URL。
        // 不能继续跟踪每条连接: 那只会增加不必要的锁操作。
        // 防止副作用: 常量模式不为已停用的定时器维护状态。
        let activity = (!config.constant_url).then(ConnectionActivity::new);
        let idle_activity = activity.clone();
        let idle_refresh = async move {
            if let Some(activity) = idle_activity {
                activity.seal_after_idle(CF_IDLE_LIFETIME).await;
            }
        };
        tokio::pin!(idle_refresh);
        let reporter_shutdown = CancellationToken::new();
        let reporter_changed = Arc::new(Notify::new());
        let mut reporter_task: Option<JoinHandle<()>> = None;
        let mut reporter_started = false;
        print_current_url(&cf_hostname, config.target_port, &access_uuid).await?;

        loop {
            // 触发条件: -const 只固定 hostname，UUID 仍须每 24 小时轮换。
            // 不能停用 UUID 定时器: KV 客户端依赖定期取得新访问码。
            // 防止副作用: 仅禁用空闲重建，避免 hostname 被替换。
            tokio::select! {
                biased;
                _ = &mut uuid_rotation => {
                    // 触发条件: UUID 轮换与新请求可能在同一轮就绪。
                    // 不能使用随机分支顺序: 边界请求可能继续取得旧 UUID。
                    // 防止副作用: -const 保留上一枚 UUID，其他模式立即淘汰。
                    access_uuid.write().await.rotate(config.constant_url);
                    uuid_rotation.as_mut().reset(time::Instant::now() + UUID_LIFETIME);
                    print_current_url(&cf_hostname, config.target_port, &access_uuid).await?;
                    if reporter_task.is_some() {
                        reporter_changed.notify_one();
                    }
                }
                event = events.recv() => match event {
                    Ok(SessionEvent::Connected { transport, location }) => {
                        println!("ready via {transport:?} at {location}");
                        if !reporter_started {
                            if let Some(backend) = &reporter_backend {
                                let reporter = match backend {
                                    ActiveReporter::CustomCenter(center) => Reporter::new_center(
                                        *center,
                                        config.key.clone(),
                                        cf_hostname.clone(),
                                        config.target_ip,
                                        access_uuid.clone(),
                                    )?,
                                    ActiveReporter::CfKv(kv) => Reporter::new_kv(
                                        kv.clone(),
                                        reporter_changed.clone(),
                                        config.key.clone(),
                                        cf_hostname.clone(),
                                        config.target_ip,
                                        access_uuid.clone(),
                                    )?,
                                };
                                let shutdown = reporter_shutdown.clone();
                                reporter_task = Some(tokio::spawn(async move {
                                    reporter.run(shutdown).await
                                }));
                            }
                            reporter_started = true;
                        }
                    }
                    Ok(SessionEvent::Reconnecting { delay, reason }) => {
                        eprintln!(
                            "connection lost ({reason}), retrying in {}ms",
                            delay.as_millis()
                        );
                    }
                    Ok(SessionEvent::Unauthorized { reason }) => {
                        // 触发条件: Cloudflare 已拒绝当前 Quick Tunnel 凭据。
                        // 不能继续当前 session: 重连仍会提交相同的失效凭据。
                        // 防止副作用: 先停止旧上报，避免它覆盖下一代 KV endpoint。
                        eprintln!(
                            "tunnel credentials rejected ({reason}), creating a new Quick Tunnel"
                        );
                        stop_reporter(&reporter_shutdown, &mut reporter_task).await?;
                        break;
                    }
                    Ok(SessionEvent::Stopped) => {
                        stop_reporter(&reporter_shutdown, &mut reporter_task).await?;
                        return Ok(());
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        stop_reporter(&reporter_shutdown, &mut reporter_task).await?;
                        return Err("tunnel event channel closed".to_string());
                    }
                },
                request = session.accept() => {
                    let request = match request {
                        Ok(request) => request,
                        Err(error) => {
                            stop_reporter(&reporter_shutdown, &mut reporter_task).await?;
                            return Err(format!("accept tunnel request failed: {error}"));
                        }
                    };
                    // 触发条件: 请求接入后可能立刻发生下一轮 UUID 轮换。
                    // 不能在异步处理器中再次读取共享 UUID: 调度延迟会改变判定时点。
                    // 防止副作用: 接入时快照保证轮换不影响已接入及已建立的连接。
                    let expected_uuids = access_uuid.read().await.accepted_values();
                    let target = target_proxy::Target::with_port_override(
                        config.target_ip,
                        config.target_port,
                    );
                    let activity = activity.clone();
                    tokio::spawn(async move {
                        if let Err(error) = target_proxy::handle_request(
                            request,
                            target,
                            expected_uuids,
                            activity,
                        ).await {
                            eprintln!("{error}");
                        }
                    });
                }
                _ = &mut idle_refresh, if !config.constant_url => {
                    println!("tunnel idle for six hours, refreshing URL");
                    stop_reporter(&reporter_shutdown, &mut reporter_task).await?;
                    session
                        .shutdown()
                        .await
                        .map_err(|error| format!("shutdown idle tunnel failed: {error}"))?;
                    *access_uuid.write().await = AccessUuid::generate();
                    uuid_rotation.as_mut().reset(time::Instant::now() + UUID_LIFETIME);
                    break;
                }
            }
        }
    }
}

/// Cancels and joins the reporter before an epoch can publish a replacement URL.
///
/// Example: idle refresh waits until the old reporter has stopped posting.
async fn stop_reporter(
    shutdown: &CancellationToken,
    reporter_task: &mut Option<JoinHandle<()>>,
) -> Result<(), String> {
    shutdown.cancel();
    if let Some(task) = reporter_task.take() {
        // 触发条件: CF URL 刷新时旧 reporter 可能正在执行一次 POST。
        // 不能只发取消信号: 旧 POST 可能晚于新 URL 上报并覆盖 center。
        // 防止副作用: 等待旧任务退出，保证 report 的 URL 代际单调前进。
        task.await
            .map_err(|error| format!("discovery reporter task failed: {error}"))?;
    }
    Ok(())
}

/// Verifies the daemon target before requesting a temporary tunnel.
///
/// Example: unreachable `192.168.1.2:22` -> bounded startup error.
async fn check_target(target: SocketAddr) -> Result<(), String> {
    time::timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| format!("connect {target} timed out"))?
        .map_err(|error| format!("connect {target} failed: {error}"))?;
    Ok(())
}

/// Prints the WSS URL corresponding to the currently active UUID.
///
/// Example: each 24-hour rotation emits the newly usable URL and default port.
async fn print_current_url(
    cf_hostname: &str,
    target_port: u16,
    access_uuid: &RwLock<AccessUuid>,
) -> Result<(), String> {
    let uuid = access_uuid.read().await.value().to_string();
    let url = target_proxy::build_wss_url(cf_hostname, &uuid, Some(target_port))?;
    println!("url: {url}");
    println!("code: {uuid}");
    Ok(())
}

/// Parses one non-zero target TCP port.
///
/// Example: `"22" -> 22`, `"0" -> error`.
fn parse_port(raw: &str, name: &str) -> Result<u16, String> {
    raw.parse::<u16>()
        .map_err(|_| format!("{name} must be 1..65535"))
        .and_then(|port| {
            if port == 0 {
                Err(format!("{name} must be 1..65535"))
            } else {
                Ok(port)
            }
        })
}

/// Returns the accepted daemon command syntax.
///
/// Example: missing `-key` -> this usage string.
fn daemon_usage() -> String {
    "usage: tmp-proxy -daemon -key <key> -ip <target_ip> [-port <target_port>] [-discover-host <ip:port>] [-const]".to_string()
}
