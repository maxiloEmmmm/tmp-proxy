use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::{self, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::access_uuid::AccessUuid;
use crate::cf_lib::{self, SessionEvent};
use crate::discovery::reporter::Reporter;
use crate::target_proxy;

const DEFAULT_TARGET_PORT: u16 = 22;
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const UUID_LIFETIME: Duration = Duration::from_secs(60);

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
    /// Optional discovery center receiving periodic reports.
    pub(crate) discover_host: Option<SocketAddr>,
}

impl Config {
    /// Parses daemon flags and enforces required `-key` and `-ip` values.
    ///
    /// Example: `-key nas -ip 10.0.0.2 -port 22` -> daemon config.
    pub(crate) fn parse(args: &[String]) -> Result<Self, String> {
        if args.len() % 2 != 0 {
            return Err(daemon_usage());
        }
        let mut key = None;
        let mut target_ip = None;
        let mut target_port = DEFAULT_TARGET_PORT;
        let mut discover_host = None;
        let mut port_seen = false;
        for pair in args.chunks_exact(2) {
            match pair[0].as_str() {
                "-key" if key.is_none() => {
                    let value = pair[1].trim();
                    if value.is_empty() {
                        return Err("daemon -key must not be empty".to_string());
                    }
                    key = Some(value.to_string());
                }
                "-ip" if target_ip.is_none() => {
                    target_ip = Some(
                        pair[1]
                            .parse()
                            .map_err(|error| format!("invalid daemon -ip: {error}"))?,
                    );
                }
                "-port" if !port_seen => {
                    target_port = parse_port(&pair[1], "daemon -port")?;
                    port_seen = true;
                }
                "-discover-host" if discover_host.is_none() => {
                    discover_host = Some(pair[1].parse().map_err(|error| {
                        format!("invalid daemon -discover-host, expected ip:port: {error}")
                    })?);
                }
                _ => return Err(daemon_usage()),
            }
        }
        Ok(Self {
            key: key.ok_or_else(daemon_usage)?,
            target_ip: target_ip.ok_or_else(daemon_usage)?,
            target_port,
            discover_host,
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
    let quick_tunnel = cf_lib::create_quick_tunnel()
        .await
        .map_err(|error| format!("create tunnel failed: {error}"))?;
    let cf_hostname = quick_tunnel.hostname;
    let session = quick_tunnel.session;
    let mut events = session.events();
    let access_uuid = Arc::new(RwLock::new(AccessUuid::generate()));
    print_current_url(&cf_hostname, &access_uuid).await?;

    let rotation_start = time::Instant::now() + UUID_LIFETIME;
    let mut rotation = time::interval_at(rotation_start, UUID_LIFETIME);
    rotation.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let reporter_shutdown = CancellationToken::new();
    let mut reporter_started = false;

    loop {
        tokio::select! {
            biased;
            _ = rotation.tick() => {
                // 触发条件: UUID 轮换与新请求可能在同一轮就绪。
                // 不能使用随机分支顺序: 边界请求可能继续取得旧 UUID。
                // 防止副作用: 优先轮换让新请求只快照新 UUID。
                *access_uuid.write().await = AccessUuid::generate();
                print_current_url(&cf_hostname, &access_uuid).await?;
            }
            event = events.recv() => match event {
                Ok(SessionEvent::Connected { transport, location }) => {
                    println!("ready via {transport:?} at {location}");
                    if !reporter_started {
                        if let Some(center) = config.discover_host {
                            let reporter = Reporter::new(
                                center,
                                config.key.clone(),
                                cf_hostname.clone(),
                                config.target_ip,
                                access_uuid.clone(),
                            )?;
                            let shutdown = reporter_shutdown.clone();
                            tokio::spawn(async move { reporter.run(shutdown).await });
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
                Ok(SessionEvent::Stopped) => {
                    reporter_shutdown.cancel();
                    return Ok(());
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    reporter_shutdown.cancel();
                    return Err("tunnel event channel closed".to_string());
                }
            },
            request = session.accept() => {
                let request = request
                    .map_err(|error| format!("accept tunnel request failed: {error}"))?;
                // 触发条件: 请求接入后可能立刻发生下一轮 UUID 轮换。
                // 不能在异步处理器中再次读取共享 UUID: 调度延迟会改变判定时点。
                // 防止副作用: 接入时快照保证轮换不影响已接入及已建立的连接。
                let expected_uuid = access_uuid.read().await.value().to_string();
                let target = target.to_string();
                tokio::spawn(async move {
                    if let Err(error) = target_proxy::handle_request(request, target, expected_uuid).await {
                        eprintln!("{error}");
                    }
                });
            }
        }
    }
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
/// Example: each one-minute rotation emits the newly usable URL.
async fn print_current_url(
    cf_hostname: &str,
    access_uuid: &RwLock<AccessUuid>,
) -> Result<(), String> {
    let uuid = access_uuid.read().await.value().to_string();
    let url = target_proxy::build_wss_url(cf_hostname, &uuid)?;
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
    "usage: tmp-proxy -daemon -key <key> -ip <target_ip> [-port <target_port>] [-discover-host <ip:port>]".to_string()
}
