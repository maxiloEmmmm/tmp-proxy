//! Sends daemon discovery records to the configured backend.

use reqwest::{Client, Url};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
use tokio::time::{self, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::access_uuid::AccessUuid;
use crate::discovery::kv::KvBackend;
use crate::discovery::Report;

const CENTER_INTERVAL: Duration = Duration::from_secs(3);
const KV_INTERVAL: Duration = Duration::from_secs(60 * 60);
const CENTER_TIMEOUT: Duration = Duration::from_secs(2);

/// Destination and change signal for a daemon reporter.
enum Backend {
    /// Existing LAN center POST endpoint.
    CustomCenter {
        /// Bounded HTTP client for periodic POST requests.
        client: Client,
        /// Full center `/report` URL.
        endpoint: Url,
    },
    /// Cloudflare KV writer plus UUID change notification.
    CfKv {
        /// KV API writer and cached namespace.
        kv: Arc<KvBackend>,
        /// Signals an access UUID change between hourly reports.
        changed: Arc<Notify>,
    },
}

/// Periodic discovery reporter owned by one daemon tunnel epoch.
///
/// Example: a connected tunnel starts one reporter for its current hostname.
pub(crate) struct Reporter {
    /// Backend chosen at daemon startup.
    backend: Backend,
    /// Stable daemon identity supplied by the user.
    key: String,
    /// Current TryCloudflare hostname.
    cf: String,
    /// Local operating-system hostname.
    hostname: String,
    /// Target IP exposed through the tunnel.
    target_ip: IpAddr,
    /// Shared rotating access UUID.
    access_uuid: Arc<RwLock<AccessUuid>>,
}

impl Reporter {
    /// Creates the original three-second LAN center reporter.
    ///
    /// Example: center `10.0.0.1:9000` -> `http://10.0.0.1:9000/report`.
    pub(crate) fn new_center(
        center: SocketAddr,
        key: String,
        cf: String,
        target_ip: IpAddr,
        access_uuid: Arc<RwLock<AccessUuid>>,
    ) -> Result<Self, String> {
        let endpoint = Url::parse(&format!("http://{center}/report"))
            .map_err(|error| format!("build discovery report URL failed: {error}"))?;
        let client = Client::builder()
            .timeout(CENTER_TIMEOUT)
            .build()
            .map_err(|error| format!("create discovery HTTP client failed: {error}"))?;
        Self::new(
            Backend::CustomCenter { client, endpoint },
            key,
            cf,
            target_ip,
            access_uuid,
        )
    }

    /// Creates an hourly KV reporter that also wakes on UUID rotation.
    ///
    /// Example: current tunnel connected -> first KV write happens immediately.
    pub(crate) fn new_kv(
        kv: Arc<KvBackend>,
        changed: Arc<Notify>,
        key: String,
        cf: String,
        target_ip: IpAddr,
        access_uuid: Arc<RwLock<AccessUuid>>,
    ) -> Result<Self, String> {
        Self::new(
            Backend::CfKv { kv, changed },
            key,
            cf,
            target_ip,
            access_uuid,
        )
    }

    /// Fills the shared report identity after a backend is selected.
    ///
    /// Example: a machine hostname `nas` -> `Report.hostname = nas`.
    fn new(
        backend: Backend,
        key: String,
        cf: String,
        target_ip: IpAddr,
        access_uuid: Arc<RwLock<AccessUuid>>,
    ) -> Result<Self, String> {
        let hostname = hostname::get()
            .map_err(|error| format!("read local hostname failed: {error}"))?
            .to_string_lossy()
            .trim()
            .to_string();
        if hostname.is_empty() {
            return Err("local hostname is empty".to_string());
        }
        Ok(Self {
            backend,
            key,
            cf,
            hostname,
            target_ip,
            access_uuid,
        })
    }

    /// Sends immediately, then on the backend interval or a KV UUID change.
    ///
    /// Example: KV UUID rotation -> report now instead of waiting one hour.
    pub(crate) async fn run(self, shutdown: CancellationToken) {
        let ready = match &self.backend {
            Backend::CustomCenter { .. } => true,
            // 触发条件: 启动时 namespace title 查询失败。
            // 不能在 Connected 后马上重查: 用户要求失败后等下一次正常上报。
            // 防止副作用: 不产生额外的 Cloudflare API 请求。
            Backend::CfKv { kv, .. } => kv.is_ready().await,
        };
        if ready {
            self.report_once().await;
        }
        let period = match self.backend {
            Backend::CustomCenter { .. } => CENTER_INTERVAL,
            Backend::CfKv { .. } => KV_INTERVAL,
        };
        let start = time::Instant::now() + period;
        let mut interval = time::interval_at(start, period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            match &self.backend {
                Backend::CustomCenter { .. } => {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = interval.tick() => self.report_once().await,
                    }
                }
                Backend::CfKv { changed, .. } => {
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = interval.tick() => self.report_once().await,
                        _ = changed.notified() => self.report_once().await,
                    }
                }
            }
        }
    }

    /// Builds the latest wire record and sends it through the active backend.
    ///
    /// Example: UUID age `17s` -> JSON containing `code_age_seconds: 17`.
    async fn report_once(&self) {
        let (code, code_age_seconds) = self.access_uuid.read().await.report_snapshot();
        let report = Report {
            key: self.key.clone(),
            cf: self.cf.clone(),
            code,
            code_age_seconds,
            hostname: self.hostname.clone(),
            ip: self.target_ip.to_string(),
        };
        let result = match &self.backend {
            Backend::CustomCenter { client, endpoint } => client
                .post(endpoint.clone())
                .json(&report)
                .send()
                .await
                .and_then(reqwest::Response::error_for_status)
                .map(|_| ())
                .map_err(|error| error.to_string()),
            Backend::CfKv { kv, .. } => kv.write(&report).await,
        };
        if let Err(error) = result {
            // 触发条件: 一次上报失败，但隧道本身仍可继续服务。
            // 不能因此退出或额外重试: 用户要求等下一次正常上报时机。
            // 防止副作用: 后端故障不影响代理连接，也不产生重复写入。
            eprintln!("discovery report failed: {error}");
        }
    }
}
