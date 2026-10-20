//! Sends daemon discovery records to the configured backend.

use reqwest::{Client, Url};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};
use tokio::time::{self, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::access_uuid::AccessUuid;
use crate::discovery::kv::{KvBackend, KvWriteError};
use crate::discovery::Report;

const CENTER_INTERVAL: Duration = Duration::from_secs(3);
const KV_INTERVAL: Duration = Duration::from_secs(60 * 60);
const KV_RETRY_INTERVAL: Duration = Duration::from_secs(60);
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

    /// Runs the scheduling policy selected by the active backend.
    ///
    /// Example: KV failure -> retry every minute until a write succeeds.
    pub(crate) async fn run(self, shutdown: CancellationToken) {
        match &self.backend {
            Backend::CustomCenter { client, endpoint } => {
                self.run_center(client, endpoint, shutdown).await
            }
            Backend::CfKv { kv, changed } => self.run_kv(kv, changed, shutdown).await,
        }
    }

    /// Sends LAN-center reports immediately and every three seconds.
    ///
    /// Example: one center failure -> log once and continue the normal schedule.
    async fn run_center(&self, client: &Client, endpoint: &Url, shutdown: CancellationToken) {
        self.report_center_once(client, endpoint).await;
        let start = time::Instant::now() + CENTER_INTERVAL;
        let mut interval = time::interval_at(start, CENTER_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => self.report_center_once(client, endpoint).await,
            }
        }
    }

    /// Retries recoverable KV failures every minute until one write succeeds.
    ///
    /// Example: startup timeout -> retry after one minute, then resume hourly writes.
    async fn run_kv(&self, kv: &KvBackend, changed: &Notify, shutdown: CancellationToken) {
        let next_attempt = time::sleep(Duration::ZERO);
        tokio::pin!(next_attempt);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = changed.notified() => {
                    next_attempt.as_mut().reset(time::Instant::now());
                }
                _ = &mut next_attempt => {
                    let delay = match self.report_kv_once(kv).await {
                        Ok(()) => KV_INTERVAL,
                        Err(error) if error.should_retry() => {
                            // 触发条件: 网络、限流或服务端故障中断本次 KV 更新。
                            // 不能等待一小时: 短暂启动抖动会让新 endpoint 长时间不可发现。
                            // 防止副作用: 单任务串行重试，避免并发写入覆盖最新状态。
                            eprintln!(
                                "discovery report failed: {error}; retrying in 60 seconds"
                            );
                            KV_RETRY_INTERVAL
                        }
                        Err(error) => {
                            eprintln!("discovery report failed: {error}");
                            KV_INTERVAL
                        }
                    };
                    next_attempt.as_mut().reset(time::Instant::now() + delay);
                }
            }
        }
    }

    /// Builds the latest discovery record from the shared UUID state.
    ///
    /// Example: UUID age `17s` -> JSON containing `code_age_seconds: 17`.
    async fn current_report(&self) -> Report {
        let (code, code_age_seconds) = self.access_uuid.read().await.report_snapshot();
        Report {
            key: self.key.clone(),
            cf: self.cf.clone(),
            code,
            code_age_seconds,
            hostname: self.hostname.clone(),
            ip: self.target_ip.to_string(),
        }
    }

    /// Sends one report to the custom LAN center.
    ///
    /// Example: HTTP 500 -> log the failure without stopping the tunnel.
    async fn report_center_once(&self, client: &Client, endpoint: &Url) {
        let report = self.current_report().await;
        if let Err(error) = client
            .post(endpoint.clone())
            .json(&report)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
        {
            eprintln!("discovery report failed: {error}");
        }
    }

    /// Sends one report through the Cloudflare KV backend.
    ///
    /// Example: HTTP 429 -> a retryable error returned to the scheduler.
    async fn report_kv_once(&self, kv: &KvBackend) -> Result<(), KvWriteError> {
        let report = self.current_report().await;
        kv.write(&report).await
    }
}
