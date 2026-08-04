use reqwest::{Client, Url};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::{self, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::access_uuid::AccessUuid;
use crate::discovery::Report;

const REPORT_INTERVAL: Duration = Duration::from_secs(3);
const REPORT_TIMEOUT: Duration = Duration::from_secs(2);

/// Periodic discovery reporter owned by daemon mode.
///
/// Example: active tunnel -> immediate report followed by one every 3 seconds.
pub(crate) struct Reporter {
    /// HTTP client with a timeout shorter than the report interval.
    client: Client,
    /// Full center `/report` endpoint.
    endpoint: Url,
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
    /// Creates a reporter after validating its endpoint and local hostname.
    ///
    /// Example: center `10.0.0.1:9000` -> `http://10.0.0.1:9000/report`.
    pub(crate) fn new(
        center: SocketAddr,
        key: String,
        cf: String,
        target_ip: IpAddr,
        access_uuid: Arc<RwLock<AccessUuid>>,
    ) -> Result<Self, String> {
        let endpoint = Url::parse(&format!("http://{center}/report"))
            .map_err(|error| format!("build discovery report URL failed: {error}"))?;
        let hostname = hostname::get()
            .map_err(|error| format!("read local hostname failed: {error}"))?
            .to_string_lossy()
            .trim()
            .to_string();
        if hostname.is_empty() {
            return Err("local hostname is empty".to_string());
        }
        let client = Client::builder()
            .timeout(REPORT_TIMEOUT)
            .build()
            .map_err(|error| format!("create discovery HTTP client failed: {error}"))?;
        Ok(Self {
            client,
            endpoint,
            key,
            cf,
            hostname,
            target_ip,
            access_uuid,
        })
    }

    /// Reports immediately and then every three seconds until cancelled.
    ///
    /// Example: center outage logs an error and retries on the next interval.
    pub(crate) async fn run(self, shutdown: CancellationToken) {
        self.report_once().await;
        let start = time::Instant::now() + REPORT_INTERVAL;
        let mut interval = time::interval_at(start, REPORT_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = interval.tick() => self.report_once().await,
            }
        }
    }

    /// Builds and posts the latest discovery record once.
    ///
    /// Example: current UUID age `17s` -> JSON containing `code_age_seconds: 17`.
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
        let result = self
            .client
            .post(self.endpoint.clone())
            .json(&report)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status);
        if let Err(error) = result {
            eprintln!("discovery report failed: {error}");
        }
    }
}
