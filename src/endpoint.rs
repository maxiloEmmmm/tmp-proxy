//! Resolves direct or KV-backed WSS endpoints for yy and zz consumers.

use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::time;
use url::Url;

use crate::discovery::config::{self, BackendConfig};
use crate::discovery::kv::KvReader;
use crate::target_proxy;

const KV_REFRESH_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);
const KV_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// Endpoint source selected by yy or zz command-line parsing.
///
/// Example: `Kv { key: "cfp/demo", query: "port=10808" }` enables refresh.
pub(crate) enum Spec {
    /// Complete WSS URL that never needs discovery refresh.
    Url(String),
    /// Complete KV key plus an optional query appended to each discovered URL.
    Kv {
        /// Full KV key including its business prefix.
        key: String,
        /// Optional raw query that cannot replace the discovered code.
        query: Option<String>,
    },
}

/// Consumer name included in KV retry and refresh logs.
///
/// Example: a zz fetch failure is logged with the `zz` prefix.
#[derive(Clone, Copy)]
pub(crate) enum Consumer {
    /// Long-running local TCP listener mode.
    Yy,
    /// Child-command mode that also requires visible refresh logs.
    Zz,
}

impl Consumer {
    /// Returns the stable CLI label used in endpoint logs.
    ///
    /// Example: `Consumer::Zz -> "zz"`.
    fn label(self) -> &'static str {
        match self {
            Self::Yy => "yy",
            Self::Zz => "zz",
        }
    }
}

/// Cloneable view of the most recently resolved WSS endpoint.
///
/// Example: each accepted TCP connection snapshots the current refreshed URL.
#[derive(Clone)]
pub(crate) struct Source {
    /// Watch receiver retaining and exposing the newest endpoint string.
    current: watch::Receiver<String>,
    /// Failure refresh signal, absent for direct URL endpoints.
    refresh_requests: Option<mpsc::Sender<()>>,
}

impl Source {
    /// Starts direct resolution or waits until the first KV fetch succeeds.
    ///
    /// Example: unavailable KV retries every ten seconds before returning.
    pub(crate) async fn start(spec: Spec, consumer: Consumer) -> Result<Self, String> {
        match spec {
            Spec::Url(wss_url) => {
                let (_, current) = watch::channel(wss_url);
                Ok(Self {
                    current,
                    refresh_requests: None,
                })
            }
            Spec::Kv { key, query } => Self::start_kv(key, query, consumer).await,
        }
    }

    /// Returns an owned snapshot without holding the watch borrow across I/O.
    ///
    /// Example: a connection accepted after refresh receives the new code.
    pub(crate) fn current(&self) -> String {
        self.current.borrow().clone()
    }

    /// Requests one coalesced KV refresh after a WSS dial failure.
    ///
    /// Example: an expired Quick Tunnel hostname -> return the new KV URL;
    /// an unchanged or direct URL -> `None`.
    pub(crate) async fn refresh_after_failure(&mut self, failed: &str) -> Option<String> {
        let refresh_requests = self.refresh_requests.as_ref()?;
        let current = self.current.borrow_and_update().clone();
        if current != failed {
            return Some(current);
        }
        let _ = refresh_requests.try_send(());
        self.current.changed().await.ok()?;
        let refreshed = self.current.borrow_and_update().clone();
        (refreshed != failed).then_some(refreshed)
    }

    /// Creates one refreshing KV source after validating local configuration.
    ///
    /// Example: first successful read starts a twelve-hour refresh cycle.
    async fn start_kv(
        key: String,
        query: Option<String>,
        consumer: Consumer,
    ) -> Result<Self, String> {
        let backend =
            config::load(None)?.ok_or("KV endpoint requires a cf_kv reporter configuration")?;
        let BackendConfig::CfKv(config) = backend else {
            return Err("KV endpoint requires reporter.type: cf_kv".to_string());
        };
        let query = normalize_query(query)?;
        let reader = KvReader::new(config)?;
        let initial = read_until_success(&reader, &key, query.as_deref(), consumer).await;
        println!("{} KV endpoint loaded for {key}", consumer.label());
        let (updates, current) = watch::channel(initial);
        let (refresh_requests, requested_refreshes) = mpsc::channel(1);
        tokio::spawn(refresh_loop(
            reader,
            key,
            query,
            consumer,
            updates,
            requested_refreshes,
        ));
        Ok(Self {
            current,
            refresh_requests: Some(refresh_requests),
        })
    }
}

/// Refreshes on schedule or WSS failure and retries KV failures every ten seconds.
///
/// Example: an expired hostname triggers an immediate KV read and wakes all waiters.
async fn refresh_loop(
    reader: KvReader,
    key: String,
    query: Option<String>,
    consumer: Consumer,
    updates: watch::Sender<String>,
    mut requested_refreshes: mpsc::Receiver<()>,
) {
    let mut last_forced_refresh: Option<time::Instant> = None;
    loop {
        let forced = tokio::select! {
            _ = time::sleep(KV_REFRESH_INTERVAL) => false,
            request = requested_refreshes.recv() => {
                if request.is_none() {
                    return;
                }
                true
            }
        };
        if forced {
            // 触发条件：失效 endpoint 会让多个本地连接同时请求刷新。
            // 不能逐连接读取 KV：浏览器或 SSH 重试会放大 API 请求。
            // 防止副作用：强制刷新至少间隔十秒，容量一的 channel 合并并发请求。
            if let Some(last_refresh) = last_forced_refresh {
                let next_refresh = last_refresh + KV_RETRY_INTERVAL;
                if next_refresh > time::Instant::now() {
                    time::sleep_until(next_refresh).await;
                }
            }
        }
        let endpoint = read_until_success(&reader, &key, query.as_deref(), consumer).await;
        updates.send_replace(endpoint);
        if forced {
            last_forced_refresh = Some(time::Instant::now());
            println!(
                "{} KV endpoint refreshed after connection failure for {key}",
                consumer.label()
            );
        } else {
            println!("{} KV endpoint refreshed for {key}", consumer.label());
        }
    }
}

/// Reads until one valid endpoint succeeds, logging each bounded retry.
///
/// Example: HTTP failure -> log, sleep ten seconds, and retry the same key.
async fn read_until_success(
    reader: &KvReader,
    key: &str,
    query: Option<&str>,
    consumer: Consumer,
) -> String {
    loop {
        match read_endpoint(reader, key, query).await {
            Ok(endpoint) => return endpoint,
            Err(error) => {
                eprintln!(
                    "{} KV endpoint fetch failed for {key}: {error}; retrying in 10 seconds",
                    consumer.label()
                );
                time::sleep(KV_RETRY_INTERVAL).await;
            }
        }
    }
}

/// Reads and converts one KV record into a complete WSS URL.
///
/// Example: hostname and code record plus `port=10808` -> dialable endpoint.
async fn read_endpoint(
    reader: &KvReader,
    key: &str,
    query: Option<&str>,
) -> Result<String, String> {
    let endpoint = reader.read(key).await?;
    let wss_url = target_proxy::build_wss_url(&endpoint.hostname, &endpoint.code, None)?;
    append_query(&wss_url, query)
}

/// Validates and normalizes an optional caller query once before retrying.
///
/// Example: `?port=10808` -> `port=10808`; `code=x` -> error.
fn normalize_query(query: Option<String>) -> Result<Option<String>, String> {
    let Some(query) = query else {
        return Ok(None);
    };
    let query = query.trim().trim_start_matches('?').trim_start_matches('&');
    if query.is_empty() || query.contains('#') || query.contains('?') {
        return Err("-query must contain a non-empty query string without ? or #".to_string());
    }
    if url::form_urlencoded::parse(query.as_bytes()).any(|(key, _)| key == "code") {
        return Err("-query must not override code".to_string());
    }
    Ok(Some(query.to_string()))
}

/// Appends one previously validated query to a generated WSS URL.
///
/// Example: URL containing code plus `port=10808` -> both query fields retained.
fn append_query(wss_url: &str, query: Option<&str>) -> Result<String, String> {
    let Some(query) = query else {
        return Ok(wss_url.to_string());
    };
    let mut url =
        Url::parse(wss_url).map_err(|error| format!("invalid generated wss url: {error}"))?;
    let combined = match url.query() {
        Some(existing) if !existing.is_empty() => format!("{existing}&{query}"),
        _ => query.to_string(),
    };
    url.set_query(Some(&combined));
    Ok(url.to_string())
}
