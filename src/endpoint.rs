//! Resolves direct or KV-backed WSS endpoints for yy and zz consumers.

use std::time::Duration;
use tokio::sync::watch;
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
}

impl Source {
    /// Starts direct resolution or waits until the first KV fetch succeeds.
    ///
    /// Example: unavailable KV retries every ten seconds before returning.
    pub(crate) async fn start(spec: Spec, consumer: Consumer) -> Result<Self, String> {
        match spec {
            Spec::Url(wss_url) => {
                let (_, current) = watch::channel(wss_url);
                Ok(Self { current })
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
        tokio::spawn(refresh_loop(reader, key, query, consumer, updates));
        Ok(Self { current })
    }
}

/// Refreshes twelve hours after success and retries failures every ten seconds.
///
/// Example: three failed reads preserve the old endpoint until the fourth succeeds.
async fn refresh_loop(
    reader: KvReader,
    key: String,
    query: Option<String>,
    consumer: Consumer,
    updates: watch::Sender<String>,
) {
    loop {
        time::sleep(KV_REFRESH_INTERVAL).await;
        let endpoint = read_until_success(&reader, &key, query.as_deref(), consumer).await;
        updates.send_replace(endpoint);
        println!("{} KV endpoint refreshed for {key}", consumer.label());
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
