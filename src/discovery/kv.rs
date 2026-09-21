//! Cloudflare Workers KV REST API backend for discovery reports.

use reqwest::{Client, Url};
use serde::Deserialize;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::discovery::config::CfKvConfig;
use crate::discovery::Report;

const ACCOUNT_ID: &str = "00000000000000000000000000000000";
const API_BASE: &str = "https://api.cloudflare.com/client/v4";
const EXPIRATION_TTL_SECONDS: u64 = 3 * 60 * 60;
const API_TIMEOUT: Duration = Duration::from_secs(10);
const NAMESPACES_PER_PAGE: usize = 1000;

/// Prepared KV client that caches the resolved namespace ID for the daemon lifetime.
pub(crate) struct KvBackend {
    /// HTTP client shared by namespace lookups and report writes.
    client: Client,
    /// Bearer token kept out of logs.
    token: String,
    /// Namespace title or ID from config.
    namespace: String,
    /// Successful namespace resolution retained across tunnel refreshes.
    namespace_id: RwLock<Option<String>>,
    /// Complete Workers KV key, `prefix/key`.
    key: String,
}

/// Cloudflare response wrapper for namespace listing and KV writes.
#[derive(Deserialize)]
struct ApiResponse<T> {
    /// Cloudflare operation result flag.
    success: bool,
    /// Operation-specific result, absent on some errors.
    result: Option<T>,
    /// Structured API error messages.
    #[serde(default)]
    errors: Vec<ApiError>,
}

/// One error returned by the Cloudflare API.
#[derive(Deserialize)]
struct ApiError {
    /// Human-readable reason safe to log without the bearer token.
    message: String,
}

/// Namespace entry from a list response.
#[derive(Deserialize)]
struct Namespace {
    /// Stable namespace ID used by the value endpoint.
    id: String,
    /// Human-readable namespace title.
    title: String,
}

impl KvBackend {
    /// Builds a KV backend and validates the full key before any network work.
    ///
    /// Example: prefix `cfp`, daemon key `nas` -> KV key `cfp/nas`.
    pub(crate) fn new(config: CfKvConfig, daemon_key: &str) -> Result<Self, String> {
        let key = format!("{}/{daemon_key}", config.prefix);
        if key.len() > 512 || key.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
            return Err("KV key must be at most 512 bytes and contain no whitespace".to_string());
        }
        let namespace_id = if is_namespace_id(&config.namespace) {
            Some(config.namespace.clone())
        } else {
            None
        };
        let client = Client::builder()
            .timeout(API_TIMEOUT)
            .build()
            .map_err(|error| format!("create Cloudflare HTTP client failed: {error}"))?;
        Ok(Self {
            client,
            token: config.token,
            namespace: config.namespace,
            namespace_id: RwLock::new(namespace_id),
            key,
        })
    }

    /// Resolves a namespace title at startup, keeping a successful ID cached.
    ///
    /// Example: title `proxy` -> its 32-character namespace ID.
    pub(crate) async fn prepare(&self) -> Result<(), String> {
        self.resolve_namespace().await.map(|_| ())
    }

    /// Indicates whether startup has already resolved the namespace.
    ///
    /// Example: failed title lookup -> false until a later normal report succeeds.
    pub(crate) async fn is_ready(&self) -> bool {
        self.namespace_id.read().await.is_some()
    }

    /// Writes one report with a fixed three-hour expiration.
    ///
    /// Example: a new UUID -> PUT latest `Report` to `cfp/nas`.
    pub(crate) async fn write(&self, report: &Report) -> Result<(), String> {
        let namespace_id = self.resolve_namespace().await?;
        let mut url =
            Url::parse(API_BASE).map_err(|error| format!("invalid CF API URL: {error}"))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| "CF API URL cannot contain path segments".to_string())?;
            segments.extend(["accounts", ACCOUNT_ID, "storage", "kv", "namespaces"]);
            segments.push(&namespace_id);
            segments.push("values");
            // 触发条件: key 带业务分组前缀，分隔符是实际的 `/`。
            // 不能整体 push `prefix/key`: URL 库会把 `/` 编成 `%2F`。
            // 防止副作用: KV 中的 key 与配置要求的 `prefix/key` 一致。
            for part in self.key.split('/') {
                segments.push(part);
            }
        }
        url.query_pairs_mut()
            .append_pair("expiration_ttl", &EXPIRATION_TTL_SECONDS.to_string());
        let response = self
            .client
            .put(url)
            .bearer_auth(&self.token)
            .json(report)
            .send()
            .await
            .map_err(|error| format!("Cloudflare KV write request failed: {error}"))?;
        let status = response.status();
        let body: ApiResponse<serde::de::IgnoredAny> = response
            .json()
            .await
            .map_err(|error| format!("Cloudflare KV write returned {status}: {error}"))?;
        if !status.is_success() || !body.success {
            return Err(format!(
                "Cloudflare KV write returned {status}: {}",
                api_error_summary(&body.errors)
            ));
        }
        Ok(())
    }

    /// Returns a cached ID or lists namespace pages until a title matches.
    ///
    /// Example: failed startup lookup -> next scheduled report tries again.
    async fn resolve_namespace(&self) -> Result<String, String> {
        if let Some(id) = self.namespace_id.read().await.as_ref() {
            return Ok(id.clone());
        }
        let mut page = 1;
        loop {
            let endpoint = format!(
                "{API_BASE}/accounts/{ACCOUNT_ID}/storage/kv/namespaces?page={page}&per_page={NAMESPACES_PER_PAGE}"
            );
            let response = self
                .client
                .get(endpoint)
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|error| format!("Cloudflare namespace lookup failed: {error}"))?;
            let status = response.status();
            let body: ApiResponse<Vec<Namespace>> = response.json().await.map_err(|error| {
                format!("Cloudflare namespace lookup returned {status}: {error}")
            })?;
            if !status.is_success() || !body.success {
                return Err(format!(
                    "Cloudflare namespace lookup returned {status}: {}",
                    api_error_summary(&body.errors)
                ));
            }
            let namespaces = body
                .result
                .ok_or("Cloudflare namespace lookup omitted result")?;
            if let Some(found) = namespaces.iter().find(|item| item.title == self.namespace) {
                let id = found.id.clone();
                *self.namespace_id.write().await = Some(id.clone());
                return Ok(id);
            }
            if namespaces.len() < NAMESPACES_PER_PAGE {
                return Err(format!(
                    "Cloudflare namespace {:?} not found",
                    self.namespace
                ));
            }
            page += 1;
        }
    }
}

/// Recognizes the 32-character hexadecimal namespace ID shape.
///
/// Example: `999c...3cbc` -> true; `proxy` -> false.
fn is_namespace_id(raw: &str) -> bool {
    raw.len() == 32 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Joins Cloudflare error messages without including request credentials.
///
/// Example: one API error -> its message; none -> `unspecified API error`.
fn api_error_summary(errors: &[ApiError]) -> String {
    if errors.is_empty() {
        "unspecified API error".to_string()
    } else {
        errors
            .iter()
            .map(|error| error.message.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Resolved endpoint fields read from one discovery KV value.
///
/// Example: KV JSON `{ "cf": "edge.trycloudflare.com", "code": "..." }` -> endpoint parts.
pub(crate) struct KvEndpoint {
    /// Public TryCloudflare hostname.
    pub(crate) hostname: String,
    /// Canonical access UUID.
    pub(crate) code: String,
}

/// Independent KV reader used by yy/zz URL discovery.
pub(crate) struct KvReader {
    /// HTTP client shared by namespace lookup and value reads.
    client: Client,
    /// Bearer token kept out of logs.
    token: String,
    /// Namespace title or ID from configuration.
    namespace: String,
    /// Cached namespace ID.
    namespace_id: RwLock<Option<String>>,
}

/// Minimal value shape consumed by yy/zz; it intentionally does not depend on `Report`.
#[derive(Deserialize)]
struct KvEndpointValue {
    /// Public TryCloudflare hostname.
    cf: String,
    /// Canonical access UUID.
    code: String,
}

impl KvReader {
    /// Creates a reader from the existing cf_kv configuration.
    ///
    /// Example: config token plus namespace -> reader ready for a full KV key.
    pub(crate) fn new(config: CfKvConfig) -> Result<Self, String> {
        let namespace_id = if is_namespace_id(&config.namespace) {
            Some(config.namespace.clone())
        } else {
            None
        };
        let client = Client::builder()
            .timeout(API_TIMEOUT)
            .build()
            .map_err(|error| format!("create Cloudflare HTTP client failed: {error}"))?;
        Ok(Self {
            client,
            token: config.token,
            namespace: config.namespace,
            namespace_id: RwLock::new(namespace_id),
        })
    }

    /// Reads one complete KV key and returns its hostname/code pair.
    ///
    /// Example: `cfp/demo` -> endpoint fields used to build the WSS URL.
    pub(crate) async fn read(&self, key: &str) -> Result<KvEndpoint, String> {
        let key = key.trim();
        if key.is_empty()
            || key.len() > 512
            || key.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(
                "KV key must be non-empty, at most 512 bytes, and contain no whitespace"
                    .to_string(),
            );
        }
        let namespace_id = self.resolve_namespace().await?;
        let mut url =
            Url::parse(API_BASE).map_err(|error| format!("invalid CF API URL: {error}"))?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| "CF API URL cannot contain path segments".to_string())?;
            segments.extend(["accounts", ACCOUNT_ID, "storage", "kv", "namespaces"]);
            segments.push(&namespace_id);
            segments.push("values");
            for part in key.split('/') {
                if part.is_empty() {
                    return Err("KV key must not contain empty path segments".to_string());
                }
                segments.push(part);
            }
        }
        let response = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|error| format!("Cloudflare KV read request failed: {error}"))?;
        let status = response.status();
        let value: KvEndpointValue = response
            .json()
            .await
            .map_err(|error| format!("Cloudflare KV read returned {status}: {error}"))?;
        if !status.is_success() {
            return Err(format!("Cloudflare KV read returned {status}"));
        }
        if value.cf.trim().is_empty() {
            return Err("KV value cf must not be empty".to_string());
        }
        if !crate::access_uuid::is_valid_v4(&value.code) {
            return Err("KV value code must contain a canonical UUID v4".to_string());
        }
        Ok(KvEndpoint {
            hostname: value.cf,
            code: value.code,
        })
    }

    /// Resolves a namespace title and caches its ID for subsequent reads.
    ///
    /// Example: namespace title `proxy` -> cached namespace ID.
    async fn resolve_namespace(&self) -> Result<String, String> {
        if let Some(id) = self.namespace_id.read().await.as_ref() {
            return Ok(id.clone());
        }
        let mut page = 1;
        loop {
            let endpoint = format!(
                "{API_BASE}/accounts/{ACCOUNT_ID}/storage/kv/namespaces?page={page}&per_page={NAMESPACES_PER_PAGE}"
            );
            let response = self
                .client
                .get(endpoint)
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(|error| format!("Cloudflare namespace lookup failed: {error}"))?;
            let status = response.status();
            let body: ApiResponse<Vec<Namespace>> = response.json().await.map_err(|error| {
                format!("Cloudflare namespace lookup returned {status}: {error}")
            })?;
            if !status.is_success() || !body.success {
                return Err(format!(
                    "Cloudflare namespace lookup returned {status}: {}",
                    api_error_summary(&body.errors)
                ));
            }
            let namespaces = body
                .result
                .ok_or("Cloudflare namespace lookup omitted result")?;
            if let Some(found) = namespaces.iter().find(|item| item.title == self.namespace) {
                let id = found.id.clone();
                *self.namespace_id.write().await = Some(id.clone());
                return Ok(id);
            }
            if namespaces.len() < NAMESPACES_PER_PAGE {
                return Err(format!(
                    "Cloudflare namespace {:?} not found",
                    self.namespace
                ));
            }
            page += 1;
        }
    }
}
