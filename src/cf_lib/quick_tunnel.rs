use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::Deserialize;
use std::time::Duration;
use uuid::Uuid;

use crate::cf_lib::CfError;

const QUICK_TUNNEL_URL: &str = "https://api.trycloudflare.com/tunnel";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Credentials returned by the account-less Quick Tunnel service.
///
/// Example: API response -> credentials used by tunnel registration.
#[derive(Clone)]
pub(crate) struct Credentials {
    /// Cloudflare account tag assigned to the temporary tunnel.
    pub(crate) account_tag: String,
    /// Secret authenticating the temporary tunnel.
    pub(crate) tunnel_secret: Vec<u8>,
    /// Binary UUID used by the registration protocol.
    pub(crate) tunnel_id: [u8; 16],
    /// Per-client identifier sent with connection registration.
    pub(crate) client_id: [u8; 16],
    /// Public `trycloudflare.com` hostname.
    pub(crate) hostname: String,
}

/// Top-level Quick Tunnel JSON response.
///
/// Example: `{ success, result, errors }` from the fixed endpoint.
#[derive(Deserialize)]
struct QuickTunnelResponse {
    /// Whether the service accepted the request.
    success: bool,
    /// Credentials present on successful responses.
    result: Option<QuickTunnelResult>,
    /// Structured errors returned by the service.
    #[serde(default)]
    errors: Vec<QuickTunnelError>,
}

/// Successful Quick Tunnel JSON payload.
///
/// Example: hostname and secret -> registration credentials.
#[derive(Deserialize)]
struct QuickTunnelResult {
    /// Temporary tunnel UUID.
    id: String,
    /// Assigned public hostname.
    hostname: String,
    /// Temporary account tag.
    account_tag: String,
    /// Base64-encoded tunnel secret.
    secret: String,
}

/// Error returned inside a Quick Tunnel JSON response.
///
/// Example: service quota failure -> readable message.
#[derive(Deserialize)]
struct QuickTunnelError {
    /// Service-specific numeric error code.
    code: i64,
    /// Human-readable service error.
    message: String,
}

/// Requests credentials from the fixed TryCloudflare endpoint.
///
/// Example: successful POST -> `Credentials`.
pub(crate) async fn create() -> Result<Credentials, CfError> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("tmp-proxy/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| CfError::new(format!("create Quick Tunnel client failed: {error}")))?;
    let response = client
        .post(QUICK_TUNNEL_URL)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .send()
        .await
        .map_err(|error| CfError::new(format!("request Quick Tunnel failed: {error}")))?
        .error_for_status()
        .map_err(|error| CfError::new(format!("Quick Tunnel HTTP error: {error}")))?
        .json::<QuickTunnelResponse>()
        .await
        .map_err(|error| CfError::new(format!("decode Quick Tunnel response failed: {error}")))?;

    if !response.success {
        let reason = response
            .errors
            .into_iter()
            .map(|error| format!("{}: {}", error.code, error.message))
            .collect::<Vec<_>>()
            .join(", ");
        return Err(CfError::new(format!(
            "Quick Tunnel service rejected request: {reason}"
        )));
    }
    let result = response
        .result
        .ok_or_else(|| CfError::new("Quick Tunnel response omitted result"))?;
    let tunnel_id = Uuid::parse_str(&result.id)
        .map_err(|error| CfError::new(format!("invalid Quick Tunnel id: {error}")))?;
    let tunnel_secret = BASE64
        .decode(result.secret)
        .map_err(|error| CfError::new(format!("invalid Quick Tunnel secret: {error}")))?;
    Ok(Credentials {
        account_tag: result.account_tag,
        tunnel_secret,
        tunnel_id: *tunnel_id.as_bytes(),
        client_id: *Uuid::new_v4().as_bytes(),
        hostname: result.hostname,
    })
}
