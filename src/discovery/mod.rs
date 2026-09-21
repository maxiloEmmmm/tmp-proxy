//! In-memory daemon discovery reporting and center service.

pub(crate) mod center;
pub(crate) mod config;
pub(crate) mod kv;
pub(crate) mod reporter;

use serde::{Deserialize, Serialize};

/// Wire record exchanged by daemon `/report` and center `/list`.
///
/// Example: key `nas-01` identifies the latest tunnel for one daemon.
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Report {
    /// Stable daemon identity supplied through `-key`.
    pub(crate) key: String,
    /// Current TryCloudflare hostname without a URL scheme.
    pub(crate) cf: String,
    /// UUID v4 accepted by new connections, carried in the stable `code` key.
    pub(crate) code: String,
    /// Whole seconds elapsed since the current UUID was generated.
    pub(crate) code_age_seconds: u64,
    /// Operating-system hostname of the daemon machine.
    pub(crate) hostname: String,
    /// Target IP supplied to daemon through `-ip`.
    pub(crate) ip: String,
}

impl Report {
    /// Validates fields required for discovery and connection setup.
    ///
    /// Example: empty key or non-v4 UUID code -> error.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.key.trim().is_empty() {
            return Err("key must not be empty".to_string());
        }
        if self.cf.trim().is_empty() {
            return Err("cf must not be empty".to_string());
        }
        if !crate::access_uuid::is_valid_v4(&self.code) {
            return Err("code must contain a canonical UUID v4".to_string());
        }
        if self.hostname.trim().is_empty() {
            return Err("hostname must not be empty".to_string());
        }
        self.ip
            .parse::<std::net::IpAddr>()
            .map_err(|error| format!("ip is invalid: {error}"))?;
        Ok(())
    }
}
