use std::time::Instant;
use uuid::{Uuid, Version};

/// Rotating UUID and the instant at which it became active.
///
/// Example: a newly generated value has RFC 9562 UUID v4 format.
pub(crate) struct AccessUuid {
    /// UUID accepted by new Cloudflare requests.
    value: String,
    /// Monotonic creation instant used to report UUID age.
    created_at: Instant,
}

impl AccessUuid {
    /// Generates a cryptographically random UUID v4 for access authentication.
    ///
    /// Example: `AccessUuid::generate() -> "550e8400-e29b-41d4-a716-446655440000"`.
    pub(crate) fn generate() -> Self {
        Self {
            value: Uuid::new_v4().to_string(),
            created_at: Instant::now(),
        }
    }

    /// Returns the UUID currently accepted by new connections.
    ///
    /// Example: newly generated state -> one canonical UUID v4 string.
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// Returns an owned UUID and its whole-second age for reporting.
    ///
    /// Example: UUID created 17.8 seconds ago -> `(uuid, 17)`.
    pub(crate) fn report_snapshot(&self) -> (String, u64) {
        (self.value.clone(), self.created_at.elapsed().as_secs())
    }
}

/// Checks that a string is a canonical lowercase UUID v4.
///
/// Example: `"550e8400-e29b-41d4-a716-446655440000" -> true`.
pub(crate) fn is_valid_v4(raw: &str) -> bool {
    let Ok(parsed) = Uuid::parse_str(raw) else {
        return false;
    };
    parsed.get_version() == Some(Version::Random) && parsed.to_string() == raw
}
