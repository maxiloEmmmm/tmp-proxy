use std::time::Duration;

const INITIAL_DELAY: Duration = Duration::from_millis(200);
const MAX_DELAY: Duration = Duration::from_secs(5);

/// Exponential reconnect delay reset after a successful registration.
///
/// Example: `200ms -> 400ms -> ... -> 5s`.
pub(crate) struct Backoff {
    /// Delay returned by the next failure.
    current: Duration,
}

impl Backoff {
    /// Creates a delay sequence at 200 milliseconds.
    ///
    /// Example: `Backoff::new().next() -> 200ms`.
    pub(crate) fn new() -> Self {
        Self {
            current: INITIAL_DELAY,
        }
    }

    /// Returns the current delay and doubles the next one up to five seconds.
    ///
    /// Example: two calls -> `200ms`, then `400ms`.
    pub(crate) fn next(&mut self) -> Duration {
        let delay = self.current;
        self.current = self.current.saturating_mul(2).min(MAX_DELAY);
        delay
    }

    /// Resets the sequence after registration succeeds.
    ///
    /// Example: `5s -> reset -> 200ms`.
    pub(crate) fn reset(&mut self) {
        self.current = INITIAL_DELAY;
    }
}
