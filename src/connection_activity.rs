use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::time::{self, Instant};

/// Shared activity tracker for one Cloudflare tunnel URL.
///
/// Example: one tracked connection keeps the tunnel out of the idle state.
#[derive(Clone)]
pub(crate) struct ConnectionActivity {
    /// State changed under one lock so idle sealing and connection entry are atomic.
    state: Arc<Mutex<ActivityState>>,
    /// Version channel waking the single idle waiter after activity changes.
    changes: watch::Sender<u64>,
}

/// Mutable activity state for one Cloudflare tunnel URL.
struct ActivityState {
    /// Number of authenticated target connections currently alive.
    active_connections: usize,
    /// Instant at which the active connection count last became zero.
    idle_since: Instant,
    /// Whether this tunnel URL may still accept new tracked connections.
    accepting: bool,
}

/// RAII lease keeping one authenticated target connection active.
///
/// Example: dropping the final lease starts a fresh idle period.
pub(crate) struct ConnectionLease {
    /// Tracker decremented when the proxied connection finishes.
    activity: ConnectionActivity,
}

impl ConnectionActivity {
    /// Creates an accepting tracker whose idle period starts immediately.
    ///
    /// Example: a new tunnel with no connections is idle from creation time.
    pub(crate) fn new() -> Self {
        let (changes, _) = watch::channel(0);
        Self {
            state: Arc::new(Mutex::new(ActivityState {
                active_connections: 0,
                idle_since: Instant::now(),
                accepting: true,
            })),
            changes,
        }
    }

    /// Starts tracking an authenticated connection unless refresh already sealed the URL.
    ///
    /// Example: accepting tracker -> `Some(lease)`; sealed tracker -> `None`.
    pub(crate) fn try_begin(&self) -> Option<ConnectionLease> {
        let mut state = self
            .state
            .lock()
            .expect("connection activity state poisoned");
        if !state.accepting {
            return None;
        }
        state.active_connections += 1;
        drop(state);
        self.notify_change();
        Some(ConnectionLease {
            activity: self.clone(),
        })
    }

    /// Waits for a continuous idle period, then atomically seals new connections.
    ///
    /// Example: zero active connections for six hours -> returns with URL sealed.
    pub(crate) async fn seal_after_idle(&self, idle_duration: Duration) {
        let mut changes = self.changes.subscribe();
        loop {
            let deadline = {
                let mut state = self
                    .state
                    .lock()
                    .expect("connection activity state poisoned");
                if state.active_connections == 0 {
                    let deadline = state.idle_since + idle_duration;
                    if Instant::now() >= deadline {
                        // 触发条件: 空闲期到点时可能恰好有新连接完成鉴权。
                        // 不能先返回再停止接入: 新连接会在回收 session 前混入。
                        // 防止副作用: 在同一把锁内封口，避免误杀已计入的连接。
                        state.accepting = false;
                        return;
                    }
                    Some(deadline)
                } else {
                    None
                }
            };

            match deadline {
                Some(deadline) => {
                    tokio::select! {
                        biased;
                        changed = changes.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                        _ = time::sleep_until(deadline) => {}
                    }
                }
                None => {
                    if changes.changed().await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// Wakes the idle waiter after one connection count transition.
    ///
    /// Example: active count `0 -> 1` increments the watched version.
    fn notify_change(&self) {
        self.changes.send_modify(|version| *version += 1);
    }
}

impl Drop for ConnectionLease {
    /// Ends one tracked connection and starts idle timing when it was the last.
    ///
    /// Example: active count `1 -> 0` records a new idle start instant.
    fn drop(&mut self) {
        let mut state = self
            .activity
            .state
            .lock()
            .expect("connection activity state poisoned");
        state.active_connections = state
            .active_connections
            .checked_sub(1)
            .expect("connection activity lease underflow");
        if state.active_connections == 0 {
            state.idle_since = Instant::now();
        }
        drop(state);
        self.activity.notify_change();
    }
}
