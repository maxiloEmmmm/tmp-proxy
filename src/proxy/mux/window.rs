use std::sync::{Arc, Mutex};

use tokio::sync::Notify;

/// Sender-side byte credit advertised by one remote receive window.
///
/// Example: capacity 1024 permits at most 1024 unacknowledged bytes.
pub(super) struct SendWindow {
    /// Mutable credit and lifecycle state.
    state: Mutex<SendState>,
    /// Waiters blocked while no byte credit is available.
    changed: Notify,
}

/// Mutable sender credit state protected by the short-lived standard mutex.
struct SendState {
    /// Maximum credit this peer advertised.
    maximum: u32,
    /// Credit not currently reserved or committed in flight.
    available: u32,
    /// Credit reserved before an adjacent TCP read but not yet emitted as DATA.
    reserved: u32,
    /// DATA bytes emitted and awaiting remote WINDOW_UPDATE.
    in_flight: u32,
    /// Whether connection teardown permanently stopped new reservations.
    closed: bool,
}

/// Reserved sender credit returned automatically until explicitly committed.
///
/// Example: reserve 32KiB, read 4KiB, then commit 4KiB and return the remainder.
pub(super) struct Reservation {
    /// Window that owns the reserved credit.
    window: Option<Arc<SendWindow>>,
    /// Number of currently reserved bytes.
    amount: u32,
}

/// Committed in-flight credit rolled back automatically until carrier handoff succeeds.
///
/// Example: failed carrier send restores credit; successful send calls `confirm`.
pub(super) struct Commit {
    /// Window owning the in-flight bytes.
    window: Option<Arc<SendWindow>>,
    /// Bytes to restore if this commit is dropped before confirmation.
    amount: u32,
}

/// Receiver-side accounting used to reject over-window DATA and batch updates.
///
/// Example: consuming 64KiB may produce one 64KiB WINDOW_UPDATE.
pub(super) struct RecvWindow {
    /// Fixed maximum receive credit.
    capacity: u32,
    /// Minimum accumulated consumption before emitting an update.
    update_threshold: u32,
    /// Credit currently advertised and unused by the peer.
    remaining: u32,
    /// Consumed bytes waiting to be returned in a batched update.
    pending_update: u32,
}

impl SendWindow {
    /// Creates a fully available sender window.
    ///
    /// Example: `new(1024)` starts with 1024 bytes of send credit.
    pub(super) fn new(capacity: u32) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(SendState {
                maximum: capacity,
                available: capacity,
                reserved: 0,
                in_flight: 0,
                closed: false,
            }),
            changed: Notify::new(),
        })
    }

    /// Waits for and reserves up to `limit` bytes without reading a TCP socket.
    ///
    /// Example: available 4KiB and limit 32KiB reserves exactly 4KiB.
    pub(super) async fn reserve(self: &Arc<Self>, limit: u32) -> Result<Reservation, String> {
        if limit == 0 {
            return Err("mux window reservation limit must be positive".to_string());
        }
        loop {
            let notified = self.changed.notified();
            {
                let mut state = self.state.lock().expect("mux send window poisoned");
                if state.closed {
                    return Err("mux send window closed".to_string());
                }
                if state.available > 0 {
                    let amount = state.available.min(limit);
                    state.available -= amount;
                    state.reserved += amount;
                    return Ok(Reservation {
                        window: Some(Arc::clone(self)),
                        amount,
                    });
                }
            }
            notified.await;
        }
    }

    /// Applies a positive remote WINDOW_UPDATE without allowing credit overflow.
    ///
    /// Example: update 512 after 512 committed bytes restores the full window.
    pub(super) fn update(&self, increment: u32) -> Result<(), String> {
        if increment == 0 {
            return Err("mux window update must be positive".to_string());
        }
        let mut state = self.state.lock().expect("mux send window poisoned");
        if increment > state.in_flight {
            return Err("mux window update exceeds in-flight bytes".to_string());
        }
        state.in_flight -= increment;
        state.available += increment;
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Closes the window and wakes tasks waiting for remote credit.
    ///
    /// Example: WSS teardown makes every pending reservation fail.
    pub(super) fn close(&self) {
        self.state.lock().expect("mux send window poisoned").closed = true;
        self.changed.notify_waiters();
    }

    /// Returns unused reserved credit after cancellation or a short TCP read.
    ///
    /// Example: a 32KiB reservation reading 5KiB returns the other 27KiB.
    fn return_reservation(&self, amount: u32) {
        if amount == 0 {
            return;
        }
        let mut state = self.state.lock().expect("mux send window poisoned");
        state.reserved = state
            .reserved
            .checked_sub(amount)
            .expect("mux reserved window underflow");
        state.available += amount;
        drop(state);
        self.changed.notify_waiters();
    }

    /// Converts reserved bytes into DATA in flight and returns unused credit.
    ///
    /// Example: reserving 32KiB and committing 4KiB moves only 4KiB in flight.
    fn commit_reservation(&self, reserved: u32, used: u32) -> Result<(), String> {
        if used > reserved {
            return Err("mux reservation commit exceeds reserved credit".to_string());
        }
        let mut state = self.state.lock().expect("mux send window poisoned");
        if reserved > state.reserved {
            return Err("mux reserved credit accounting underflow".to_string());
        }
        state.reserved -= reserved;
        state.available += reserved - used;
        state.in_flight = state
            .in_flight
            .checked_add(used)
            .ok_or_else(|| "mux in-flight window overflow".to_string())?;
        if state.available + state.reserved + state.in_flight != state.maximum {
            return Err("mux send window accounting mismatch".to_string());
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    /// Restores committed bytes when DATA never reaches the shared carrier.
    ///
    /// Example: carrier shutdown turns 4KiB in flight back into available credit.
    fn cancel_in_flight(&self, amount: u32) {
        if amount == 0 {
            return;
        }
        let mut state = self.state.lock().expect("mux send window poisoned");
        state.in_flight = state
            .in_flight
            .checked_sub(amount)
            .expect("mux in-flight rollback underflow");
        state.available += amount;
        drop(state);
        self.changed.notify_waiters();
    }
}

impl Reservation {
    /// Returns the number of bytes that may be read from the adjacent TCP.
    ///
    /// Example: a partially available window may return less than max frame size.
    pub(super) fn amount(&self) -> u32 {
        self.amount
    }

    /// Shrinks a reservation and immediately returns the excess credit.
    ///
    /// Example: stream credit 32KiB plus connection credit 8KiB leaves 8KiB usable.
    pub(super) fn shrink_to(&mut self, amount: u32) -> Result<(), String> {
        if amount == 0 || amount > self.amount {
            return Err("invalid mux reservation shrink".to_string());
        }
        if let Some(window) = &self.window {
            window.return_reservation(self.amount - amount);
        }
        self.amount = amount;
        Ok(())
    }

    /// Commits bytes with rollback ownership transferred to the carrier scheduler.
    ///
    /// Example: DATA queued for WSS holds a guard until carrier handoff succeeds.
    pub(super) fn commit_guarded(mut self, used: u32) -> Result<Commit, String> {
        let window = self
            .window
            .as_ref()
            .cloned()
            .ok_or_else(|| "mux reservation already committed".to_string())?;
        window.commit_reservation(self.amount, used)?;
        self.window.take();
        self.amount = 0;
        Ok(Commit {
            window: Some(window),
            amount: used,
        })
    }
}

impl Commit {
    /// Confirms that DATA reached the carrier and must await remote WINDOW_UPDATE.
    ///
    /// Example: successful channel handoff disarms automatic credit rollback.
    pub(super) fn confirm(mut self) {
        self.window.take();
        self.amount = 0;
    }
}

impl Drop for Commit {
    /// Restores in-flight credit when queued DATA is cancelled or carrier send fails.
    ///
    /// Example: RESET removing pending DATA cannot leak connection credit.
    fn drop(&mut self) {
        if let Some(window) = self.window.take() {
            window.cancel_in_flight(self.amount);
        }
    }
}

impl Drop for Reservation {
    /// Returns all uncommitted credit when a read or send path is cancelled.
    ///
    /// Example: `WouldBlock` drops its reservation without shrinking the window.
    fn drop(&mut self) {
        if let Some(window) = self.window.take() {
            window.return_reservation(self.amount);
        }
    }
}

impl RecvWindow {
    /// Creates receive accounting with a bounded update batching threshold.
    ///
    /// Example: capacity 1MiB and threshold 64KiB reduce control-frame chatter.
    pub(super) fn new(capacity: u32, update_threshold: u32) -> Result<Self, String> {
        if capacity == 0 || update_threshold == 0 || update_threshold > capacity {
            return Err("invalid mux receive window configuration".to_string());
        }
        Ok(Self {
            capacity,
            update_threshold,
            remaining: capacity,
            pending_update: 0,
        })
    }

    /// Charges received DATA before it enters the per-stream inbound queue.
    ///
    /// Example: receiving beyond `remaining` is a protocol violation.
    pub(super) fn receive(&mut self, bytes: u32) -> Result<(), String> {
        if bytes == 0 || bytes > self.remaining {
            return Err("mux peer exceeded receive window".to_string());
        }
        self.remaining -= bytes;
        Ok(())
    }

    /// Records bytes actually written to the adjacent TCP and batches an update.
    ///
    /// Example: accumulated consumption reaching the threshold returns its increment.
    pub(super) fn consume(&mut self, bytes: u32) -> Result<Option<u32>, String> {
        let outstanding = self
            .capacity
            .saturating_sub(self.remaining)
            .saturating_sub(self.pending_update);
        if bytes == 0 || bytes > outstanding {
            return Err("mux receive consumption exceeds delivered bytes".to_string());
        }
        self.pending_update = self
            .pending_update
            .checked_add(bytes)
            .ok_or_else(|| "mux receive consumption overflow".to_string())?;
        if self.pending_update < self.update_threshold && self.remaining > 0 {
            return Ok(None);
        }
        Ok(Some(self.release_pending()))
    }

    /// Drops unread bytes and returns their count for aggregate-credit recovery.
    ///
    /// Example: resetting after consuming 2KiB of 8KiB returns 6KiB as discarded.
    pub(super) fn discard_unconsumed(&mut self) -> u32 {
        let unconsumed = self
            .capacity
            .saturating_sub(self.remaining)
            .saturating_sub(self.pending_update);
        self.remaining = self.capacity;
        self.pending_update = 0;
        unconsumed
    }

    /// Restores all pending consumed bytes to the advertised receive balance.
    ///
    /// Example: pending 4096 increases remaining by 4096 and clears pending.
    fn release_pending(&mut self) -> u32 {
        let increment = self.pending_update;
        self.pending_update = 0;
        self.remaining = self.remaining.saturating_add(increment).min(self.capacity);
        increment
    }
}

#[cfg(test)]
#[path = "window_test.rs"]
mod window_test;
