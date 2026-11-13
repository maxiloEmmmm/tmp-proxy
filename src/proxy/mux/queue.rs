use std::sync::Mutex;

use bytes::{Bytes, BytesMut};
use tokio::sync::Notify;

/// Byte-bounded inbound queue between the WSS reader and adjacent TCP writer.
///
/// Example: many one-byte DATA frames still consume only their exact byte capacity.
pub(super) struct ByteQueue {
    /// Maximum queued bytes derived from the advertised stream window.
    capacity: usize,
    /// Mutable contiguous buffer and input lifecycle.
    state: Mutex<QueueState>,
    /// Consumer wakeup after data or close transitions.
    readable: Notify,
}

/// Mutable queue state guarded without holding a lock across await.
struct QueueState {
    /// Coalesced bytes preserving DATA arrival order.
    buffer: BytesMut,
    /// Whether FIN or RESET prevents future pushes.
    closed: bool,
}

impl ByteQueue {
    /// Creates a lazily allocated queue with a strict byte capacity.
    ///
    /// Example: capacity 1MiB allocates nothing close to 1MiB until data arrives.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(QueueState {
                buffer: BytesMut::new(),
                closed: false,
            }),
            readable: Notify::new(),
        }
    }

    /// Appends one DATA payload while enforcing the receive-window byte bound.
    ///
    /// Example: 1024 one-byte frames coalesce into one 1024-byte buffer.
    pub(super) fn push(&self, payload: &Bytes) -> Result<(), String> {
        let mut state = self.state.lock().expect("mux byte queue poisoned");
        if state.closed {
            return Err("mux DATA arrived after stream input closed".to_string());
        }
        let new_len = state
            .buffer
            .len()
            .checked_add(payload.len())
            .ok_or_else(|| "mux byte queue length overflow".to_string())?;
        if new_len > self.capacity {
            return Err("mux byte queue exceeded receive window".to_string());
        }
        // 为什么这里接受一次拷贝：
        // - 触发条件：合法 peer 可发送大量极小 DATA 帧。
        // - 不能保存无限 Bytes 节点：元数据内存会绕过字节 window。
        // - 防止副作用：连续缓冲把总内存严格限制在 receive window 内。
        state.buffer.extend_from_slice(payload);
        drop(state);
        self.readable.notify_one();
        Ok(())
    }

    /// Returns the next coalesced chunk or `None` after FIN drains all bytes.
    ///
    /// Example: max 32KiB prevents one TCP write from monopolizing the consumer.
    pub(super) async fn pop(&self, maximum: usize) -> Option<Bytes> {
        loop {
            let notified = self.readable.notified();
            {
                let mut state = self.state.lock().expect("mux byte queue poisoned");
                if !state.buffer.is_empty() {
                    let read = state.buffer.len().min(maximum);
                    return Some(state.buffer.split_to(read).freeze());
                }
                if state.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Applies FIN while preserving queued bytes for ordered drain.
    ///
    /// Example: DATA followed by FIN still reaches TCP before write shutdown.
    pub(super) fn close_input(&self) {
        self.state.lock().expect("mux byte queue poisoned").closed = true;
        self.readable.notify_waiters();
    }

    /// Applies RESET by closing input and discarding every queued byte immediately.
    ///
    /// Example: reset stream memory is released without waiting for TCP consumption.
    pub(super) fn abort(&self) {
        let mut state = self.state.lock().expect("mux byte queue poisoned");
        state.closed = true;
        state.buffer.clear();
        drop(state);
        self.readable.notify_waiters();
    }
}

#[cfg(test)]
#[path = "queue_test.rs"]
mod queue_test;
