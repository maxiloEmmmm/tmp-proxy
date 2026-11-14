use std::{collections::VecDeque, sync::Mutex};

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

/// One complete UDP packet retained by a datagram queue.
///
/// Example: one opaque UDP payload remains one indivisible item.
pub(super) struct DatagramPacket {
    /// Opaque UDP payload.
    pub(super) payload: Bytes,
}

/// Packet- and byte-bounded queue that drops new UDP traffic under congestion.
///
/// Example: a full queue discards one datagram instead of blocking TCP streams.
pub(super) struct DatagramQueue {
    /// Maximum number of retained packet objects.
    packet_capacity: usize,
    /// Maximum aggregate payload bytes.
    byte_capacity: usize,
    /// Mutable datagram contents and lifecycle.
    state: Mutex<DatagramQueueState>,
    /// Consumer wakeup after data or close transitions.
    readable: Notify,
}

/// Mutable UDP queue state guarded without holding a lock across await.
struct DatagramQueueState {
    /// Complete packets in arrival order.
    packets: VecDeque<DatagramPacket>,
    /// Aggregate payload bytes retained by `packets`.
    bytes: usize,
    /// Whether association closure prevents future packets.
    closed: bool,
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

impl DatagramQueue {
    /// Creates an empty bounded datagram queue.
    ///
    /// Example: `(64, 128KiB)` bounds both tiny and large packet attacks.
    pub(super) fn new(packet_capacity: usize, byte_capacity: usize) -> Self {
        Self {
            packet_capacity,
            byte_capacity,
            state: Mutex::new(DatagramQueueState {
                packets: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            readable: Notify::new(),
        }
    }

    /// Enqueues one complete packet or drops it when either bound is full.
    ///
    /// Example: congestion returns `false`; callers continue serving sibling flows.
    pub(super) fn push(&self, payload: Bytes) -> bool {
        let mut state = self.state.lock().expect("mux datagram queue poisoned");
        let Some(new_bytes) = state.bytes.checked_add(payload.len()) else {
            return false;
        };
        if state.closed
            || state.packets.len() >= self.packet_capacity
            || new_bytes > self.byte_capacity
        {
            return false;
        }
        state.packets.push_back(DatagramPacket { payload });
        state.bytes = new_bytes;
        drop(state);
        self.readable.notify_one();
        true
    }

    /// Receives the next complete packet or `None` after association closure.
    ///
    /// Example: packet boundaries survive independently of adjacent packet sizes.
    pub(super) async fn pop(&self) -> Option<DatagramPacket> {
        loop {
            let notified = self.readable.notified();
            {
                let mut state = self.state.lock().expect("mux datagram queue poisoned");
                if let Some(packet) = state.packets.pop_front() {
                    state.bytes = state.bytes.saturating_sub(packet.payload.len());
                    return Some(packet);
                }
                if state.closed {
                    return None;
                }
            }
            notified.await;
        }
    }

    /// Closes and discards an unordered UDP queue immediately.
    ///
    /// Example: carrier failure wakes a blocked association receiver with `None`.
    pub(super) fn close(&self) {
        let mut state = self.state.lock().expect("mux datagram queue poisoned");
        state.closed = true;
        state.packets.clear();
        state.bytes = 0;
        drop(state);
        self.readable.notify_waiters();
    }
}

#[cfg(test)]
#[path = "queue_test.rs"]
mod queue_test;
