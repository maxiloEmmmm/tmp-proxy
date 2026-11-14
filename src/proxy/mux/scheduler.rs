use std::collections::HashMap;

use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit};

use super::{protocol::Frame, window::Commit};

/// Capacity reserved for lifecycle and window control frames.
const CONTROL_QUEUE_CAPACITY: usize = 256;

/// Capacity reserved for one pending DATA command per possible active stream.
const DATA_QUEUE_CAPACITY: usize = 256;

/// Capacity reserved for lossy UDP packets, isolated from lifecycle control.
const DATAGRAM_QUEUE_CAPACITY: usize = 256;

/// Maximum consecutive control frames before one ready DATA frame must progress.
const CONTROL_BURST_LIMIT: usize = 32;

/// Cloneable handle feeding the single ordered mux carrier writer.
///
/// Example: WINDOW_UPDATE uses `send_control`, while stream payload uses `send_data`.
#[derive(Clone)]
pub(super) struct Outbound {
    /// High-priority lifecycle and window frame queue.
    control: mpsc::Sender<Frame>,
    /// Per-stream DATA lifecycle events consumed by the fair scheduler.
    data: mpsc::Sender<DataEvent>,
    /// Lossy UDP packet queue that cannot occupy lifecycle control capacity.
    datagram: mpsc::Sender<Frame>,
}

/// DATA frame retained until the shared carrier accepts it.
struct DataCommand {
    /// Logical stream owning this DATA frame.
    stream_id: u32,
    /// Encoded logical stream DATA frame.
    frame: Frame,
    /// Payload bytes charged to the byte-fair virtual finish.
    bytes: usize,
    /// Per-stream credit already committed before the peer can acknowledge DATA.
    stream_credit: Commit,
    /// Connection credit already committed before the peer can acknowledge DATA.
    connection_credit: Commit,
    /// Permit enforcing at most one unhanded DATA frame for this stream.
    _slot: OwnedSemaphorePermit,
    /// Completion returned only after carrier handoff preserves DATA/FIN order.
    delivered: oneshot::Sender<Result<(), String>>,
}

/// DATA scheduler mutation serialized with frame selection.
enum DataEvent {
    /// Adds one stream's sole pending DATA frame.
    Enqueue(DataCommand),
    /// Marks a stream inactive after its adjacent TCP no longer reports readable data.
    Idle {
        /// Logical stream identifier whose next DATA must rejoin at global time.
        stream_id: u32,
    },
    /// Removes an idle or reset stream and acknowledges pending-frame cancellation.
    Remove {
        /// Logical stream identifier to forget.
        stream_id: u32,
        /// Completion proving no pending DATA remains in the fair queue.
        removed: oneshot::Sender<()>,
    },
}

/// Persistent byte-fair state for one logical stream.
struct FlowState {
    /// Total virtual bytes charged to this stream.
    virtual_finish: u128,
    /// Sole DATA frame currently eligible for carrier selection.
    pending: Option<DataCommand>,
    /// Whether consecutive readable TCP data keeps this stream in the active set.
    active: bool,
}

/// Single-egress fair queue shared by every logical stream on one endpoint.
struct FairQueue {
    /// Stream scheduling state retained across idle/rejoin transitions.
    flows: HashMap<u32, FlowState>,
    /// Furthest virtual time reached by any selected stream.
    virtual_time: u128,
}

impl Outbound {
    /// Starts one scheduler that serializes frames into the carrier channel.
    ///
    /// Example: a unit-test carrier can directly connect this receiver to another peer.
    pub(super) fn start(carrier: mpsc::Sender<Frame>, initial: Frame) -> Self {
        let (control, control_rx) = mpsc::channel(CONTROL_QUEUE_CAPACITY);
        let (data, data_rx) = mpsc::channel(DATA_QUEUE_CAPACITY);
        let (datagram, datagram_rx) = mpsc::channel(DATAGRAM_QUEUE_CAPACITY);
        control
            .try_send(initial)
            .expect("fresh mux control queue must accept hello");
        tokio::spawn(run_scheduler(carrier, control_rx, data_rx, datagram_rx));
        Self {
            control,
            data,
            datagram,
        }
    }

    /// Queues one lifecycle or window frame ahead of ordinary DATA.
    ///
    /// Example: a zero-window stream can still send RESET and WINDOW_UPDATE.
    pub(super) async fn send_control(&self, frame: Frame) -> Result<(), String> {
        self.control
            .send(frame)
            .await
            .map_err(|_| "mux control scheduler closed".to_string())
    }

    /// Attempts one unordered UDP frame without waiting behind a congested carrier.
    ///
    /// Example: a full bounded queue drops one packet while TCP DATA still progresses.
    pub(super) fn try_send_datagram(&self, frame: Frame) -> Result<bool, String> {
        match self.datagram.try_send(frame) {
            Ok(()) => Ok(true),
            Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err("mux control scheduler closed".to_string())
            }
        }
    }

    /// Queues one DATA frame and waits until the ordered carrier accepts it.
    ///
    /// Example: the caller cannot emit FIN until this DATA is ahead of it on the carrier.
    pub(super) async fn send_data(
        &self,
        stream_id: u32,
        payload: bytes::Bytes,
        stream_credit: Commit,
        connection_credit: Commit,
        slot: OwnedSemaphorePermit,
    ) -> Result<(), String> {
        let bytes = payload.len();
        let (delivered, result) = oneshot::channel();
        self.data
            .send(DataEvent::Enqueue(DataCommand {
                stream_id,
                frame: Frame::Data { stream_id, payload },
                bytes,
                stream_credit,
                connection_credit,
                _slot: slot,
                delivered,
            }))
            .await
            .map_err(|_| "mux data scheduler closed".to_string())?;
        result
            .await
            .map_err(|_| "mux DATA carrier handoff cancelled".to_string())?
    }

    /// Removes one stream after ensuring its pending DATA cannot follow FIN or RESET.
    ///
    /// Example: local RESET first cancels queued DATA, then emits the RESET control frame.
    pub(super) async fn remove_stream(&self, stream_id: u32) -> Result<(), String> {
        let (removed, result) = oneshot::channel();
        self.data
            .send(DataEvent::Remove { stream_id, removed })
            .await
            .map_err(|_| "mux data scheduler closed".to_string())?;
        result
            .await
            .map_err(|_| "mux stream scheduler removal cancelled".to_string())
    }

    /// Marks a stream idle before waiting for new adjacent TCP readability.
    ///
    /// Example: a later DATA command aligns to global time instead of claiming old service debt.
    pub(super) async fn mark_idle(&self, stream_id: u32) -> Result<(), String> {
        self.data
            .send(DataEvent::Idle { stream_id })
            .await
            .map_err(|_| "mux data scheduler closed".to_string())
    }
}

impl FairQueue {
    /// Creates an empty byte-fair queue at virtual time zero.
    ///
    /// Example: the first active stream begins at virtual finish zero.
    fn new() -> Self {
        Self {
            flows: HashMap::new(),
            virtual_time: 0,
        }
    }

    /// Applies one DATA event without waiting on carrier IO.
    ///
    /// Example: an idle stream rejoins at current virtual time instead of claiming old credit.
    fn apply(&mut self, event: DataEvent) {
        match event {
            DataEvent::Enqueue(command) => {
                let state = self.flows.entry(command.stream_id).or_insert(FlowState {
                    virtual_finish: self.virtual_time,
                    pending: None,
                    active: false,
                });
                if !state.active {
                    // Rejoining below global time would let an idle stream monopolize old debt.
                    state.virtual_finish = state.virtual_finish.max(self.virtual_time);
                    state.active = true;
                }
                if state.pending.is_some() {
                    // The per-stream slot makes this unreachable; fail closed if invariants drift.
                    let _ = command
                        .delivered
                        .send(Err("duplicate pending mux DATA frame".to_string()));
                    return;
                }
                state.pending = Some(command);
            }
            DataEvent::Idle { stream_id } => {
                if let Some(state) = self.flows.get_mut(&stream_id) {
                    // A pending frame still represents readable work and cannot be made idle.
                    if state.pending.is_none() {
                        state.active = false;
                    }
                }
            }
            DataEvent::Remove { stream_id, removed } => {
                if let Some(mut state) = self.flows.remove(&stream_id) {
                    if let Some(command) = state.pending.take() {
                        let _ = command
                            .delivered
                            .send(Err("mux stream removed before DATA handoff".to_string()));
                    }
                }
                let _ = removed.send(());
            }
        }
    }

    /// Selects the least-served pending stream and charges its actual payload bytes.
    ///
    /// Example: a 1KiB frame advances one thirty-second as far as a 32KiB frame.
    fn pop_next(&mut self) -> Option<DataCommand> {
        let stream_id = self
            .flows
            .iter()
            .filter(|(_, state)| state.pending.is_some())
            .min_by_key(|(stream_id, state)| (state.virtual_finish, **stream_id))
            .map(|(stream_id, _)| *stream_id)?;
        let state = self
            .flows
            .get_mut(&stream_id)
            .expect("selected mux flow must exist");
        let command = state
            .pending
            .take()
            .expect("selected mux flow must have DATA");
        state.virtual_finish = state.virtual_finish.saturating_add(command.bytes as u128);
        self.virtual_time = self.virtual_time.max(state.virtual_finish);
        Some(command)
    }

    /// Reports whether at least one TCP DATA command is ready for carrier service.
    ///
    /// Example: a ready DATA command limits UDP service to one packet before it progresses.
    fn has_pending(&self) -> bool {
        self.flows.values().any(|state| state.pending.is_some())
    }

    /// Fails every pending DATA waiter after carrier shutdown.
    ///
    /// Example: WSS EOF wakes all streams instead of leaving carrier handoffs pending.
    fn fail_pending(&mut self, reason: &str) {
        for state in self.flows.values_mut() {
            if let Some(command) = state.pending.take() {
                let _ = command.delivered.send(Err(reason.to_string()));
            }
        }
    }
}

/// Runs the only producer for the ordered carrier with bounded control priority.
///
/// Example: thirty-two WINDOW_UPDATE frames may precede DATA, but the thirty-third cannot.
async fn run_scheduler(
    carrier: mpsc::Sender<Frame>,
    mut control: mpsc::Receiver<Frame>,
    mut data: mpsc::Receiver<DataEvent>,
    mut datagram: mpsc::Receiver<Frame>,
) {
    let mut fair = FairQueue::new();
    let mut consecutive_control = 0usize;
    let mut control_closed = false;
    let mut data_closed = false;
    let mut datagram_closed = false;
    let mut datagram_since_data = false;
    loop {
        while let Ok(event) = data.try_recv() {
            fair.apply(event);
        }

        if consecutive_control < CONTROL_BURST_LIMIT {
            if let Ok(frame) = control.try_recv() {
                if carrier.send(frame).await.is_err() {
                    fair.fail_pending("mux carrier closed");
                    return;
                }
                consecutive_control += 1;
                continue;
            }
        }

        if fair.has_pending() && !datagram_since_data {
            if let Ok(frame) = datagram.try_recv() {
                if carrier.send(frame).await.is_err() {
                    fair.fail_pending("mux carrier closed");
                    return;
                }
                datagram_since_data = true;
                consecutive_control = 0;
                continue;
            }
        }

        if let Some(command) = fair.pop_next() {
            let result = carrier
                .send(command.frame)
                .await
                .map_err(|_| "mux carrier closed".to_string());
            let failed = result.is_err();
            if !failed {
                command.stream_credit.confirm();
                command.connection_credit.confirm();
            }
            let _ = command.delivered.send(result);
            if failed {
                fair.fail_pending("mux carrier closed");
                return;
            }
            consecutive_control = 0;
            datagram_since_data = false;
            continue;
        }

        if let Ok(frame) = datagram.try_recv() {
            if carrier.send(frame).await.is_err() {
                fair.fail_pending("mux carrier closed");
                return;
            }
            datagram_since_data = true;
            consecutive_control = 0;
            continue;
        }

        if let Ok(frame) = control.try_recv() {
            if carrier.send(frame).await.is_err() {
                fair.fail_pending("mux carrier closed");
                return;
            }
            consecutive_control = consecutive_control.saturating_add(1);
            continue;
        }

        if control_closed && data_closed && datagram_closed {
            return;
        }
        tokio::select! {
            biased;
            event = data.recv(), if !data_closed => match event {
                Some(event) => fair.apply(event),
                None => data_closed = true,
            },
            frame = control.recv(), if !control_closed => match frame {
                Some(frame) => {
                    if carrier.send(frame).await.is_err() {
                        fair.fail_pending("mux carrier closed");
                        return;
                    }
                    consecutive_control = consecutive_control.saturating_add(1);
                }
                None => control_closed = true,
            },
            frame = datagram.recv(), if !datagram_closed => match frame {
                Some(frame) => {
                    if carrier.send(frame).await.is_err() {
                        fair.fail_pending("mux carrier closed");
                        return;
                    }
                    datagram_since_data = true;
                    consecutive_control = 0;
                }
                None => datagram_closed = true,
            },
        }
    }
}

#[cfg(test)]
#[path = "scheduler_test.rs"]
mod scheduler_test;
