use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex, Notify, Semaphore};

use super::{
    protocol::{Frame, VERSION},
    queue::{ByteQueue, DatagramQueue},
    scheduler::Outbound,
    window::{RecvWindow, Reservation, SendWindow},
};

/// Per-stream receive window advertised by the default mux configuration.
pub(super) const DEFAULT_STREAM_WINDOW: u32 = 4 * 1024 * 1024;

/// Aggregate receive window advertised by the default mux configuration.
pub(super) const DEFAULT_CONNECTION_WINDOW: u32 = 16 * 1024 * 1024;

/// Largest payload placed in one DATA or DATAGRAM frame.
pub(super) const DEFAULT_MAX_FRAME: u32 = 65_507;

/// Maximum simultaneously registered logical streams.
pub(super) const DEFAULT_MAX_STREAMS: u32 = 256;

/// Receive consumption accumulated before returning window credit.
const WINDOW_UPDATE_THRESHOLD: u32 = 64 * 1024;

/// Maximum complete UDP packets retained for one association.
const DATAGRAM_QUEUE_PACKETS: usize = 64;

/// Maximum aggregate UDP payload retained for one association.
const DATAGRAM_QUEUE_BYTES: usize = 128 * 1024;

/// Maximum time a rejected stream retains in-flight DATA while awaiting RESET.
const REJECTED_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Stream exists but its remote target has not acknowledged readiness.
const STREAM_OPENING: u8 = 0;

/// Stream target is ready and normal bidirectional forwarding is active.
const STREAM_OPEN: u8 = 1;

/// Stream target failed; queued DATA is retained until the peer RESET arrives.
const STREAM_REJECTED: u8 = 2;

/// Stable reset code used when a local TCP bridge fails.
pub(super) const RESET_LOCAL_IO: u16 = 1;

/// Stable reset code used when a remote target cannot be opened.
pub(super) const RESET_OPEN_FAILED: u16 = 2;

/// Mux endpoint role controlling stream identifier allocation and OPEN acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Role {
    /// Opens odd-numbered streams for locally accepted yy TCP connections.
    Client,
    /// Accepts client OPEN frames and connects daemon-side target TCP streams.
    Server,
}

/// Local receive limits announced to the peer in the hello frame.
#[derive(Clone, Copy)]
pub(super) struct Config {
    /// Per-stream receive credit in bytes.
    pub(super) stream_window: u32,
    /// Aggregate receive credit in bytes.
    pub(super) connection_window: u32,
    /// Largest accepted DATA payload in bytes.
    pub(super) max_frame: u32,
    /// Largest number of concurrent streams.
    pub(super) max_streams: u32,
}

/// One independently testable mux peer connected through frame channels.
///
/// Example: unit tests cross-connect two endpoints without WebSocket or Cloudflare.
#[derive(Clone)]
pub(super) struct Endpoint {
    /// Shared stream registry and connection lifecycle.
    inner: Arc<EndpointInner>,
    /// Server-side OPEN requests waiting for target connection handling.
    incoming: Arc<AsyncMutex<mpsc::Receiver<IncomingStream>>>,
    /// Server-side UDP OPEN requests waiting for socket allocation.
    incoming_datagrams: Arc<AsyncMutex<mpsc::Receiver<IncomingDatagram>>>,
}

/// Shared endpoint state used by the frame driver and logical stream handles.
struct EndpointInner {
    /// Client or server behavior for this peer.
    role: Role,
    /// Locally advertised receive limits.
    config: Config,
    /// Control and DATA scheduler handle.
    outbound: Outbound,
    /// Currently registered stream state by identifier.
    streams: Mutex<HashMap<u32, Arc<StreamState>>>,
    /// Currently registered UDP association state by identifier.
    datagrams: Mutex<HashMap<u32, Arc<DatagramState>>>,
    /// Remote hello limits and connection send window.
    remote: Mutex<Option<Arc<RemoteState>>>,
    /// Wakes open/accept operations after the remote hello arrives.
    hello_ready: Notify,
    /// Next locally allocated stream identifier.
    next_stream_id: AtomicU32,
    /// Locally advertised aggregate receive window.
    recv_connection: Mutex<RecvWindow>,
    /// Server-side queue receiving validated OPEN requests.
    incoming: mpsc::Sender<IncomingStream>,
    /// Server-side queue receiving validated UDP association requests.
    incoming_datagrams: mpsc::Sender<IncomingDatagram>,
    /// Whether the carrier or protocol has terminated.
    closed: AtomicBool,
    /// Wakes operations waiting for a usable connection.
    closed_notify: Notify,
}

/// Limits received from the remote hello frame.
struct RemoteState {
    /// Send credit shared by all streams.
    send_connection: Arc<SendWindow>,
    /// Initial send credit created for every new stream.
    stream_window: u32,
    /// Largest DATA payload accepted by the remote peer.
    max_frame: u32,
    /// Largest number of streams accepted by the remote peer.
    max_streams: u32,
}

/// Shared state for one bidirectional logical TCP stream.
struct StreamState {
    /// Logical stream identifier.
    id: u32,
    /// Stream-specific send credit advertised by the remote peer.
    send_window: Arc<SendWindow>,
    /// Stream-specific receive credit advertised by this peer.
    recv_window: Mutex<RecvWindow>,
    /// Byte-bounded queue feeding the adjacent TCP writer.
    inbound: ByteQueue,
    /// Single-frame outbound slot preventing DATA queue buildup.
    data_slot: Arc<Semaphore>,
    /// Target readiness state independent from early DATA flow.
    open_state: AtomicU8,
    /// Whether RESET or connection shutdown ended this stream.
    closed: AtomicBool,
    /// Wakes bridge tasks after stream termination.
    closed_notify: Notify,
}

/// Shared state for one unordered UDP association.
struct DatagramState {
    /// Stable association identifier.
    id: u32,
    /// Bounded queue preserving individual incoming packets.
    inbound: DatagramQueue,
    /// Completion channel for a locally initiated association OPEN.
    open_result: Mutex<Option<oneshot::Sender<Result<(), String>>>>,
    /// Whether CLOSE or carrier shutdown ended this association.
    closed: AtomicBool,
    /// Wakes receivers after association termination.
    closed_notify: Notify,
}

/// Application-facing logical stream with explicit chunk consumption.
///
/// Example: write adjacent TCP bytes with a send permit, then consume inbound bytes.
pub(super) struct Stream {
    /// Owning endpoint used for frame emission and connection window accounting.
    endpoint: Weak<EndpointInner>,
    /// Shared logical stream state.
    state: Arc<StreamState>,
}

/// Application-facing unordered UDP association.
///
/// Example: one local UDP peer exchanges opaque datagrams through one shared carrier.
pub(in crate::proxy) struct Datagram {
    /// Owning endpoint used for frame emission and lifecycle.
    endpoint: Weak<EndpointInner>,
    /// Shared logical association state.
    state: Arc<DatagramState>,
}

/// Credit reservation proving that adjacent TCP may be read for this stream.
///
/// Example: zero remote window prevents construction of this permit.
pub(super) struct SendPermit {
    /// Owning endpoint used to send the resulting DATA frame.
    endpoint: Arc<EndpointInner>,
    /// Logical stream state.
    state: Arc<StreamState>,
    /// Per-stream byte reservation.
    stream_credit: Reservation,
    /// Aggregate connection byte reservation.
    connection_credit: Reservation,
    /// One-frame queue slot held until scheduler handoff.
    slot: tokio::sync::OwnedSemaphorePermit,
    /// Maximum bytes allowed by both reservations.
    amount: u32,
}

/// Server-side OPEN request awaiting target TCP connection success or rejection.
///
/// Example: target port 10808 is connected before calling `accept`.
pub(super) struct IncomingStream {
    /// Target port requested by the client.
    target_port: u16,
    /// Logical stream pending acceptance.
    stream: Option<Stream>,
}

/// Server-side UDP association awaiting socket allocation.
///
/// Example: the daemon binds an ephemeral UDP socket before accepting it.
pub(super) struct IncomingDatagram {
    /// Fixed target port requested when this association was opened.
    target_port: u16,
    /// Logical association pending acceptance.
    datagram: Option<Datagram>,
}

impl Default for Config {
    /// Returns the production receive and concurrency limits.
    ///
    /// Example: one stream starts with a 256KiB receive window.
    fn default() -> Self {
        Self {
            stream_window: DEFAULT_STREAM_WINDOW,
            connection_window: DEFAULT_CONNECTION_WINDOW,
            max_frame: DEFAULT_MAX_FRAME,
            max_streams: DEFAULT_MAX_STREAMS,
        }
    }
}

impl Endpoint {
    /// Starts a mux peer over caller-owned inbound and outbound frame channels.
    ///
    /// Example: a WebSocket adapter supplies frames in production; tests cross-connect channels.
    pub(super) fn start(
        role: Role,
        config: Config,
        carrier_out: mpsc::Sender<Frame>,
        carrier_in: mpsc::Receiver<Frame>,
    ) -> Result<Self, String> {
        validate_config(config)?;
        let outbound = Outbound::start(
            carrier_out,
            Frame::Hello {
                version: VERSION,
                stream_window: config.stream_window,
                connection_window: config.connection_window,
                max_frame: config.max_frame,
                max_streams: config.max_streams,
            },
        );
        let (incoming_tx, incoming_rx) = mpsc::channel(config.max_streams as usize);
        let (incoming_datagram_tx, incoming_datagram_rx) =
            mpsc::channel(config.max_streams as usize);
        let inner = Arc::new(EndpointInner {
            role,
            config,
            outbound,
            streams: Mutex::new(HashMap::new()),
            datagrams: Mutex::new(HashMap::new()),
            remote: Mutex::new(None),
            hello_ready: Notify::new(),
            next_stream_id: AtomicU32::new(match role {
                Role::Client => 1,
                Role::Server => 2,
            }),
            recv_connection: Mutex::new(RecvWindow::new(
                config.connection_window,
                WINDOW_UPDATE_THRESHOLD.min(config.connection_window),
            )?),
            incoming: incoming_tx,
            incoming_datagrams: incoming_datagram_tx,
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        });
        tokio::spawn(run_inbound(Arc::clone(&inner), carrier_in));
        Ok(Self {
            inner,
            incoming: Arc::new(AsyncMutex::new(incoming_rx)),
            incoming_datagrams: Arc::new(AsyncMutex::new(incoming_datagram_rx)),
        })
    }

    /// Opens one client-initiated logical stream after OPEN reaches the carrier.
    ///
    /// Example: target port 10808 may send client-first bytes while the daemon connects it.
    pub(super) async fn open(&self, target_port: u16) -> Result<Stream, String> {
        if self.inner.role != Role::Client {
            return Err("invalid mux client open request".to_string());
        }
        let remote = self.inner.wait_remote().await?;
        let id = self.inner.allocate_stream_id(remote.max_streams)?;
        let (_, stream) = self.inner.create_stream(id, &remote, true)?;
        let result = self
            .inner
            .outbound
            .send_ordered_control(Frame::Open {
                stream_id: id,
                target_port,
            })
            .await;
        if let Err(error) = result {
            let _ = self
                .inner
                .remove_stream(id, "mux OPEN carrier handoff failed")
                .await;
            return Err(error);
        }
        Ok(stream)
    }

    /// Accepts the next server-side OPEN without acknowledging it prematurely.
    ///
    /// Example: the daemon connects target TCP before calling `IncomingStream::accept`.
    pub(super) async fn accept(&self) -> Result<IncomingStream, String> {
        if self.inner.role != Role::Server {
            return Err("mux client cannot accept remote streams".to_string());
        }
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| "mux incoming stream queue closed".to_string())
    }

    /// Opens one client-initiated UDP association and waits for remote readiness.
    ///
    /// Example: target port 10808 returns an association only after DATAGRAM_OPEN_OK.
    pub(super) async fn open_datagram(&self, target_port: u16) -> Result<Datagram, String> {
        if self.inner.role != Role::Client {
            return Err("invalid mux client datagram open request".to_string());
        }
        let remote = self.inner.wait_remote().await?;
        let id = self.inner.allocate_stream_id(remote.max_streams)?;
        let (state, datagram) = self.inner.create_datagram(id, true)?;
        let (result_tx, result_rx) = oneshot::channel();
        *state
            .open_result
            .lock()
            .expect("mux datagram open result poisoned") = Some(result_tx);
        self.inner
            .outbound
            .send_control(Frame::DatagramOpen {
                association_id: id,
                target_port,
            })
            .await?;
        match result_rx.await {
            Ok(Ok(())) => Ok(datagram),
            Ok(Err(error)) => Err(error),
            Err(_) => Err("mux datagram open was cancelled".to_string()),
        }
    }

    /// Accepts the next server-side UDP association without acknowledging it prematurely.
    ///
    /// Example: the daemon connects its fixed target before accepting the association.
    pub(super) async fn accept_datagram(&self) -> Result<IncomingDatagram, String> {
        if self.inner.role != Role::Server {
            return Err("mux client cannot accept remote datagrams".to_string());
        }
        self.incoming_datagrams
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| "mux incoming datagram queue closed".to_string())
    }

    /// Reports whether the carrier or protocol has terminated.
    ///
    /// Example: a pooled client replaces an endpoint after this returns true.
    pub(super) fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Waits until connection shutdown, suitable for keeping a server request alive.
    ///
    /// Example: WebSocket EOF wakes the daemon mux handler.
    pub(super) async fn closed(&self) {
        if self.is_closed() {
            return;
        }
        self.inner.closed_notify.notified().await;
    }
}

impl EndpointInner {
    /// Waits for the peer hello without blocking carrier shutdown.
    ///
    /// Example: opening a stream before hello pauses until remote limits arrive.
    async fn wait_remote(&self) -> Result<Arc<RemoteState>, String> {
        loop {
            let notified = self.hello_ready.notified();
            if let Some(remote) = self
                .remote
                .lock()
                .expect("mux remote state poisoned")
                .clone()
            {
                return Ok(remote);
            }
            if self.closed.load(Ordering::Acquire) {
                return Err("mux connection closed before hello".to_string());
            }
            tokio::select! {
                _ = notified => {}
                _ = self.closed_notify.notified() => {}
            }
        }
    }

    /// Allocates the next role-specific stream identifier within peer limits.
    ///
    /// Example: the client allocates 1, 3, 5 without colliding with server IDs.
    fn allocate_stream_id(&self, remote_max_streams: u32) -> Result<u32, String> {
        let stream_count = self.streams.lock().expect("mux streams poisoned").len();
        let datagram_count = self.datagrams.lock().expect("mux datagrams poisoned").len();
        if stream_count.saturating_add(datagram_count) >= remote_max_streams as usize {
            return Err("mux remote stream limit reached".to_string());
        }
        let id = self.next_stream_id.fetch_add(2, Ordering::AcqRel);
        if id == 0 || id > u32::MAX - 2 {
            return Err("mux stream identifier space exhausted".to_string());
        }
        Ok(id)
    }

    /// Creates and registers one stream using limits from both hello messages.
    ///
    /// Example: a client OPEN registers state before its ordered carrier handoff.
    fn create_stream(
        self: &Arc<Self>,
        id: u32,
        remote: &RemoteState,
        local_open: bool,
    ) -> Result<(Arc<StreamState>, Stream), String> {
        let state = Arc::new(StreamState {
            id,
            send_window: SendWindow::new(remote.stream_window),
            recv_window: Mutex::new(RecvWindow::new(
                self.config.stream_window,
                WINDOW_UPDATE_THRESHOLD.min(self.config.stream_window),
            )?),
            inbound: ByteQueue::new(self.config.stream_window as usize),
            data_slot: Arc::new(Semaphore::new(1)),
            open_state: AtomicU8::new(STREAM_OPENING),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        });
        let mut streams = self.streams.lock().expect("mux streams poisoned");
        let datagrams = self.datagrams.lock().expect("mux datagrams poisoned");
        if streams.contains_key(&id) || datagrams.contains_key(&id) {
            return Err("duplicate mux stream identifier".to_string());
        }
        if !local_open
            && streams.len().saturating_add(datagrams.len()) >= self.config.max_streams as usize
        {
            return Err("mux local stream limit reached".to_string());
        }
        drop(datagrams);
        streams.insert(id, Arc::clone(&state));
        drop(streams);
        Ok((
            Arc::clone(&state),
            Stream {
                endpoint: Arc::downgrade(self),
                state,
            },
        ))
    }

    /// Creates and registers one bounded unordered datagram association.
    ///
    /// Example: a local open installs its result channel before DATAGRAM_OPEN is sent.
    fn create_datagram(
        self: &Arc<Self>,
        id: u32,
        local_open: bool,
    ) -> Result<(Arc<DatagramState>, Datagram), String> {
        let state = Arc::new(DatagramState {
            id,
            inbound: DatagramQueue::new(DATAGRAM_QUEUE_PACKETS, DATAGRAM_QUEUE_BYTES),
            open_result: Mutex::new(None),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        });
        let streams = self.streams.lock().expect("mux streams poisoned");
        let mut datagrams = self.datagrams.lock().expect("mux datagrams poisoned");
        if streams.contains_key(&id) || datagrams.contains_key(&id) {
            return Err("duplicate mux association identifier".to_string());
        }
        if !local_open
            && streams.len().saturating_add(datagrams.len()) >= self.config.max_streams as usize
        {
            return Err("mux local stream limit reached".to_string());
        }
        datagrams.insert(id, Arc::clone(&state));
        drop(datagrams);
        drop(streams);
        Ok((
            Arc::clone(&state),
            Datagram {
                endpoint: Arc::downgrade(self),
                state,
            },
        ))
    }

    /// Closes the connection and every stream after carrier or protocol failure.
    ///
    /// Example: one WSS EOF wakes all TCP bridge tasks without replaying bytes.
    fn close_all(&self, reason: &str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        let streams: Vec<_> = self
            .streams
            .lock()
            .expect("mux streams poisoned")
            .values()
            .cloned()
            .collect();
        for stream in streams {
            stream.close(reason);
        }
        let datagrams: Vec<_> = self
            .datagrams
            .lock()
            .expect("mux datagrams poisoned")
            .values()
            .cloned()
            .collect();
        for datagram in datagrams {
            datagram.close(reason);
        }
        if let Some(remote) = self
            .remote
            .lock()
            .expect("mux remote state poisoned")
            .as_ref()
        {
            remote.send_connection.close();
        }
        self.hello_ready.notify_waiters();
        self.closed_notify.notify_waiters();
    }

    /// Removes one completed stream and cancels any pending fair-scheduler DATA.
    ///
    /// Example: resetting a stream prevents its queued DATA from following RESET.
    async fn remove_stream(&self, stream_id: u32, reason: &str) -> Result<(), String> {
        let state = self
            .streams
            .lock()
            .expect("mux streams poisoned")
            .remove(&stream_id);
        let Some(state) = state else {
            return Ok(());
        };
        let discarded = state
            .recv_window
            .lock()
            .expect("mux receive window poisoned")
            .discard_unconsumed();
        state.close(reason);
        self.outbound.remove_stream(stream_id).await?;
        if discarded == 0 {
            return Ok(());
        }
        // 触发条件：RESET 或本地 IO 错误丢弃了尚未写入相邻 TCP 的 DATA。
        // 不能遗留连接 credit：多个异常 stream 会永久耗尽共享 window。
        // 防止副作用：仅按实际丢弃字节返还，已消费字节仍由正常批量更新负责。
        let connection_update = self
            .recv_connection
            .lock()
            .expect("mux connection receive window poisoned")
            .consume(discarded)?;
        if let Some(increment) = connection_update {
            self.outbound
                .send_control(Frame::ConnectionWindowUpdate { increment })
                .await?;
        }
        Ok(())
    }

    /// Removes one datagram association and wakes all blocked operations.
    ///
    /// Example: DATAGRAM_CLOSE releases its queue without affecting sibling streams.
    fn remove_datagram(&self, association_id: u32, reason: &str) {
        let state = self
            .datagrams
            .lock()
            .expect("mux datagrams poisoned")
            .remove(&association_id);
        if let Some(state) = state {
            state.close(reason);
        }
    }
}

impl StreamState {
    /// Marks one stream closed and releases every blocked bridge operation.
    ///
    /// Example: RESET closes send windows and the inbound DATA queue.
    fn close(&self, _reason: &str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.send_window.close();
        self.inbound.abort();
        self.closed_notify.notify_waiters();
    }
}

impl DatagramState {
    /// Marks one association closed and releases its bounded packet queue.
    ///
    /// Example: carrier EOF wakes a receiver and resolves a pending open with an error.
    fn close(&self, reason: &str) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inbound.close();
        if let Some(result) = self
            .open_result
            .lock()
            .expect("mux datagram open result poisoned")
            .take()
        {
            let _ = result.send(Err(reason.to_string()));
        }
        self.closed_notify.notify_waiters();
    }
}

impl Stream {
    /// Returns this logical stream's stable identifier.
    ///
    /// Example: the first client stream returns 1.
    pub(super) fn id(&self) -> u32 {
        self.state.id
    }

    /// Waits for send credit after the adjacent TCP reports readable data.
    ///
    /// Example: zero peer window blocks here before any TCP read occurs.
    pub(super) async fn reserve_send(&self) -> Result<SendPermit, String> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        let remote = endpoint.wait_remote().await?;
        let slot = Arc::clone(&self.state.data_slot)
            .acquire_owned()
            .await
            .map_err(|_| "mux stream data slot closed".to_string())?;
        let limit = endpoint.config.max_frame.min(remote.max_frame);
        let mut stream_credit = self.state.send_window.reserve(limit).await?;
        let mut connection_credit = remote
            .send_connection
            .reserve(stream_credit.amount())
            .await?;
        let amount = stream_credit.amount().min(connection_credit.amount());
        stream_credit.shrink_to(amount)?;
        connection_credit.shrink_to(amount)?;
        Ok(SendPermit {
            endpoint,
            state: Arc::clone(&self.state),
            stream_credit,
            connection_credit,
            slot,
            amount,
        })
    }

    /// Receives the next DATA chunk destined for the adjacent TCP.
    ///
    /// Example: FIN causes this method to return `None` after queued chunks drain.
    pub(super) async fn recv_chunk(&self) -> Option<Bytes> {
        if self.state.closed.load(Ordering::Acquire) {
            return None;
        }
        tokio::select! {
            biased;
            _ = self.state.closed_notify.notified() => None,
            payload = self.state.inbound.pop(DEFAULT_MAX_FRAME as usize) => payload,
        }
    }

    /// Releases receive credit only after bytes reached the adjacent TCP.
    ///
    /// Example: writing 32KiB to TCP may emit one stream WINDOW_UPDATE.
    pub(super) async fn consumed(&self, bytes: usize) -> Result<(), String> {
        let bytes =
            u32::try_from(bytes).map_err(|_| "mux consumed byte count overflow".to_string())?;
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        let stream_update = self
            .state
            .recv_window
            .lock()
            .expect("mux receive window poisoned")
            .consume(bytes)?;
        let connection_update = endpoint
            .recv_connection
            .lock()
            .expect("mux connection receive window poisoned")
            .consume(bytes)?;
        if let Some(increment) = stream_update {
            endpoint
                .outbound
                .send_control(Frame::WindowUpdate {
                    stream_id: self.state.id,
                    increment,
                })
                .await?;
        }
        if let Some(increment) = connection_update {
            endpoint
                .outbound
                .send_control(Frame::ConnectionWindowUpdate { increment })
                .await?;
        }
        Ok(())
    }

    /// Sends a half-close after adjacent TCP EOF while preserving inbound DATA.
    ///
    /// Example: browser CloseWrite becomes FIN for this stream only.
    pub(super) async fn finish_send(&self) -> Result<(), String> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint
            .outbound
            .send_control(Frame::Fin {
                stream_id: self.state.id,
            })
            .await
    }

    /// Marks this stream idle before its adjacent TCP waits for new readable data.
    ///
    /// Example: an interactive stream rejoining later cannot spend historical fair-share debt.
    pub(super) async fn mark_send_idle(&self) -> Result<(), String> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint.outbound.mark_idle(self.state.id).await
    }

    /// Aborts this logical stream and notifies the peer.
    ///
    /// Example: target TCP reset sends RESET without closing the shared WSS.
    pub(super) async fn reset(&self, code: u16) -> Result<(), String> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint
            .remove_stream(self.state.id, "local mux stream reset")
            .await?;
        endpoint
            .outbound
            .send_control(Frame::Reset {
                stream_id: self.state.id,
                code,
            })
            .await
    }

    /// Releases a normally finished stream after both TCP directions complete.
    ///
    /// Example: paired FIN frames remove the id so later streams retain capacity.
    pub(super) async fn complete(&self) -> Result<(), String> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint
            .remove_stream(self.state.id, "mux stream completed")
            .await
    }

    /// Waits for RESET or carrier closure.
    ///
    /// Example: a blocked TCP task wakes when its WSS session disappears.
    pub(super) async fn closed(&self) {
        if self.state.closed.load(Ordering::Acquire) {
            return;
        }
        self.state.closed_notify.notified().await;
    }
}

impl Datagram {
    /// Returns this association's stable identifier.
    ///
    /// Example: the first client association returns 1 when no stream preceded it.
    pub(super) fn id(&self) -> u32 {
        self.state.id
    }

    /// Attempts to send one complete opaque packet without blocking TCP progress.
    ///
    /// Example: carrier congestion returns `false` so only this packet is dropped.
    pub(in crate::proxy) async fn send(&self, payload: Bytes) -> Result<bool, String> {
        if payload.is_empty() {
            return Err("mux datagram payload cannot be empty".to_string());
        }
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        if self.state.closed.load(Ordering::Acquire) {
            return Err("mux datagram association closed".to_string());
        }
        let remote = endpoint.wait_remote().await?;
        let maximum = endpoint.config.max_frame.min(remote.max_frame) as usize;
        if payload.len() > maximum {
            return Err("mux datagram exceeds remote frame limit".to_string());
        }
        endpoint.outbound.try_send_datagram(Frame::Datagram {
            association_id: self.state.id,
            payload,
        })
    }

    /// Receives the next complete opaque packet while preserving its boundary.
    ///
    /// Example: two input packets produce two independent receive results.
    pub(in crate::proxy) async fn recv(&self) -> Option<Bytes> {
        if self.state.closed.load(Ordering::Acquire) {
            return None;
        }
        tokio::select! {
            biased;
            _ = self.state.closed_notify.notified() => None,
            packet = self.state.inbound.pop() => packet.map(|packet| packet.payload),
        }
    }

    /// Closes one association locally and notifies its peer.
    ///
    /// Example: an expired local UDP peer releases only its own mux association.
    pub(in crate::proxy) async fn close(&self) -> Result<(), String> {
        let endpoint = self
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint.remove_datagram(self.state.id, "local mux datagram close");
        endpoint
            .outbound
            .send_control(Frame::DatagramClose {
                association_id: self.state.id,
            })
            .await
    }
}

impl SendPermit {
    /// Returns the exact upper bound for the next adjacent TCP read.
    ///
    /// Example: remote credit 8KiB limits a nominal 32KiB read to 8KiB.
    pub(super) fn amount(&self) -> usize {
        self.amount as usize
    }

    /// Commits read bytes as one DATA frame and returns unused credit.
    ///
    /// Example: a 100-byte TCP read consumes exactly 100 remote window bytes.
    pub(super) async fn send(self, payload: Bytes) -> Result<(), String> {
        let used =
            u32::try_from(payload.len()).map_err(|_| "mux DATA length overflow".to_string())?;
        if used == 0 || used > self.amount {
            return Err("mux DATA exceeds reserved send credit".to_string());
        }
        let stream_credit = self.stream_credit.commit_guarded(used)?;
        let connection_credit = self.connection_credit.commit_guarded(used)?;
        self.endpoint
            .outbound
            .send_data(
                self.state.id,
                payload,
                stream_credit,
                connection_credit,
                self.slot,
            )
            .await?;
        Ok(())
    }
}

impl IncomingStream {
    /// Returns the remote target port requested by OPEN.
    ///
    /// Example: an HTTP proxy stream may request port 10808.
    pub(super) fn target_port(&self) -> u16 {
        self.target_port
    }

    /// Acknowledges target TCP readiness and returns the logical stream.
    ///
    /// Example: daemon connects target first, then emits OPEN_OK.
    pub(super) async fn accept(mut self) -> Result<Stream, String> {
        let stream = self
            .stream
            .take()
            .ok_or_else(|| "mux incoming stream already resolved".to_string())?;
        if stream.state.closed.load(Ordering::Acquire) {
            return Err("mux incoming stream closed before target ready".to_string());
        }
        stream
            .state
            .open_state
            .compare_exchange(
                STREAM_OPENING,
                STREAM_OPEN,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "mux incoming stream was already resolved".to_string())?;
        let endpoint = stream
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint
            .outbound
            .send_control(Frame::OpenOk {
                stream_id: stream.id(),
            })
            .await?;
        Ok(stream)
    }

    /// Rejects a target connection failure without terminating other streams.
    ///
    /// Example: connection refused emits OPEN_ERROR for only this stream.
    pub(super) async fn reject(mut self, code: u16) -> Result<(), String> {
        let stream = self
            .stream
            .take()
            .ok_or_else(|| "mux incoming stream already resolved".to_string())?;
        if stream.state.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        stream
            .state
            .open_state
            .compare_exchange(
                STREAM_OPENING,
                STREAM_REJECTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| "mux incoming stream was already resolved".to_string())?;
        let endpoint = stream
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint
            .outbound
            .send_control(Frame::OpenError {
                stream_id: stream.id(),
                code,
            })
            .await?;

        // 触发条件：目标连接失败，但客户端可能已有 DATA 在双向载体中飞行。
        // 不能立即删状态：晚到 DATA 会被误判为未知 stream，并泄漏共享 window。
        // 防止副作用：正常由客户端 RESET 精确回收；超时只兜底旧版或恶意客户端。
        let stream_id = stream.id();
        tokio::spawn(async move {
            tokio::time::sleep(REJECTED_STREAM_TIMEOUT).await;
            let rejected = optional_stream_state(&endpoint, stream_id)
                .is_some_and(|state| state.open_state.load(Ordering::Acquire) == STREAM_REJECTED);
            if rejected {
                let _ = endpoint
                    .remove_stream(stream_id, "rejected mux stream cleanup timeout")
                    .await;
            }
        });
        Ok(())
    }
}

impl IncomingDatagram {
    /// Returns the fixed target port requested when the association was opened.
    ///
    /// Example: `10808` selects the daemon's configured host at UDP port 10808.
    pub(super) fn target_port(&self) -> u16 {
        self.target_port
    }

    /// Acknowledges target UDP socket readiness and returns the association.
    ///
    /// Example: the daemon connects its UDP socket before emitting DATAGRAM_OPEN_OK.
    pub(super) async fn accept(mut self) -> Result<Datagram, String> {
        let datagram = self
            .datagram
            .take()
            .ok_or_else(|| "mux incoming datagram already resolved".to_string())?;
        let endpoint = datagram
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint
            .outbound
            .send_control(Frame::DatagramOpenOk {
                association_id: datagram.id(),
            })
            .await?;
        Ok(datagram)
    }

    /// Rejects one UDP association without terminating the shared carrier.
    ///
    /// Example: an unavailable target emits DATAGRAM_OPEN_ERROR for only this association.
    pub(super) async fn reject(mut self, code: u16) -> Result<(), String> {
        let datagram = self
            .datagram
            .take()
            .ok_or_else(|| "mux incoming datagram already resolved".to_string())?;
        let endpoint = datagram
            .endpoint
            .upgrade()
            .ok_or_else(|| "mux endpoint released".to_string())?;
        endpoint.remove_datagram(datagram.id(), "remote datagram target open failed");
        endpoint
            .outbound
            .send_control(Frame::DatagramOpenError {
                association_id: datagram.id(),
                code,
            })
            .await
    }
}

/// Validates local configuration before any driver task is started.
///
/// Example: max frame larger than stream window is rejected.
fn validate_config(config: Config) -> Result<(), String> {
    if config.stream_window == 0
        || config.connection_window == 0
        || config.max_frame == 0
        || config.max_frame > config.stream_window
        || config.max_streams == 0
    {
        return Err("invalid mux endpoint configuration".to_string());
    }
    Ok(())
}

/// Drives inbound frames until carrier EOF or a protocol violation.
///
/// Example: a frame received before HELLO closes the whole mux connection.
async fn run_inbound(inner: Arc<EndpointInner>, mut carrier: mpsc::Receiver<Frame>) {
    while let Some(frame) = carrier.recv().await {
        if let Err(error) = handle_frame(&inner, frame).await {
            inner.close_all(&error);
            return;
        }
    }
    inner.close_all("mux carrier closed");
}

/// Applies one decoded frame to connection or stream state.
///
/// Example: DATA keeps stream credit charged but returns connection credit after demux.
async fn handle_frame(inner: &Arc<EndpointInner>, frame: Frame) -> Result<(), String> {
    if matches!(frame, Frame::Hello { .. }) {
        return handle_hello(inner, frame);
    }
    let remote = inner
        .remote
        .lock()
        .expect("mux remote state poisoned")
        .clone()
        .ok_or_else(|| "mux frame arrived before hello".to_string())?;
    match frame {
        Frame::Open {
            stream_id,
            target_port,
        } => handle_open(inner, &remote, stream_id, target_port).await,
        Frame::OpenOk { stream_id } => handle_open_ok(inner, stream_id),
        Frame::OpenError { stream_id, code } => handle_open_error(inner, stream_id, code).await,
        Frame::Data { stream_id, payload } => handle_data(inner, stream_id, payload).await,
        Frame::Fin { stream_id } => handle_fin(inner, stream_id),
        Frame::Reset { stream_id, code } => handle_reset(inner, stream_id, code).await,
        Frame::WindowUpdate {
            stream_id,
            increment,
        } => match optional_stream_state(inner, stream_id) {
            Some(stream) => stream.send_window.update(increment),
            None => Ok(()),
        },
        Frame::ConnectionWindowUpdate { increment } => remote.send_connection.update(increment),
        Frame::DatagramOpen {
            association_id,
            target_port,
        } => handle_datagram_open(inner, association_id, target_port).await,
        Frame::DatagramOpenOk { association_id } => {
            complete_datagram_open(inner, association_id, Ok(()))
        }
        Frame::DatagramOpenError {
            association_id,
            code,
        } => complete_datagram_open(
            inner,
            association_id,
            Err(format!(
                "remote datagram target open failed with code {code}"
            )),
        ),
        Frame::Datagram {
            association_id,
            payload,
        } => handle_datagram(inner, association_id, payload),
        Frame::DatagramClose { association_id } => {
            inner.remove_datagram(association_id, "remote mux datagram close");
            Ok(())
        }
        Frame::Hello { .. } => unreachable!("hello handled before match"),
    }
}

/// Installs exactly one compatible remote hello and its connection send window.
///
/// Example: version mismatch terminates before any stream can open.
fn handle_hello(inner: &Arc<EndpointInner>, frame: Frame) -> Result<(), String> {
    let Frame::Hello {
        version,
        stream_window,
        connection_window,
        max_frame,
        max_streams,
    } = frame
    else {
        return Err("expected mux hello".to_string());
    };
    if version != VERSION || max_frame > stream_window {
        return Err("incompatible mux hello".to_string());
    }
    let mut remote = inner.remote.lock().expect("mux remote state poisoned");
    if remote.is_some() {
        return Err("duplicate mux hello".to_string());
    }
    *remote = Some(Arc::new(RemoteState {
        send_connection: SendWindow::new(connection_window),
        stream_window,
        max_frame,
        max_streams,
    }));
    drop(remote);
    inner.hello_ready.notify_waiters();
    Ok(())
}

/// Creates one server-side pending stream from a valid client OPEN.
///
/// Example: odd stream id 1 and port 10808 enter the daemon accept queue.
async fn handle_open(
    inner: &Arc<EndpointInner>,
    remote: &RemoteState,
    stream_id: u32,
    target_port: u16,
) -> Result<(), String> {
    if inner.role != Role::Server || stream_id % 2 == 0 {
        return Err("invalid remote mux OPEN".to_string());
    }
    let (_, stream) = inner.create_stream(stream_id, remote, false)?;
    inner
        .incoming
        .send(IncomingStream {
            target_port,
            stream: Some(stream),
        })
        .await
        .map_err(|_| "mux server accept queue closed".to_string())
}

/// Creates one server-side pending UDP association from a valid open frame.
///
/// Example: odd association id 1 enters the daemon accept queue with its fixed port.
async fn handle_datagram_open(
    inner: &Arc<EndpointInner>,
    association_id: u32,
    target_port: u16,
) -> Result<(), String> {
    if inner.role != Role::Server || association_id % 2 == 0 {
        return Err("invalid remote mux DATAGRAM_OPEN".to_string());
    }
    let (_, datagram) = inner.create_datagram(association_id, false)?;
    inner
        .incoming_datagrams
        .send(IncomingDatagram {
            target_port,
            datagram: Some(datagram),
        })
        .await
        .map_err(|_| "mux server datagram accept queue closed".to_string())
}

/// Marks one locally opened stream ready without gating its early DATA.
///
/// Example: OPEN_OK changes stream 1 from opening to open after client bytes already flowed.
fn handle_open_ok(inner: &EndpointInner, stream_id: u32) -> Result<(), String> {
    if inner.role != Role::Client {
        return Err("invalid mux OPEN_OK for server endpoint".to_string());
    }
    let Some(state) = optional_stream_state(inner, stream_id) else {
        // A crossed local RESET may legitimately remove the stream before late OPEN_OK arrives.
        return Ok(());
    };
    state
        .open_state
        .compare_exchange(
            STREAM_OPENING,
            STREAM_OPEN,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| "unexpected mux OPEN_OK response".to_string())?;
    Ok(())
}

/// Rejects one locally opened stream and orders RESET after all earlier DATA.
///
/// Example: OPEN_ERROR code 2 closes stream 1, restores credit, then confirms cleanup with RESET.
async fn handle_open_error(
    inner: &Arc<EndpointInner>,
    stream_id: u32,
    code: u16,
) -> Result<(), String> {
    if inner.role != Role::Client {
        return Err("invalid mux OPEN_ERROR for server endpoint".to_string());
    }
    let Some(state) = optional_stream_state(inner, stream_id) else {
        // Crossed RESET and duplicate cleanup responses are harmless after local removal.
        return Ok(());
    };
    state
        .open_state
        .compare_exchange(
            STREAM_OPENING,
            STREAM_REJECTED,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map_err(|_| "unexpected mux OPEN_ERROR response".to_string())?;
    inner
        .remove_stream(stream_id, "remote target open failed")
        .await?;
    inner
        .outbound
        .send_control(Frame::Reset { stream_id, code })
        .await
}

/// Resolves one locally pending UDP association response.
///
/// Example: DATAGRAM_OPEN_ERROR removes only the rejected association.
fn complete_datagram_open(
    inner: &Arc<EndpointInner>,
    association_id: u32,
    result: Result<(), String>,
) -> Result<(), String> {
    let state = datagram_state(inner, association_id)?;
    let sender = state
        .open_result
        .lock()
        .expect("mux datagram open result poisoned")
        .take()
        .ok_or_else(|| "unexpected mux DATAGRAM_OPEN response".to_string())?;
    let failed = result.is_err();
    let _ = sender.send(result);
    if failed {
        inner.remove_datagram(association_id, "remote datagram target open failed");
    }
    Ok(())
}

/// Charges both receive windows and queues DATA until the adjacent TCP consumes it.
///
/// Example: stalled targets cumulatively retain at most the aggregate connection window.
async fn handle_data(inner: &EndpointInner, stream_id: u32, payload: Bytes) -> Result<(), String> {
    let bytes = u32::try_from(payload.len()).map_err(|_| "mux DATA length overflow".to_string())?;
    if bytes == 0 || bytes > inner.config.max_frame {
        return Err("mux DATA exceeds local frame limit".to_string());
    }
    let state = stream_state(inner, stream_id)?;
    state
        .recv_window
        .lock()
        .expect("mux receive window poisoned")
        .receive(bytes)?;
    inner
        .recv_connection
        .lock()
        .expect("mux connection receive window poisoned")
        .receive(bytes)?;
    state.inbound.push(&payload)?;
    Ok(())
}

/// Queues one complete incoming UDP packet or drops it under local congestion.
///
/// Example: a full association queue drops one packet without blocking TCP DATA.
fn handle_datagram(
    inner: &EndpointInner,
    association_id: u32,
    payload: Bytes,
) -> Result<(), String> {
    if payload.is_empty() || payload.len() > inner.config.max_frame as usize {
        return Err("mux datagram exceeds local frame limit".to_string());
    }
    let state = datagram_state(inner, association_id)?;
    let _ = state.inbound.push(payload);
    Ok(())
}

/// Applies a remote half-close by closing only the inbound DATA queue.
///
/// Example: FIN lets queued bytes drain before adjacent TCP shutdown.
fn handle_fin(inner: &EndpointInner, stream_id: u32) -> Result<(), String> {
    if let Some(stream) = optional_stream_state(inner, stream_id) {
        stream.inbound.close_input();
    }
    Ok(())
}

/// Applies a remote stream reset without closing the shared carrier.
///
/// Example: one target TCP failure leaves sibling streams alive.
async fn handle_reset(inner: &Arc<EndpointInner>, stream_id: u32, code: u16) -> Result<(), String> {
    if optional_stream_state(inner, stream_id).is_none() {
        return Ok(());
    }
    inner
        .remove_stream(stream_id, &format!("remote mux reset code {code}"))
        .await
}

/// Looks up one active stream or returns a stable protocol error.
///
/// Example: DATA for an unknown id is rejected rather than allocated implicitly.
fn stream_state(inner: &EndpointInner, stream_id: u32) -> Result<Arc<StreamState>, String> {
    optional_stream_state(inner, stream_id).ok_or_else(|| format!("unknown mux stream {stream_id}"))
}

/// Looks up a stream for idempotent late control frames after local cleanup.
///
/// Example: crossed RESET or delayed WINDOW_UPDATE for a removed id is harmless.
fn optional_stream_state(inner: &EndpointInner, stream_id: u32) -> Option<Arc<StreamState>> {
    inner
        .streams
        .lock()
        .expect("mux streams poisoned")
        .get(&stream_id)
        .cloned()
}

/// Looks up one active UDP association or returns a stable protocol error.
///
/// Example: a datagram for an unknown id is rejected rather than allocated implicitly.
fn datagram_state(
    inner: &EndpointInner,
    association_id: u32,
) -> Result<Arc<DatagramState>, String> {
    inner
        .datagrams
        .lock()
        .expect("mux datagrams poisoned")
        .get(&association_id)
        .cloned()
        .ok_or_else(|| format!("unknown mux datagram association {association_id}"))
}

#[cfg(test)]
#[path = "core_test.rs"]
mod core_test;
