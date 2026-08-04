use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::cf_lib::backoff::Backoff;
use crate::cf_lib::edge_discovery;
use crate::cf_lib::quick_tunnel::{self, Credentials};
use crate::cf_lib::transport::http2::Http2Transport;
use crate::cf_lib::transport::quic::QuicTransport;
use crate::cf_lib::transport::ActiveTransport;
use crate::cf_lib::{CfError, IncomingRequest, SessionEvent};

const REQUEST_QUEUE_CAPACITY: usize = 128;
const EVENT_QUEUE_CAPACITY: usize = 32;

/// Quick Tunnel result containing its public hostname and live session.
///
/// Example: create -> hostname `x.trycloudflare.com` plus request session.
pub struct QuickTunnel {
    /// Public hostname assigned by TryCloudflare.
    pub hostname: String,
    /// Live reconnecting Cloudflare session.
    pub session: Session,
}

/// Reconnecting Cloudflare request session.
///
/// Example: `accept()` receives requests until `shutdown()` is called.
pub struct Session {
    /// Shared state used by concurrently called public methods.
    inner: Arc<SessionInner>,
}

/// Shared channels and supervisor ownership for one session.
struct SessionInner {
    /// Incoming requests serialized for the application.
    requests: Mutex<mpsc::Receiver<IncomingRequest>>,
    /// Broadcast source for connection lifecycle events.
    events: broadcast::Sender<SessionEvent>,
    /// Cancellation token observed by connection attempts and active transports.
    shutdown: CancellationToken,
    /// Supervisor task joined exactly once during explicit shutdown.
    supervisor: Mutex<Option<JoinHandle<()>>>,
}

impl Session {
    /// Receives the next Cloudflare request across reconnects.
    ///
    /// Example: `session.accept().await -> IncomingRequest`.
    pub async fn accept(&self) -> Result<IncomingRequest, CfError> {
        self.inner
            .requests
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| CfError::new("Cloudflare session stopped"))
    }

    /// Subscribes to future connection lifecycle events.
    ///
    /// Example: reconnect -> `SessionEvent::Reconnecting`.
    pub fn events(&self) -> broadcast::Receiver<SessionEvent> {
        self.inner.events.subscribe()
    }

    /// Gracefully stops reconnecting and unregisters the active transport.
    ///
    /// Example: `session.shutdown().await -> ()`.
    pub async fn shutdown(&self) -> Result<(), CfError> {
        self.inner.shutdown.cancel();
        if let Some(supervisor) = self.inner.supervisor.lock().await.take() {
            supervisor
                .await
                .map_err(|error| CfError::new(format!("Cloudflare supervisor failed: {error}")))?;
        }
        Ok(())
    }
}

impl Clone for Session {
    /// Clones the lightweight handle to one shared session.
    ///
    /// Example: request loop and shutdown owner can hold separate handles.
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for SessionInner {
    /// Cancels background work when the last public handle disappears.
    ///
    /// Example: dropping an abandoned session stops reconnect attempts.
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Creates credentials and starts the reconnect supervisor.
///
/// Example: fixed TryCloudflare endpoint -> live `QuickTunnel`.
pub(crate) async fn create() -> Result<QuickTunnel, CfError> {
    let credentials = quick_tunnel::create().await?;
    let hostname = credentials.hostname.clone();
    let (request_sender, request_receiver) = mpsc::channel(REQUEST_QUEUE_CAPACITY);
    let (event_sender, _) = broadcast::channel(EVENT_QUEUE_CAPACITY);
    let shutdown = CancellationToken::new();
    let supervisor_shutdown = shutdown.clone();
    let supervisor_events = event_sender.clone();
    let supervisor = tokio::spawn(async move {
        supervise(
            credentials,
            request_sender,
            supervisor_events,
            supervisor_shutdown,
        )
        .await;
    });
    let session = Session {
        inner: Arc::new(SessionInner {
            requests: Mutex::new(request_receiver),
            events: event_sender,
            shutdown,
            supervisor: Mutex::new(Some(supervisor)),
        }),
    };
    Ok(QuickTunnel { hostname, session })
}

/// Maintains one active edge transport until explicit shutdown.
///
/// Example: failure -> reconnect event -> exponential delay -> new round.
async fn supervise(
    credentials: Credentials,
    requests: mpsc::Sender<IncomingRequest>,
    events: broadcast::Sender<SessionEvent>,
    shutdown: CancellationToken,
) {
    let mut backoff = Backoff::new();
    let mut attempts = 0_u8;
    loop {
        if shutdown.is_cancelled() {
            break;
        }
        match connect_round(&credentials, attempts, &shutdown).await {
            Ok(transport) => {
                attempts = 0;
                backoff.reset();
                let _ = events.send(SessionEvent::Connected {
                    transport: transport.kind(),
                    location: transport.location().to_string(),
                });
                match transport.run(requests.clone(), shutdown.clone()).await {
                    Ok(()) if shutdown.is_cancelled() => break,
                    Ok(()) => {
                        attempts = attempts.saturating_add(1);
                    }
                    Err(error) => {
                        attempts = attempts.saturating_add(1);
                        if !wait_before_retry(&events, &shutdown, &mut backoff, error.to_string())
                            .await
                        {
                            break;
                        }
                    }
                }
            }
            Err(error) => {
                attempts = attempts.saturating_add(1);
                if !wait_before_retry(&events, &shutdown, &mut backoff, error.to_string()).await {
                    break;
                }
            }
        }
    }
    let _ = events.send(SessionEvent::Stopped);
}

/// Tries QUIC then HTTP/2 against the discovered edge pool.
///
/// Example: UDP blocked on every edge -> HTTP/2 fallback attempts.
async fn connect_round(
    credentials: &Credentials,
    previous_attempts: u8,
    shutdown: &CancellationToken,
) -> Result<ActiveTransport, CfError> {
    let edges = tokio::select! {
        _ = shutdown.cancelled() => return Err(CfError::new("Cloudflare session is shutting down")),
        result = edge_discovery::resolve() => result?,
    };
    let mut failures = Vec::new();
    for edge in &edges {
        let result = tokio::select! {
            _ = shutdown.cancelled() => return Err(CfError::new("Cloudflare session is shutting down")),
            result = QuicTransport::connect(*edge, credentials, previous_attempts) => result,
        };
        match result {
            Ok(transport) => return Ok(ActiveTransport::Quic(transport)),
            Err(error) => failures.push(format!("QUIC {}: {error}", edge.socket)),
        }
        let result = tokio::select! {
            _ = shutdown.cancelled() => return Err(CfError::new("Cloudflare session is shutting down")),
            result = Http2Transport::connect(*edge, credentials, previous_attempts) => result,
        };
        match result {
            Ok(transport) => return Ok(ActiveTransport::Http2(transport)),
            Err(error) => failures.push(format!("HTTP/2 {}: {error}", edge.socket)),
        }
    }
    Err(CfError::new(format!(
        "all Cloudflare edge connections failed: {}",
        failures.join("; ")
    )))
}

/// Emits reconnect state and waits for the current exponential delay.
///
/// Example: first failure -> event with `200ms`, then wait or shutdown.
async fn wait_before_retry(
    events: &broadcast::Sender<SessionEvent>,
    shutdown: &CancellationToken,
    backoff: &mut Backoff,
    reason: String,
) -> bool {
    let delay = backoff.next();
    let _ = events.send(SessionEvent::Reconnecting { delay, reason });
    tokio::select! {
        _ = shutdown.cancelled() => false,
        _ = time::sleep(delay) => true,
    }
}
