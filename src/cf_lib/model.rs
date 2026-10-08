use bytes::Bytes;
use h2::{RecvStream as H2RecvStream, SendStream as H2SendStream};
use http::HeaderMap;
use quinn::{RecvStream as QuicRecvStream, SendStream as QuicSendStream};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::cf_lib::transport::PendingResponse;

/// Error returned by the Cloudflare client boundary.
///
/// Example: `CfError::new("dns failed") -> displayable error`.
#[derive(Debug, Clone)]
pub struct CfError {
    /// Human-readable error including the failed operation.
    message: String,
    /// Machine-readable category used by reconnect policy.
    kind: CfErrorKind,
}

/// Recovery category attached to one Cloudflare client error.
///
/// Example: a registration `Unauthorized` response -> `Unauthorized`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CfErrorKind {
    /// Error that may recover while retaining the current tunnel credentials.
    Other,
    /// Cloudflare rejected the current tunnel credentials as unauthorized.
    Unauthorized,
}

impl CfError {
    /// Creates an error with operation context.
    ///
    /// Example: `CfError::new("connect failed")`.
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: CfErrorKind::Other,
        }
    }

    /// Creates an error for credentials rejected by Cloudflare registration.
    ///
    /// Example: `Unauthorized: Tunnel not found` -> replacement tunnel required.
    pub(crate) fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            kind: CfErrorKind::Unauthorized,
        }
    }

    /// Reports whether reconnecting with the same credentials cannot recover.
    ///
    /// Example: an unauthorized registration error -> `true`.
    pub(crate) fn is_unauthorized(&self) -> bool {
        self.kind == CfErrorKind::Unauthorized
    }
}

impl Display for CfError {
    /// Formats the stable user-facing error text.
    ///
    /// Example: `format!("{}", error) -> "connect failed"`.
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CfError {}

impl From<io::Error> for CfError {
    /// Converts an I/O error at an already-known operation boundary.
    ///
    /// Example: `io::Error -> CfError`.
    fn from(error: io::Error) -> Self {
        Self::new(error.to_string())
    }
}

/// Cloudflare transport selected for a registered session.
///
/// Example: UDP succeeds -> `Quic`; UDP fails -> `Http2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// QUIC over UDP port 7844.
    Quic,
    /// HTTP/2 over TCP port 7844.
    Http2,
}

/// Type attached to one Cloudflare data request.
///
/// Example: browser upgrade request -> `WebSocket`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Ordinary HTTP request.
    Http,
    /// HTTP request upgraded to WebSocket semantics.
    WebSocket,
    /// Raw TCP stream request.
    Tcp,
}

/// State emitted while the session connects and reconnects.
///
/// Example: successful registration -> `Connected`.
#[derive(Debug, Clone)]
pub enum SessionEvent {
    /// Tunnel registered at a Cloudflare location.
    Connected {
        /// Active edge transport.
        transport: TransportKind,
        /// Cloudflare location code returned by registration.
        location: String,
    },
    /// Both transports failed and the supervisor will retry.
    Reconnecting {
        /// Delay before the next connection round.
        delay: std::time::Duration,
        /// Last connection error.
        reason: String,
    },
    /// Cloudflare rejected the current tunnel credentials.
    Unauthorized {
        /// Registration rejection returned by the Cloudflare edge.
        reason: String,
    },
    /// Session completed a graceful shutdown.
    Stopped,
}

/// Response metadata supplied before application bytes are streamed.
///
/// Example: WebSocket acceptance -> status `101` plus accept header.
#[derive(Debug, Clone)]
pub struct CfResponse {
    /// HTTP-like response status used by Cloudflare transports.
    pub status: u16,
    /// Response headers forwarded to the Cloudflare edge.
    pub headers: HeaderMap,
}

impl CfResponse {
    /// Creates a response without headers.
    ///
    /// Example: `CfResponse::new(403) -> rejection response`.
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
        }
    }
}

/// One request accepted from either Cloudflare transport.
///
/// Example: `/tcp?code=<uuid>` plus WebSocket metadata -> `IncomingRequest`.
pub struct IncomingRequest {
    /// Request protocol selected by Cloudflare.
    pub kind: RequestKind,
    /// Destination URL or TCP address supplied by Cloudflare.
    pub destination: String,
    /// Transport-neutral request metadata.
    pub metadata: HashMap<String, String>,
    /// Single-use response handle retaining the native stream.
    responder: Option<PendingResponse>,
}

impl IncomingRequest {
    /// Creates a request from a transport-specific response handle.
    ///
    /// Example: decoded QUIC metadata -> application request.
    pub(crate) fn new(
        kind: RequestKind,
        destination: String,
        metadata: HashMap<String, String>,
        responder: PendingResponse,
    ) -> Self {
        Self {
            kind,
            destination,
            metadata,
            responder: Some(responder),
        }
    }

    /// Sends a successful response and returns the unified byte stream.
    ///
    /// Example: `request.respond(CfResponse::new(101)).await -> CfStream`.
    pub async fn respond(mut self, response: CfResponse) -> Result<CfStream, CfError> {
        self.responder
            .take()
            .ok_or_else(|| CfError::new("request was already answered"))?
            .respond(response)
            .await
    }

    /// Rejects the request and closes its native stream.
    ///
    /// Example: `request.reject(403).await -> ()`.
    pub async fn reject(mut self, status: u16) -> Result<(), CfError> {
        self.responder
            .take()
            .ok_or_else(|| CfError::new("request was already answered"))?
            .reject(status)
            .await
    }
}

/// Transport-neutral bidirectional stream returned after a response.
///
/// Example: `tokio::io::copy_bidirectional(tcp, cf_stream)`.
pub struct CfStream {
    /// Active native stream implementation.
    inner: StreamInner,
}

/// Native streams hidden behind `CfStream`.
enum StreamInner {
    /// QUIC bidirectional stream halves.
    Quic {
        /// QUIC send half.
        send: QuicSendStream,
        /// QUIC receive half.
        recv: QuicRecvStream,
    },
    /// HTTP/2 request and response bodies.
    Http2 {
        /// HTTP/2 response body.
        send: H2SendStream<Bytes>,
        /// HTTP/2 request body.
        recv: H2RecvStream,
        /// Partially consumed DATA frame.
        buffered: Bytes,
        /// Whether END_STREAM was already sent by a prior shutdown poll.
        send_closed: bool,
    },
}

impl CfStream {
    /// Wraps QUIC bidirectional stream halves.
    ///
    /// Example: native QUIC streams -> `CfStream`.
    pub(crate) fn quic(send: QuicSendStream, recv: QuicRecvStream) -> Self {
        Self {
            inner: StreamInner::Quic { send, recv },
        }
    }

    /// Wraps HTTP/2 request and response body streams.
    ///
    /// Example: H2 body streams -> `CfStream`.
    pub(crate) fn http2(send: H2SendStream<Bytes>, recv: H2RecvStream) -> Self {
        Self {
            inner: StreamInner::Http2 {
                send,
                recv,
                buffered: Bytes::new(),
                send_closed: false,
            },
        }
    }
}

impl AsyncRead for CfStream {
    /// Reads application bytes and releases HTTP/2 receive capacity.
    ///
    /// Example: one DATA frame -> bytes in `ReadBuf`.
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.inner {
            StreamInner::Quic { recv, .. } => Pin::new(recv).poll_read(cx, output),
            StreamInner::Http2 { recv, buffered, .. } => {
                if buffered.is_empty() {
                    match ready!(recv.poll_data(cx)) {
                        Some(Ok(data)) => *buffered = data,
                        Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                        None => return Poll::Ready(Ok(())),
                    }
                }
                let len = output.remaining().min(buffered.len());
                output.put_slice(&buffered.split_to(len));
                recv.flow_control()
                    .release_capacity(len)
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for CfStream {
    /// Writes application bytes with HTTP/2 flow-control awareness.
    ///
    /// Example: 16 KiB input -> one or more H2 DATA frames.
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.inner {
            StreamInner::Quic { send, .. } => AsyncWrite::poll_write(Pin::new(send), cx, input),
            StreamInner::Http2 { send, .. } => {
                if input.is_empty() {
                    return Poll::Ready(Ok(0));
                }
                send.reserve_capacity(input.len());
                let capacity = match ready!(send.poll_capacity(cx)) {
                    Some(Ok(capacity)) => capacity,
                    Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                    None => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "HTTP/2 stream closed",
                        )))
                    }
                };
                let len = capacity.min(input.len());
                send.send_data(Bytes::copy_from_slice(&input[..len]), false)
                    .map_err(io::Error::other)?;
                Poll::Ready(Ok(len))
            }
        }
    }

    /// Flushes bytes already handed to the native transport.
    ///
    /// Example: WebSocket frame boundary -> transport flush.
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            StreamInner::Quic { send, .. } => AsyncWrite::poll_flush(Pin::new(send), cx),
            StreamInner::Http2 { .. } => Poll::Ready(Ok(())),
        }
    }

    /// Gracefully closes the send half of the native stream.
    ///
    /// Example: TCP EOF -> QUIC finish or H2 END_STREAM.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            StreamInner::Quic { send, .. } => AsyncWrite::poll_shutdown(Pin::new(send), cx),
            StreamInner::Http2 {
                send, send_closed, ..
            } => {
                if *send_closed {
                    return Poll::Ready(Ok(()));
                }
                send.send_data(Bytes::new(), true)
                    .map_err(io::Error::other)?;
                *send_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}
