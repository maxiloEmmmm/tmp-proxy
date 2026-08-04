//! Native Cloudflare edge transports and response adapters.

pub(crate) mod http2;
pub(crate) mod quic;

use bytes::Bytes;
use h2::server::SendResponse;
use http::{Response, StatusCode};
use quinn::{RecvStream, SendStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::cf_lib::{CfError, CfResponse, CfStream, IncomingRequest, TransportKind};

/// Single-use native response handle attached to an incoming request.
///
/// Example: QUIC metadata stream or HTTP/2 request -> one response handle.
pub(crate) enum PendingResponse {
    /// QUIC request stream waiting for ConnectResponse metadata.
    Quic {
        /// QUIC send half used for response metadata and application bytes.
        send: SendStream,
        /// QUIC receive half containing application bytes after metadata.
        recv: RecvStream,
    },
    /// HTTP/2 request waiting for response headers.
    Http2 {
        /// HTTP/2 response sender allocated by the server connection.
        response: SendResponse<Bytes>,
        /// HTTP/2 request body containing application bytes.
        recv: h2::RecvStream,
    },
}

impl PendingResponse {
    /// Sends transport-native acceptance metadata and returns a byte stream.
    ///
    /// Example: WebSocket status `101` -> accepted `CfStream`.
    pub(crate) async fn respond(self, response: CfResponse) -> Result<CfStream, CfError> {
        match self {
            Self::Quic { mut send, recv } => {
                crate::cf_lib::protocol::data::write_response(&mut send, &response).await?;
                Ok(CfStream::quic(send, recv))
            }
            Self::Http2 {
                response: mut sender,
                recv,
            } => {
                let response = http2::build_response(&response)?;
                let send = sender.send_response(response, false).map_err(|error| {
                    CfError::new(format!("send HTTP/2 response failed: {error}"))
                })?;
                Ok(CfStream::http2(send, recv))
            }
        }
    }

    /// Sends a transport-native rejection and closes the stream.
    ///
    /// Example: pairing mismatch -> status `403` and no response body.
    pub(crate) async fn reject(self, status: u16) -> Result<(), CfError> {
        match self {
            Self::Quic { mut send, .. } => {
                crate::cf_lib::protocol::data::write_rejection(&mut send, status).await?;
                send.finish()
                    .map_err(|error| CfError::new(format!("finish QUIC rejection failed: {error}")))
            }
            Self::Http2 {
                response: mut sender,
                ..
            } => {
                let status = StatusCode::from_u16(status)
                    .map_err(|error| CfError::new(format!("invalid rejection status: {error}")))?;
                let response = Response::builder()
                    .status(status)
                    .header("cf-cloudflared-response-meta", r#"{"src":"cloudflared"}"#)
                    .body(())
                    .map_err(|error| {
                        CfError::new(format!("build HTTP/2 rejection failed: {error}"))
                    })?;
                sender.send_response(response, true).map_err(|error| {
                    CfError::new(format!("send HTTP/2 rejection failed: {error}"))
                })?;
                Ok(())
            }
        }
    }
}

/// Connected edge transport with a registered control plane.
///
/// Example: QUIC succeeds, otherwise the session stores HTTP/2 here.
pub(crate) enum ActiveTransport {
    /// Registered QUIC transport.
    Quic(quic::QuicTransport),
    /// Registered HTTP/2 transport.
    Http2(http2::Http2Transport),
}

impl ActiveTransport {
    /// Returns the public transport discriminator.
    ///
    /// Example: active QUIC connection -> `TransportKind::Quic`.
    pub(crate) fn kind(&self) -> TransportKind {
        match self {
            Self::Quic(_) => TransportKind::Quic,
            Self::Http2(_) => TransportKind::Http2,
        }
    }

    /// Returns the Cloudflare colo reported during registration.
    ///
    /// Example: edge registration response -> `"SJC"`.
    pub(crate) fn location(&self) -> &str {
        match self {
            Self::Quic(transport) => transport.location(),
            Self::Http2(transport) => transport.location(),
        }
    }

    /// Serves data requests until disconnect or explicit shutdown.
    ///
    /// Example: active connection -> incoming request channel.
    pub(crate) async fn run(
        self,
        requests: mpsc::Sender<IncomingRequest>,
        shutdown: CancellationToken,
    ) -> Result<(), CfError> {
        match self {
            Self::Quic(transport) => transport.run(requests, shutdown).await,
            Self::Http2(transport) => transport.run(requests, shutdown).await,
        }
    }
}
