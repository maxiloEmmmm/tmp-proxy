use quinn::{ClientConfig, Connection, Endpoint, VarInt};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::cf_lib::control_plane::ControlPlane;
use crate::cf_lib::edge_discovery::EdgeAddress;
use crate::cf_lib::protocol::data;
use crate::cf_lib::quick_tunnel::Credentials;
use crate::cf_lib::tls;
use crate::cf_lib::{CfError, CfStream, IncomingRequest};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Registered QUIC connection and its control plane.
///
/// Example: UDP edge connection accepts one bidirectional stream per request.
pub(crate) struct QuicTransport {
    /// Endpoint retained for the lifetime of the QUIC connection.
    endpoint: Endpoint,
    /// Established edge connection.
    connection: Connection,
    /// Registration RPC stream used during graceful shutdown.
    control: ControlPlane,
    /// Cloudflare colo reported by registration.
    location: String,
}

impl QuicTransport {
    /// Connects, bootstraps, and registers against one discovered edge.
    ///
    /// Example: UDP address plus credentials -> registered QUIC transport.
    pub(crate) async fn connect(
        edge: EdgeAddress,
        credentials: &Credentials,
        previous_attempts: u8,
    ) -> Result<Self, CfError> {
        let bind = match edge.socket.ip() {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let mut endpoint = Endpoint::client(bind)
            .map_err(|error| CfError::new(format!("create QUIC endpoint failed: {error}")))?;
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls::quic_config()?.as_ref().clone())
                .map_err(|error| CfError::new(format!("configure QUIC TLS failed: {error}")))?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(crypto)));
        let connecting = endpoint
            .connect(edge.socket, tls::quic_server_name())
            .map_err(|error| CfError::new(format!("start QUIC connection failed: {error}")))?;
        let connection = time::timeout(CONNECT_TIMEOUT, connecting)
            .await
            .map_err(|_| CfError::new("QUIC edge connection timed out"))?
            .map_err(|error| CfError::new(format!("connect QUIC edge failed: {error}")))?;
        let (send, recv) = time::timeout(CONNECT_TIMEOUT, connection.open_bi())
            .await
            .map_err(|_| CfError::new("open QUIC control stream timed out"))?
            .map_err(|error| CfError::new(format!("open QUIC control stream failed: {error}")))?;
        let (control, details) = ControlPlane::register(
            CfStream::quic(send, recv),
            credentials,
            previous_attempts,
            true,
        )
        .await?;
        Ok(Self {
            endpoint,
            connection,
            control,
            location: details.location,
        })
    }

    /// Returns the registered Cloudflare colo.
    ///
    /// Example: successful registration -> `"LAX"`.
    pub(crate) fn location(&self) -> &str {
        &self.location
    }

    /// Accepts QUIC request streams until the connection closes.
    ///
    /// Example: one data stream -> one `IncomingRequest` sent upstream.
    pub(crate) async fn run(
        mut self,
        requests: mpsc::Sender<IncomingRequest>,
        shutdown: CancellationToken,
    ) -> Result<(), CfError> {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    let result = self.control.unregister().await;
                    self.connection.close(VarInt::from_u32(0), b"shutdown");
                    self.endpoint.wait_idle().await;
                    return result;
                }
                closed = self.connection.closed() => {
                    return Err(CfError::new(format!("QUIC edge connection closed: {closed}")));
                }
                stream = self.connection.accept_bi() => {
                    let (send, recv) = stream
                        .map_err(|error| CfError::new(format!("accept QUIC stream failed: {error}")))?;
                    let requests = requests.clone();
                    tokio::spawn(async move {
                        if let Err(error) = forward_request(send, recv, requests).await {
                            eprintln!("Cloudflare QUIC request failed: {error}");
                        }
                    });
                }
            }
        }
    }
}

/// Decodes one QUIC request stream and forwards its response handle.
///
/// Example: data preamble plus metadata -> application request channel.
async fn forward_request(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    requests: mpsc::Sender<IncomingRequest>,
) -> Result<(), CfError> {
    let request = data::read_request(&mut recv).await?;
    requests
        .send(IncomingRequest::new(
            request.kind,
            request.destination,
            request.metadata,
            super::PendingResponse::Quic { send, recv },
        ))
        .await
        .map_err(|_| CfError::new("Cloudflare request receiver closed"))
}
