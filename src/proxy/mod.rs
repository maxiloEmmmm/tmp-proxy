mod legacy;
mod mux;
mod websocket;

use tokio::net::TcpStream;

use crate::{
    cf_lib::IncomingRequest,
    connection_activity::ConnectionActivity,
    endpoint,
    target_proxy::{self, Target},
};

/// User-selected proxy protocol hidden behind the common client facade.
///
/// Example: no CLI override selects `Mode::Mux`; `-legacy` selects `Legacy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Mode {
    /// One persistent WebSocket carrying many logical TCP streams.
    Mux,
    /// Compatibility mode using one WebSocket for every TCP stream.
    Legacy,
}

/// Concrete client implementation selected once during yy or zz startup.
enum ClientInner {
    /// Default multiplexed implementation.
    Mux(mux::Client),
    /// Existing 1:1 compatibility implementation.
    Legacy(legacy::Client),
}

/// Unified client facade preventing mode branches from leaking into callers.
///
/// Example: yy always calls `handle_tcp` regardless of selected protocol.
pub(crate) struct Client {
    /// Concrete enum-dispatched implementation with no trait object.
    inner: ClientInner,
}

/// Unified server facade accepting both request paths on the same daemon.
///
/// Example: `/mux` and `/tcp` are routed internally without daemon adaptation.
#[derive(Clone)]
pub(crate) struct Server {
    /// Multiplexed request handler.
    mux: mux::Server,
    /// Legacy request handler.
    legacy: legacy::Server,
}

impl Client {
    /// Constructs exactly one concrete client implementation for this process.
    ///
    /// Example: `Mode::Mux` creates a lazy shared-WSS session pool.
    pub(crate) fn new(mode: Mode, endpoint: endpoint::Source) -> Result<Self, String> {
        let connector = websocket::Connector::from_env()?;
        let inner = match mode {
            Mode::Mux => ClientInner::Mux(mux::Client::new(endpoint, connector)),
            Mode::Legacy => ClientInner::Legacy(legacy::Client::new(endpoint, connector)),
        };
        Ok(Self { inner })
    }

    /// Handles one adjacent business TCP without exposing the selected mode.
    ///
    /// Example: sing-box TCP is either opened as a stream or a legacy WSS.
    pub(crate) async fn handle_tcp(&self, tcp: TcpStream) -> Result<(), String> {
        match &self.inner {
            ClientInner::Mux(client) => client.handle_tcp(tcp).await,
            ClientInner::Legacy(client) => client.handle_tcp(tcp).await,
        }
    }
}

impl Server {
    /// Creates both server handlers so every daemon remains backward compatible.
    ///
    /// Example: one target policy is cloned into mux and legacy handlers.
    pub(crate) fn new(target: Target) -> Self {
        Self {
            mux: mux::Server::new(target.clone()),
            legacy: legacy::Server::new(target),
        }
    }

    /// Routes one request internally by path and preserves a single daemon API.
    ///
    /// Example: `/mux` reaches mux while `/tcp` reaches legacy handling.
    pub(crate) async fn handle_request(
        &self,
        request: IncomingRequest,
        expected_uuids: Vec<String>,
        activity: Option<ConnectionActivity>,
    ) -> Result<(), String> {
        match target_proxy::request_path(&request).as_deref() {
            Some("/mux") => {
                self.mux
                    .handle_request(request, expected_uuids, activity)
                    .await
            }
            Some("/tcp") => {
                self.legacy
                    .handle_request(request, expected_uuids, activity)
                    .await
            }
            _ => target_proxy::reject_request(request, 404).await,
        }
    }
}
