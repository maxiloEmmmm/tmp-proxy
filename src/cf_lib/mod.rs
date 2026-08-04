//! Cloudflare Quick Tunnel client used by the application.

mod backoff;
mod control_plane;
mod edge_discovery;
mod model;
mod protocol;
mod quick_tunnel;
mod session;
mod tls;
mod transport;

pub use model::{
    CfError, CfResponse, CfStream, IncomingRequest, RequestKind, SessionEvent, TransportKind,
};
#[allow(unused_imports)]
pub use session::{QuickTunnel, Session};

/// Creates and starts one account-less Cloudflare Quick Tunnel.
///
/// Example: `create_quick_tunnel().await -> QuickTunnel`.
pub async fn create_quick_tunnel() -> Result<QuickTunnel, CfError> {
    session::create().await
}
