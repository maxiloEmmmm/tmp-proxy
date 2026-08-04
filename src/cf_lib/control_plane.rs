use std::time::Duration;
use tokio::time;

use crate::cf_lib::protocol::rpc::{RegistrationDetails, RpcClient};
use crate::cf_lib::quick_tunnel::Credentials;
use crate::cf_lib::{CfError, CfStream};

const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(15);

/// Registered control plane retained for graceful shutdown.
///
/// Example: transport connects -> register -> keep RPC stream alive.
pub(crate) struct ControlPlane {
    /// Minimal RPC client bound to the transport control stream.
    rpc: RpcClient<CfStream>,
}

impl ControlPlane {
    /// Bootstraps and registers a control stream within the fixed timeout.
    ///
    /// Example: QUIC passes `write_signature=true`; HTTP/2 passes `false`.
    pub(crate) async fn register(
        stream: CfStream,
        credentials: &Credentials,
        previous_attempts: u8,
        write_signature: bool,
    ) -> Result<(Self, RegistrationDetails), CfError> {
        time::timeout(REGISTRATION_TIMEOUT, async {
            let mut rpc = RpcClient::connect(stream, write_signature).await?;
            let details = rpc.register(credentials, previous_attempts).await?;
            Ok((Self { rpc }, details))
        })
        .await
        .map_err(|_| CfError::new("Cloudflare registration timed out"))?
    }

    /// Requests graceful unregister without extending shutdown indefinitely.
    ///
    /// Example: `session.shutdown()` -> bounded unregister RPC.
    pub(crate) async fn unregister(&mut self) -> Result<(), CfError> {
        time::timeout(REGISTRATION_TIMEOUT, self.rpc.unregister())
            .await
            .map_err(|_| CfError::new("Cloudflare unregister timed out"))?
    }
}
