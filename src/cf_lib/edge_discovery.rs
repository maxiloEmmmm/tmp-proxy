use hickory_resolver::Resolver;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time;

use crate::cf_lib::CfError;

const EDGE_SRV_NAME: &str = "_origintunneld._tcp.argotunnel.com.";
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

/// One Cloudflare edge address discovered through the official SRV record.
///
/// Example: SRV target plus A record -> `198.41.x.x:7844`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EdgeAddress {
    /// Resolved edge socket address.
    pub(crate) socket: SocketAddr,
    /// SRV priority used to order connection attempts.
    priority: u16,
    /// SRV weight used as a stable preference within one priority.
    weight: u16,
}

/// Resolves all currently advertised Cloudflare tunnel edge addresses.
///
/// Example: official SRV record -> ordered region address pool.
pub(crate) async fn resolve() -> Result<Vec<EdgeAddress>, CfError> {
    let resolver = Resolver::builder_tokio()
        .map_err(|error| CfError::new(format!("load system DNS configuration failed: {error}")))?
        .build();
    let srv = time::timeout(DNS_TIMEOUT, resolver.srv_lookup(EDGE_SRV_NAME))
        .await
        .map_err(|_| CfError::new("Cloudflare Edge SRV lookup timed out"))?
        .map_err(|error| CfError::new(format!("Cloudflare Edge SRV lookup failed: {error}")))?;

    let mut addresses = Vec::new();
    for record in srv.iter() {
        let target = record.target().to_utf8();
        let ips = time::timeout(DNS_TIMEOUT, resolver.lookup_ip(target.clone()))
            .await
            .map_err(|_| CfError::new(format!("Cloudflare Edge lookup timed out: {target}")))?
            .map_err(|error| {
                CfError::new(format!("resolve Cloudflare Edge {target} failed: {error}"))
            })?;
        for ip in ips.iter() {
            addresses.push(EdgeAddress {
                socket: SocketAddr::new(ip, record.port()),
                priority: record.priority(),
                weight: record.weight(),
            });
        }
    }
    addresses.sort_by_key(|address| (address.priority, std::cmp::Reverse(address.weight)));
    addresses.dedup_by_key(|address| address.socket);
    if addresses.is_empty() {
        return Err(CfError::new(
            "Cloudflare Edge discovery returned no addresses",
        ));
    }
    Ok(addresses)
}
