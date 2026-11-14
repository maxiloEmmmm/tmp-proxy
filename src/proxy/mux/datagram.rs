use bytes::Bytes;
use tokio::net::UdpSocket;

use super::core::Datagram;

/// Maximum legal UDP payload for IPv4; IPv6 accepts no larger application payload.
const MAX_UDP_PAYLOAD: usize = 65_507;

/// Bridges one connected UDP socket and one mux datagram association.
///
/// Example: target packet `reply` becomes one opaque mux DATAGRAM in the reverse direction.
pub(super) async fn bridge_udp(socket: UdpSocket, datagram: Datagram) -> Result<(), String> {
    let result = bridge_udp_inner(&socket, &datagram).await;
    let _ = datagram.close().await;
    result
}

/// Runs bidirectional packet forwarding while preserving every packet boundary.
///
/// Example: two socket receives produce exactly two association sends.
async fn bridge_udp_inner(socket: &UdpSocket, datagram: &Datagram) -> Result<(), String> {
    let mut buffer = vec![0_u8; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            received = socket.recv(&mut buffer) => {
                let received = received.map_err(|error| format!("receive target UDP failed: {error}"))?;
                if received == 0 {
                    continue;
                }
                let _ = datagram.send(Bytes::copy_from_slice(&buffer[..received])).await?;
            }
            packet = datagram.recv() => {
                let Some(packet) = packet else {
                    return Ok(());
                };
                socket.send(&packet).await
                    .map_err(|error| format!("send target UDP failed: {error}"))?;
            }
        }
    }
}
