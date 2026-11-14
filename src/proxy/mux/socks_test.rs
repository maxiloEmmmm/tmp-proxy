use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time,
};

use super::{bridge_udp, is_socks5, read_reply, read_request, success_reply, MuxControl};
use crate::proxy::mux::core::{Config, Datagram, Endpoint, Role, Stream};

/// Creates one connected TCP pair without involving the operating proxy services.
///
/// Example: the accepted side enters yy while the connected side acts as sing-box.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP test listener");
    let address = listener.local_addr().expect("read TCP test address");
    let connecting = tokio::spawn(async move { TcpStream::connect(address).await });
    let (accepted, _) = listener.accept().await.expect("accept TCP test peer");
    let connected = connecting
        .await
        .expect("join TCP test connect")
        .expect("connect TCP test peer");
    (accepted, connected)
}

/// Creates directly cross-connected mux peers without WebSocket or daemon code.
///
/// Example: client frames enter the server core through one bounded channel.
fn peer_pair() -> (Endpoint, Endpoint) {
    let (client_tx, server_rx) = mpsc::channel(64);
    let (server_tx, client_rx) = mpsc::channel(64);
    let client = Endpoint::start(Role::Client, Config::default(), client_tx, client_rx)
        .expect("start client mux peer");
    let server = Endpoint::start(Role::Server, Config::default(), server_tx, server_rx)
        .expect("start server mux peer");
    (client, server)
}

/// Opens one acknowledged mux stream pair for SOCKS5 control traffic.
///
/// Example: the client and server receive matching stream identifiers.
async fn stream_pair(client: &Endpoint, server: &Endpoint) -> (Stream, Stream) {
    let opening = client.clone();
    let task = tokio::spawn(async move { opening.open(10808).await });
    let incoming = server.accept().await.expect("accept control stream");
    let remote = incoming.accept().await.expect("acknowledge control stream");
    let local = task
        .await
        .expect("join control open")
        .expect("open control stream");
    (local, remote)
}

/// Opens one acknowledged mux datagram pair for SOCKS5 UDP packets.
///
/// Example: the association targets the dynamic B-side relay port 53001.
async fn datagram_pair(client: &Endpoint, server: &Endpoint) -> (Datagram, Datagram) {
    let opening = client.clone();
    let task = tokio::spawn(async move { opening.open_datagram(53_001).await });
    let incoming = server.accept_datagram().await.expect("accept datagram");
    assert_eq!(incoming.target_port(), 53_001);
    let remote = incoming.accept().await.expect("acknowledge datagram");
    let local = task
        .await
        .expect("join datagram open")
        .expect("open datagram");
    (local, remote)
}

/// Verifies mixed-port detection does not consume the SOCKS5 version byte.
///
/// Example: peeking `0x05` leaves the same byte available to the handshake parser.
#[tokio::test]
async fn detection_preserves_first_byte() {
    let (yy, mut client) = tcp_pair().await;
    client.write_all(&[5]).await.expect("write SOCKS5 byte");
    assert!(is_socks5(&yy).await.expect("detect SOCKS5"));
    let mut observed = [0_u8; 1];
    yy.try_read(&mut observed).expect("read preserved byte");
    assert_eq!(observed, [5]);
}

/// Verifies a fragmented domain-form UDP ASSOCIATE is reassembled exactly.
///
/// Example: one byte per write still produces the original command packet.
#[tokio::test]
async fn fragmented_udp_associate_is_preserved() {
    let (mut yy, mut client) = tcp_pair().await;
    let request = [
        5, 3, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0, 53,
    ];
    let writer = tokio::spawn(async move {
        for byte in request {
            client.write_all(&[byte]).await.expect("write fragment");
            tokio::task::yield_now().await;
        }
    });
    let parsed = read_request(&mut yy).await.expect("parse request");
    writer.await.expect("join fragmented writer");
    assert_eq!(parsed.command, 3);
    assert_eq!(&parsed.raw[..], &request);
}

/// Verifies reply parsing extracts a dynamic port and retains immediate target data.
///
/// Example: SOCKS5 success plus `SSH-2.0` in one DATA frame preserves the banner.
#[tokio::test]
async fn reply_parser_retains_following_payload() {
    let (client, server) = peer_pair();
    let (local, remote) = stream_pair(&client, &server).await;
    let payload = Bytes::from_static(&[
        5, 0, 0, 1, 127, 0, 0, 1, 0xcf, 0x09, b'S', b'S', b'H', b'-', b'2', b'.', b'0',
    ]);
    remote
        .reserve_send()
        .await
        .expect("reserve reply")
        .send(payload)
        .await
        .expect("send reply and banner");

    let mut control = MuxControl::new(local);
    let reply = read_reply(&mut control).await.expect("parse reply");
    assert_eq!(reply.status, 0);
    assert_eq!(reply.port, 53_001);
    assert_eq!(&reply.raw[..], &[5, 0, 0, 1, 127, 0, 0, 1, 0xcf, 0x09]);
    let (_, prefix) = control.into_parts();
    assert_eq!(&prefix[..], b"SSH-2.0");
}

/// Verifies IPv4 and IPv6 local relay replies encode the actual ephemeral port.
///
/// Example: ports 40000 and 40001 remain the final two network-order bytes.
#[test]
fn local_relay_reply_supports_both_address_families() {
    let ipv4: SocketAddr = "127.0.0.1:40000".parse().expect("parse IPv4");
    let ipv6: SocketAddr = "[::1]:40001".parse().expect("parse IPv6");
    let reply4 = success_reply(ipv4);
    let reply6 = success_reply(ipv6);
    assert_eq!(&reply4[..4], &[5, 0, 0, 1]);
    assert_eq!(&reply4[reply4.len() - 2..], &40000_u16.to_be_bytes());
    assert_eq!(&reply6[..4], &[5, 0, 0, 4]);
    assert_eq!(&reply6[reply6.len() - 2..], &40001_u16.to_be_bytes());
}

/// Verifies opaque SOCKS5 UDP packets cross the mux and control EOF tears it down.
///
/// Example: request and reply retain packet boundaries before TCP closure ends the task.
#[tokio::test]
async fn udp_bridge_round_trips_and_follows_control_lifetime() {
    let (client_endpoint, server_endpoint) = peer_pair();
    let (local_control, remote_control) = stream_pair(&client_endpoint, &server_endpoint).await;
    let (local_datagram, remote_datagram) = datagram_pair(&client_endpoint, &server_endpoint).await;
    let (yy_control, mut socks_control) = tcp_pair().await;
    let relay = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind local UDP relay");
    let relay_address = relay.local_addr().expect("read UDP relay address");
    let udp_client = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind SOCKS5 UDP client");
    let bridge = tokio::spawn(bridge_udp(
        yy_control,
        relay,
        local_datagram,
        MuxControl::new(local_control),
    ));

    let request = b"\0\0\0\x01\x08\x08\x08\x08\0\x35query";
    udp_client
        .send_to(request, relay_address)
        .await
        .expect("send local UDP request");
    let tunneled = time::timeout(Duration::from_secs(1), remote_datagram.recv())
        .await
        .expect("UDP request timeout")
        .expect("receive UDP request");
    assert_eq!(&tunneled[..], request);

    let response = Bytes::from_static(b"\0\0\0\x01\x08\x08\x08\x08\0\x35reply");
    assert!(remote_datagram
        .send(response.clone())
        .await
        .expect("send UDP response"));
    let mut buffer = [0_u8; 64];
    let received = time::timeout(Duration::from_secs(1), udp_client.recv(&mut buffer))
        .await
        .expect("UDP response timeout")
        .expect("receive UDP response");
    assert_eq!(&buffer[..received], &response[..]);

    socks_control
        .shutdown()
        .await
        .expect("close client control");
    time::timeout(Duration::from_secs(1), bridge)
        .await
        .expect("bridge close timeout")
        .expect("join UDP bridge")
        .expect("close UDP bridge");
    assert!(
        time::timeout(Duration::from_secs(1), remote_datagram.recv())
            .await
            .expect("datagram close timeout")
            .is_none()
    );
    assert!(
        time::timeout(Duration::from_secs(1), remote_control.recv_chunk())
            .await
            .expect("control close timeout")
            .is_none()
    );
}
