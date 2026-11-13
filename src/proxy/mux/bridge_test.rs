use std::time::Duration;

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time,
};

use super::bridge_tcp;
use crate::proxy::mux::core::{Config, Endpoint, Role};

/// Creates a connected loopback TCP pair for adjacent-side flow-control tests.
///
/// Example: the first socket enters mux while the second acts as sing-box.
async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback listener");
    let address = listener.local_addr().expect("read loopback address");
    let connect = tokio::spawn(async move { TcpStream::connect(address).await });
    let (accepted, _) = listener.accept().await.expect("accept loopback tcp");
    let connected = connect
        .await
        .expect("join connect")
        .expect("connect loopback");
    (accepted, connected)
}

/// Creates client and server mux cores directly cross-connected by frame channels.
///
/// Example: no WebSocket or Cloudflare module participates in this unit test.
fn peer_pair(config: Config) -> (Endpoint, Endpoint) {
    let (client_to_server_tx, client_to_server_rx) = mpsc::channel(64);
    let (server_to_client_tx, server_to_client_rx) = mpsc::channel(64);
    let client = Endpoint::start(
        Role::Client,
        config,
        client_to_server_tx,
        server_to_client_rx,
    )
    .expect("start client endpoint");
    let server = Endpoint::start(
        Role::Server,
        config,
        server_to_client_tx,
        client_to_server_rx,
    )
    .expect("start server endpoint");
    (client, server)
}

/// Verifies zero remote window stops adjacent TCP progression until consumption.
///
/// Example: eight TCP bytes arrive as two four-byte chunks separated by WINDOW_UPDATE.
#[tokio::test]
async fn zero_window_stops_adjacent_tcp_until_update() {
    let config = Config {
        stream_window: 4,
        connection_window: 8,
        max_frame: 4,
        max_streams: 2,
    };
    let (client, server) = peer_pair(config);
    let opening_client = client.clone();
    let open = tokio::spawn(async move { opening_client.open(10808).await });
    let incoming = server.accept().await.expect("accept mux stream");
    let server_stream = incoming.accept().await.expect("acknowledge stream");
    let client_stream = open.await.expect("join open").expect("open stream");
    let (mux_tcp, mut business_tcp) = tcp_pair().await;
    let bridge = tokio::spawn(bridge_tcp(mux_tcp, client_stream));

    business_tcp
        .write_all(b"12345678")
        .await
        .expect("write adjacent tcp");
    let first = server_stream
        .recv_chunk()
        .await
        .expect("first window chunk");
    assert_eq!(&first[..], b"1234");
    assert!(
        time::timeout(Duration::from_millis(30), server_stream.recv_chunk())
            .await
            .is_err()
    );

    server_stream
        .consumed(first.len())
        .await
        .expect("return first window");
    let second = time::timeout(Duration::from_secs(1), server_stream.recv_chunk())
        .await
        .expect("second chunk resumed")
        .expect("second window chunk");
    assert_eq!(&second[..], b"5678");
    server_stream
        .consumed(second.len())
        .await
        .expect("return second window");

    business_tcp
        .shutdown()
        .await
        .expect("half-close business tcp");
    server_stream
        .finish_send()
        .await
        .expect("finish remote direction");
    time::timeout(Duration::from_secs(1), bridge)
        .await
        .expect("bridge completed")
        .expect("join bridge")
        .expect("bridge result");
}
