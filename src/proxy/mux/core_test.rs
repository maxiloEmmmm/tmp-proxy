use std::time::Duration;

use bytes::Bytes;
use tokio::{sync::mpsc, time};

use super::{
    Config, Endpoint, Role, DEFAULT_CONNECTION_WINDOW, DEFAULT_MAX_FRAME, DEFAULT_MAX_STREAMS,
    DEFAULT_STREAM_WINDOW,
};

/// Verifies production defaults provide high-BDP throughput without weakening the global cap.
///
/// Example: 185ms RTT gets 4MiB per stream while all streams still share 16MiB.
#[test]
fn default_windows_cover_high_latency_links() {
    let config = Config::default();
    assert_eq!(config.stream_window, 4 * 1024 * 1024);
    assert_eq!(config.connection_window, 16 * 1024 * 1024);
    assert_eq!(config.stream_window, DEFAULT_STREAM_WINDOW);
    assert_eq!(config.connection_window, DEFAULT_CONNECTION_WINDOW);
    assert_eq!(config.max_frame, DEFAULT_MAX_FRAME);
    assert_eq!(config.max_streams, DEFAULT_MAX_STREAMS);
}

/// Creates two directly cross-connected mux peers without network or WebSocket code.
///
/// Example: client outbound frames become server inbound frames and vice versa.
fn peer_pair(config: Config) -> (Endpoint, Endpoint) {
    let (client_to_server_tx, client_to_server_rx) = mpsc::channel(64);
    let (server_to_client_tx, server_to_client_rx) = mpsc::channel(64);
    let client = Endpoint::start(
        Role::Client,
        config,
        client_to_server_tx,
        server_to_client_rx,
    )
    .expect("start client peer");
    let server = Endpoint::start(
        Role::Server,
        config,
        server_to_client_tx,
        client_to_server_rx,
    )
    .expect("start server peer");
    (client, server)
}

/// Opens one stream only after the server explicitly accepts its target port.
///
/// Example: OPEN for 10808 produces matching client and server stream id 1.
async fn open_stream_pair(client: &Endpoint, server: &Endpoint) -> (super::Stream, super::Stream) {
    let opening_client = client.clone();
    let open = tokio::spawn(async move { opening_client.open(10808).await });
    let incoming = server.accept().await.expect("accept OPEN");
    assert_eq!(incoming.target_port(), 10808);
    let server_stream = incoming.accept().await.expect("acknowledge OPEN");
    let client_stream = open.await.expect("join OPEN").expect("OPEN_OK");
    assert_eq!(client_stream.id(), server_stream.id());
    (client_stream, server_stream)
}

/// Verifies bidirectional stream routing and explicit consumption accounting.
///
/// Example: bytes sent by stream 1 arrive only at its paired stream 1.
#[tokio::test]
async fn stream_transfers_in_both_directions() {
    let (client, server) = peer_pair(Config::default());
    let (client_stream, server_stream) = open_stream_pair(&client, &server).await;

    let permit = client_stream.reserve_send().await.expect("client credit");
    permit
        .send(Bytes::from_static(b"request"))
        .await
        .expect("send request");
    let request = server_stream.recv_chunk().await.expect("receive request");
    assert_eq!(&request[..], b"request");
    server_stream
        .consumed(request.len())
        .await
        .expect("consume request");

    let permit = server_stream.reserve_send().await.expect("server credit");
    permit
        .send(Bytes::from_static(b"response"))
        .await
        .expect("send response");
    let response = client_stream.recv_chunk().await.expect("receive response");
    assert_eq!(&response[..], b"response");
    client_stream
        .consumed(response.len())
        .await
        .expect("consume response");
}

/// Verifies an exhausted stream window prevents more reads until consumption.
///
/// Example: stream 1 stalls at four bytes while stream 3 still uses remaining connection credit.
#[tokio::test]
async fn zero_window_blocks_only_its_stream() {
    let config = Config {
        stream_window: 4,
        connection_window: 8,
        max_frame: 4,
        max_streams: 4,
    };
    let (client, server) = peer_pair(config);
    let (client_one, server_one) = open_stream_pair(&client, &server).await;
    let (client_two, server_two) = open_stream_pair(&client, &server).await;

    client_one
        .reserve_send()
        .await
        .expect("stream one credit")
        .send(Bytes::from_static(b"1111"))
        .await
        .expect("fill stream one window");
    let waiting_stream = tokio::spawn(async move { client_one.reserve_send().await });
    time::sleep(Duration::from_millis(10)).await;
    assert!(!waiting_stream.is_finished());

    client_two
        .reserve_send()
        .await
        .expect("stream two credit")
        .send(Bytes::from_static(b"2222"))
        .await
        .expect("send on stream two");
    let two = server_two.recv_chunk().await.expect("receive stream two");
    assert_eq!(&two[..], b"2222");

    let one = server_one.recv_chunk().await.expect("receive stream one");
    server_one
        .consumed(one.len())
        .await
        .expect("restore stream one");
    let resumed = time::timeout(Duration::from_secs(1), waiting_stream)
        .await
        .expect("stream one resumed")
        .expect("join stream one")
        .expect("reserve restored credit");
    assert_eq!(resumed.amount(), 4);
}

/// Verifies shared connection credit waits for actual target consumption.
///
/// Example: stream 1 holds all connection bytes until its adjacent TCP consumes them.
#[tokio::test]
async fn connection_credit_waits_for_stream_consumption() {
    let config = Config {
        stream_window: 4,
        connection_window: 4,
        max_frame: 4,
        max_streams: 2,
    };
    let (client, server) = peer_pair(config);
    let (client_one, server_one) = open_stream_pair(&client, &server).await;
    let (client_two, server_two) = open_stream_pair(&client, &server).await;

    client_one
        .reserve_send()
        .await
        .expect("first stream credit")
        .send(Bytes::from_static(b"slow"))
        .await
        .expect("fill first stream window");
    let held = server_one
        .recv_chunk()
        .await
        .expect("hold slow stream DATA");
    assert_eq!(&held[..], b"slow");

    let waiting = tokio::spawn(async move { client_two.reserve_send().await });
    time::sleep(Duration::from_millis(30)).await;
    assert!(!waiting.is_finished());

    server_one
        .consumed(held.len())
        .await
        .expect("consume slow DATA");
    let permit = time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("connection credit returned after consumption")
        .expect("join second stream")
        .expect("second stream credit");
    permit
        .send(Bytes::from_static(b"fast"))
        .await
        .expect("send second stream DATA");
    assert_eq!(
        &server_two.recv_chunk().await.expect("receive fast DATA")[..],
        b"fast"
    );
}

/// Verifies stalled streams cumulatively stop at the aggregate memory window.
///
/// Example: two four-byte stalled streams fill an eight-byte connection window.
#[tokio::test]
async fn aggregate_window_bounds_many_stalled_streams() {
    let config = Config {
        stream_window: 4,
        connection_window: 8,
        max_frame: 4,
        max_streams: 4,
    };
    let (client, server) = peer_pair(config);
    let mut stalled = Vec::new();
    for marker in 1_u8..=2 {
        let (client_stream, server_stream) = open_stream_pair(&client, &server).await;
        let permit = time::timeout(Duration::from_secs(1), client_stream.reserve_send())
            .await
            .expect("connection still has credit")
            .expect("new stream credit");
        permit
            .send(Bytes::from(vec![marker; 4]))
            .await
            .expect("send stalled DATA");
        let held = server_stream
            .recv_chunk()
            .await
            .expect("hold unconsumed DATA");
        assert_eq!(&held[..], &[marker; 4]);
        stalled.push((client_stream, server_stream, held));
    }

    let (client_three, server_three) = open_stream_pair(&client, &server).await;
    let waiting = tokio::spawn(async move { client_three.reserve_send().await });
    time::sleep(Duration::from_millis(30)).await;
    assert!(!waiting.is_finished());

    stalled[0]
        .1
        .consumed(stalled[0].2.len())
        .await
        .expect("consume one stalled stream");
    let permit = time::timeout(Duration::from_secs(1), waiting)
        .await
        .expect("aggregate credit restored")
        .expect("join third stream")
        .expect("third stream credit");
    permit
        .send(Bytes::from_static(b"3333"))
        .await
        .expect("send after aggregate credit return");
    assert_eq!(
        &server_three.recv_chunk().await.expect("receive third DATA")[..],
        b"3333"
    );
}

/// Verifies RESET discards one stalled stream without disturbing the shared carrier.
///
/// Example: resetting a full-window stream allows its successor to send immediately.
#[tokio::test]
async fn reset_after_stalled_data_keeps_connection_alive() {
    let config = Config {
        stream_window: 4,
        connection_window: 4,
        max_frame: 4,
        max_streams: 2,
    };
    let (client, server) = peer_pair(config);
    let (client_one, server_one) = open_stream_pair(&client, &server).await;
    client_one
        .reserve_send()
        .await
        .expect("first stream credit")
        .send(Bytes::from_static(b"full"))
        .await
        .expect("fill connection window");
    let queued = server_one
        .recv_chunk()
        .await
        .expect("queued first stream data");
    assert_eq!(&queued[..], b"full");
    server_one.reset(9).await.expect("reset first stream");

    let (client_two, server_two) = open_stream_pair(&client, &server).await;
    let permit = time::timeout(Duration::from_secs(1), client_two.reserve_send())
        .await
        .expect("connection credit restored")
        .expect("second stream credit");
    permit
        .send(Bytes::from_static(b"next"))
        .await
        .expect("send successor data");
    assert_eq!(
        &server_two.recv_chunk().await.expect("receive successor")[..],
        b"next"
    );
}

/// Verifies completed streams release the concurrency slot for later OPEN requests.
///
/// Example: max_streams one still permits sequential stream identifiers 1 then 3.
#[tokio::test]
async fn completed_stream_releases_registration() {
    let config = Config {
        stream_window: 4,
        connection_window: 4,
        max_frame: 4,
        max_streams: 1,
    };
    let (client, server) = peer_pair(config);
    let (client_one, server_one) = open_stream_pair(&client, &server).await;
    client_one.complete().await.expect("complete client stream");
    server_one.complete().await.expect("complete server stream");

    let (client_two, server_two) = open_stream_pair(&client, &server).await;
    assert_eq!(client_two.id(), 3);
    assert_eq!(server_two.id(), 3);
}

/// Verifies crossed stream resets are idempotent and do not kill the shared carrier.
///
/// Example: both adjacent TCP sides fail together, then a later stream still opens.
#[tokio::test]
async fn crossed_resets_keep_connection_alive() {
    let config = Config {
        stream_window: 4,
        connection_window: 8,
        max_frame: 4,
        max_streams: 2,
    };
    let (client, server) = peer_pair(config);
    let (client_one, server_one) = open_stream_pair(&client, &server).await;
    let (client_reset, server_reset) = tokio::join!(client_one.reset(7), server_one.reset(8));
    client_reset.expect("client reset");
    server_reset.expect("server reset");

    let (client_two, server_two) = open_stream_pair(&client, &server).await;
    assert_eq!(client_two.id(), 3);
    assert_eq!(server_two.id(), 3);
}
