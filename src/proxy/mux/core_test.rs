use std::time::Duration;

use bytes::Bytes;
use tokio::{sync::mpsc, time};

use crate::proxy::mux::protocol::DestinationAddress;

use super::{
    Config, Destination, Endpoint, Frame, Role, DEFAULT_CONNECTION_WINDOW, DEFAULT_MAX_FRAME,
    DEFAULT_MAX_STREAMS, DEFAULT_STREAM_WINDOW, VERSION,
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

/// Verifies a destination-bearing OPEN reaches the server without legacy port ambiguity.
///
/// Example: direct `192.0.2.154:22` reports target_port zero and its full direct target.
#[tokio::test]
async fn direct_tcp_destination_reaches_server_accept() {
    let (carrier_out_tx, mut carrier_out_rx) = mpsc::channel(16);
    let (carrier_in_tx, carrier_in_rx) = mpsc::channel(16);
    let server = Endpoint::start(
        Role::Server,
        Config::default(),
        carrier_out_tx,
        carrier_in_rx,
    )
    .expect("start direct server");
    assert!(matches!(
        carrier_out_rx.recv().await,
        Some(Frame::Hello { .. })
    ));
    carrier_in_tx
        .send(test_hello())
        .await
        .expect("send remote hello");
    carrier_in_tx
        .send(Frame::OpenDestination {
            stream_id: 1,
            destination: Destination {
                address: DestinationAddress::Ipv4("192.0.2.154".parse().expect("IPv4")),
                port: 22,
            },
        })
        .await
        .expect("send direct OPEN");
    let incoming = time::timeout(Duration::from_secs(1), server.accept())
        .await
        .expect("direct OPEN arrived")
        .expect("accept direct OPEN");
    assert_eq!(incoming.target_port(), 0);
    assert_eq!(
        incoming.direct_target().as_deref(),
        Some("192.0.2.154:22")
    );
}

/// Verifies direct UDP metadata preserves IPv6 bracket formatting for Tokio.
///
/// Example: `2001:db8::1:53` reaches the daemon as `[2001:db8::1]:53`.
#[tokio::test]
async fn direct_udp_destination_reaches_server_accept() {
    let (carrier_out_tx, mut carrier_out_rx) = mpsc::channel(16);
    let (carrier_in_tx, carrier_in_rx) = mpsc::channel(16);
    let server = Endpoint::start(
        Role::Server,
        Config::default(),
        carrier_out_tx,
        carrier_in_rx,
    )
    .expect("start direct UDP server");
    assert!(matches!(
        carrier_out_rx.recv().await,
        Some(Frame::Hello { .. })
    ));
    carrier_in_tx
        .send(test_hello())
        .await
        .expect("send remote hello");
    carrier_in_tx
        .send(Frame::DatagramOpenDestination {
            association_id: 1,
            destination: Destination {
                address: DestinationAddress::Ipv6("2001:db8::1".parse().expect("IPv6")),
                port: 53,
            },
        })
        .await
        .expect("send direct DATAGRAM_OPEN");
    let incoming = time::timeout(Duration::from_secs(1), server.accept_datagram())
        .await
        .expect("direct DATAGRAM_OPEN arrived")
        .expect("accept direct DATAGRAM_OPEN");
    assert_eq!(incoming.target_port(), 0);
    assert_eq!(
        incoming.direct_target().as_deref(),
        Some("[2001:db8::1]:53")
    );
}

/// Builds one valid remote HELLO for raw-frame core tests.
///
/// Example: a server receives these limits before accepting an OPEN.
fn test_hello() -> Frame {
    Frame::Hello {
        version: VERSION,
        stream_window: DEFAULT_STREAM_WINDOW,
        connection_window: DEFAULT_CONNECTION_WINDOW,
        max_frame: DEFAULT_MAX_FRAME,
        max_streams: DEFAULT_MAX_STREAMS,
    }
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

/// Opens one datagram association only after the server acknowledges it.
///
/// Example: association id 1 becomes usable by both peers after OPEN_OK.
async fn open_datagram_pair(
    client: &Endpoint,
    server: &Endpoint,
) -> (super::Datagram, super::Datagram) {
    let opening_client = client.clone();
    let open = tokio::spawn(async move { opening_client.open_datagram(10808).await });
    let incoming = server
        .accept_datagram()
        .await
        .expect("accept datagram OPEN");
    assert_eq!(incoming.target_port(), 10808);
    let server_datagram = incoming.accept().await.expect("acknowledge datagram OPEN");
    let client_datagram = open
        .await
        .expect("join datagram OPEN")
        .expect("datagram OPEN_OK");
    assert_eq!(client_datagram.id(), server_datagram.id());
    (client_datagram, server_datagram)
}

/// Verifies UDP datagrams retain boundaries and association isolation.
///
/// Example: two associations may reuse one carrier without receiving each other's packets.
#[tokio::test]
async fn datagrams_transfer_bidirectionally_without_cross_talk() {
    let (client, server) = peer_pair(Config::default());
    let (client_one, server_one) = open_datagram_pair(&client, &server).await;
    let (client_two, server_two) = open_datagram_pair(&client, &server).await;

    assert!(client_one
        .send(Bytes::from_static(b"one"))
        .await
        .expect("send first datagram"));
    assert!(client_two
        .send(Bytes::from_static(b"two"))
        .await
        .expect("send second datagram"));
    let one = server_one.recv().await.expect("receive first datagram");
    let two = server_two.recv().await.expect("receive second datagram");
    assert_eq!(&one[..], b"one");
    assert_eq!(&two[..], b"two");

    assert!(server_one
        .send(Bytes::from_static(b"reply"))
        .await
        .expect("send datagram reply"));
    let reply = client_one.recv().await.expect("receive datagram reply");
    assert_eq!(&reply[..], b"reply");
}

/// Verifies closing one association leaves sibling associations and TCP streams usable.
///
/// Example: association 1 closes while association 3 still transfers one packet.
#[tokio::test]
async fn datagram_close_isolated_from_sibling_traffic() {
    let (client, server) = peer_pair(Config::default());
    let (client_one, server_one) = open_datagram_pair(&client, &server).await;
    let (client_two, server_two) = open_datagram_pair(&client, &server).await;

    client_one.close().await.expect("close first association");
    assert!(time::timeout(Duration::from_secs(1), server_one.recv())
        .await
        .expect("remote close propagated")
        .is_none());
    assert!(client_two
        .send(Bytes::from_static(b"alive"))
        .await
        .expect("send on sibling association"));
    assert_eq!(
        &server_two.recv().await.expect("receive sibling packet")[..],
        b"alive"
    );

    let (client_stream, server_stream) = open_stream_pair(&client, &server).await;
    client_stream
        .reserve_send()
        .await
        .expect("reserve TCP after UDP close")
        .send(Bytes::from_static(b"tcp"))
        .await
        .expect("send TCP after UDP close");
    assert_eq!(
        &server_stream.recv_chunk().await.expect("receive TCP")[..],
        b"tcp"
    );
}

/// Verifies one rejected association does not terminate the shared carrier.
///
/// Example: target failure for id 1 is followed by a successful id 3 association.
#[tokio::test]
async fn datagram_open_rejection_keeps_carrier_alive() {
    let (client, server) = peer_pair(Config::default());
    let opening_client = client.clone();
    let rejected = tokio::spawn(async move { opening_client.open_datagram(10808).await });
    server
        .accept_datagram()
        .await
        .expect("accept rejected association")
        .reject(2)
        .await
        .expect("reject association");
    assert!(rejected.await.expect("join rejected open").is_err());

    let (client_datagram, server_datagram) = open_datagram_pair(&client, &server).await;
    assert!(client_datagram
        .send(Bytes::from_static(b"next"))
        .await
        .expect("send after rejection"));
    assert_eq!(
        &server_datagram
            .recv()
            .await
            .expect("receive after rejection")[..],
        b"next"
    );
}

/// Verifies oversized UDP input is rejected locally without poisoning the carrier.
///
/// Example: 65,508 bytes fail while a following small packet still transfers.
#[tokio::test]
async fn oversized_datagram_does_not_close_carrier() {
    let (client, server) = peer_pair(Config::default());
    let (client_datagram, server_datagram) = open_datagram_pair(&client, &server).await;
    assert!(client_datagram
        .send(Bytes::from(vec![0_u8; DEFAULT_MAX_FRAME as usize + 1]))
        .await
        .is_err());
    assert!(client_datagram
        .send(Bytes::from_static(b"small"))
        .await
        .expect("send valid packet"));
    assert_eq!(
        &server_datagram.recv().await.expect("receive valid packet")[..],
        b"small"
    );
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

/// Verifies OPEN returns before target acknowledgement and permits client-first DATA.
///
/// Example: stream 1 sends `hello` while its server state is still opening.
#[tokio::test]
async fn open_returns_and_sends_data_before_open_ok() {
    let (client, server) = peer_pair(Config::default());
    let client_stream = time::timeout(Duration::from_secs(1), client.open(10808))
        .await
        .expect("OPEN must not wait for OPEN_OK")
        .expect("OPEN carrier handoff");
    let incoming = server.accept().await.expect("accept pending OPEN");
    assert_eq!(
        incoming
            .stream
            .as_ref()
            .expect("pending server stream")
            .state
            .open_state
            .load(std::sync::atomic::Ordering::Acquire),
        super::STREAM_OPENING
    );

    client_stream
        .reserve_send()
        .await
        .expect("reserve early DATA")
        .send(Bytes::from_static(b"hello"))
        .await
        .expect("send early DATA");
    let queued = incoming
        .stream
        .as_ref()
        .expect("pending server stream")
        .recv_chunk()
        .await
        .expect("receive early DATA");
    assert_eq!(&queued[..], b"hello");

    let server_stream = incoming.accept().await.expect("acknowledge OPEN");
    assert_eq!(client_stream.id(), server_stream.id());
}

/// Verifies pre-ack DATA remains bounded by stream and connection windows.
///
/// Example: four bytes stop the next four until the daemon consumes the first chunk.
#[tokio::test]
async fn early_data_obeys_window_before_open_ok() {
    let config = Config {
        stream_window: 4,
        connection_window: 4,
        max_frame: 4,
        max_streams: 1,
    };
    let (client, server) = peer_pair(config);
    let client_stream = client.open(10808).await.expect("open early stream");
    let incoming = server.accept().await.expect("accept pending OPEN");
    let sending = tokio::spawn(async move {
        client_stream
            .reserve_send()
            .await
            .expect("reserve first early chunk")
            .send(Bytes::from_static(b"1234"))
            .await
            .expect("send first early chunk");
        client_stream
            .reserve_send()
            .await
            .expect("reserve second early chunk")
            .send(Bytes::from_static(b"5678"))
            .await
            .expect("send second early chunk");
        client_stream
    });

    let remote = incoming.stream.as_ref().expect("pending server stream");
    let first = remote
        .recv_chunk()
        .await
        .expect("receive first early chunk");
    assert_eq!(&first[..], b"1234");
    time::sleep(Duration::from_millis(20)).await;
    assert!(!sending.is_finished());
    remote
        .consumed(first.len())
        .await
        .expect("return early DATA credit");
    let second = remote
        .recv_chunk()
        .await
        .expect("receive second early chunk");
    assert_eq!(&second[..], b"5678");

    let client_stream = sending.await.expect("join early DATA sender");
    let server_stream = incoming.accept().await.expect("acknowledge OPEN");
    assert_eq!(client_stream.id(), server_stream.id());
}

/// Verifies rejection drains in-flight DATA through RESET and restores all capacity.
///
/// Example: rejected full-window id 1 is followed by healthy id 3 on the same carrier.
#[tokio::test]
async fn rejected_early_data_restores_window_and_stream_slot() {
    let config = Config {
        stream_window: 4,
        connection_window: 4,
        max_frame: 4,
        max_streams: 1,
    };
    let (client, server) = peer_pair(config);
    let rejected = client.open(10808).await.expect("open rejected stream");
    let incoming = server.accept().await.expect("accept rejected OPEN");
    rejected
        .reserve_send()
        .await
        .expect("reserve rejected DATA")
        .send(Bytes::from_static(b"drop"))
        .await
        .expect("send rejected DATA");
    incoming.reject(2).await.expect("reject pending OPEN");
    time::timeout(Duration::from_secs(1), rejected.closed())
        .await
        .expect("OPEN_ERROR closed client stream");

    let (client_stream, server_stream) =
        time::timeout(Duration::from_secs(1), open_stream_pair(&client, &server))
            .await
            .expect("RESET restored stream slot");
    client_stream
        .reserve_send()
        .await
        .expect("rejection restored connection credit")
        .send(Bytes::from_static(b"next"))
        .await
        .expect("send successor DATA");
    assert_eq!(
        &server_stream.recv_chunk().await.expect("receive successor")[..],
        b"next"
    );
    assert_eq!(client_stream.id(), 3);
}

/// Verifies concurrent pre-ack streams retain independent queues and identifiers.
///
/// Example: streams 1 and 3 carry `one` and `two` without cross-talk before either OPEN_OK.
#[tokio::test]
async fn concurrent_early_streams_are_isolated() {
    let (client, server) = peer_pair(Config::default());
    let client_one = client.open(10808).await.expect("open first stream");
    let client_two = client.open(10808).await.expect("open second stream");
    let incoming_one = server.accept().await.expect("accept first OPEN");
    let incoming_two = server.accept().await.expect("accept second OPEN");

    client_one
        .reserve_send()
        .await
        .expect("reserve first DATA")
        .send(Bytes::from_static(b"one"))
        .await
        .expect("send first DATA");
    client_two
        .reserve_send()
        .await
        .expect("reserve second DATA")
        .send(Bytes::from_static(b"two"))
        .await
        .expect("send second DATA");
    assert_eq!(
        &incoming_one
            .stream
            .as_ref()
            .expect("first pending stream")
            .recv_chunk()
            .await
            .expect("receive first DATA")[..],
        b"one"
    );
    assert_eq!(
        &incoming_two
            .stream
            .as_ref()
            .expect("second pending stream")
            .recv_chunk()
            .await
            .expect("receive second DATA")[..],
        b"two"
    );
    assert_eq!(incoming_one.accept().await.expect("accept first").id(), 1);
    assert_eq!(incoming_two.accept().await.expect("accept second").id(), 3);
}

/// Verifies a crossed late OPEN_OK after local RESET is harmless to the carrier.
///
/// Example: removed stream 1 ignores its delayed acknowledgement, then stream 3 opens normally.
#[tokio::test]
async fn late_open_ok_after_reset_keeps_carrier_alive() {
    let (client, server) = peer_pair(Config::default());
    let client_one = client.open(10808).await.expect("open first stream");
    let incoming_one = server.accept().await.expect("accept first OPEN");
    let stream_id = client_one.id();
    client_one.reset(7).await.expect("reset opening stream");

    super::handle_frame(
        &client.inner,
        crate::proxy::mux::protocol::Frame::OpenOk { stream_id },
    )
    .await
    .expect("ignore crossed OPEN_OK");
    time::timeout(
        Duration::from_secs(1),
        incoming_one
            .stream
            .as_ref()
            .expect("pending first stream")
            .closed(),
    )
    .await
    .expect("server received opening RESET");
    assert!(incoming_one.accept().await.is_err());

    let (client_two, server_two) = open_stream_pair(&client, &server).await;
    assert_eq!(client_two.id(), 3);
    assert_eq!(server_two.id(), 3);
}
