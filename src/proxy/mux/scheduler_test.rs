use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::{sync::oneshot, sync::Semaphore, time};

use super::{DataCommand, DataEvent, FairQueue, Outbound, CONTROL_BURST_LIMIT};
use crate::proxy::mux::protocol::Frame;
use crate::proxy::mux::window::SendWindow;

/// Creates one scheduler command with an independently observable delivery result.
///
/// Example: stream 3 plus four bytes produces one four-byte DATA command.
async fn command(
    stream_id: u32,
    bytes: usize,
) -> (DataCommand, oneshot::Receiver<Result<(), String>>) {
    let slot = Arc::new(Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("acquire test DATA slot");
    let stream_window = SendWindow::new(bytes as u32);
    let connection_window = SendWindow::new(bytes as u32);
    let stream_credit = stream_window
        .reserve(bytes as u32)
        .await
        .expect("reserve test stream credit")
        .commit_guarded(bytes as u32)
        .expect("commit test stream credit");
    let connection_credit = connection_window
        .reserve(bytes as u32)
        .await
        .expect("reserve test connection credit")
        .commit_guarded(bytes as u32)
        .expect("commit test connection credit");
    let (delivered, result) = oneshot::channel();
    (
        DataCommand {
            stream_id,
            frame: Frame::Data {
                stream_id,
                payload: Bytes::from(vec![stream_id as u8; bytes]),
            },
            bytes,
            stream_credit,
            connection_credit,
            _slot: slot,
            delivered,
        },
        result,
    )
}

/// Sends one production-shaped DATA command with guarded stream and connection credit.
///
/// Example: four bytes reserve and commit four bytes in both windows before handoff.
async fn send_data(outbound: Outbound, payload: Bytes) -> Result<(), String> {
    let bytes = u32::try_from(payload.len()).expect("test DATA length fits u32");
    let stream_window = SendWindow::new(bytes);
    let connection_window = SendWindow::new(bytes);
    let stream_credit = stream_window
        .reserve(bytes)
        .await
        .expect("reserve stream credit")
        .commit_guarded(bytes)
        .expect("commit stream credit");
    let connection_credit = connection_window
        .reserve(bytes)
        .await
        .expect("reserve connection credit")
        .commit_guarded(bytes)
        .expect("commit connection credit");
    let slot = Arc::new(Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("acquire DATA slot");
    outbound
        .send_data(1, payload, stream_credit, connection_credit, slot)
        .await
}

/// Adds one command to a fair queue while discarding its unused delivery observer.
///
/// Example: enqueue stream 1 with 32KiB makes it eligible for the next selection.
async fn enqueue(queue: &mut FairQueue, stream_id: u32, bytes: usize) {
    let (command, _result) = command(stream_id, bytes).await;
    queue.apply(DataEvent::Enqueue(command));
}

/// Returns the stream id selected by the pure fair scheduler.
///
/// Example: equal virtual finishes select the lower stream id deterministically.
fn pop_id(queue: &mut FairQueue) -> u32 {
    queue
        .pop_next()
        .expect("expected pending DATA command")
        .stream_id
}

/// Verifies continuously active tiny frames receive byte rather than frame fairness.
///
/// Example: 1KiB stream runs 32 times while a 32KiB stream waits at equal service.
#[tokio::test]
async fn continuous_tiny_flow_catches_bulk_by_bytes() {
    let mut queue = FairQueue::new();
    enqueue(&mut queue, 1, 32 * 1024).await;
    enqueue(&mut queue, 3, 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    enqueue(&mut queue, 1, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 3);
    for _ in 0..31 {
        enqueue(&mut queue, 3, 1024).await;
        assert_eq!(pop_id(&mut queue), 3);
    }
    enqueue(&mut queue, 3, 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
}

/// Verifies equal bulk streams alternate with a bounded one-frame service skew.
///
/// Example: streams 1 and 3 produce selection order 1,3,1,3.
#[tokio::test]
async fn equal_bulk_flows_alternate() {
    let mut queue = FairQueue::new();
    enqueue(&mut queue, 1, 32 * 1024).await;
    enqueue(&mut queue, 3, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    enqueue(&mut queue, 1, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 3);
    enqueue(&mut queue, 3, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    enqueue(&mut queue, 1, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 3);
}

/// Verifies an idle stream rejoins at global virtual time without historical debt.
///
/// Example: stream 1 pauses while stream 3 advances, then neither monopolizes rejoin.
#[tokio::test]
async fn idle_rejoin_aligns_to_global_time() {
    let mut queue = FairQueue::new();
    enqueue(&mut queue, 1, 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    queue.apply(DataEvent::Idle { stream_id: 1 });

    enqueue(&mut queue, 3, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 3);
    enqueue(&mut queue, 3, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 3);

    enqueue(&mut queue, 1, 1024).await;
    enqueue(&mut queue, 3, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    assert!(
        queue
            .flows
            .get(&1)
            .expect("stream one state")
            .virtual_finish
            >= 65 * 1024
    );
}

/// Verifies a newly opened stream starts at current service time rather than zero.
///
/// Example: a late stream cannot send an old 64KiB deficit burst.
#[tokio::test]
async fn new_flow_starts_at_global_time() {
    let mut queue = FairQueue::new();
    enqueue(&mut queue, 1, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    enqueue(&mut queue, 1, 32 * 1024).await;
    assert_eq!(pop_id(&mut queue), 1);
    enqueue(&mut queue, 3, 1024).await;
    assert_eq!(
        queue
            .flows
            .get(&3)
            .expect("new stream state")
            .virtual_finish,
        64 * 1024
    );
}

/// Verifies removing a stream fails its queued DATA instead of leaking a waiter.
///
/// Example: RESET before carrier handoff returns an error to the DATA producer.
#[tokio::test]
async fn removal_cancels_pending_data() {
    let mut queue = FairQueue::new();
    let (command, delivered) = command(1, 4).await;
    queue.apply(DataEvent::Enqueue(command));
    let (removed, removed_result) = oneshot::channel();
    queue.apply(DataEvent::Remove {
        stream_id: 1,
        removed,
    });
    removed_result.await.expect("remove acknowledgement");
    assert!(delivered.await.expect("delivery result").is_err());
    assert!(queue.pop_next().is_none());
}

/// Verifies DATA completion waits for carrier capacity and therefore orders later FIN.
///
/// Example: a full carrier holds DATA producer until HELLO is drained.
#[tokio::test]
async fn data_waits_for_carrier_handoff_before_fin() {
    let (carrier, mut received) = tokio::sync::mpsc::channel(1);
    let outbound = Outbound::start(carrier, Frame::Fin { stream_id: 0 });
    time::sleep(Duration::from_millis(10)).await;

    let sender = outbound.clone();
    let data = tokio::spawn(send_data(sender, Bytes::from_static(b"tail")));
    time::sleep(Duration::from_millis(10)).await;
    assert!(!data.is_finished());
    assert!(matches!(
        received.recv().await,
        Some(Frame::Fin { stream_id: 0 })
    ));
    data.await.expect("join DATA sender").expect("handoff DATA");
    outbound
        .send_control(Frame::Fin { stream_id: 1 })
        .await
        .expect("queue FIN");
    assert!(matches!(
        received.recv().await,
        Some(Frame::Data { stream_id: 1, .. })
    ));
    assert!(matches!(
        received.recv().await,
        Some(Frame::Fin { stream_id: 1 })
    ));
}

/// Verifies an endless control producer cannot permanently starve pending DATA.
///
/// Example: DATA appears no later than one configured control burst.
#[tokio::test]
async fn bounded_control_priority_allows_data_progress() {
    let (carrier, mut received) = tokio::sync::mpsc::channel(1);
    let outbound = Outbound::start(carrier, Frame::Fin { stream_id: 0 });
    for stream_id in 10..10 + (CONTROL_BURST_LIMIT as u32 * 2) {
        outbound
            .send_control(Frame::Fin { stream_id })
            .await
            .expect("queue control frame");
    }
    let sender = outbound.clone();
    let data = tokio::spawn(send_data(sender, Bytes::from_static(b"data")));

    assert!(matches!(
        received.recv().await,
        Some(Frame::Fin { stream_id: 0 })
    ));
    let mut controls = 0usize;
    loop {
        match received.recv().await.expect("scheduled frame") {
            Frame::Data { stream_id: 1, .. } => break,
            Frame::Fin { .. } => controls += 1,
            frame => panic!("unexpected frame: {frame:?}"),
        }
    }
    assert!(controls <= CONTROL_BURST_LIMIT);
    data.await
        .expect("join DATA sender")
        .expect("DATA progressed");
}

/// Verifies carrier shutdown wakes a DATA producer with an explicit error.
///
/// Example: dropping the sole carrier receiver fails the next pending handoff.
#[tokio::test]
async fn carrier_close_fails_pending_data() {
    let (carrier, received) = tokio::sync::mpsc::channel(1);
    let outbound = Outbound::start(carrier, Frame::Fin { stream_id: 0 });
    time::sleep(Duration::from_millis(10)).await;
    let sender = outbound.clone();
    let data = tokio::spawn(send_data(sender, Bytes::from_static(b"data")));
    drop(received);
    assert!(data.await.expect("join DATA sender").is_err());
}

/// Verifies a failed carrier handoff restores both stream and connection credit.
///
/// Example: four cancelled DATA bytes become immediately reservable in both windows.
#[tokio::test]
async fn carrier_failure_rolls_back_all_credit() {
    let (carrier, received) = tokio::sync::mpsc::channel(1);
    let outbound = Outbound::start(carrier, Frame::Fin { stream_id: 0 });
    time::sleep(Duration::from_millis(10)).await;
    let stream_window = SendWindow::new(4);
    let connection_window = SendWindow::new(4);
    let stream_credit = stream_window
        .reserve(4)
        .await
        .expect("reserve stream credit")
        .commit_guarded(4)
        .expect("commit stream credit");
    let connection_credit = connection_window
        .reserve(4)
        .await
        .expect("reserve connection credit")
        .commit_guarded(4)
        .expect("commit connection credit");
    let slot = Arc::new(Semaphore::new(1))
        .acquire_owned()
        .await
        .expect("acquire DATA slot");
    drop(received);
    assert!(outbound
        .send_data(
            1,
            Bytes::from_static(b"data"),
            stream_credit,
            connection_credit,
            slot,
        )
        .await
        .is_err());
    assert_eq!(
        stream_window
            .reserve(4)
            .await
            .expect("stream credit rolled back")
            .amount(),
        4
    );
    assert_eq!(
        connection_window
            .reserve(4)
            .await
            .expect("connection credit rolled back")
            .amount(),
        4
    );
}
