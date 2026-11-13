use bytes::Bytes;

use super::ByteQueue;

/// Verifies many tiny frames share one strict byte budget instead of frame slots.
///
/// Example: four one-byte pushes pop as one ordered four-byte chunk.
#[tokio::test]
async fn tiny_frames_are_coalesced_by_bytes() {
    let queue = ByteQueue::new(4);
    for byte in [b"1", b"2", b"3", b"4"] {
        queue
            .push(&Bytes::copy_from_slice(byte))
            .expect("push tiny frame");
    }
    assert!(queue.push(&Bytes::from_static(b"5")).is_err());
    assert_eq!(
        &queue.pop(4).await.expect("pop coalesced bytes")[..],
        b"1234"
    );
}

/// Verifies FIN drains queued bytes while RESET discards them immediately.
///
/// Example: close returns data then EOF; abort returns EOF directly.
#[tokio::test]
async fn close_and_abort_have_distinct_drain_semantics() {
    let draining = ByteQueue::new(4);
    draining
        .push(&Bytes::from_static(b"data"))
        .expect("push data");
    draining.close_input();
    assert_eq!(&draining.pop(4).await.expect("drain data")[..], b"data");
    assert!(draining.pop(4).await.is_none());

    let aborted = ByteQueue::new(4);
    aborted
        .push(&Bytes::from_static(b"data"))
        .expect("push data");
    aborted.abort();
    assert!(aborted.pop(4).await.is_none());
}
