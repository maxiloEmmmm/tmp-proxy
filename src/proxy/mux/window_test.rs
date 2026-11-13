use std::{sync::Arc, time::Duration};

use tokio::time;

use super::{RecvWindow, SendWindow};

/// Verifies committed credit blocks until the peer explicitly restores it.
///
/// Example: a full four-byte send window waits for WINDOW_UPDATE.
#[tokio::test]
async fn send_window_blocks_and_resumes() {
    let window = SendWindow::new(4);
    window
        .reserve(4)
        .await
        .expect("reserve full window")
        .commit_guarded(4)
        .expect("commit full window")
        .confirm();

    let waiting = Arc::clone(&window);
    let task = tokio::spawn(async move { waiting.reserve(1).await });
    time::sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());

    window.update(4).expect("restore window");
    assert_eq!(
        task.await.expect("join waiter").expect("reserve").amount(),
        1
    );
}

/// Verifies cancellation and short reads return unused reservations.
///
/// Example: dropping four reserved bytes leaves all four available again.
#[tokio::test]
async fn reservation_returns_unused_credit() {
    let window = SendWindow::new(4);
    drop(window.reserve(4).await.expect("reserve"));
    let reservation = window.reserve(4).await.expect("reserve again");
    reservation
        .commit_guarded(1)
        .expect("commit one byte")
        .confirm();
    window.update(1).expect("ack one byte");
    assert_eq!(
        window.reserve(4).await.expect("reserve restored").amount(),
        4
    );
}

/// Verifies an unconfirmed carrier commit restores all in-flight credit on drop.
///
/// Example: failed WSS handoff rolls four committed bytes back to available.
#[tokio::test]
async fn guarded_commit_rolls_back_before_handoff() {
    let window = SendWindow::new(4);
    let commit = window
        .reserve(4)
        .await
        .expect("reserve guarded credit")
        .commit_guarded(4)
        .expect("commit guarded credit");
    drop(commit);
    assert_eq!(
        window
            .reserve(4)
            .await
            .expect("reserve rolled back credit")
            .amount(),
        4
    );
}

/// Verifies confirmed carrier credit remains in flight until remote acknowledgement.
///
/// Example: confirming four bytes still blocks a new reservation before WINDOW_UPDATE.
#[tokio::test]
async fn confirmed_guard_waits_for_window_update() {
    let window = SendWindow::new(4);
    window
        .reserve(4)
        .await
        .expect("reserve guarded credit")
        .commit_guarded(4)
        .expect("commit guarded credit")
        .confirm();
    let waiting = Arc::clone(&window);
    let task = tokio::spawn(async move { waiting.reserve(1).await });
    time::sleep(Duration::from_millis(10)).await;
    assert!(!task.is_finished());
    window.update(4).expect("ack confirmed credit");
    assert_eq!(
        task.await.expect("join waiter").expect("reserve").amount(),
        1
    );
}

/// Verifies WINDOW_UPDATE cannot acknowledge reserved or nonexistent DATA.
///
/// Example: credit reserved before TCP read is not yet eligible for acknowledgement.
#[tokio::test]
async fn update_is_bounded_by_actual_in_flight_data() {
    let window = SendWindow::new(4);
    let reserved = window.reserve(4).await.expect("reserve");
    assert!(window.update(1).is_err());
    reserved
        .commit_guarded(2)
        .expect("commit two bytes")
        .confirm();
    assert!(window.update(3).is_err());
    window.update(2).expect("ack exact in-flight bytes");
    assert_eq!(
        window.reserve(4).await.expect("reserve restored").amount(),
        4
    );
}

/// Verifies receive credit is returned only after downstream consumption.
///
/// Example: receiving four bytes without consuming them leaves no window update.
#[test]
fn receive_window_tracks_actual_consumption() {
    let mut window = RecvWindow::new(4, 2).expect("create receive window");
    window.receive(4).expect("receive full window");
    assert!(window.receive(1).is_err());
    assert_eq!(window.consume(1).expect("consume one"), Some(1));
    assert_eq!(window.consume(3).expect("consume rest"), Some(3));
    assert!(window.consume(1).is_err());
}

/// Verifies reset recovery returns only bytes not already consumed downstream.
///
/// Example: consuming two of six received bytes leaves four bytes to discard.
#[test]
fn discard_reports_only_unconsumed_bytes() {
    let mut window = RecvWindow::new(8, 4).expect("create receive window");
    window.receive(6).expect("receive six bytes");
    assert_eq!(window.consume(2).expect("consume two bytes"), None);
    assert_eq!(window.discard_unconsumed(), 4);
    window.receive(8).expect("window restored after discard");
}
