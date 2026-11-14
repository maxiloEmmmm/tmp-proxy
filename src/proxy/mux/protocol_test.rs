use bytes::Bytes;

use super::{decode, encode, Frame, VERSION};

/// Verifies every frame variant survives one binary encode/decode cycle.
///
/// Example: DATA stream 7 with `abc` returns the identical frame.
#[test]
fn frame_round_trips() {
    let frames = [
        Frame::Hello {
            version: VERSION,
            stream_window: 1024,
            connection_window: 4096,
            max_frame: 512,
            max_streams: 8,
        },
        Frame::Open {
            stream_id: 1,
            target_port: 10808,
        },
        Frame::OpenOk { stream_id: 1 },
        Frame::OpenError {
            stream_id: 1,
            code: 2,
        },
        Frame::Data {
            stream_id: 1,
            payload: Bytes::from_static(b"abc"),
        },
        Frame::Fin { stream_id: 1 },
        Frame::Reset {
            stream_id: 1,
            code: 3,
        },
        Frame::WindowUpdate {
            stream_id: 1,
            increment: 512,
        },
        Frame::ConnectionWindowUpdate { increment: 1024 },
        Frame::DatagramOpen {
            association_id: 3,
            target_port: 10808,
        },
        Frame::DatagramOpenOk { association_id: 3 },
        Frame::DatagramOpenError {
            association_id: 3,
            code: 4,
        },
        Frame::Datagram {
            association_id: 3,
            payload: Bytes::from_static(b"opaque"),
        },
        Frame::DatagramClose { association_id: 3 },
    ];

    for frame in frames {
        assert_eq!(decode(encode(frame.clone())).expect("decode frame"), frame);
    }
}

/// Verifies malformed or progress-free frames are rejected at the codec edge.
///
/// Example: WINDOW_UPDATE with zero increment never reaches window state.
#[test]
fn invalid_frames_are_rejected() {
    assert!(decode(Bytes::from_static(&[1, 0])).is_err());
    assert!(decode(Bytes::from_static(&[8, 0, 0, 0, 1, 0, 0, 0, 0])).is_err());
    assert!(decode(Bytes::from_static(&[5, 0, 0, 0, 0, 1])).is_err());
    assert!(decode(Bytes::from_static(&[13, 0, 0, 0, 3])).is_err());
}
