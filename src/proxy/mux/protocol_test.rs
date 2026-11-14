use bytes::Bytes;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::{decode, encode, Destination, DestinationAddress, Frame, VERSION};

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
        Frame::OpenDestination {
            stream_id: 3,
            destination: Destination {
                address: DestinationAddress::Domain("example.com".to_string()),
                port: 443,
            },
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
        Frame::DatagramOpenDestination {
            association_id: 5,
            destination: Destination {
                address: DestinationAddress::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
                port: 53,
            },
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

/// Verifies all direct destination address families retain exact values.
///
/// Example: IPv6 `2001:db8::1:443` survives one OPEN encode/decode cycle.
#[test]
fn direct_destination_address_families_round_trip() {
    let destinations = [
        Destination {
            address: DestinationAddress::Ipv4(Ipv4Addr::new(192, 168, 32, 154)),
            port: 22,
        },
        Destination {
            address: DestinationAddress::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port: 443,
        },
        Destination {
            address: DestinationAddress::Domain("xn--fsq.example".to_string()),
            port: 8443,
        },
    ];
    for (index, destination) in destinations.into_iter().enumerate() {
        let frame = Frame::OpenDestination {
            stream_id: 1 + index as u32 * 2,
            destination,
        };
        assert_eq!(
            decode(encode(frame.clone())).expect("decode direct OPEN"),
            frame
        );
    }
}

/// Verifies direct destination decoding fails closed on malformed metadata.
///
/// Example: zero port and a domain length mismatch never reach Tokio connect.
#[test]
fn invalid_direct_destinations_are_rejected() {
    let invalid = [
        Bytes::from_static(&[2, 0, 0, 0, 1, 1, 127, 0, 0, 1, 0, 0]),
        Bytes::from_static(&[2, 0, 0, 0, 1, 3, 4, b'a', b'b', 0, 80]),
        Bytes::from_static(&[2, 0, 0, 0, 1, 3, 1, 0xff, 0, 80]),
        Bytes::from_static(&[2, 0, 0, 0, 1, 9, 1, 2, 3, 4, 0, 80]),
    ];
    for frame in invalid {
        assert!(decode(frame).is_err());
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
