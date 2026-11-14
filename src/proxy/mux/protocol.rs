use bytes::{BufMut, Bytes, BytesMut};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Current mux wire version, used by both peers during the hello exchange.
pub(super) const VERSION: u16 = 1;

/// Bytes occupied by the common opcode and stream identifier header.
const HEADER_LEN: usize = 5;

/// Destination address supplied directly by an integrated sing-box outbound.
///
/// Example: `Domain("example.com")` preserves remote DNS routing at the daemon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DestinationAddress {
    /// Concrete IPv4 destination.
    Ipv4(Ipv4Addr),
    /// Concrete IPv6 destination.
    Ipv6(Ipv6Addr),
    /// ASCII domain name encoded with the standard SOCKS address shape.
    Domain(String),
}

/// Complete destination carried by a direct OPEN or DATAGRAM_OPEN frame.
///
/// Example: `example.com:443` lets the daemon connect without an intermediate SOCKS proxy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Destination {
    /// Host address or domain selected by sing-box routing.
    pub(super) address: DestinationAddress,
    /// Non-zero target transport port.
    pub(super) port: u16,
}

impl Destination {
    /// Formats one destination for Tokio TCP or UDP resolution.
    ///
    /// Example: IPv6 `::1` and port `22` becomes `[::1]:22`.
    pub(super) fn connect_address(&self) -> String {
        match &self.address {
            DestinationAddress::Ipv4(address) => format!("{address}:{}", self.port),
            DestinationAddress::Ipv6(address) => format!("[{address}]:{}", self.port),
            DestinationAddress::Domain(address) => format!("{address}:{}", self.port),
        }
    }
}

/// Mux protocol frame carried by exactly one WebSocket binary message.
///
/// Example: `Frame::Data { stream_id: 1, payload }` transports one TCP chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum Frame {
    /// Announces protocol and receive limits for this peer.
    Hello {
        /// Protocol version understood by the sender.
        version: u16,
        /// Receive credit initially available to every stream.
        stream_window: u32,
        /// Aggregate receive credit initially available to the connection.
        connection_window: u32,
        /// Largest accepted DATA payload.
        max_frame: u32,
        /// Largest number of concurrently open streams.
        max_streams: u32,
    },
    /// Requests one remote target TCP connection.
    Open {
        /// Logical stream identifier allocated by the opener.
        stream_id: u32,
        /// Target TCP port requested from the remote proxy.
        target_port: u16,
    },
    /// Requests a direct daemon-side TCP connection to an original sing-box destination.
    OpenDestination {
        /// Logical stream identifier allocated by the opener.
        stream_id: u32,
        /// Original destination that replaces the legacy fixed target port.
        destination: Destination,
    },
    /// Confirms that the requested target TCP connection is ready.
    OpenOk {
        /// Logical stream identifier being confirmed.
        stream_id: u32,
    },
    /// Rejects a stream whose target TCP connection could not be opened.
    OpenError {
        /// Logical stream identifier being rejected.
        stream_id: u32,
        /// Stable machine-readable failure code.
        code: u16,
    },
    /// Carries one ordered byte chunk for a logical TCP stream.
    Data {
        /// Logical stream receiving the payload.
        stream_id: u32,
        /// Opaque TCP bytes.
        payload: Bytes,
    },
    /// Closes the sender's write direction while preserving the reverse direction.
    Fin {
        /// Logical stream whose sending direction reached EOF.
        stream_id: u32,
    },
    /// Aborts both directions of one logical stream.
    Reset {
        /// Logical stream being aborted.
        stream_id: u32,
        /// Stable machine-readable reset reason.
        code: u16,
    },
    /// Restores per-stream send credit after bytes reached the adjacent TCP.
    WindowUpdate {
        /// Logical stream receiving more credit.
        stream_id: u32,
        /// Number of newly available bytes.
        increment: u32,
    },
    /// Restores aggregate connection send credit.
    ConnectionWindowUpdate {
        /// Number of newly available bytes.
        increment: u32,
    },
    /// Opens one unordered UDP datagram association.
    DatagramOpen {
        /// Association identifier allocated by the opener.
        association_id: u32,
        /// Fixed daemon-side UDP access port selected for the association.
        target_port: u16,
    },
    /// Opens one UDP association directly to the original sing-box destination.
    DatagramOpenDestination {
        /// Association identifier allocated by the opener.
        association_id: u32,
        /// Original connected UDP destination.
        destination: Destination,
    },
    /// Confirms that a UDP datagram association is ready.
    DatagramOpenOk {
        /// Association identifier being confirmed.
        association_id: u32,
    },
    /// Rejects a UDP datagram association.
    DatagramOpenError {
        /// Association identifier being rejected.
        association_id: u32,
        /// Stable machine-readable failure code.
        code: u16,
    },
    /// Carries one complete UDP datagram without stream semantics.
    Datagram {
        /// Association receiving this datagram.
        association_id: u32,
        /// Opaque datagram payload whose boundary must be preserved.
        payload: Bytes,
    },
    /// Closes one UDP datagram association.
    DatagramClose {
        /// Association identifier being closed.
        association_id: u32,
    },
}

/// Encodes one mux frame into one WebSocket binary message.
///
/// Example: `Open { stream_id: 1, target_port: 80 } -> binary frame`.
pub(super) fn encode(frame: Frame) -> Bytes {
    match frame {
        Frame::Hello {
            version,
            stream_window,
            connection_window,
            max_frame,
            max_streams,
        } => {
            let mut output = frame_header(1, 0, 18);
            output.put_u16(version);
            output.put_u32(stream_window);
            output.put_u32(connection_window);
            output.put_u32(max_frame);
            output.put_u32(max_streams);
            output.freeze()
        }
        Frame::Open {
            stream_id,
            target_port,
        } => {
            let mut output = frame_header(2, stream_id, 2);
            output.put_u16(target_port);
            output.freeze()
        }
        Frame::OpenDestination {
            stream_id,
            destination,
        } => encode_destination_frame(2, stream_id, &destination),
        Frame::OpenOk { stream_id } => frame_header(3, stream_id, 0).freeze(),
        Frame::OpenError { stream_id, code } => encode_code_frame(4, stream_id, code),
        Frame::Data { stream_id, payload } => {
            let mut output = frame_header(5, stream_id, payload.len());
            output.extend_from_slice(&payload);
            output.freeze()
        }
        Frame::Fin { stream_id } => frame_header(6, stream_id, 0).freeze(),
        Frame::Reset { stream_id, code } => encode_code_frame(7, stream_id, code),
        Frame::WindowUpdate {
            stream_id,
            increment,
        } => encode_increment_frame(8, stream_id, increment),
        Frame::ConnectionWindowUpdate { increment } => encode_increment_frame(9, 0, increment),
        Frame::DatagramOpen {
            association_id,
            target_port,
        } => {
            let mut output = frame_header(10, association_id, 2);
            output.put_u16(target_port);
            output.freeze()
        }
        Frame::DatagramOpenDestination {
            association_id,
            destination,
        } => encode_destination_frame(10, association_id, &destination),
        Frame::DatagramOpenOk { association_id } => frame_header(11, association_id, 0).freeze(),
        Frame::DatagramOpenError {
            association_id,
            code,
        } => encode_code_frame(12, association_id, code),
        Frame::Datagram {
            association_id,
            payload,
        } => {
            let mut output = frame_header(13, association_id, payload.len());
            output.extend_from_slice(&payload);
            output.freeze()
        }
        Frame::DatagramClose { association_id } => frame_header(14, association_id, 0).freeze(),
    }
}

/// Decodes one complete WebSocket binary message into a mux frame.
///
/// Example: a truncated OPEN payload returns a protocol error.
pub(super) fn decode(input: Bytes) -> Result<Frame, String> {
    if input.len() < HEADER_LEN {
        return Err("mux frame header is truncated".to_string());
    }
    let opcode = input[0];
    let stream_id = u32::from_be_bytes([input[1], input[2], input[3], input[4]]);
    let payload = input.slice(HEADER_LEN..);
    match opcode {
        1 => decode_hello(stream_id, &payload),
        2 if stream_id != 0 && payload.len() == 2 => Ok(Frame::Open {
            stream_id,
            target_port: u16::from_be_bytes([payload[0], payload[1]]),
        }),
        2 if stream_id != 0 => Ok(Frame::OpenDestination {
            stream_id,
            destination: decode_destination(&payload)?,
        }),
        3 if stream_id != 0 && payload.is_empty() => Ok(Frame::OpenOk { stream_id }),
        4 if stream_id != 0 => decode_code(stream_id, &payload, true),
        5 if stream_id != 0 && !payload.is_empty() => Ok(Frame::Data { stream_id, payload }),
        6 if stream_id != 0 && payload.is_empty() => Ok(Frame::Fin { stream_id }),
        7 if stream_id != 0 => decode_code(stream_id, &payload, false),
        8 if stream_id != 0 => decode_increment(stream_id, &payload),
        9 if stream_id == 0 => decode_connection_increment(&payload),
        10 if stream_id != 0 && payload.len() == 2 => Ok(Frame::DatagramOpen {
            association_id: stream_id,
            target_port: u16::from_be_bytes([payload[0], payload[1]]),
        }),
        10 if stream_id != 0 => Ok(Frame::DatagramOpenDestination {
            association_id: stream_id,
            destination: decode_destination(&payload)?,
        }),
        11 if stream_id != 0 && payload.is_empty() => Ok(Frame::DatagramOpenOk {
            association_id: stream_id,
        }),
        12 if stream_id != 0 => decode_datagram_open_error(stream_id, &payload),
        13 if stream_id != 0 && !payload.is_empty() => Ok(Frame::Datagram {
            association_id: stream_id,
            payload,
        }),
        14 if stream_id != 0 && payload.is_empty() => Ok(Frame::DatagramClose {
            association_id: stream_id,
        }),
        _ => Err(format!(
            "invalid mux frame opcode={opcode} stream_id={stream_id}"
        )),
    }
}

/// Encodes one original destination using the standard SOCKS address representation.
///
/// Example: `example.com:443` becomes type 3, length, domain bytes, and port.
fn encode_destination_frame(opcode: u8, stream_id: u32, destination: &Destination) -> Bytes {
    let address_length = match &destination.address {
        DestinationAddress::Ipv4(_) => 1 + 4,
        DestinationAddress::Ipv6(_) => 1 + 16,
        DestinationAddress::Domain(domain) => 2 + domain.len(),
    };
    let mut output = frame_header(opcode, stream_id, address_length + 2);
    match &destination.address {
        DestinationAddress::Ipv4(address) => {
            output.put_u8(1);
            output.extend_from_slice(&address.octets());
        }
        DestinationAddress::Ipv6(address) => {
            output.put_u8(4);
            output.extend_from_slice(&address.octets());
        }
        DestinationAddress::Domain(domain) => {
            output.put_u8(3);
            output.put_u8(domain.len() as u8);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    output.put_u16(destination.port);
    output.freeze()
}

/// Decodes and validates one direct destination without resolving its domain locally.
///
/// Example: type 1 plus four address bytes and port becomes an IPv4 destination.
fn decode_destination(payload: &[u8]) -> Result<Destination, String> {
    let Some(address_type) = payload.first().copied() else {
        return Err("mux destination is truncated".to_string());
    };
    let (address, port_offset) = match address_type {
        1 if payload.len() == 7 => (
            DestinationAddress::Ipv4(Ipv4Addr::new(
                payload[1], payload[2], payload[3], payload[4],
            )),
            5,
        ),
        4 if payload.len() == 19 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&payload[1..17]);
            (DestinationAddress::Ipv6(Ipv6Addr::from(octets)), 17)
        }
        3 if payload.len() >= 4 => {
            let domain_length = payload[1] as usize;
            let expected_length = 2_usize.saturating_add(domain_length).saturating_add(2);
            if domain_length == 0 || payload.len() != expected_length {
                return Err("invalid mux destination domain length".to_string());
            }
            let domain = std::str::from_utf8(&payload[2..2 + domain_length])
                .map_err(|_| "mux destination domain is not UTF-8".to_string())?;
            if !domain.is_ascii() || domain.chars().any(char::is_whitespace) {
                return Err("mux destination domain must be non-whitespace ASCII".to_string());
            }
            (
                DestinationAddress::Domain(domain.to_string()),
                2 + domain_length,
            )
        }
        _ => return Err("invalid mux destination address".to_string()),
    };
    let port = u16::from_be_bytes([payload[port_offset], payload[port_offset + 1]]);
    if port == 0 {
        return Err("mux destination port must be non-zero".to_string());
    }
    Ok(Destination { address, port })
}

/// Decodes one UDP association rejection without sharing TCP-specific naming.
///
/// Example: association 3 plus code 2 becomes `DatagramOpenError`.
fn decode_datagram_open_error(association_id: u32, payload: &[u8]) -> Result<Frame, String> {
    if payload.len() != 2 {
        return Err("invalid mux datagram open error frame".to_string());
    }
    Ok(Frame::DatagramOpenError {
        association_id,
        code: u16::from_be_bytes([payload[0], payload[1]]),
    })
}

/// Creates a common frame header with enough space for its payload.
///
/// Example: opcode 5 and stream 7 produce a five-byte DATA header.
fn frame_header(opcode: u8, stream_id: u32, payload_len: usize) -> BytesMut {
    let mut output = BytesMut::with_capacity(HEADER_LEN.saturating_add(payload_len));
    output.put_u8(opcode);
    output.put_u32(stream_id);
    output
}

/// Encodes a two-byte error-code control frame.
///
/// Example: RESET for stream 3 with code 1 produces a seven-byte frame.
fn encode_code_frame(opcode: u8, stream_id: u32, code: u16) -> Bytes {
    let mut output = frame_header(opcode, stream_id, 2);
    output.put_u16(code);
    output.freeze()
}

/// Encodes a four-byte positive window increment.
///
/// Example: increment 32768 is represented in network byte order.
fn encode_increment_frame(opcode: u8, stream_id: u32, increment: u32) -> Bytes {
    let mut output = frame_header(opcode, stream_id, 4);
    output.put_u32(increment);
    output.freeze()
}

/// Decodes and validates the connection hello payload.
///
/// Example: zero receive window is rejected before streams can open.
fn decode_hello(stream_id: u32, payload: &[u8]) -> Result<Frame, String> {
    if stream_id != 0 || payload.len() != 18 {
        return Err("invalid mux hello frame".to_string());
    }
    let version = u16::from_be_bytes([payload[0], payload[1]]);
    let stream_window = read_u32(payload, 2);
    let connection_window = read_u32(payload, 6);
    let max_frame = read_u32(payload, 10);
    let max_streams = read_u32(payload, 14);
    if stream_window == 0 || connection_window == 0 || max_frame == 0 || max_streams == 0 {
        return Err("mux hello limits must be positive".to_string());
    }
    Ok(Frame::Hello {
        version,
        stream_window,
        connection_window,
        max_frame,
        max_streams,
    })
}

/// Decodes OPEN_ERROR or RESET without duplicating their length checks.
///
/// Example: `open_error=true` maps code 2 to `Frame::OpenError`.
fn decode_code(stream_id: u32, payload: &[u8], open_error: bool) -> Result<Frame, String> {
    if payload.len() != 2 {
        return Err("invalid mux error frame".to_string());
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if open_error {
        Ok(Frame::OpenError { stream_id, code })
    } else {
        Ok(Frame::Reset { stream_id, code })
    }
}

/// Decodes one per-stream WINDOW_UPDATE frame.
///
/// Example: zero increment is rejected because it cannot make progress.
fn decode_increment(stream_id: u32, payload: &[u8]) -> Result<Frame, String> {
    let increment = decode_positive_increment(payload)?;
    Ok(Frame::WindowUpdate {
        stream_id,
        increment,
    })
}

/// Decodes one connection-level WINDOW_UPDATE frame.
///
/// Example: stream id zero plus increment 1024 restores aggregate credit.
fn decode_connection_increment(payload: &[u8]) -> Result<Frame, String> {
    Ok(Frame::ConnectionWindowUpdate {
        increment: decode_positive_increment(payload)?,
    })
}

/// Decodes a positive four-byte increment shared by both window frame types.
///
/// Example: `[0, 0, 4, 0] -> 1024`.
fn decode_positive_increment(payload: &[u8]) -> Result<u32, String> {
    if payload.len() != 4 {
        return Err("invalid mux window update frame".to_string());
    }
    let increment = read_u32(payload, 0);
    if increment == 0 {
        return Err("mux window increment must be positive".to_string());
    }
    Ok(increment)
}

/// Reads one network-order u32 from a previously length-checked slice.
///
/// Example: bytes at offset 2 decode a hello stream window.
fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

#[cfg(test)]
#[path = "protocol_test.rs"]
mod protocol_test;
