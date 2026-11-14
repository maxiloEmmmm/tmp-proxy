use bytes::{BufMut, Bytes, BytesMut};

/// Current mux wire version, used by both peers during the hello exchange.
pub(super) const VERSION: u16 = 1;

/// Bytes occupied by the common opcode and stream identifier header.
const HEADER_LEN: usize = 5;

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
