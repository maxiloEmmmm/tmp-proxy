//! Cloudflare and Cap'n Proto wire encoders.

pub(crate) mod codec;
pub(crate) mod data;
pub(crate) mod rpc;

pub(crate) use crate::quic_metadata_protocol_capnp;
pub(crate) use crate::tunnelrpc_capnp;
