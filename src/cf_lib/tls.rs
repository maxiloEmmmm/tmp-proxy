use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

use crate::cf_lib::CfError;

const QUIC_SERVER_NAME: &str = "quic.cftunnel.com";
const HTTP2_SERVER_NAME: &str = "h2.cftunnel.com";
const QUIC_ALPN: &[u8] = b"argotunnel";
const CLOUDFLARE_CA_DER_BASE64: &str = "MIICiTCCAi6gAwIBAgIUXZP3MWb8MKwBE1Qbawsp1sfA/Y4wCgYIKoZIzj0EAwIwgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQLEy9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0eTAeFw0xOTA4MjMyMTA4MDBaFw0yOTA4MTUxNzAwMDBaMIGPMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEZMBcGA1UEChMQQ2xvdWRGbGFyZSwgSW5jLjE4MDYGA1UECxMvQ2xvdWRGbGFyZSBPcmlnaW4gU1NMIEVDQyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASR+sGALuaGshnUbcxKry+0LEXZ4NY6JUAtSeA6g87K3jaAxpIg9G50PokpfWkhbarLfpcZu0UAoYy2su0EhN7wo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUhTBdOypw1O3VkmcH/es5tBoOOKcwHwYDVR0jBBgwFoAUhTBdOypw1O3VkmcH/es5tBoOOKcwCgYIKoZIzj0EAwIDSQAwRgIhAKilfntP2ILGZjwajktkBtXE1pB4Y/fjAfLkIRUzrI15AiEA5UCLXYZZ9m2c3fKwIenMMojL1eqydsgqj/wK4p5kagQ=";

/// Builds the TLS configuration used by Cloudflare QUIC.
///
/// Example: Cloudflare CA plus `argotunnel` ALPN -> QUIC client config.
pub(crate) fn quic_config() -> Result<Arc<ClientConfig>, CfError> {
    let mut config = base_config()?;
    config.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Builds the TLS configuration used by the HTTP/2 fallback.
///
/// Example: Cloudflare CA plus H2 SNI -> TLS client config.
pub(crate) fn http2_config() -> Result<Arc<ClientConfig>, CfError> {
    Ok(Arc::new(base_config()?))
}

/// Returns the QUIC edge TLS server name.
///
/// Example: QUIC connection -> `quic.cftunnel.com`.
pub(crate) fn quic_server_name() -> &'static str {
    QUIC_SERVER_NAME
}

/// Returns the HTTP/2 edge TLS server name.
///
/// Example: TCP TLS connection -> `h2.cftunnel.com`.
pub(crate) fn http2_server_name() -> &'static str {
    HTTP2_SERVER_NAME
}

/// Creates a TLS 1.3 configuration with PQ-first AWS-LC key exchange.
///
/// Example: X25519MLKEM768 can negotiate before classical fallback groups.
fn base_config() -> Result<ClientConfig, CfError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut roots = RootCertStore::empty();
    let der = BASE64
        .decode(CLOUDFLARE_CA_DER_BASE64)
        .map_err(|error| CfError::new(format!("decode Cloudflare CA failed: {error}")))?;
    roots
        .add(CertificateDer::from(der))
        .map_err(|error| CfError::new(format!("load Cloudflare CA failed: {error}")))?;
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| CfError::new(format!("configure TLS 1.3 failed: {error}")))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}
