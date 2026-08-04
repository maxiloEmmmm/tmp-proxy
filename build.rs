/// Generates Rust bindings for the Cloudflare Cap'n Proto wire contracts.
///
/// Example: `cargo check --bin tmp-proxy` generates bindings in `OUT_DIR`.
fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("src/cf_lib/protocol/schema")
        .file("src/cf_lib/protocol/schema/quic_metadata_protocol.capnp")
        .file("src/cf_lib/protocol/schema/tunnelrpc.capnp")
        .run()
        .expect("compile Cloudflare Cap'n Proto schemas");
}
