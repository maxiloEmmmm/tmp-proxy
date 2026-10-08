use capnp::message::{Builder, Reader};
use capnp_rpc::rpc_capnp::{cap_descriptor, message, return_};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::cf_lib::protocol::codec;
use crate::cf_lib::protocol::tunnelrpc_capnp::{connection_response, registration_server};
use crate::cf_lib::quick_tunnel::Credentials;
use crate::cf_lib::CfError;

const REGISTRATION_INTERFACE_ID: u64 = 0xf716_95ec_7fe8_5497;
const REGISTER_METHOD_ID: u16 = 0;
const UNREGISTER_METHOD_ID: u16 = 1;
const RPC_SIGNATURE: [u8; 6] = [0x52, 0xBB, 0x82, 0x5C, 0xDB, 0x65];

/// Successful registration data needed by the session boundary.
///
/// Example: edge response with `locationName=SJC` -> `location="SJC"`.
pub(crate) struct RegistrationDetails {
    /// Cloudflare colo code serving this connection.
    pub(crate) location: String,
}

/// Minimal sequential Cap'n Proto RPC client for Cloudflare registration.
///
/// Example: bootstrap -> register -> unregister on one control stream.
pub(crate) struct RpcClient<S> {
    /// Bidirectional transport carrying unpacked Cap'n Proto messages.
    stream: S,
    /// Imported registration capability returned by bootstrap.
    capability_id: u32,
    /// Question identifier allocated to the next method call.
    next_question_id: u32,
}

impl<S> RpcClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Bootstraps the registration capability on a new control stream.
    ///
    /// Example: a QUIC stream writes the RPC signature before bootstrap.
    pub(crate) async fn connect(mut stream: S, write_signature: bool) -> Result<Self, CfError> {
        if write_signature {
            stream
                .write_all(&RPC_SIGNATURE)
                .await
                .map_err(|error| CfError::new(format!("write RPC signature failed: {error}")))?;
        }

        let question_id = 0;
        let mut request = Builder::new_default();
        request
            .init_root::<message::Builder<'_>>()
            .init_bootstrap()
            .set_question_id(question_id);
        let encoded = codec::encode_message(&request)?;
        drop(request);
        codec::write_encoded(&mut stream, &encoded).await?;

        let response = read_return(&mut stream, question_id).await?;
        let capability_id = bootstrap_capability(&response)?;
        drop(response);
        write_finish(&mut stream, question_id, false).await?;
        Ok(Self {
            stream,
            capability_id,
            next_question_id: 1,
        })
    }

    /// Registers one Quick Tunnel connection with the edge.
    ///
    /// Example: temporary credentials plus attempt `0` -> colo details.
    pub(crate) async fn register(
        &mut self,
        credentials: &Credentials,
        previous_attempts: u8,
    ) -> Result<RegistrationDetails, CfError> {
        let question_id = self.allocate_question();
        let mut request = Builder::new_default();
        {
            let mut call = request.init_root::<message::Builder<'_>>().init_call();
            call.set_question_id(question_id);
            call.reborrow()
                .init_target()
                .set_imported_cap(self.capability_id);
            call.set_interface_id(REGISTRATION_INTERFACE_ID);
            call.set_method_id(REGISTER_METHOD_ID);
            let content = call.init_params().init_content();
            let mut params =
                content.init_as::<registration_server::register_connection_params::Builder<'_>>();
            let mut auth = params.reborrow().init_auth();
            auth.set_account_tag(&credentials.account_tag);
            auth.set_tunnel_secret(&credentials.tunnel_secret);
            params.set_tunnel_id(&credentials.tunnel_id);
            params.set_conn_index(0);
            let mut options = params.init_options();
            let mut client = options.reborrow().init_client();
            client.set_client_id(&credentials.client_id);
            let mut features = client.reborrow().init_features(3);
            features.set(0, "serialized_headers");
            features.set(1, "support_quic_eof");
            features.set(2, "postquantum");
            client.set_version(concat!("tmp-proxy/", env!("CARGO_PKG_VERSION")));
            client.set_arch(std::env::consts::ARCH);
            options.set_origin_local_ip(&[]);
            options.set_replace_existing(false);
            options.set_compression_quality(0);
            options.set_num_previous_attempts(previous_attempts);
        }
        let encoded = codec::encode_message(&request)?;
        drop(request);
        codec::write_encoded(&mut self.stream, &encoded).await?;

        let response = read_return(&mut self.stream, question_id).await?;
        let details = parse_registration(&response)?;
        drop(response);
        write_finish(&mut self.stream, question_id, true).await?;
        Ok(details)
    }

    /// Gracefully unregisters the active edge connection.
    ///
    /// Example: session shutdown -> `unregisterConnection()`.
    pub(crate) async fn unregister(&mut self) -> Result<(), CfError> {
        let question_id = self.allocate_question();
        let mut request = Builder::new_default();
        {
            let mut call = request.init_root::<message::Builder<'_>>().init_call();
            call.set_question_id(question_id);
            call.reborrow()
                .init_target()
                .set_imported_cap(self.capability_id);
            call.set_interface_id(REGISTRATION_INTERFACE_ID);
            call.set_method_id(UNREGISTER_METHOD_ID);
            call.init_params()
                .init_content()
                .init_as::<registration_server::unregister_connection_params::Builder<'_>>();
        }
        let encoded = codec::encode_message(&request)?;
        drop(request);
        codec::write_encoded(&mut self.stream, &encoded).await?;
        let response = read_return(&mut self.stream, question_id).await?;
        ensure_empty_success(&response)?;
        drop(response);
        write_finish(&mut self.stream, question_id, true).await?;
        write_release(&mut self.stream, self.capability_id).await
    }

    /// Allocates a monotonically increasing RPC question identifier.
    ///
    /// Example: after bootstrap, calls receive ids `1`, then `2`.
    fn allocate_question(&mut self) -> u32 {
        let id = self.next_question_id;
        self.next_question_id = self.next_question_id.wrapping_add(1);
        id
    }
}

/// Reads messages until the matching RPC return arrives.
///
/// Example: question `1` ignores unrelated protocol messages and returns answer `1`.
async fn read_return<S>(
    stream: &mut S,
    question_id: u32,
) -> Result<Reader<capnp::serialize::OwnedSegments>, CfError>
where
    S: AsyncRead + Unpin,
{
    loop {
        let response = codec::read_message(stream).await?;
        let root = codec::root::<message::Reader<'_>>(&response)?;
        match root
            .which()
            .map_err(|error| CfError::new(format!("read RPC message type failed: {error}")))?
        {
            message::Return(value) => {
                let value = value
                    .map_err(|error| CfError::new(format!("read RPC return failed: {error}")))?;
                if value.get_answer_id() == question_id {
                    return Ok(response);
                }
            }
            message::Abort(value) => {
                let value = value
                    .map_err(|error| CfError::new(format!("read RPC abort failed: {error}")))?;
                let reason_text = value.get_reason().ok();
                let reason = reason_text
                    .as_ref()
                    .and_then(|text| text.to_str().ok())
                    .unwrap_or("unknown abort");
                return Err(CfError::new(format!("Cloudflare aborted RPC: {reason}")));
            }
            message::Unimplemented(_) => {
                return Err(CfError::new("Cloudflare rejected an RPC message"));
            }
            _ => {
                // Trigger: Cap'n Proto peers may interleave bookkeeping messages.
                // They are unrelated to our sequential outstanding question, so treating
                // them as its result would corrupt state. Ignoring them prevents false replies.
            }
        }
    }
}

/// Extracts the exported bootstrap capability identifier.
///
/// Example: first `senderHosted` descriptor -> imported capability id.
fn bootstrap_capability(
    response: &Reader<capnp::serialize::OwnedSegments>,
) -> Result<u32, CfError> {
    let payload = return_results(response)?;
    let table = payload.get_cap_table().map_err(|error| {
        CfError::new(format!("read bootstrap capability table failed: {error}"))
    })?;
    if table.is_empty() {
        return Err(CfError::new(
            "bootstrap returned no registration capability",
        ));
    }
    match table
        .get(0)
        .which()
        .map_err(|error| CfError::new(format!("read bootstrap capability failed: {error}")))?
    {
        cap_descriptor::SenderHosted(id) => Ok(id),
        cap_descriptor::SenderPromise(id) => Ok(id),
        _ => Err(CfError::new("bootstrap returned an unsupported capability")),
    }
}

/// Parses the application-level registration union from an RPC return.
///
/// Example: `connectionDetails` -> location; `error` -> `CfError`.
fn parse_registration(
    response: &Reader<capnp::serialize::OwnedSegments>,
) -> Result<RegistrationDetails, CfError> {
    let payload = return_results(response)?;
    let results = payload
        .get_content()
        .get_as::<registration_server::register_connection_results::Reader<'_>>()
        .map_err(|error| CfError::new(format!("decode registration result failed: {error}")))?;
    let response = results
        .get_result()
        .map_err(|error| CfError::new(format!("read registration response failed: {error}")))?;
    match response
        .get_result()
        .which()
        .map_err(|error| CfError::new(format!("read registration response type failed: {error}")))?
    {
        connection_response::result::ConnectionDetails(details) => {
            let details = details.map_err(|error| {
                CfError::new(format!("read registration details failed: {error}"))
            })?;
            let location_text = details
                .get_location_name()
                .map_err(|error| CfError::new(format!("read edge location failed: {error}")))?;
            let location = location_text
                .to_str()
                .map_err(|error| CfError::new(format!("edge location is not UTF-8: {error}")))?
                .to_string();
            Ok(RegistrationDetails { location })
        }
        connection_response::result::Error(error) => {
            let error = error.map_err(|error| {
                CfError::new(format!("read registration error failed: {error}"))
            })?;
            let cause_text = error.get_cause().ok();
            let cause = cause_text
                .as_ref()
                .and_then(|text| text.to_str().ok())
                .unwrap_or("registration rejected");
            let message = format!("Cloudflare registration failed: {cause}");
            if cause.to_ascii_lowercase().contains("unauthorized") {
                // 触发条件: Cloudflare 明确拒绝当前 tunnel 凭据。
                // 不能继续普通重连: 同一 ID 和 secret 不会重新变为有效。
                // 防止副作用: 保留错误类别，让 daemon 重新申请 Quick Tunnel。
                Err(CfError::unauthorized(message))
            } else {
                Err(CfError::new(message))
            }
        }
    }
}

/// Confirms that an RPC method returned normal results.
///
/// Example: unregister return with an empty payload -> success.
fn ensure_empty_success(response: &Reader<capnp::serialize::OwnedSegments>) -> Result<(), CfError> {
    return_results(response).map(|_| ())
}

/// Returns the payload from a successful RPC return or its remote exception.
///
/// Example: `return.results` -> payload reader.
fn return_results<'a>(
    response: &'a Reader<capnp::serialize::OwnedSegments>,
) -> Result<capnp_rpc::rpc_capnp::payload::Reader<'a>, CfError> {
    let root = codec::root::<message::Reader<'_>>(response)?;
    let returned = match root
        .which()
        .map_err(|error| CfError::new(format!("read RPC return type failed: {error}")))?
    {
        message::Return(value) => {
            value.map_err(|error| CfError::new(format!("read RPC return failed: {error}")))?
        }
        _ => return Err(CfError::new("expected RPC return message")),
    };
    match returned
        .which()
        .map_err(|error| CfError::new(format!("read RPC result type failed: {error}")))?
    {
        return_::Results(payload) => {
            payload.map_err(|error| CfError::new(format!("read RPC results failed: {error}")))
        }
        return_::Exception(exception) => {
            let exception = exception
                .map_err(|error| CfError::new(format!("read RPC exception failed: {error}")))?;
            let reason_text = exception.get_reason().ok();
            let reason = reason_text
                .as_ref()
                .and_then(|text| text.to_str().ok())
                .unwrap_or("remote exception");
            Err(CfError::new(format!("Cloudflare RPC failed: {reason}")))
        }
        _ => Err(CfError::new("Cloudflare returned unsupported RPC result")),
    }
}

/// Releases one completed question and its result capabilities.
///
/// Example: completed register question `1` -> `Finish(1)`.
async fn write_finish<S>(
    stream: &mut S,
    question_id: u32,
    release_result_caps: bool,
) -> Result<(), CfError>
where
    S: AsyncWrite + Unpin,
{
    let mut message = Builder::new_default();
    {
        let mut finish = message.init_root::<message::Builder<'_>>().init_finish();
        finish.set_question_id(question_id);
        finish.set_release_result_caps(release_result_caps);
    }
    let encoded = codec::encode_message(&message)?;
    drop(message);
    codec::write_encoded(stream, &encoded).await
}

/// Releases the imported registration capability during graceful shutdown.
///
/// Example: imported capability `0` -> `Release(0, 1)`.
async fn write_release<S>(stream: &mut S, capability_id: u32) -> Result<(), CfError>
where
    S: AsyncWrite + Unpin,
{
    let mut message = Builder::new_default();
    {
        let mut release = message.init_root::<message::Builder<'_>>().init_release();
        release.set_id(capability_id);
        release.set_reference_count(1);
    }
    let encoded = codec::encode_message(&message)?;
    drop(message);
    codec::write_encoded(stream, &encoded).await
}
