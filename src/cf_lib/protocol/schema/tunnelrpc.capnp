# Derived from cloudflare/cloudflared under Apache-2.0.
@0xdb8274f9144abc7e;

struct ClientInfo {
  clientId @0 :Data;
  features @1 :List(Text);
  version @2 :Text;
  arch @3 :Text;
}

struct ConnectionOptions {
  client @0 :ClientInfo;
  originLocalIp @1 :Data;
  replaceExisting @2 :Bool;
  compressionQuality @3 :UInt8;
  numPreviousAttempts @4 :UInt8;
}

struct ConnectionResponse {
  result :union {
    error @0 :ConnectionError;
    connectionDetails @1 :ConnectionDetails;
  }
}

struct ConnectionError {
  cause @0 :Text;
  retryAfter @1 :Int64;
  shouldRetry @2 :Bool;
}

struct ConnectionDetails {
  uuid @0 :Data;
  locationName @1 :Text;
  tunnelIsRemotelyManaged @2 :Bool;
}

struct TunnelAuth {
  accountTag @0 :Text;
  tunnelSecret @1 :Data;
}

interface RegistrationServer {
  registerConnection @0 (auth :TunnelAuth, tunnelId :Data, connIndex :UInt8, options :ConnectionOptions) -> (result :ConnectionResponse);
  unregisterConnection @1 () -> ();
  updateLocalConfiguration @2 (config :Data) -> ();
}
