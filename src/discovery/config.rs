//! Loads the optional daemon discovery backend from one YAML file.

use serde::Deserialize;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Validated configuration for one discovery backend.
pub(crate) enum BackendConfig {
    /// Existing LAN center endpoint.
    CustomCenter(SocketAddr),
    /// Cloudflare Workers KV endpoint and credentials.
    CfKv(CfKvConfig),
}

/// Values needed for Cloudflare KV reporting.
pub(crate) struct CfKvConfig {
    /// Bearer token resolved from YAML or the named environment variable.
    pub(crate) token: String,
    /// Namespace title or 32-character namespace ID.
    pub(crate) namespace: String,
    /// Required key prefix; the full key is `prefix/key`.
    pub(crate) prefix: String,
}

/// YAML document with an optional reporter section.
#[derive(Deserialize)]
struct RawConfig {
    /// Backend choice and its fields.
    reporter: Option<RawReporter>,
}

/// Reporter shape selected by `reporter.type`.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum RawReporter {
    /// LAN center address in `ip:port` form.
    CustomCenter {
        /// LAN center socket address.
        host: String,
    },
    /// Cloudflare KV credentials and namespace.
    CfKv {
        /// Literal API token, mutually exclusive with `token_env`.
        token: Option<String>,
        /// Name of an environment variable containing the API token.
        token_env: Option<String>,
        /// Namespace title or ID.
        namespace: String,
        /// Required key prefix.
        prefix: String,
    },
}

/// Loads one backend, giving the CLI center flag absolute precedence.
///
/// Example: `-discover-host 127.0.0.1:9000` -> center without reading YAML.
pub(crate) fn load(cli_center: Option<SocketAddr>) -> Result<Option<BackendConfig>, String> {
    if let Some(center) = cli_center {
        // 触发条件: CLI 明确覆盖配置文件。
        // 不能先读取 YAML: 损坏或缺失的文件会破坏现有 systemd 启动方式。
        // 防止副作用: 原有 -discover-host 部署不依赖新配置文件。
        return Ok(Some(BackendConfig::CustomCenter(center)));
    }

    let explicit_path = env::var_os("CFP_CONFIG");
    let path = match explicit_path.as_ref() {
        Some(raw) if raw.is_empty() => return Err("CFP_CONFIG must not be empty".to_string()),
        Some(raw) => PathBuf::from(raw),
        None => {
            let home = env::var_os("HOME").ok_or("HOME is not set for CFP config path")?;
            PathBuf::from(home).join(".config/cfp/config.yaml")
        }
    };

    let source = match fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && explicit_path.is_none() => {
            return Ok(None);
        }
        Err(error) => {
            return Err(format!(
                "read CFP config {} failed: {error}",
                path.display()
            ))
        }
    };
    let parsed: RawConfig = serde_yaml::from_str(&source)
        .map_err(|error| format!("parse CFP config {} failed: {error}", path.display()))?;
    parsed.reporter.map(validate_reporter).transpose()
}

/// Converts the YAML reporter into a validated runtime backend.
///
/// Example: `token_env: CF_TOKEN` -> token from the process environment.
fn validate_reporter(raw: RawReporter) -> Result<BackendConfig, String> {
    match raw {
        RawReporter::CustomCenter { host } => {
            let center = host
                .parse::<SocketAddr>()
                .map_err(|error| format!("reporter.host must be ip:port: {error}"))?;
            Ok(BackendConfig::CustomCenter(center))
        }
        RawReporter::CfKv {
            token,
            token_env,
            namespace,
            prefix,
        } => {
            let token = match (token, token_env) {
                (Some(token), None) => token,
                (None, Some(name)) if !name.trim().is_empty() => env::var(&name)
                    .map_err(|_| format!("reporter.token_env {name} is not set or invalid"))?,
                _ => {
                    return Err("reporter must set exactly one of token or token_env".to_string());
                }
            };
            if token.trim().is_empty() {
                return Err("reporter token must not be empty".to_string());
            }
            if namespace.trim().is_empty() {
                return Err("reporter.namespace must not be empty".to_string());
            }
            if prefix.trim().is_empty() {
                return Err("reporter.prefix must not be empty".to_string());
            }
            Ok(BackendConfig::CfKv(CfKvConfig {
                token,
                namespace: namespace.trim().to_string(),
                prefix: prefix.trim().to_string(),
            }))
        }
    }
}
