//! Local configuration schema, loaded from a TOML file.
//!
//! v0 has no networking, so this file is loaded once at startup from disk
//! (`--config <path>` on the CLI, or a platform default path for the
//! service). Once the executor is packed into a boot ISO, this is where
//! configgen-templated identity/role values will land.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::authz::Role;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutorConfig {
    pub identity: IdentityConfig,
    #[serde(default)]
    pub backend: BackendConfig,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub service: ServiceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Correlates this executor instance to a VM record on the backend.
    /// Issued by `POST /api/executor/register` alongside `agent_token`.
    /// Placeholder for vmkit's still-missing guest-correlation mechanism:
    /// today a human copies both values here by hand before the agent
    /// connects; once isokit/configgen can bake a config into the boot ISO,
    /// this same field lands there automatically instead.
    pub vm_id: String,
    /// The bearer token minted alongside `vm_id` by the backend's register
    /// endpoint, presented on `phonehome::connect` to authenticate this
    /// agent's WebSocket. Required only by the `connect`/`service run`
    /// paths — the one-shot `run` CLI path never talks to a backend.
    #[serde(default)]
    pub agent_token: String,
    /// Fallback role used only by the one-shot `run` CLI path, which has no
    /// backend in the loop to supply one. The `connect` path ignores this —
    /// the backend forwards the caller's real role with every dispatched
    /// command instead (see `phonehome`), which is the authoritative gate.
    pub role: Role,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackendConfig {
    /// Base URL of the EC-PKI-Playground backend, e.g. `http://host:8000`.
    /// Required by the `connect`/`service run` paths; unread by `run`.
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_shell_binary")]
    pub shell_binary: String,
    #[serde(default = "default_script_timeout_secs")]
    pub script_timeout_secs: u64,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            shell_binary: default_shell_binary(),
            script_timeout_secs: default_script_timeout_secs(),
        }
    }
}

fn default_shell_binary() -> String {
    if cfg!(windows) {
        "powershell.exe".to_string()
    } else {
        // The Linux product templates' own shell. A dev box that wants to
        // exercise the Windows handlers still sets this to `pwsh` explicitly —
        // `powershell::build_shell` picks the matching implementation from the
        // name, so that keeps working without a second config knob.
        "/bin/bash".to_string()
    }
}

fn default_script_timeout_secs() -> u64 {
    900
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            log_level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse config file '{path}': {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
}

impl ExecutorConfig {
    pub fn load_from_file(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| {
            ConfigError::Read {
                path: path.to_path_buf(),
                source,
            }
        })?;
        toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })
    }

    /// Platform default config path — used by the Windows Service path, which
    /// has no CLI `--config` argument to draw from.
    ///
    /// The Linux arm must match `40-install-executor.sh` byte for byte: that
    /// script installs the rendered `executor.toml` to this path with mode
    /// 0600, and the systemd unit passes it explicitly. A relative
    /// `executor.toml` (what this was while the agent was Windows-only) would
    /// resolve against the service's working directory, which is `/`.
    pub fn default_path() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\ProgramData\PkiExecutor\config.toml")
        } else {
            PathBuf::from("/etc/pki-executor/config.toml")
        }
    }

    pub fn load_default() -> Result<Self, ConfigError> {
        Self::load_from_file(&Self::default_path())
    }
}
