//! Console entry point. `run` is the one-shot command dispatch path — it
//! works on any OS and is the only path exercised in this dev environment
//! and in Linux CI. Windows Service integration hooks into this same `Cli`
//! enum (see `service` module).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{
    commands::build_default_registry,
    config::ExecutorConfig,
    powershell::{PowerShellExecutor, RealPowerShell},
    report::{OpRunState, ProgressSink},
};

#[derive(Parser)]
#[command(
    name = "pki-orchestrator",
    about = "VM-resident PKI orchestrator agent"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-shot command dispatch — works on any OS; the dev/test path.
    Run {
        #[arg(long, default_value = "executor.toml")]
        config: PathBuf,
        /// Registered command name, e.g. `cert.verify`.
        command: String,
        /// key=value, repeatable.
        #[arg(long = "param")]
        params: Vec<String>,
    },
    /// Windows Service Control Manager integration (Windows-only).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Phone home to the backend and serve dispatched commands. Works on
    /// any OS — the dev/Linux-testable path for what `service run` does on
    /// Windows under the SCM.
    Connect {
        #[arg(long, default_value = "executor.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand, Clone, Copy)]
pub enum ServiceAction {
    /// Register this binary with the SCM.
    Install,
    /// Remove this binary's registration from the SCM.
    Uninstall,
    /// Entry point the SCM actually launches (also runnable directly).
    Run,
}

struct StdoutProgressSink;

impl ProgressSink for StdoutProgressSink {
    fn report(&self, state: OpRunState) {
        if let Ok(line) = serde_json::to_string(&state) {
            println!("{line}");
        }
    }
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run {
            config,
            command,
            params,
        } => run_once(&config, &command, params),
        Command::Service { action } => crate::service::handle(action),
        Command::Connect { config } => connect(&config),
    }
}

fn connect(config_path: &Path) -> Result<()> {
    let config =
        ExecutorConfig::load_from_file(config_path).with_context(|| {
            format!("loading config from {}", config_path.display())
        })?;
    crate::service::console::run_loop(&config)
}

fn run_once(
    config_path: &Path,
    command: &str,
    raw_params: Vec<String>,
) -> Result<()> {
    let config =
        ExecutorConfig::load_from_file(config_path).with_context(|| {
            format!("loading config from {}", config_path.display())
        })?;

    let mut params = HashMap::new();
    for entry in raw_params {
        let (key, value) = entry.split_once('=').with_context(|| {
            format!("--param must be key=value, got '{entry}'")
        })?;
        params.insert(key.to_string(), value.to_string());
    }

    let registry = build_default_registry();
    let shell: Arc<dyn PowerShellExecutor> =
        Arc::new(RealPowerShell::new(config.execution.shell_binary.clone()));
    let sink = StdoutProgressSink;

    let result = registry.dispatch(
        command,
        config.identity.role,
        params,
        &sink,
        shell,
    )?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
