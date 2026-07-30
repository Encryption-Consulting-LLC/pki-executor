//! The core run-loop body, shared by both the console dev/CI path (`connect`
//! CLI subcommand) and the real Windows-Service-invoked path (see
//! `service::scm`). There is exactly one control-flow implementation, not
//! two.
//!
//! This bridges the sync CLI/SCM entry points to the async phone-home loop
//! (`crate::phonehome::run_forever`) with a dedicated Tokio runtime — the
//! rest of the crate stays synchronous; only the networking layer is async.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::{
    commands::build_default_registry,
    config::ExecutorConfig,
    phonehome,
    powershell::{PowerShellExecutor, RealPowerShell},
};

/// Acquire the machine-wide single-instance lock, held for the process
/// lifetime (the OS releases it on any exit, clean or not). `share_mode(0)`
/// means no other process can open the file while we hold it, so a second
/// agent (e.g. the service plus a manual `connect` run) fails fast instead of
/// dueling with this one over the backend connection (4409 evictions).
#[cfg(windows)]
fn acquire_instance_lock() -> Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = std::path::Path::new(r"C:\ProgramData\PkiExecutor");
    std::fs::create_dir_all(dir)
        .context("creating the agent data directory")?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(dir.join("agent.lock"))
        .context(
            "another pki-executor instance is already running \
             (could not acquire agent.lock)",
        )
}

#[cfg(not(windows))]
fn acquire_instance_lock() -> Result<()> {
    Ok(()) // dev/CI-only path — the guard is Windows-specific
}

pub fn run_loop(config: &ExecutorConfig) -> Result<()> {
    acquire_instance_lock()?;
    let registry = Arc::new(build_default_registry());
    let shell: Arc<dyn PowerShellExecutor> =
        Arc::new(RealPowerShell::new(config.execution.shell_binary.clone()));

    tracing::info!(
        vm_id = %config.identity.vm_id,
        command_count = registry.len(),
        "executor connecting to backend"
    );

    let runtime = tokio::runtime::Runtime::new()
        .context("building the phone-home tokio runtime")?;
    runtime.block_on(phonehome::run_forever(config, registry, shell))
}
