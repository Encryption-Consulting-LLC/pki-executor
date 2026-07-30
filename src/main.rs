use anyhow::Result;
use clap::Parser;
use pki_executor::cli::{Cli, Command};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // Backstop only: install a process-level rustls crypto provider for any TLS
    // path that resolves it globally. The phone-home connection does NOT rely on
    // this — it passes an explicit provider via `builder_with_provider` (see
    // `phonehome::tls_connector`), because in the release Windows build this
    // global install was not observed at the connect site and rustls panicked on
    // the first handshake. Ignore the error a redundant install would return.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // Console-path logging only — `service run` sets up its own file-based
    // subscriber in `service::scm` (a Windows Service has no attached
    // console to write to), and must be the only one to call `.init()`.
    if !matches!(cli.command, Command::Service { .. }) {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }

    pki_executor::cli::run(cli)
}
