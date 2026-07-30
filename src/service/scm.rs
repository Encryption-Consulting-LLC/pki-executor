//! Windows Service Control Manager glue. Compiled only under `cfg(windows)`
//! (see `service/mod.rs`) — this file is not part of the build on Linux, so
//! it is validated by CI's `windows-latest` job, not locally.

use std::{ffi::OsString, sync::mpsc, time::Duration};

use anyhow::{Context, Result};
use tracing_subscriber::EnvFilter;
use windows_service::{
    define_windows_service,
    service::{
        ServiceAccess, ServiceControl, ServiceControlAccept,
        ServiceErrorControl, ServiceExitCode, ServiceInfo, ServiceStartType,
        ServiceState, ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
    service_manager::{ServiceManager, ServiceManagerAccess},
};

const SERVICE_NAME: &str = "PkiExecutor";
const SERVICE_DISPLAY_NAME: &str = "PKI Executor";

pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let exe_path =
        std::env::current_exe().context("resolving current exe path")?;

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("run"),
        ],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };

    manager.create_service(&info, ServiceAccess::empty())?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT,
    )?;
    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;
    Ok(())
}

pub fn run() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("starting service dispatcher")?;
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(err) = run_service() {
        tracing::error!(?err, "service run failed");
    }
}

fn run_service() -> Result<()> {
    // A Windows Service has no attached console — stdout is silently
    // discarded, so logging MUST go to a file, set up before anything else.
    init_file_logging()?;

    let (shutdown_tx, shutdown_rx) = mpsc::channel();

    let handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        service_control_handler::register(SERVICE_NAME, handler)?;

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP
            | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    let config = crate::config::ExecutorConfig::load_default()
        .context("loading service config")?;

    // The phone-home loop never returns in normal operation, so it runs on
    // its own thread; this thread's only job is waiting for a stop signal
    // from the SCM. The loop's connection is torn down when the process
    // exits after this function returns — there is no graceful in-loop
    // shutdown signal wired up yet (v0 scope).
    std::thread::spawn(move || {
        if let Err(err) = super::console::run_loop(&config) {
            tracing::error!(?err, "phone-home loop exited");
        }
    });

    let _ = shutdown_rx.recv();

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

fn init_file_logging() -> Result<()> {
    let work_dir = std::path::PathBuf::from(r"C:\ProgramData\PkiExecutor\logs");
    std::fs::create_dir_all(&work_dir).ok();
    let file_appender =
        tracing_appender::rolling::daily(work_dir, "executor.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    // Leaked deliberately: the guard must live for the process lifetime to
    // flush on drop, and this process only exits via the SCM stop path above.
    Box::leak(Box::new(guard));
    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        // A log FILE has no terminal to interpret colour codes, so ANSI escapes
        // are just noise (`\x1b[2m…\x1b[0m`) littering every field when the file
        // is opened in Notepad. Plain text only for the file sink.
        .with_ansi(false)
        // Honour RUST_LOG like the console path (`main.rs`) so the phone-home
        // frame logging in `phonehome` can be dialled up to `debug` in the
        // field without a rebuild; default `info` keeps the command-level
        // to-and-fro visible.
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    Ok(())
}
