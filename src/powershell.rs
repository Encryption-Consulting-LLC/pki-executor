//! PowerShell execution, abstracted behind a trait so command handlers are
//! testable without a real shell (or a Windows box).
//!
//! Shells out via `std::process::Command` rather than binding `windows-rs`
//! COM APIs: every v0 command has a plain PowerShell equivalent, and this is
//! the only approach genuinely testable from a non-Windows dev machine. The
//! one step in `vm-building.md` that is genuinely COM-only (Online Responder
//! / `CertAdm.OCSPAdmin`) is explicitly out of scope for v0 — see the README.

use std::process::Command;

#[derive(Debug, Clone)]
pub struct PowerShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl PowerShellOutput {
    pub fn succeeded(&self) -> bool {
        self.exit_code == 0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PowerShellError {
    #[error("failed to spawn '{binary}': {source}")]
    Spawn {
        binary: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write temp script file: {source}")]
    TempScript {
        #[source]
        source: std::io::Error,
    },
    #[error("script exited with code {exit_code}: {stderr}")]
    NonZeroExit { exit_code: i32, stderr: String },
}

/// Executes a PowerShell script and returns its output. Implementations are
/// swappable so command handlers can be unit-tested without a real shell.
pub trait PowerShellExecutor: Send + Sync {
    fn run(
        &self,
        script: &str,
        args: &[String],
    ) -> Result<PowerShellOutput, PowerShellError>;
}

/// Shells out to `binary` (default `powershell.exe`; override to `pwsh` for
/// real cross-platform execution during Linux dev — see
/// `ExecutionConfig::shell_binary`).
pub struct RealPowerShell {
    pub binary: String,
}

impl RealPowerShell {
    pub fn new(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }
}

impl PowerShellExecutor for RealPowerShell {
    fn run(
        &self,
        script: &str,
        args: &[String],
    ) -> Result<PowerShellOutput, PowerShellError> {
        // `-Command <script> <args>` never binds args to the script's
        // `param()` block: PowerShell joins everything after `-Command` into
        // one command string, so the args re-parse as extra statements —
        // params stay empty and untrusted arg text reaches the parser.
        // `-File` binds them positionally as literal strings, but requires a
        // real `.ps1` on disk (the extension is mandatory on Windows).
        let mut file = tempfile::Builder::new()
            .prefix("pki-executor-")
            .suffix(".ps1")
            .tempfile()
            .map_err(|source| PowerShellError::TempScript { source })?;
        std::io::Write::write_all(&mut file, script.as_bytes())
            .map_err(|source| PowerShellError::TempScript { source })?;

        // Close our write handle *before* invoking PowerShell. On Windows a
        // still-open handle can stop `powershell.exe` from loading the `.ps1`
        // (the read is denied against our open write handle), which surfaced
        // as a silent non-zero exit on CI. `into_temp_path` flushes and closes
        // the file while leaving it on disk; the returned `TempPath` deletes it
        // when dropped at the end of this function — after `output()` has run.
        let path = file.into_temp_path();

        // `-ExecutionPolicy Bypass` is required for `-File`: an unsigned
        // `.ps1` on disk is blocked under the default machine policy
        // (Restricted/RemoteSigned), which silently fails the script and is
        // exactly what broke this on Windows CI. `-Command` isn't subject to
        // the file-based policy, hence why the mock path never saw it.
        let output = Command::new(&self.binary)
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&path)
            .args(args)
            .output()
            .map_err(|source| PowerShellError::Spawn {
                binary: self.binary.clone(),
                source,
            })?;

        Ok(PowerShellOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(-1),
        })
    }
}

/// Returns pre-programmed responses in FIFO order, and records every script
/// it was asked to run — for tests only.
#[derive(Default)]
pub struct MockPowerShell {
    responses: std::sync::Mutex<
        std::collections::VecDeque<Result<PowerShellOutput, PowerShellError>>,
    >,
    pub calls: std::sync::Mutex<Vec<String>>,
}

impl MockPowerShell {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_response(
        &self,
        response: Result<PowerShellOutput, PowerShellError>,
    ) {
        self.responses.lock().unwrap().push_back(response);
    }

    pub fn push_success(&self, stdout: impl Into<String>) {
        self.push_response(Ok(PowerShellOutput {
            stdout: stdout.into(),
            stderr: String::new(),
            exit_code: 0,
        }));
    }

    pub fn push_failure(&self, exit_code: i32, stderr: impl Into<String>) {
        self.push_response(Ok(PowerShellOutput {
            stdout: String::new(),
            stderr: stderr.into(),
            exit_code,
        }));
    }
}

impl PowerShellExecutor for MockPowerShell {
    fn run(
        &self,
        script: &str,
        _args: &[String],
    ) -> Result<PowerShellOutput, PowerShellError> {
        self.calls.lock().unwrap().push(script.to_string());
        self.responses.lock().unwrap().pop_front().unwrap_or(Ok(
            PowerShellOutput {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: 0,
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_returns_queued_responses_in_order() {
        let mock = MockPowerShell::new();
        mock.push_success("first");
        mock.push_success("second");

        let first = mock.run("script-a", &[]).unwrap();
        let second = mock.run("script-b", &[]).unwrap();

        assert_eq!(first.stdout, "first");
        assert_eq!(second.stdout, "second");
        assert_eq!(*mock.calls.lock().unwrap(), vec!["script-a", "script-b"]);
    }

    #[test]
    fn mock_defaults_to_empty_success_when_queue_drained() {
        let mock = MockPowerShell::new();
        let output = mock.run("script", &[]).unwrap();
        assert!(output.succeeded());
        assert_eq!(output.stdout, "");
    }

    #[cfg(windows)]
    #[test]
    fn real_powershell_can_invoke_the_actual_shell() {
        let shell = RealPowerShell::new("powershell.exe");
        let output = shell.run("$PSVersionTable.PSVersion.Major", &[]).unwrap();
        assert!(output.succeeded());
    }

    // Regression: `-Command` never bound args to `param()` (they re-parsed
    // as extra statements); `-File` must.
    #[cfg(windows)]
    #[test]
    fn real_powershell_binds_positional_args_to_param() {
        let shell = RealPowerShell::new("powershell.exe");
        let output = shell
            .run("param([string]$X) Write-Output $X", &["bound".to_string()])
            .unwrap();
        assert!(output.succeeded());
        assert_eq!(output.stdout.trim(), "bound");
    }
}
