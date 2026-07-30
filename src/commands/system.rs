//! System-level commands (Phase L).
//!
//! `system.reboot` is the one command whose *success* looks like a dropped
//! connection: rebooting cmdlets in this catalog never self-reboot
//! (`Install-ADDSForest -NoRebootOnCompletion`, `Add-Computer` without
//! `-Restart`) — the backend sequence engine dispatches this as a separate
//! step it marks `expects_disconnect`, then waits for the agent's next
//! phone-home. The `shutdown /r /t <delay>` grace window is what lets the
//! done-frame flush over the socket before the OS goes down.

use std::path::PathBuf;

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{invalid, param, require_success},
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `shutdown /r /t <delaySeconds>` — schedule a reboot and report done.
pub struct SystemReboot;

impl CommandHandler for SystemReboot {
    fn name(&self) -> &'static str {
        "system.reboot"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let delay = param(ctx, "delaySeconds").unwrap_or("10");
        match delay.parse::<u32>() {
            Ok(d) if (5..=120).contains(&d) => {}
            _ => {
                return Err(invalid(
                    "delaySeconds",
                    "must be an integer in 5-120",
                ));
            }
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "scheduling reboot",
            50.0,
        ));

        let script = "param([string]$Delay) \
            shutdown /r /t $Delay /c 'pki-executor plan reboot'; \
            exit $LASTEXITCODE";
        let output =
            require_success(ctx.shell.run(script, &[delay.to_string()])?)?;
        drop(output);

        let result = json!({ "rebooting": true, "delay_seconds": delay });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// One-shot boot snapshot: uptime plus whether the base image's
/// `FirstBootFinalize` scheduled task is still registered. The backend's
/// boot-settle gate probes this to tell the intermediate firstboot boot
/// (finalize reboot still pending) from the final settled boot, instead of
/// inferring it from connection-stability heuristics. Read tier — reveals
/// nothing a guest couldn't already see.
///
/// Computed natively, never via PowerShell: on exactly the boots this probe
/// exists for (a fresh clone's post-setup servicing/ngen storm, pre-logon),
/// `powershell.exe` cold-start plus the WMI-backed cmdlets block until a
/// console logon — every shelled-out probe wedged and the settle gate hung.
///
/// * uptime: `GetTickCount64`, monotonic per boot — also immune to the NTP
///   wall-clock steps that could make a `(Get-Date) - LastBootUpTime`
///   difference go backwards and false-reset the backend's same-boot check.
/// * finalize pending: the task is registered with no `-TaskPath`
///   (FirstBoot.ps1), so its XML lives at `%SystemRoot%\System32\Tasks\
///   FirstBootFinalize` and unregistration deletes the file — a plain
///   filesystem existence check that cannot hang.
pub struct SystemBootInfo {
    /// Milliseconds since boot — injected for tests.
    tick_ms: fn() -> u64,
    /// The Task Scheduler XML root (`%SystemRoot%\System32\Tasks`).
    tasks_dir: PathBuf,
}

impl Default for SystemBootInfo {
    fn default() -> Self {
        Self {
            tick_ms: real_tick_ms,
            tasks_dir: default_tasks_dir(),
        }
    }
}

#[cfg(windows)]
fn real_tick_ms() -> u64 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetTickCount64() -> u64;
    }
    unsafe { GetTickCount64() }
}

#[cfg(not(windows))]
fn real_tick_ms() -> u64 {
    // Dev builds: /proc/uptime's first field is seconds since boot.
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|secs| (secs * 1000.0) as u64)
        .unwrap_or(0)
}

fn default_tasks_dir() -> PathBuf {
    let root = std::env::var("SystemRoot")
        .unwrap_or_else(|_| r"C:\Windows".to_string());
    PathBuf::from(root).join("System32").join("Tasks")
}

impl CommandHandler for SystemBootInfo {
    fn name(&self) -> &'static str {
        "system.boot_info"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "reading boot info",
            50.0,
        ));

        let uptime_s = (self.tick_ms)() / 1000;
        let task_file = self.tasks_dir.join("FirstBootFinalize");
        let pending = task_file.exists();

        // Whether the finalize task is mid-run isn't observable without the
        // Schedule service (a COM/WMI query — the exact hang this rewrite
        // removes). Report false always: the backend only used it to avoid
        // kicking a mid-run finalize, and at force-reboot uptime a forced
        // reboot converges to the same reboot the finalize would do anyway.
        let result = json!({
            "uptimeS": uptime_s,
            "finalizePending": pending,
            "finalizeRunning": false,
            "raw": format!(
                "tick uptime {uptime_s}s; finalize task file {} {}",
                task_file.display(),
                if pending { "present" } else { "absent" },
            ),
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{powershell::MockPowerShell, report::NullProgressSink};
    use std::{collections::HashMap, sync::Arc};

    fn ctx_params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn reboot_defaults_to_ten_seconds() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = SystemReboot.execute(&ctx).unwrap();
        assert_eq!(result["rebooting"], true);
        assert_eq!(result["delay_seconds"], "10");
    }

    #[test]
    fn reboot_rejects_out_of_range_delay() {
        for delay in ["0", "3", "300", "-1", "ten"] {
            let params = ctx_params(&[("delaySeconds", delay)]);
            let sink = NullProgressSink;
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(matches!(
                SystemReboot.execute(&ctx),
                Err(CommandError::InvalidParam { .. })
            ));
        }
    }

    #[test]
    fn reboot_propagates_shutdown_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "Access is denied.(5)");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            SystemReboot.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    fn boot_info(tick_ms: fn() -> u64, tasks_dir: PathBuf) -> SystemBootInfo {
        SystemBootInfo { tick_ms, tasks_dir }
    }

    /// Runs the handler with an empty context — no shell responses queued,
    /// which doubles as the no-PowerShell proof: a shell call would pop the
    /// (empty) mock queue's default, and `calls` below asserts zero.
    fn run_boot_info(
        handler: &SystemBootInfo,
    ) -> (serde_json::Value, Arc<MockPowerShell>) {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: shell.clone(),
        };
        (handler.execute(&ctx).unwrap(), shell)
    }

    #[test]
    fn boot_info_reports_a_settled_boot() {
        let dir = tempfile::tempdir().unwrap();
        let handler = boot_info(|| 412_000, dir.path().to_path_buf());
        let (result, shell) = run_boot_info(&handler);
        assert_eq!(result["uptimeS"], 412);
        assert_eq!(result["finalizePending"], false);
        assert_eq!(result["finalizeRunning"], false);
        assert!(shell.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn boot_info_reports_finalize_pending() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("FirstBootFinalize"), "<Task/>")
            .unwrap();
        let handler = boot_info(|| 38_000, dir.path().to_path_buf());
        let (result, _) = run_boot_info(&handler);
        assert_eq!(result["uptimeS"], 38);
        assert_eq!(result["finalizePending"], true);
        // Not observable without the Schedule service — pinned to false.
        assert_eq!(result["finalizeRunning"], false);
        assert!(result["raw"].as_str().unwrap().contains("present"));
    }

    #[test]
    fn boot_info_default_reads_the_real_system() {
        // The Default wiring (real tick source + Tasks dir) must produce a
        // plausible snapshot on any dev or CI machine: a positive uptime and
        // a boolean pending flag (false everywhere but a mid-firstboot VM).
        let (result, _) = run_boot_info(&SystemBootInfo::default());
        assert!(result["uptimeS"].as_u64().unwrap() > 0);
        assert!(result["finalizePending"].is_boolean());
    }

    #[test]
    fn boot_info_is_read_tier() {
        assert_eq!(
            SystemBootInfo::default().required_capability(),
            Capability::VmRead
        );
    }
}
