//! Linux implementations of the shared command names.
//!
//! `build_default_registry` registers the Windows handlers unconditionally and
//! then, under `cfg(unix)`, *layers* these over them by name
//! (`CommandRegistry::register` overwrites) — so the catalog's name and
//! capability set stays byte-identical on both platforms and only the behaviour
//! behind a name changes. That is what lets one
//! `tests/fixtures/command_catalog.json` keep speaking for both, and it is why
//! every handler here keeps its Windows sibling's **result shape**: the
//! backend's sequence engine, `wait_for_settled_boot` and the manifest all
//! parse one shape regardless of which OS answered.
//!
//! What is deliberately *not* here: `system.boot_info`'s `finalizePending`.
//! The Windows probe reads a Task Scheduler XML file that firstboot
//! unregisters; there is no Linux equivalent to key it off, so the Linux arm
//! reports it honestly as `false` rather than leaning on the shared
//! `default_tasks_dir()`, which on Linux yields the literal
//! `C:\Windows/System32/Tasks` and could only ever answer `false` by accident.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required, valid_posix_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// 256 KiB decoded — the same relay cap the Windows `file.*` pair enforces.
const RELAY_CAP_BYTES: usize = 256 * 1024;
const RELAY_CAP_B64: usize = RELAY_CAP_BYTES / 3 * 4 + 4;

/// The Linux relay allowlist. Deliberately narrow, and deliberately *not* a
/// superset of anywhere a product installer writes: `file.write` is reachable
/// by any provisioning caller, so the only paths it may reach are the product
/// tree the backend put there and a scratch dir nothing else owns.
const ALLOWED_PREFIXES: &[&str] = &[
    "/opt/certsecure-manager/",
    "/var/lib/pki-executor/transfer/",
];

fn relay_path_ok(path: &str) -> bool {
    valid_posix_path(path)
        && !path.contains("..")
        && ALLOWED_PREFIXES
            .iter()
            .any(|prefix| path.len() > prefix.len() && path.starts_with(prefix))
}

fn invalid_relay_path() -> CommandError {
    invalid(
        "path",
        "must be an absolute path under /opt/certsecure-manager/ or \
         /var/lib/pki-executor/transfer/",
    )
}

/// `uname -n` — the Linux half of `hostname.read`.
pub struct HostnameRead;

impl CommandHandler for HostnameRead {
    fn name(&self) -> &'static str {
        "hostname.read"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress
            .report(crate::report::OpRunState::running("reading", 50.0));
        let output = require_success(ctx.shell.run("uname -n", &[])?)?;
        let result = json!({ "hostname": output.stdout.trim() });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `/etc/os-release` + `uname -r`, shaped exactly like the Windows
/// `Win32_OperatingSystem` answer so the lab-health aggregate needs no branch.
/// `product_type` follows the Windows encoding (1 workstation, 2 domain
/// controller, 3 server): a Linux product appliance is a server, and it can
/// never be a domain controller.
pub struct SystemIdentity;

impl CommandHandler for SystemIdentity {
    fn name(&self) -> &'static str {
        "system.identity"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "reading system identity",
            50.0,
        ));

        // `.` the file rather than parse it: os-release is defined as
        // shell-sourceable, and PRETTY_NAME routinely contains spaces and
        // parentheses that a naive cut would mangle.
        let script = r#"set -eu
. /etc/os-release
printf '{"hostname":"%s","operating_system":"%s","version":"%s","product_type":3,"server":true}' \
  "$(uname -n)" "${PRETTY_NAME:-${NAME:-Linux}}" "$(uname -r)"
"#;
        let output = require_success(ctx.shell.run(script, &[])?)?;
        let result = parse_json(&output.stdout);
        if !result.is_object() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: 1,
                    stderr: "system.identity returned invalid JSON".into(),
                },
            ));
        }
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Schedule a reboot after a grace window, so the step's done-frame flushes
/// over the socket before the box goes down — the same contract
/// `shutdown /r /t <delay>` provides on Windows.
///
/// `shutdown -r` takes *minutes*, not seconds, so it cannot express this
/// window at all; a transient systemd timer can, and falls back to a detached
/// `sleep` on an image without `systemd-run`.
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

        let script = r#"set -eu
delay="$1"
if command -v systemd-run >/dev/null 2>&1; then
  systemd-run --quiet --on-active="${delay}s" /usr/bin/systemctl reboot
else
  # Detached from this shell so the executor's wait on it returns immediately
  # and the reboot still happens after the grace window.
  nohup sh -c "sleep ${delay}; /sbin/shutdown -r now" >/dev/null 2>&1 &
fi
"#;
        let output =
            require_success(ctx.shell.run(script, &[delay.to_string()])?)?;
        drop(output);

        let result = json!({ "rebooting": true, "delay_seconds": delay });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Uptime from `/proc/uptime`, with `finalizePending` pinned false.
///
/// The Linux firstboot runner owns exactly one reboot and registers no
/// scheduled task, so there is nothing for the pending flag to observe; the
/// backend's settle gate therefore decides purely on the uptime floor plus its
/// confirming same-boot probe, which is the branch it already takes on a
/// current Windows image.
pub struct SystemBootInfo {
    /// Milliseconds since boot — injected for tests.
    uptime_ms: fn() -> u64,
}

impl Default for SystemBootInfo {
    fn default() -> Self {
        Self {
            uptime_ms: real_uptime_ms,
        }
    }
}

fn real_uptime_ms() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
        .map(|secs| (secs * 1000.0) as u64)
        .unwrap_or(0)
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
        let uptime_s = (self.uptime_ms)() / 1000;
        let result = json!({
            "uptimeS": uptime_s,
            "finalizePending": false,
            "finalizeRunning": false,
            "raw": format!(
                "/proc/uptime {uptime_s}s; no firstboot finalize task on Linux",
            ),
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Read one relay-eligible file as base64 (+ sha256), same result shape as the
/// Windows `file.read`.
pub struct FileRead;

impl CommandHandler for FileRead {
    fn name(&self) -> &'static str {
        "file.read"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = required(ctx, "path")?;
        if !relay_path_ok(path) {
            return Err(invalid_relay_path());
        }

        ctx.progress
            .report(crate::report::OpRunState::running("reading file", 30.0));

        let script = r#"set -eu
path="$1"
cap="$2"
size=$(stat -c %s "$path")
if [ "$size" -gt "$cap" ]; then
  echo "file exceeds the relay cap" >&2
  exit 1
fi
printf '{"contentB64":"%s","sha256":"%s","size":%s}' \
  "$(base64 -w0 "$path")" "$(sha256sum "$path" | cut -d' ' -f1)" "$size"
"#;
        let args = [path.to_string(), RELAY_CAP_BYTES.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let payload = parse_json(&output.stdout);
        if payload["contentB64"].as_str().is_none() {
            return Err(invalid("path", "file could not be read"));
        }
        let result = json!({
            "path": path,
            "contentB64": payload["contentB64"],
            "sha256": payload["sha256"],
            "size": payload["size"]
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Write one relay-carried file from base64 (+ sha256 readback).
pub struct FileWrite;

impl CommandHandler for FileWrite {
    fn name(&self) -> &'static str {
        "file.write"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = required(ctx, "path")?;
        if !relay_path_ok(path) {
            return Err(invalid_relay_path());
        }
        let content = required(ctx, "contentB64")?;
        if content.len() > RELAY_CAP_B64 {
            return Err(invalid("contentB64", "exceeds the 256 KiB relay cap"));
        }
        let b64_ok = !content.is_empty()
            && content
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c));
        if !b64_ok {
            return Err(invalid("contentB64", "must be base64"));
        }

        ctx.progress
            .report(crate::report::OpRunState::running("writing file", 30.0));

        let script = r#"set -eu
path="$1"
mkdir -p "$(dirname "$path")"
printf '%s' "$2" | base64 -d > "$path"
sha256sum "$path" | cut -d' ' -f1
"#;
        let args = [path.to_string(), content.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "path": path,
            "sha256": output.stdout.trim()
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

// Kept so the struct field above stays constructible from tests without
// exposing the injection point publicly.
impl SystemBootInfo {
    #[cfg(test)]
    fn with_uptime(uptime_ms: fn() -> u64) -> Self {
        Self { uptime_ms }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{powershell::MockPowerShell, report::NullProgressSink};
    use std::{collections::HashMap, sync::Arc};

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn hostname_read_trims_the_shell_output() {
        let map = HashMap::new();
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("certsecure01\n");
        let ctx = CommandContext {
            params: &map,
            progress: &NullProgressSink,
            shell,
        };
        assert_eq!(
            HostnameRead.execute(&ctx).unwrap()["hostname"],
            "certsecure01"
        );
    }

    #[test]
    fn system_identity_keeps_the_windows_result_shape() {
        let map = HashMap::new();
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"hostname":"cs01","operating_system":"Ubuntu 24.04.3 LTS","version":"6.8.0-79-generic","product_type":3,"server":true}"#,
        );
        let ctx = CommandContext {
            params: &map,
            progress: &NullProgressSink,
            shell,
        };
        let result = SystemIdentity.execute(&ctx).unwrap();
        assert_eq!(result["hostname"], "cs01");
        assert_eq!(result["server"], true);
        assert_eq!(result["product_type"], 3);
    }

    #[test]
    fn reboot_rejects_out_of_range_delay() {
        for delay in ["0", "3", "300", "-1", "ten"] {
            let map = params(&[("delaySeconds", delay)]);
            let ctx = CommandContext {
                params: &map,
                progress: &NullProgressSink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(matches!(
                SystemReboot.execute(&ctx),
                Err(CommandError::InvalidParam { .. })
            ));
        }
    }

    /// The settle gate keys on `finalizePending` being a *boolean* and on
    /// uptime advancing; a Linux guest must answer both without ever reading
    /// the Windows Tasks directory.
    #[test]
    fn boot_info_reports_uptime_and_never_a_pending_finalize() {
        let handler = SystemBootInfo::with_uptime(|| 412_000);
        let map = HashMap::new();
        let shell = Arc::new(MockPowerShell::new());
        let ctx = CommandContext {
            params: &map,
            progress: &NullProgressSink,
            shell: shell.clone(),
        };
        let result = handler.execute(&ctx).unwrap();
        assert_eq!(result["uptimeS"], 412);
        assert_eq!(result["finalizePending"], false);
        assert_eq!(result["finalizeRunning"], false);
        // No shell call: the probe runs on the boots where a cold interpreter
        // is least trustworthy, exactly as on Windows.
        assert!(shell.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn relay_rejects_paths_outside_the_allowlist() {
        for path in [
            "/etc/passwd",
            "/opt/certsecure-manager/../../etc/shadow",
            "C:\\Transfer\\root-ca.crt",
            "/opt/certsecure-manager/",
            "opt/certsecure-manager/x",
        ] {
            let map = params(&[("path", path)]);
            let ctx = CommandContext {
                params: &map,
                progress: &NullProgressSink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(
                matches!(
                    FileRead.execute(&ctx),
                    Err(CommandError::InvalidParam { .. })
                ),
                "{path} should be rejected"
            );
        }
    }

    /// The layering only works while every override answers to the *same*
    /// name and capability as the handler it replaces — otherwise the unix
    /// build would grow (or lose) a catalog entry and the shared fixture would
    /// stop speaking for both platforms.
    #[test]
    fn every_override_matches_its_windows_sibling() {
        let overrides: Vec<(&dyn CommandHandler, &dyn CommandHandler)> = vec![
            (&HostnameRead, &crate::commands::hostname_read::HostnameRead),
            (
                &SystemIdentity,
                &crate::commands::system_identity::SystemIdentity,
            ),
            (&SystemReboot, &crate::commands::system::SystemReboot),
            (&FileRead, &crate::commands::file::FileRead),
            (&FileWrite, &crate::commands::file::FileWrite),
        ];
        for (linux, windows) in overrides {
            assert_eq!(linux.name(), windows.name());
            assert_eq!(
                linux.required_capability(),
                windows.required_capability(),
                "{} changed capability",
                linux.name()
            );
        }
        let boot = crate::commands::system::SystemBootInfo::default();
        assert_eq!(SystemBootInfo::default().name(), boot.name());
        assert_eq!(
            SystemBootInfo::default().required_capability(),
            boot.required_capability()
        );
    }

    #[test]
    fn relay_accepts_a_path_inside_the_product_tree() {
        let map = params(&[("path", "/opt/certsecure-manager/conf/cert.pem")]);
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(r#"{"contentB64":"QQ==","sha256":"ab","size":1}"#);
        let ctx = CommandContext {
            params: &map,
            progress: &NullProgressSink,
            shell,
        };
        let result = FileRead.execute(&ctx).unwrap();
        assert_eq!(result["contentB64"], "QQ==");
    }
}
