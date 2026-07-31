//! Certificate distribution commands (Phase L) — the two `certutil` moves
//! every root-cert handoff in `vm-building.md` is built from:
//!
//! * `cert.addstore` — trust a carried cert (or CRL, `kind=crl`) in a local
//!   machine store (CA02/SRV1 trusting the offline root).
//! * `cert.dspublish` — publish a cert/CRL into the AD Configuration
//!   partition. Runs **on the DC**, where the agent's LocalSystem identity
//!   is directory-privileged — dispatching it to a mere member server would
//!   fail on rights.
//!
//! `certutil` doesn't throw PowerShell errors, so both scripts propagate its
//! exit code explicitly (`exit $LASTEXITCODE`).

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, require_success, required, valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

const STORES: &[&str] = &["root", "ca"];

/// What the carried file holds. `certutil -addstore` takes either, but only a
/// certificate has a thumbprint to read back — parsing a CRL as an
/// `X509Certificate2` throws, which would fail a step whose `certutil` half
/// already succeeded.
const KINDS: &[&str] = &["cert", "crl"];

/// `certutil -addstore -f <store> <path>` + thumbprint readback (certs only).
pub struct CertAddStore;

impl CommandHandler for CertAddStore {
    fn name(&self) -> &'static str {
        "cert.addstore"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let store = required(ctx, "store")?;
        if !STORES.contains(&store) {
            return Err(invalid("store", "must be 'root' or 'ca'"));
        }
        let path = required(ctx, "path")?;
        if !valid_windows_path(path) {
            return Err(invalid("path", "must be an absolute Windows path"));
        }
        let kind = param(ctx, "kind").unwrap_or("cert");
        if !KINDS.contains(&kind) {
            return Err(invalid("kind", "must be 'cert' or 'crl'"));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "adding to store",
            30.0,
        ));

        let script = "param([string]$Store,[string]$Path,[string]$Kind) \
            $out = certutil -addstore -f $Store $Path 2>&1 | Out-String; \
            if ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine($out); exit $LASTEXITCODE }; \
            if ($Kind -eq 'crl') { '' } \
            else { (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Path)).Thumbprint }";
        let args = [store.to_string(), path.to_string(), kind.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let thumbprint = output.stdout.trim();
        let result = json!({
            "store": store,
            "path": path,
            "kind": kind,
            "thumbprint": if thumbprint.is_empty() { serde_json::Value::Null } else { json!(thumbprint) }
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Attribute values `certutil -dspublish` accepts here: the cert container
/// keywords, or (for CRLs) the publishing CA's machine name.
fn valid_ds_attribute(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// `certutil -f -dspublish <path> <attribute>` — e.g. `RootCA` for the root
/// cert, or the root CA's machine name for its CRL.
pub struct CertDsPublish;

impl CommandHandler for CertDsPublish {
    fn name(&self) -> &'static str {
        "cert.dspublish"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = required(ctx, "path")?;
        if !valid_windows_path(path) {
            return Err(invalid("path", "must be an absolute Windows path"));
        }
        let attribute = required(ctx, "attribute")?;
        if !valid_ds_attribute(attribute) {
            return Err(invalid(
                "attribute",
                "must be a dspublish keyword (e.g. 'RootCA') or a CA machine name",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "publishing to AD",
            30.0,
        ));

        let script = "param([string]$Path,[string]$Attribute) \
            certutil -f -dspublish $Path $Attribute; \
            exit $LASTEXITCODE";
        let args = [path.to_string(), attribute.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "path": path,
            "attribute": attribute,
            "raw": output.stdout
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
    fn addstore_rejects_unknown_store() {
        let params = ctx_params(&[
            ("store", "disallowed"),
            ("path", "C:\\Transfer\\EC-Root-CA.crt"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertAddStore.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn addstore_rejects_relative_path() {
        let params = ctx_params(&[("store", "root"), ("path", "..\\evil.crt")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertAddStore.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn addstore_reports_thumbprint() {
        let params = ctx_params(&[
            ("store", "root"),
            ("path", "C:\\Transfer\\EC-Root-CA.crt"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("AB12CD34EF56\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CertAddStore.execute(&ctx).unwrap();
        assert_eq!(result["thumbprint"], "AB12CD34EF56");
        assert_eq!(result["store"], "root");
        assert_eq!(result["kind"], "cert");
    }

    #[test]
    fn addstore_rejects_unknown_kind() {
        let params = ctx_params(&[
            ("store", "ca"),
            ("path", "C:\\Transfer\\EC-Root-CA.crl"),
            ("kind", "ctl"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertAddStore.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn addstore_skips_the_thumbprint_readback_for_a_crl() {
        let params = ctx_params(&[
            ("store", "ca"),
            ("path", "C:\\Transfer\\EC-Root-CA.crl"),
            ("kind", "crl"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: shell.clone(),
        };
        let result = CertAddStore.execute(&ctx).unwrap();
        assert_eq!(result["kind"], "crl");
        assert!(result["thumbprint"].is_null());
        let script = shell.calls.lock().unwrap()[0].clone();
        assert!(script.contains("if ($Kind -eq 'crl') { '' }"));
    }

    #[test]
    fn dspublish_requires_attribute() {
        let params = ctx_params(&[("path", "C:\\Transfer\\EC-Root-CA.crt")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertDsPublish.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn dspublish_rejects_injection_shaped_attribute() {
        let params = ctx_params(&[
            ("path", "C:\\Transfer\\EC-Root-CA.crl"),
            ("attribute", "CA01; format C:"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CertDsPublish.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn dspublish_succeeds_for_root_cert_and_crl_forms() {
        for attribute in ["RootCA", "guest-abc12-ca01"] {
            let params = ctx_params(&[
                ("path", "C:\\Transfer\\EC-Root-CA.crt"),
                ("attribute", attribute),
            ]);
            let sink = NullProgressSink;
            let shell = Arc::new(MockPowerShell::new());
            shell.push_success("Certificate added to DS store.");
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell,
            };
            let result = CertDsPublish.execute(&ctx).unwrap();
            assert_eq!(result["attribute"], attribute);
        }
    }

    #[test]
    fn dspublish_propagates_certutil_failure() {
        let params = ctx_params(&[
            ("path", "C:\\Transfer\\EC-Root-CA.crt"),
            ("attribute", "RootCA"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "CertUtil: -dsPublish command FAILED");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            CertDsPublish.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }
}
