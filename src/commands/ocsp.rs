//! Online Responder (OCSP) commands (Phase L).
//!
//! `ocsp.install` puts the Online Responder role service on the web host —
//! deliberately *only* that role service (no Certification Authority on
//! SRV1). Idempotent: an already-configured responder is a success, so
//! converging plans re-run clean.
//!
//! `ocsp.configure_revocation` is the catalog's **CertAdm COM canary**:
//! there are no first-class cmdlets for a revocation configuration, so it
//! drives `CertAdm.OCSPAdmin` directly. The lab guide itself marks the COM
//! skeleton "not copy-paste-ready — verify every property first"; per the
//! Phase L canary protocol this script must be frozen against a
//! hand-configured `ocsp.msc` dump (`$ocsp.OCSPCAConfigurationCollection |
//! Format-List *`) before the deploy path relies on it. The step is fatal in
//! the deploy plan, so a COM property that doesn't match reality fails the
//! op rather than shipping a silently unconfigured responder — which is why
//! the COM block labels the phase it threw in.
//!
//! `SigningFlags` is the one property no longer on that footing: it is composed
//! from the documented `OCSP_SF_*` values and its two documented constraints are
//! asserted in tests, because guessing it is exactly what shipped a responder
//! that reported itself configured and answered HTTP 500 to every request. The
//! remaining provider properties are still canary.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required,
        valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `Install-WindowsFeature ADCS-Online-Cert` + `Install-AdcsOnlineResponder`.
pub struct OcspInstall;

impl CommandHandler for OcspInstall {
    fn name(&self) -> &'static str {
        "ocsp.install"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "installing Online Responder",
            20.0,
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools | Out-Null; \
            Import-Module ADCSDeployment; \
            try { Install-AdcsOnlineResponder -Force | Out-Null } \
            catch { if ($_.Exception.Message -notmatch 'already') { throw } }; \
            (Get-Service ocspsvc).Status.ToString()";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let result = json!({
            "installed": true,
            "service": output.stdout.trim()
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

// Signing flags for a revocation configuration, from the table on
// `IOCSPCAConfiguration::put_SigningFlags` (certadm.h). The names below were
// right all along; an earlier revision paired each with the value of the flag
// one slot beneath it and hardcoded the sum as `0x175`, which set
// MANUAL_ASSIGN_SIGNINGCERT (an administrator supplies the certificate) while
// nothing here ever assigns `SigningCertificate`. A responder configured that
// way reads back perfectly over COM -- `configured: true`, a template, a
// CAConfig -- and answers every request with HTTP 500, because
// `ErrorCode 0x8009100E CRYPT_E_SIGNER_NOT_FOUND` means it has no signer at all.
//
// So they are declared and composed rather than summed by hand, and the two
// documented constraints are asserted in the tests below:
//   * exactly one of USE_CACERT / AUTODISCOVER_SIGNINGCERT /
//     MANUAL_ASSIGN_SIGNINGCERT must be set;
//   * AUTOENROLLMENT additionally requires AUTODISCOVER_SIGNINGCERT.
const OCSP_SF_SILENT: u32 = 0x001;
const OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL: u32 = 0x004;
const OCSP_SF_FORCE_SIGNINGCERT_ISSUER_ISCA: u32 = 0x008;
const OCSP_SF_AUTODISCOVER_SIGNINGCERT: u32 = 0x010;
const OCSP_SF_RESPONDER_ID_KEYHASH: u32 = 0x040;
const OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT: u32 = 0x200;
// The two certificate sources this lab does not use, named so the exclusivity
// constraint can be asserted rather than assumed: USE_CACERT needs the responder
// on the CA host, and MANUAL_ASSIGN is what `0x175` wrongly selected.
#[cfg(test)]
const OCSP_SF_USE_CACERT: u32 = 0x002;
#[cfg(test)]
const OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT: u32 = 0x020;

/// Default responder signing flags: discover and auto-enroll a delegated signing
/// certificate issued by the configured CA, renew it silently, and identify
/// responses by key hash. NONCE support is deliberately absent -- Windows
/// CryptoAPI clients don't send nonces, and enabling it suppresses response
/// caching. It was only ever set as a side effect of the shifted values.
const OCSP_SIGNING_FLAGS: u32 = OCSP_SF_SILENT
    | OCSP_SF_ALLOW_SIGNINGCERT_AUTORENEWAL
    | OCSP_SF_FORCE_SIGNINGCERT_ISSUER_ISCA
    | OCSP_SF_AUTODISCOVER_SIGNINGCERT
    | OCSP_SF_RESPONDER_ID_KEYHASH
    | OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT;

/// CLSID of the Microsoft CRL-based revocation provider.
const CRL_PROVIDER_CLSID: &str = "{4956d17f-88fd-4198-b287-1e6e65883b19}";

fn valid_config_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c))
}

/// The issuing CA's config string (`host\CA Common Name`).
fn valid_ca_config(value: &str) -> bool {
    match value.split_once('\\') {
        Some((host, ca_name)) => {
            (1..=253).contains(&host.len())
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ".-".contains(c))
                && (1..=64).contains(&ca_name.len())
                && ca_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c))
        }
        None => false,
    }
}

fn valid_url_list(raw: &str) -> bool {
    raw.split(',').map(str::trim).all(|url| {
        !url.is_empty()
            && (url.starts_with("http://") || url.starts_with("https://"))
            && !url.chars().any(|c| "\"'`;$ ".contains(c))
    })
}

/// Create (or replace) a named revocation configuration on the local Online
/// Responder via `CertAdm.OCSPAdmin`: CA cert read from `caCertPath`, the
/// CRL-based revocation provider pointed at the supplied base/delta CRL
/// URLs, validity-period refresh disabled in favour of a fixed refresh
/// interval (the lab's 15-minute setting).
///
/// The CA certificate is read off disk rather than fetched with
/// `certutil -config <ca> -ca.cert`: the plan already relays it to this host
/// (the CertEnroll copy the CDP/AIA vdir serves), and the fetch it replaces
/// wrote to a fixed path without `-f`, which made this command succeed at
/// most once per VM and then fail forever with a message blaming the CA.
pub struct OcspConfigureRevocation;

impl CommandHandler for OcspConfigureRevocation {
    fn name(&self) -> &'static str {
        "ocsp.configure_revocation"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let name = required(ctx, "name")?;
        if !valid_config_name(name) {
            return Err(invalid(
                "name",
                "must be 1-64 chars of [A-Za-z0-9 ._-]",
            ));
        }
        let ca_config = required(ctx, "caConfig")?;
        if !valid_ca_config(ca_config) {
            return Err(invalid(
                "caConfig",
                "must be a 'host\\CA Common Name' config string",
            ));
        }
        let ca_cert_path = required(ctx, "caCertPath")?;
        if !valid_windows_path(ca_cert_path) {
            return Err(invalid(
                "caCertPath",
                "must be an absolute Windows path",
            ));
        }
        let template = param(ctx, "template").unwrap_or("OCSPResponseSigning");
        let template_ok = (1..=64).contains(&template.len())
            && template
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
        if !template_ok {
            return Err(invalid("template", "must be a template CN name"));
        }
        let refresh_minutes = param(ctx, "refreshMinutes").unwrap_or("15");
        match refresh_minutes.parse::<u32>() {
            Ok(m) if (1..=1440).contains(&m) => {}
            _ => {
                return Err(invalid(
                    "refreshMinutes",
                    "must be an integer in 1-1440",
                ));
            }
        }
        let base_crl_urls = required(ctx, "baseCrlUrls")?;
        if !valid_url_list(base_crl_urls) {
            return Err(invalid(
                "baseCrlUrls",
                "must be a comma-separated list of http(s) URLs",
            ));
        }
        let delta_crl_urls = param(ctx, "deltaCrlUrls").unwrap_or_default();
        if !delta_crl_urls.is_empty() && !valid_url_list(delta_crl_urls) {
            return Err(invalid(
                "deltaCrlUrls",
                "must be a comma-separated list of http(s) URLs",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "configuring revocation",
            30.0,
        ));

        // Replace-then-create keeps the command idempotent; RefreshTimeOut
        // (ms) both disables validity-period refresh and sets the manual
        // interval — the lab's "15 min" GUI step. `$stage` carries the COM
        // block's phase into the throw: the block is one long line, so a bare
        // COM HRESULT would otherwise surface as an opaque `char:343`.
        let script = "param([string]$Name,[string]$CaConfig,[string]$CaCertPath,[string]$Template,[string]$RefreshMinutes,[string]$BaseCrlUrls,[string]$DeltaCrlUrls,[string]$SigningFlags,[string]$ProviderClsid) \
            $ErrorActionPreference = 'Stop'; \
            if (-not (Test-Path -LiteralPath $CaCertPath)) { throw \"CA certificate not found at $CaCertPath\" }; \
            $caCertBytes = [System.IO.File]::ReadAllBytes($CaCertPath); \
            $stage = 'opening the responder configuration'; \
            try { \
                $ocsp = New-Object -ComObject CertAdm.OCSPAdmin; \
                $ocsp.GetConfiguration($env:COMPUTERNAME, $true); \
                $stage = 'creating the revocation configuration'; \
                $existing = @($ocsp.OCSPCAConfigurationCollection | Where-Object { $_.Identifier -eq $Name }); \
                if ($existing.Count -gt 0) { $ocsp.OCSPCAConfigurationCollection.DeleteCAConfiguration($Name) }; \
                $cfg = $ocsp.OCSPCAConfigurationCollection.CreateCAConfiguration($Name, $caCertBytes); \
                $stage = 'setting revocation configuration properties'; \
                $cfg.CAConfig = $CaConfig; \
                $cfg.SigningCertificateTemplate = $Template; \
                $cfg.HashAlgorithm = 'SHA256'; \
                $cfg.SigningFlags = [int]$SigningFlags; \
                $props = New-Object -ComObject CertAdm.OCSPPropertyCollection; \
                [void]$props.CreateProperty('BaseCrlUrls', [string[]]@($BaseCrlUrls -split ',')); \
                if ($DeltaCrlUrls) { [void]$props.CreateProperty('DeltaCrlUrls', [string[]]@($DeltaCrlUrls -split ',')) }; \
                [void]$props.CreateProperty('RefreshTimeOut', [int]$RefreshMinutes * 60000); \
                $cfg.ProviderProperties = $props.GetAllProperties(); \
                $cfg.ProviderCLSID = $ProviderClsid; \
                $stage = 'saving the responder configuration'; \
                $ocsp.SetConfiguration($env:COMPUTERNAME, $true) \
            } catch { throw \"$stage failed: $($_.Exception.Message)\" }; \
            $Name";
        let args = [
            name.to_string(),
            ca_config.to_string(),
            ca_cert_path.to_string(),
            template.to_string(),
            refresh_minutes.to_string(),
            base_crl_urls.to_string(),
            delta_crl_urls.to_string(),
            OCSP_SIGNING_FLAGS.to_string(),
            CRL_PROVIDER_CLSID.to_string(),
        ];
        require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "name": name,
            "ca_config": ca_config,
            "ca_cert_path": ca_cert_path,
            "template": template,
            "refresh_minutes": refresh_minutes,
            "base_crl_urls": base_crl_urls,
            "delta_crl_urls": if delta_crl_urls.is_empty() { serde_json::Value::Null } else { json!(delta_crl_urls) }
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// COM readback of every revocation configuration plus an HTTP probe of the
/// local `/ocsp` endpoint. Reports facts (an empty collection or a dead
/// endpoint is a successful read) — the engine's predicate decides.
pub struct OcspVerify;

impl CommandHandler for OcspVerify {
    fn name(&self) -> &'static str {
        "ocsp.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "verifying responder",
            50.0,
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            $ocsp = New-Object -ComObject CertAdm.OCSPAdmin; \
            $ocsp.GetConfiguration($env:COMPUTERNAME, $true); \
            $configs = @($ocsp.OCSPCAConfigurationCollection | ForEach-Object { @{ identifier = $_.Identifier; caConfig = $_.CAConfig; template = $_.SigningCertificateTemplate; hashAlgorithm = $_.HashAlgorithm } }); \
            $status = 0; \
            try { $status = [int](Invoke-WebRequest -Uri 'http://localhost/ocsp' -UseBasicParsing -TimeoutSec 15).StatusCode } \
            catch { if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } }; \
            @{ configurations = $configs; httpStatus = $status } | ConvertTo-Json -Depth 4";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let probe = parse_json(&output.stdout);
        let configured = probe["configurations"]
            .as_array()
            .map(|c| !c.is_empty())
            .unwrap_or(false);
        let result = json!({
            "configured": configured,
            "configurations": probe["configurations"],
            "http_status": probe["httpStatus"],
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

    fn revocation_params() -> HashMap<String, String> {
        ctx_params(&[
            ("name", "EC-Issuing-CA"),
            (
                "caConfig",
                "ca02.EncryptionConsulting.com\\EncryptionConsulting Issuing CA",
            ),
            (
                "caCertPath",
                "C:\\CertEnroll\\ca02.EncryptionConsulting.com_EncryptionConsulting Issuing CA.crt",
            ),
            (
                "baseCrlUrls",
                "http://pki.EncryptionConsulting.com/CertEnroll/EncryptionConsulting%20Issuing%20CA.crl",
            ),
            (
                "deltaCrlUrls",
                "http://pki.EncryptionConsulting.com/CertEnroll/EncryptionConsulting%20Issuing%20CA+.crl",
            ),
            ("refreshMinutes", "15"),
        ])
    }

    #[test]
    fn configure_requires_name_ca_config_cert_path_and_base_crls() {
        for missing in ["name", "caConfig", "caCertPath", "baseCrlUrls"] {
            let mut params = revocation_params();
            params.remove(missing);
            let sink = NullProgressSink;
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(
                matches!(
                    OcspConfigureRevocation.execute(&ctx),
                    Err(CommandError::MissingParam(_))
                ),
                "expected MissingParam when '{missing}' is absent"
            );
        }
    }

    #[test]
    fn configure_rejects_config_string_without_ca_name() {
        let mut params = revocation_params();
        params
            .insert("caConfig".into(), "ca02.EncryptionConsulting.com".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            OcspConfigureRevocation.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_rejects_relative_ca_certificate_path() {
        let mut params = revocation_params();
        params.insert("caCertPath".into(), "issuing.crt".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            OcspConfigureRevocation.execute(&ctx),
            Err(CommandError::InvalidParam { name, .. }) if name == "caCertPath"
        ));
    }

    #[test]
    fn configure_rejects_non_http_crl_url() {
        let mut params = revocation_params();
        params.insert("baseCrlUrls".into(), "ftp://pki.example/x.crl".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            OcspConfigureRevocation.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_rejects_out_of_range_refresh() {
        let mut params = revocation_params();
        params.insert("refreshMinutes".into(), "0".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            OcspConfigureRevocation.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_reports_the_applied_config() {
        let params = revocation_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("EC-Issuing-CA\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = OcspConfigureRevocation.execute(&ctx).unwrap();
        assert_eq!(result["name"], "EC-Issuing-CA");
        assert_eq!(result["template"], "OCSPResponseSigning");
        assert_eq!(result["refresh_minutes"], "15");
    }

    /// The fetch this replaced wrote a fixed temp path without `-f`, so it
    /// could only ever succeed once per VM. Nothing may shell out again.
    #[test]
    fn configure_reads_the_ca_certificate_off_disk() {
        let params = revocation_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("EC-Issuing-CA\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        OcspConfigureRevocation.execute(&ctx).unwrap();
        let script = &shell.calls.lock().unwrap()[0];
        assert!(!script.contains("certutil"));
        assert!(script.contains("[System.IO.File]::ReadAllBytes($CaCertPath)"));
    }

    /// A raw COM HRESULT out of a single-line script says only `char:343`.
    #[test]
    fn configure_labels_the_com_stage_it_throws_in() {
        let params = revocation_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("EC-Issuing-CA\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        OcspConfigureRevocation.execute(&ctx).unwrap();
        let script = &shell.calls.lock().unwrap()[0];
        assert!(script.contains("catch { throw \"$stage failed:"));
        for stage in [
            "opening the responder configuration",
            "creating the revocation configuration",
            "setting revocation configuration properties",
            "saving the responder configuration",
        ] {
            assert!(script.contains(stage), "missing stage label: {stage}");
        }
    }

    #[test]
    fn verify_reports_configured_responder() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"configurations":[{"identifier":"EC-Issuing-CA","caConfig":"ca02\\EC Issuing CA","template":"OCSPResponseSigning","hashAlgorithm":"SHA256"}],"httpStatus":200}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = OcspVerify.execute(&ctx).unwrap();
        assert_eq!(result["configured"], true);
        assert_eq!(result["http_status"], 200);
    }

    #[test]
    fn verify_reports_unconfigured_responder_without_erroring() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(r#"{"configurations":[],"httpStatus":0}"#);
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = OcspVerify.execute(&ctx).unwrap();
        assert_eq!(result["configured"], false);
    }

    #[test]
    fn install_reports_service_status() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("Running\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = OcspInstall.execute(&ctx).unwrap();
        assert_eq!(result["installed"], true);
        assert_eq!(result["service"], "Running");
    }

    #[test]
    fn install_propagates_role_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "Install-WindowsFeature failed");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            OcspInstall.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    /// `IOCSPCAConfiguration::put_SigningFlags`: "you must specify one of the
    /// values OCSP_SF_USE_CACERT, OCSP_SF_AUTODISCOVER_SIGNINGCERT, or
    /// OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT". `0x175` set two of the three, which is
    /// how the responder ended up waiting for a certificate nobody assigns.
    #[test]
    fn signing_flags_pick_exactly_one_certificate_source() {
        let sources = [
            OCSP_SF_USE_CACERT,
            OCSP_SF_AUTODISCOVER_SIGNINGCERT,
            OCSP_SF_MANUAL_ASSIGN_SIGNINGCERT,
        ];
        let selected = sources
            .iter()
            .filter(|flag| OCSP_SIGNING_FLAGS & *flag != 0)
            .count();
        assert_eq!(selected, 1, "flags = {OCSP_SIGNING_FLAGS:#05x}");
        assert_eq!(
            OCSP_SIGNING_FLAGS & OCSP_SF_AUTODISCOVER_SIGNINGCERT,
            OCSP_SF_AUTODISCOVER_SIGNINGCERT
        );
    }

    /// Same page: "If you specify OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT, you
    /// must also specify OCSP_SF_AUTODISCOVER_SIGNINGCERT."
    #[test]
    fn signing_cert_autoenrollment_implies_autodiscovery() {
        if OCSP_SIGNING_FLAGS & OCSP_SF_ALLOW_SIGNINGCERT_AUTOENROLLMENT != 0 {
            assert_ne!(
                OCSP_SIGNING_FLAGS & OCSP_SF_AUTODISCOVER_SIGNINGCERT,
                0
            );
        }
    }

    /// Pins the composed value so a future edit to the flag set is a visible
    /// decision rather than a silently different number on the wire.
    #[test]
    fn signing_flags_compose_to_the_documented_default() {
        assert_eq!(OCSP_SIGNING_FLAGS, 0x25D);
    }
}
