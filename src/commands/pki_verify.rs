use crate::{
    authz::Capability,
    commands::util::{invalid, parse_json, require_success, required},
    registry::{CommandContext, CommandError, CommandHandler},
};

fn valid_ca_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c))
}

fn valid_template(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

fn valid_http_url(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.chars().any(|c| "\"'`;$ <>".contains(c))
        && value.len() <= 512
}

/// Read back the enterprise PKI objects and concrete HTTP publication files
/// from the domain controller, where LocalSystem can query Configuration NC.
pub struct PkiVerify;

impl CommandHandler for PkiVerify {
    fn name(&self) -> &'static str {
        "pki.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let root_ca = required(ctx, "rootCaCommonName")?;
        let issuing_ca = required(ctx, "issuingCaCommonName")?;
        if !valid_ca_name(root_ca) {
            return Err(invalid(
                "rootCaCommonName",
                "must be a valid CA common name",
            ));
        }
        if !valid_ca_name(issuing_ca) {
            return Err(invalid(
                "issuingCaCommonName",
                "must be a valid CA common name",
            ));
        }

        let templates_raw = required(ctx, "templates")?;
        let templates: Vec<_> =
            templates_raw.split(',').map(str::trim).collect();
        if templates.is_empty()
            || !templates.iter().all(|value| valid_template(value))
        {
            return Err(invalid(
                "templates",
                "must be a comma-separated list of template CN names",
            ));
        }

        let urls_raw = required(ctx, "httpUrls")?;
        let urls: Vec<String> =
            serde_json::from_str(urls_raw).map_err(|_| {
                invalid("httpUrls", "must be a JSON array of HTTP URLs")
            })?;
        if urls.is_empty() || !urls.iter().all(|value| valid_http_url(value)) {
            return Err(invalid(
                "httpUrls",
                "must contain one or more valid HTTP URLs",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "verifying enterprise PKI publication",
            50.0,
        ));

        // The `$publicationUrls` two-step below is load-bearing: Windows
        // PowerShell 5.1 writes a decoded JSON array to the pipeline as one
        // object, so `@($HttpUrls | ConvertFrom-Json)` nests it and the loop
        // binds every URL at once. `Invoke-WebRequest -Uri <array>` then throws
        // into the catch, leaving status 0 and reporting the whole PKI
        // unhealthy. The script is one physical line (`\` continuations), so
        // this cannot be a `#` comment in the script itself.
        let script = "param([string]$RootCa,[string]$IssuingCa,[string]$Templates,[string]$HttpUrls) \
            $ErrorActionPreference = 'Stop'; \
            Import-Module ActiveDirectory; \
            $configDn = (Get-ADRootDSE).configurationNamingContext; \
            $pkiBase = \"CN=Public Key Services,CN=Services,$configDn\"; \
            function Child-Names([string]$Container) { @(Get-ADObject -SearchBase \"CN=$Container,$pkiBase\" -SearchScope OneLevel -Filter * | Select-Object -ExpandProperty Name) }; \
            $ntAuth = Get-ADObject -Identity \"CN=NTAuthCertificates,$pkiBase\" -Properties cACertificate; \
            $ntAuthOk = @($ntAuth.cACertificate).Count -gt 0; \
            $aiaNames = Child-Names 'AIA'; \
            $cdpNames = Child-Names 'CDP'; \
            $caNames = Child-Names 'Certification Authorities'; \
            $enrollmentNames = Child-Names 'Enrollment Services'; \
            $templateNames = Child-Names 'Certificate Templates'; \
            $aiaOk = $aiaNames -contains $RootCa -and $aiaNames -contains $IssuingCa; \
            $cdpOk = $cdpNames -contains $RootCa -and $cdpNames -contains $IssuingCa; \
            $caOk = $caNames -contains $RootCa; \
            $enrollmentOk = $enrollmentNames -contains $IssuingCa; \
            $requiredTemplates = @($Templates -split ',' | ForEach-Object { $_.Trim() }); \
            $missingTemplates = @($requiredTemplates | Where-Object { $templateNames -notcontains $_ }); \
            $http = @(); \
            $publicationUrls = $HttpUrls | ConvertFrom-Json; \
            foreach ($url in @($publicationUrls)) { \
                $status = 0; \
                try { $status = [int](Invoke-WebRequest -Uri $url -UseBasicParsing -Method Head -TimeoutSec 20).StatusCode } catch { if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode } }; \
                $http += @{ url = $url; status = $status; ok = ($status -ge 200 -and $status -lt 300) } \
            }; \
            $httpOk = @($http | Where-Object { -not $_.ok }).Count -eq 0; \
            $templatesOk = $missingTemplates.Count -eq 0; \
            @{ healthy = ($ntAuthOk -and $aiaOk -and $cdpOk -and $caOk -and $enrollmentOk -and $templatesOk -and $httpOk); containers = @{ nt_auth = $ntAuthOk; aia = $aiaOk; cdp = $cdpOk; certification_authorities = $caOk; enrollment_services = $enrollmentOk }; templates = @{ ok = $templatesOk; required = $requiredTemplates; missing = $missingTemplates }; http_artifacts = @{ ok = $httpOk; results = $http }; observed = @{ aia = $aiaNames; cdp = $cdpNames; certification_authorities = $caNames; enrollment_services = $enrollmentNames } } | ConvertTo-Json -Depth 6 -Compress";
        let output = require_success(ctx.shell.run(
            script,
            &[
                root_ca.to_string(),
                issuing_ca.to_string(),
                templates.join(","),
                urls_raw.to_string(),
            ],
        )?)?;
        let result = parse_json(&output.stdout);
        if !result.is_object() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: 1,
                    stderr: "pki.verify returned invalid JSON".into(),
                },
            ));
        }

        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{powershell::MockPowerShell, report::NullProgressSink};
    use serde_json::json;
    use std::{collections::HashMap, sync::Arc};

    fn params() -> HashMap<String, String> {
        [
            ("rootCaCommonName", "EC-Root-CA"),
            ("issuingCaCommonName", "EC-Issuing-CA"),
            ("templates", "OCSPResponseSigning,Workstation"),
            (
                "httpUrls",
                r#"["http://pki.encon.test/CertEnroll/root.crt"]"#,
            ),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
    }

    #[test]
    fn reports_enterprise_pki_health() {
        let params = params();
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            json!({
                "healthy": true,
                "containers": {
                    "nt_auth": true,
                    "aia": true,
                    "cdp": true,
                    "certification_authorities": true,
                    "enrollment_services": true
                },
                "templates": {"ok": true, "required": [], "missing": []},
                "http_artifacts": {"ok": true, "results": []}
            })
            .to_string(),
        );
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell,
        };

        let result = PkiVerify.execute(&ctx).unwrap();

        assert_eq!(result["healthy"], true);
        assert_eq!(result["containers"]["nt_auth"], true);
    }

    /// Same defect as `dns.verify`, but silent: with the array nested by
    /// Windows PowerShell 5.1, `Invoke-WebRequest -Uri <array>` throws into the
    /// catch, `$status` stays 0, and every multi-URL lab reports unhealthy.
    #[test]
    fn script_decodes_the_url_array_without_nesting_it() {
        let params = params();
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(json!({"healthy": true}).to_string());
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell: shell.clone(),
        };

        PkiVerify.execute(&ctx).unwrap();

        let calls = shell.calls.lock().unwrap();
        assert!(
            !calls[0].contains("| ConvertFrom-Json)"),
            "the decode wraps ConvertFrom-Json in @(), which nests the array on Windows PowerShell 5.1"
        );
        assert!(
            calls[0]
                .contains("$publicationUrls = $HttpUrls | ConvertFrom-Json")
        );
        assert!(calls[0].contains("foreach ($url in @($publicationUrls))"));
    }

    #[test]
    fn rejects_non_http_artifact_url() {
        let mut params = params();
        params.insert("httpUrls".into(), r#"["file:///secret"]"#.into());
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell: Arc::new(MockPowerShell::new()),
        };

        assert!(matches!(
            PkiVerify.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }
}
