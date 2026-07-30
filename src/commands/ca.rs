//! ADCS Certificate Authority provisioning commands (Phase F, extended for
//! the Phase L two-tier lab).
//!
//! `ca.install` stands up either tier: a Standalone Root CA (the offline
//! root — CAPolicy.inf with renewal + AlternateSignatureAlgorithm=0), or an
//! Enterprise Subordinate CA (CPS-policy CAPolicy.inf, install runs under
//! the operator's domain-admin credential via the cmdlet's own `-Credential`
//! because an Enterprise CA registers itself in AD, and returns the CSR path
//! for the cross-signing handshake — the expected "installation is
//! incomplete" warning is allowlisted). The follow-up commands mirror the
//! lab's post-install passes: `ca.configure_settings` (the `certutil
//! -setreg` batch + audit policy), `ca.configure_cdp_aia` (full
//! flag-prefixed AIA/CDP publication arrays) and `ca.publish_crl`.
//!
//! All inputs arrive as dispatch params — the backend resolves them from
//! template config and plan context; the agent holds no template state.
//! Gated on `Capability::VmProvision` (both roles): a guest provisioning
//! *its own* throwaway CA is the product's point; the backend enforces
//! per-VM ownership on the dispatch route.
//!
//! Like every handler, all user values reach PowerShell through a `param()`
//! block + args array, never string-interpolated into the script text; the
//! domain-admin password is never echoed into results or errors.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required, valid_secret,
        valid_username, valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

const CA_TYPES: &[&str] = &["Root", "Issuing"];
const KEY_ALGORITHMS: &[&str] = &["RSA", "ECDSA", "ML-DSA-87"];
const KEY_LENGTHS: &[&str] = &["2048", "4096"];
const HASH_ALGORITHMS: &[&str] = &["SHA256", "SHA384", "SHA512"];
const PERIODS: &[&str] = &["Hours", "Days", "Weeks", "Months", "Years"];

/// Post-quantum provider string as exposed by the Windows Server 2025 CNG
/// software KSP. The parameter set is delimited with a COLON (`ML-DSA:87`),
/// not a hyphen — the AD CS "Cryptography for CA" list and the
/// `Install-AdcsCertificationAuthority -CryptoProviderName` example both use
/// `ML-DSA:87#Microsoft Software Key Storage Provider`. A hyphenated string is
/// an unknown provider and makes SetCASetupProperty fail with 0x80070057.
/// (Requires WS2025 + the 2026-05 security update KB5087539.)
const MLDSA_PROVIDER: &str =
    "ML-DSA:87#Microsoft Software Key Storage Provider";

/// ML-DSA-87's public-key size expressed in bits, which is what
/// `Install-AdcsCertificationAuthority -KeyLength` wants: 2,592 bytes × 8.
const MLDSA_KEY_LENGTH_BITS: &str = "20736";

fn cng_provider(algorithm: &str) -> &'static str {
    match algorithm {
        "ECDSA" => "ECDSA_P384#Microsoft Software Key Storage Provider",
        "ML-DSA-87" => MLDSA_PROVIDER,
        // RSA (and any future default)
        _ => "RSA#Microsoft Software Key Storage Provider",
    }
}

fn valid_common_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._-".contains(c))
}

/// Shared cryptography params (algorithm / RSA key length / hash), validated
/// once for both CA tiers.
struct CryptoParams {
    algorithm: String,
    provider: &'static str,
    key_length: Option<String>,
    hash_algorithm: Option<String>,
}

fn crypto_params(ctx: &CommandContext) -> Result<CryptoParams, CommandError> {
    let algorithm = param(ctx, "keyAlgorithm").unwrap_or("RSA");
    if !KEY_ALGORITHMS.contains(&algorithm) {
        return Err(invalid(
            "keyAlgorithm",
            "must be 'RSA', 'ECDSA' or 'ML-DSA-87'",
        ));
    }
    let is_pqc = algorithm == "ML-DSA-87";

    // ML-DSA-87 is a fixed-parameter PQC scheme, but the cmdlet still expects
    // BOTH -KeyLength and -HashAlgorithm — omitting them lets ADCS fall back to
    // RSA-shaped defaults the ML-DSA provider rejects (0x80070057). KeyLength is
    // the fixed public-key size in bits (20736) and the hash MUST be NoHash,
    // because ML-DSA hashes the message internally rather than pre-hashing.
    // For RSA the length is caller-chosen; ECDSA is curve-fixed (no length).
    let key_length = if is_pqc {
        Some(MLDSA_KEY_LENGTH_BITS.to_string())
    } else if algorithm == "RSA" {
        let kl = param(ctx, "keyLength").unwrap_or("4096");
        if !KEY_LENGTHS.contains(&kl) {
            return Err(invalid("keyLength", "must be '2048' or '4096'"));
        }
        Some(kl.to_string())
    } else {
        None
    };

    let hash_algorithm = if is_pqc {
        Some("NoHash".to_string())
    } else {
        let ha = param(ctx, "hashAlgorithm").unwrap_or("SHA256");
        if !HASH_ALGORITHMS.contains(&ha) {
            return Err(invalid(
                "hashAlgorithm",
                "must be 'SHA256', 'SHA384' or 'SHA512'",
            ));
        }
        Some(ha.to_string())
    };

    Ok(CryptoParams {
        algorithm: algorithm.to_string(),
        provider: cng_provider(algorithm),
        key_length,
        hash_algorithm,
    })
}

/// `Install-AdcsCertificationAuthority` for either lab tier.
pub struct CaInstall;

impl CaInstall {
    fn execute_root(
        &self,
        ctx: &CommandContext,
        common_name: &str,
        crypto: &CryptoParams,
        validity_years: &str,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "installing root CA",
            20.0,
        ));

        // CAPolicy.inf is built line-by-line (not a here-string) to sidestep
        // PowerShell's column-zero `"@` rule; single-quoted lines keep the
        // literal `$Windows NT$` marker from interpolating.
        let script = "param([string]$CommonName,[string]$Provider,[string]$KeyLength,[string]$HashAlgorithm,[string]$ValidityYears) \
            $ErrorActionPreference = 'Stop'; \
            $capolicy = @( \
                '[Version]', \
                'Signature=\"$Windows NT$\"', \
                '', \
                '[Certsrv_Server]', \
                'RenewalKeyLength=2048', \
                'RenewalValidityPeriod=Years', \
                \"RenewalValidityPeriodUnits=$ValidityYears\", \
                'AlternateSignatureAlgorithm=0' \
            ) -join \"`r`n\"; \
            Set-Content -Path (Join-Path $env:SystemRoot 'CAPolicy.inf') -Value $capolicy -Encoding ASCII; \
            Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null; \
            Import-Module ADCSDeployment; \
            $caParams = @{ \
                CAType = 'StandaloneRootCA'; \
                CACommonName = $CommonName; \
                CryptoProviderName = $Provider; \
                ValidityPeriod = 'Years'; \
                ValidityPeriodUnits = [int]$ValidityYears; \
                Force = $true \
            }; \
            if ($KeyLength) { $caParams['KeyLength'] = [int]$KeyLength }; \
            if ($HashAlgorithm) { $caParams['HashAlgorithmName'] = $HashAlgorithm }; \
            Install-AdcsCertificationAuthority @caParams | Out-Null";
        let args = [
            common_name.to_string(),
            crypto.provider.to_string(),
            crypto.key_length.clone().unwrap_or_default(),
            crypto.hash_algorithm.clone().unwrap_or_default(),
            validity_years.to_string(),
        ];
        require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "caType": "StandaloneRootCA",
            "commonName": common_name,
            "keyAlgorithm": crypto.algorithm,
            "keyLength": crypto.key_length,
            "hashAlgorithm": crypto.hash_algorithm,
            "validityYears": validity_years
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }

    fn execute_issuing(
        &self,
        ctx: &CommandContext,
        common_name: &str,
        crypto: &CryptoParams,
        validity_years: &str,
    ) -> Result<serde_json::Value, CommandError> {
        // CPS policy statement — optional; both parts validated when present.
        let cps_url = param(ctx, "cpsUrl").unwrap_or_default();
        if !(cps_url.is_empty()
            || cps_url.starts_with("http://")
            || cps_url.starts_with("https://"))
        {
            return Err(invalid("cpsUrl", "must be an http(s) URL"));
        }
        let cps_oid = param(ctx, "cpsOid").unwrap_or("1.2.3.4.1455.67.89.5");
        let oid_ok = cps_oid.split('.').count() >= 2
            && cps_oid.split('.').all(|part| {
                !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())
            });
        if !oid_ok {
            return Err(invalid("cpsOid", "must be a dotted-decimal OID"));
        }

        let csr_path =
            param(ctx, "csrPath").unwrap_or("C:\\Transfer\\IssuingCA.req");
        if !valid_windows_path(csr_path) {
            return Err(invalid("csrPath", "must be an absolute Windows path"));
        }

        // An Enterprise CA registers itself in AD — LocalSystem on a member
        // server can't; the install runs under the operator's domain-admin
        // credential via the cmdlet's own -Credential.
        let username = required(ctx, "username")?;
        if !valid_username(username) {
            return Err(invalid(
                "username",
                "must be a plain, domain\\user or user@domain account name",
            ));
        }
        let password = required(ctx, "password")?;
        if !valid_secret(password) {
            return Err(invalid(
                "password",
                "must be non-empty and not begin with '-'",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "installing issuing CA",
            20.0,
        ));

        // A subordinate install that writes a CSR deliberately finishes "not
        // started" — Install-AdcsCertificationAuthority surfaces that as an
        // ErrorString containing "incomplete"; anything else is a real
        // failure. The CSR path is the script's output.
        let script = "param([string]$CommonName,[string]$Provider,[string]$KeyLength,[string]$HashAlgorithm,[string]$ValidityYears,[string]$CpsOid,[string]$CpsUrl,[string]$CsrPath,[string]$Username,[string]$Password) \
            $ErrorActionPreference = 'Stop'; \
            $lines = @('[Version]', 'Signature=\"$Windows NT$\"'); \
            if ($CpsUrl) { $lines += @('[PolicyStatementExtension]', 'Policies=InternalPolicy', '[InternalPolicy]', \"OID=$CpsOid\", \"URL=$CpsUrl\") }; \
            $lines += @( \
                '[Certsrv_Server]', \
                'RenewalKeyLength=2048', \
                'RenewalValidityPeriod=Years', \
                \"RenewalValidityPeriodUnits=$ValidityYears\", \
                'LoadDefaultTemplates=0', \
                'AlternateSignatureAlgorithm=0' \
            ); \
            Set-Content -Path (Join-Path $env:SystemRoot 'CAPolicy.inf') -Value ($lines -join \"`r`n\") -Encoding ASCII; \
            Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools | Out-Null; \
            Import-Module ADCSDeployment; \
            New-Item -ItemType Directory -Force -Path (Split-Path $CsrPath) | Out-Null; \
            $secure = ConvertTo-SecureString $Password -AsPlainText -Force; \
            $cred = New-Object System.Management.Automation.PSCredential($Username, $secure); \
            $caParams = @{ \
                CAType = 'EnterpriseSubordinateCA'; \
                CACommonName = $CommonName; \
                CryptoProviderName = $Provider; \
                OutputCertRequestFile = $CsrPath; \
                Credential = $cred; \
                Force = $true \
            }; \
            if ($KeyLength) { $caParams['KeyLength'] = [int]$KeyLength }; \
            if ($HashAlgorithm) { $caParams['HashAlgorithmName'] = $HashAlgorithm }; \
            $res = Install-AdcsCertificationAuthority @caParams -WarningAction SilentlyContinue; \
            if ($res.ErrorString -and $res.ErrorString -notmatch 'incomplete') { throw $res.ErrorString }; \
            $CsrPath";
        let args = [
            common_name.to_string(),
            crypto.provider.to_string(),
            crypto.key_length.clone().unwrap_or_default(),
            crypto.hash_algorithm.clone().unwrap_or_default(),
            validity_years.to_string(),
            cps_oid.to_string(),
            cps_url.to_string(),
            csr_path.to_string(),
            username.to_string(),
            password.to_string(),
        ];
        require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "caType": "EnterpriseSubordinateCA",
            "commonName": common_name,
            "keyAlgorithm": crypto.algorithm,
            "keyLength": crypto.key_length,
            "hashAlgorithm": crypto.hash_algorithm,
            "csr_path": csr_path,
            "cpsUrl": if cps_url.is_empty() { serde_json::Value::Null } else { json!(cps_url) }
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

impl CommandHandler for CaInstall {
    fn name(&self) -> &'static str {
        "ca.install"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let ca_type = param(ctx, "caType").unwrap_or("Root");
        if !CA_TYPES.contains(&ca_type) {
            return Err(invalid("caType", "must be 'Root' or 'Issuing'"));
        }

        let common_name = required(ctx, "commonName")?;
        if !valid_common_name(common_name) {
            return Err(invalid(
                "commonName",
                "must be 1-64 chars of [A-Za-z0-9 ._-]",
            ));
        }

        let crypto = crypto_params(ctx)?;

        // Root: the CA cert's own lifetime AND the CAPolicy renewal window.
        // Issuing: the CAPolicy renewal window only (the cert's lifetime is
        // set by the root's ValidityPeriodUnits at signing time).
        let default_years = if ca_type == "Root" { "20" } else { "10" };
        let validity_years =
            param(ctx, "validityYears").unwrap_or(default_years);
        match validity_years.parse::<u32>() {
            Ok(y) if (1..=50).contains(&y) => {}
            _ => {
                return Err(invalid(
                    "validityYears",
                    "must be an integer in 1-50",
                ));
            }
        }

        if ca_type == "Issuing" {
            self.execute_issuing(ctx, common_name, &crypto, validity_years)
        } else {
            self.execute_root(ctx, common_name, &crypto, validity_years)
        }
    }
}

/// The lab's post-install `certutil -setreg` batch: DSConfigDN, CRL/delta/
/// overlap periods, issued-cert validity, and the audit filter (which also
/// enables Object Access auditing). Applies exactly the params present, then
/// restarts certsvc.
pub struct CaConfigureSettings;

impl CommandHandler for CaConfigureSettings {
    fn name(&self) -> &'static str {
        "ca.configure_settings"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let ds_config_dn = param(ctx, "dsConfigDn").unwrap_or_default();
        if !ds_config_dn.is_empty() {
            let dn_ok = ds_config_dn.starts_with("CN=Configuration,DC=")
                && ds_config_dn.len() <= 200
                && ds_config_dn
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "=,.-".contains(c));
            if !dn_ok {
                return Err(invalid(
                    "dsConfigDn",
                    "must be a CN=Configuration,DC=... distinguished name",
                ));
            }
        }

        let mut applied = serde_json::Map::new();
        if !ds_config_dn.is_empty() {
            applied.insert("dsConfigDn".into(), json!(ds_config_dn));
        }

        let mut unit_of = |key: &str,
                           max: u32|
         -> Result<String, CommandError> {
            let value = param(ctx, key).unwrap_or_default();
            if !value.is_empty() {
                match value.parse::<u32>() {
                    Ok(v) if v <= max => {
                        applied.insert(key.into(), json!(value));
                    }
                    _ => {
                        return Err(CommandError::InvalidParam {
                            name: key.into(),
                            reason: format!("must be an integer in 0-{max}"),
                        });
                    }
                }
            }
            Ok(value.to_string())
        };
        let crl_units = unit_of("crlPeriodUnits", 9999)?;
        let delta_units = unit_of("crlDeltaPeriodUnits", 9999)?;
        let overlap_units = unit_of("crlOverlapUnits", 9999)?;
        let validity_units = unit_of("validityPeriodUnits", 9999)?;
        let audit_filter = unit_of("auditFilter", 127)?;

        let mut period_of = |key: &str| -> Result<String, CommandError> {
            let value = param(ctx, key).unwrap_or_default();
            if !value.is_empty() {
                if !PERIODS.contains(&value) {
                    return Err(CommandError::InvalidParam {
                        name: key.into(),
                        reason:
                            "must be 'Hours', 'Days', 'Weeks', 'Months' or 'Years'"
                                .into()
                    });
                }
                applied.insert(key.into(), json!(value));
            }
            Ok(value.to_string())
        };
        let crl_period = period_of("crlPeriod")?;
        let delta_period = period_of("crlDeltaPeriod")?;
        let overlap_period = period_of("crlOverlapPeriod")?;
        let validity_period = period_of("validityPeriod")?;

        if applied.is_empty() {
            return Err(CommandError::MissingParam(
                "at least one CA setting".into(),
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "applying CA settings",
            30.0,
        ));

        let script = "param([string]$DsConfigDn,[string]$CrlPeriodUnits,[string]$CrlPeriod,[string]$CrlDeltaPeriodUnits,[string]$CrlDeltaPeriod,[string]$CrlOverlapUnits,[string]$CrlOverlapPeriod,[string]$ValidityPeriodUnits,[string]$ValidityPeriod,[string]$AuditFilter) \
            $ErrorActionPreference = 'Stop'; \
            function Set-CaReg([string]$Key,[string]$Value) { certutil -setreg $Key $Value | Out-Null; if ($LASTEXITCODE -ne 0) { throw \"certutil -setreg $Key failed\" } }; \
            if ($DsConfigDn) { Set-CaReg 'CA\\DSConfigDN' $DsConfigDn }; \
            if ($CrlPeriodUnits) { Set-CaReg 'CA\\CRLPeriodUnits' $CrlPeriodUnits }; \
            if ($CrlPeriod) { Set-CaReg 'CA\\CRLPeriod' $CrlPeriod }; \
            if ($CrlDeltaPeriodUnits) { Set-CaReg 'CA\\CRLDeltaPeriodUnits' $CrlDeltaPeriodUnits }; \
            if ($CrlDeltaPeriod) { Set-CaReg 'CA\\CRLDeltaPeriod' $CrlDeltaPeriod }; \
            if ($CrlOverlapUnits) { Set-CaReg 'CA\\CRLOverlapPeriodUnits' $CrlOverlapUnits }; \
            if ($CrlOverlapPeriod) { Set-CaReg 'CA\\CRLOverlapPeriod' $CrlOverlapPeriod }; \
            if ($ValidityPeriodUnits) { Set-CaReg 'CA\\ValidityPeriodUnits' $ValidityPeriodUnits }; \
            if ($ValidityPeriod) { Set-CaReg 'CA\\ValidityPeriod' $ValidityPeriod }; \
            if ($AuditFilter) { \
                Set-CaReg 'CA\\AuditFilter' $AuditFilter; \
                auditpol /set /category:'Object Access' /success:enable /failure:enable | Out-Null \
            }; \
            Restart-Service certsvc";
        let args = [
            ds_config_dn.to_string(),
            crl_units,
            crl_period,
            delta_units,
            delta_period,
            overlap_units,
            overlap_period,
            validity_units,
            validity_period,
            audit_filter,
        ];
        require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({ "applied": applied });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// One flag-prefixed publication entry (`"2:http://pki.../%3%8%9.crl"`).
/// The %-token substitution is certutil's, so tokens pass through verbatim;
/// only the URL scheme/anchor and a conservative character set are checked.
fn valid_publication_entry(entry: &str) -> bool {
    let Some((flags, location)) = entry.split_once(':') else {
        return false;
    };
    let flags_ok = !flags.is_empty()
        && flags.chars().all(|c| c.is_ascii_digit())
        && flags.parse::<u32>().is_ok_and(|f| f <= 1023);
    if !flags_ok || location.is_empty() || location.len() > 300 {
        return false;
    }
    let anchored = location.starts_with("ldap:///")
        || location.starts_with("http://")
        || location.starts_with("https://")
        || location.starts_with("file://")
        || location.starts_with("\\\\")
        || (location.len() > 3
            && location.as_bytes()[1] == b':'
            && location.as_bytes()[2] == b'\\'
            && location.chars().next().unwrap().is_ascii_alphabetic());
    anchored && !location.chars().any(|c| "\"'`;$\n\r".contains(c))
}

/// Replace the CA's full AIA (`CACertPublicationURLs`) and CDP
/// (`CRLPublicationURLs`) arrays with caller-supplied flag-prefixed entries
/// (newline-separated in the params), purge the machine Kerberos tickets,
/// and restart certsvc. `-setreg` overwrites the whole array — safe to
/// re-run.
pub struct CaConfigureCdpAia;

impl CommandHandler for CaConfigureCdpAia {
    fn name(&self) -> &'static str {
        "ca.configure_cdp_aia"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let split = |raw: &str| -> Vec<String> {
            raw.split('\n')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(str::to_string)
                .collect()
        };
        let aia_entries = split(param(ctx, "aiaUrls").unwrap_or_default());
        let cdp_entries = split(param(ctx, "cdpUrls").unwrap_or_default());
        if aia_entries.is_empty() && cdp_entries.is_empty() {
            return Err(CommandError::MissingParam(
                "aiaUrls or cdpUrls".into(),
            ));
        }
        for (name, entries) in
            [("aiaUrls", &aia_entries), ("cdpUrls", &cdp_entries)]
        {
            if let Some(bad) =
                entries.iter().find(|e| !valid_publication_entry(e))
            {
                return Err(CommandError::InvalidParam {
                    name: name.into(),
                    reason: format!(
                        "entry '{bad}' is not a flag-prefixed publication URL"
                    ),
                });
            }
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "configuring CDP/AIA",
            40.0,
        ));

        // certutil's multi-entry syntax wants the entries joined by a
        // LITERAL backslash-n inside one argument (as in the lab guide's
        // quoted strings) — not real newlines.
        let aia_joined = aia_entries.join("\\n");
        let cdp_joined = cdp_entries.join("\\n");

        // klist purge drops the machine account's cached Kerberos tickets
        // (logon id 0x3e7 = SYSTEM) so LDAP publishing sees fresh group
        // membership; best-effort, certutil failures are the hard gate.
        let script = "param([string]$AiaUrls,[string]$CdpUrls) \
            $ErrorActionPreference = 'Stop'; \
            if ($AiaUrls) { certutil -setreg CA\\CACertPublicationURLs $AiaUrls | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'certutil -setreg CACertPublicationURLs failed' } }; \
            if ($CdpUrls) { certutil -setreg CA\\CRLPublicationURLs $CdpUrls | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'certutil -setreg CRLPublicationURLs failed' } }; \
            klist -li 0x3e7 purge | Out-Null; \
            Restart-Service certsvc";
        let args = [aia_joined, cdp_joined];
        require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "aia_urls": aia_entries,
            "cdp_urls": cdp_entries
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `certutil -crl` — publish a fresh CRL (and delta, where configured), then
/// identify the exact CA certificate/base CRL/delta CRL filenames published in
/// CertEnroll so downstream relays use observed names rather than guesses.
pub struct CaPublishCrl;

impl CommandHandler for CaPublishCrl {
    fn name(&self) -> &'static str {
        "ca.publish_crl"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let cert_enroll_path = param(ctx, "certEnrollPath")
            .unwrap_or("C:\\Windows\\System32\\CertSrv\\CertEnroll");
        if !valid_windows_path(cert_enroll_path) {
            return Err(invalid(
                "certEnrollPath",
                "must be an absolute Windows path",
            ));
        }
        ctx.progress
            .report(crate::report::OpRunState::running("publishing CRL", 50.0));

        let script = "param([string]$CertEnroll) \
            $ErrorActionPreference = 'Stop'; \
            $probeDir = Join-Path $env:TEMP ('pki-executor-' + [guid]::NewGuid().ToString('N')); \
            New-Item -ItemType Directory -Force -Path $probeDir | Out-Null; \
            function Invoke-CertUtil([string[]]$Arguments) { \
                & certutil @Arguments 2>&1 | Out-Null; \
                if ($LASTEXITCODE -ne 0) { throw ('certutil ' + ($Arguments -join ' ') + ' failed') } \
            }; \
            function Find-Certificate([string]$ProbePath) { \
                $thumbprint = (Get-PfxCertificate -FilePath $ProbePath).Thumbprint; \
                $match = Get-ChildItem -LiteralPath $certEnroll -File -Filter '*.crt' | \
                    Where-Object { \
                        try { (Get-PfxCertificate -FilePath $_.FullName).Thumbprint -eq $thumbprint } \
                        catch { $false } \
                    } | Select-Object -First 1; \
                if (-not $match) { throw 'current CA certificate is missing from CertEnroll' }; \
                $match.Name \
            }; \
            function Find-Crl([string]$ProbePath) { \
                $hash = (Get-FileHash -LiteralPath $ProbePath -Algorithm SHA256).Hash; \
                $match = Get-ChildItem -LiteralPath $certEnroll -File -Filter '*.crl' | \
                    Where-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -eq $hash } | \
                    Select-Object -First 1; \
                if (-not $match) { throw 'current CRL is missing from CertEnroll' }; \
                $match.Name \
            }; \
            try { \
                Invoke-CertUtil @('-crl'); \
                $certificateProbe = Join-Path $probeDir 'ca.crt'; \
                $baseProbe = Join-Path $probeDir 'base.crl'; \
                Invoke-CertUtil @('-f', '-ca.cert', $certificateProbe); \
                Invoke-CertUtil @('-f', '-GetCRL', $baseProbe); \
                $certificateFileName = Find-Certificate $certificateProbe; \
                $baseCrlFileName = Find-Crl $baseProbe; \
                $certificateContentB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $certEnroll $certificateFileName))); \
                $baseCrlContentB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $certEnroll $baseCrlFileName))); \
                $deltaCrlFileName = $null; \
                $deltaCrlContentB64 = $null; \
                $configurationKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration'; \
                $active = (Get-ItemProperty -LiteralPath $configurationKey).Active; \
                $caKey = Join-Path $configurationKey $active; \
                $deltaUnits = (Get-ItemProperty -LiteralPath $caKey -Name CRLDeltaPeriodUnits -ErrorAction SilentlyContinue).CRLDeltaPeriodUnits; \
                if ([int]$deltaUnits -gt 0) { \
                    $deltaProbe = Join-Path $probeDir 'delta.crl'; \
                    Invoke-CertUtil @('-f', '-GetCRL', $deltaProbe, '0', 'delta'); \
                    $deltaCrlFileName = Find-Crl $deltaProbe; \
                    $deltaCrlContentB64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $certEnroll $deltaCrlFileName))) \
                }; \
                [pscustomobject]@{ \
                    certificateFileName = $certificateFileName; \
                    baseCrlFileName = $baseCrlFileName; \
                    deltaCrlFileName = $deltaCrlFileName; \
                    certificateContentB64 = $certificateContentB64; \
                    baseCrlContentB64 = $baseCrlContentB64; \
                    deltaCrlContentB64 = $deltaCrlContentB64 \
                } | ConvertTo-Json -Compress \
            } finally { \
                Remove-Item -LiteralPath $probeDir -Recurse -Force -ErrorAction SilentlyContinue \
            }";
        let output = require_success(
            ctx.shell.run(script, &[cert_enroll_path.to_string()])?,
        )?;

        let observed = parse_json(&output.stdout);
        let result = json!({
            "published": true,
            "certificateFileName": observed["certificateFileName"],
            "baseCrlFileName": observed["baseCrlFileName"],
            "deltaCrlFileName": observed["deltaCrlFileName"],
            "certificateContentB64": observed["certificateContentB64"],
            "baseCrlContentB64": observed["baseCrlContentB64"],
            "deltaCrlContentB64": observed["deltaCrlContentB64"],
            "raw": output.stdout
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// The root-CA half of the cross-signing handshake (runs on the offline
/// root): `certreq -submit` the carried CSR, parse the RequestId, issue it
/// with `certutil -resubmit`, and `certreq -retrieve` the signed cert to a
/// relay path. The CA config string is resolved locally from the CertSvc
/// registry — the caller never has to know the root's CA name.
pub struct CaSignRequest;

impl CommandHandler for CaSignRequest {
    fn name(&self) -> &'static str {
        "ca.sign_request"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let csr_path = required(ctx, "csrPath")?;
        if !valid_windows_path(csr_path) {
            return Err(invalid("csrPath", "must be an absolute Windows path"));
        }
        let cert_path = required(ctx, "certPath")?;
        if !valid_windows_path(cert_path) {
            return Err(invalid(
                "certPath",
                "must be an absolute Windows path",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "signing certificate request",
            30.0,
        ));

        let script = "param([string]$CsrPath,[string]$CertPath) \
            $ErrorActionPreference = 'Stop'; \
            $active = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration').Active; \
            $config = \"$env:COMPUTERNAME\\$active\"; \
            $submit = certreq -submit -config $config $CsrPath 2>&1 | Out-String; \
            if ($submit -notmatch 'RequestId:\\s*(\\d+)') { throw \"certreq -submit did not return a RequestId: $submit\" }; \
            $requestId = $Matches[1]; \
            certutil -resubmit $requestId | Out-Null; \
            if ($LASTEXITCODE -ne 0) { throw \"certutil -resubmit $requestId failed\" }; \
            New-Item -ItemType Directory -Force -Path (Split-Path $CertPath) | Out-Null; \
            certreq -retrieve -config $config $requestId $CertPath | Out-Null; \
            if ($LASTEXITCODE -ne 0) { throw \"certreq -retrieve $requestId failed\" }; \
            $requestId";
        let args = [csr_path.to_string(), cert_path.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let request_id = output.stdout.trim().to_string();
        if request_id.is_empty()
            || !request_id.chars().all(|c| c.is_ascii_digit())
        {
            return Err(invalid(
                "csrPath",
                "signing did not yield a numeric RequestId",
            ));
        }
        let result = json!({
            "request_id": request_id,
            "cert_path": cert_path
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// The issuing-CA half of the handshake: `certutil -installcert` the signed
/// cert carried back from the root, then start certsvc.
pub struct CaInstallCert;

impl CommandHandler for CaInstallCert {
    fn name(&self) -> &'static str {
        "ca.install_cert"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let cert_path = required(ctx, "certPath")?;
        if !valid_windows_path(cert_path) {
            return Err(invalid(
                "certPath",
                "must be an absolute Windows path",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "installing CA certificate",
            30.0,
        ));

        let script = "param([string]$CertPath) \
            $ErrorActionPreference = 'Stop'; \
            certutil -installcert $CertPath | Out-Null; \
            if ($LASTEXITCODE -ne 0) { throw 'certutil -installcert failed' }; \
            Start-Service CertSvc; \
            (Get-Service CertSvc).Status.ToString()";
        let output =
            require_success(ctx.shell.run(script, &[cert_path.to_string()])?)?;

        let result = json!({
            "cert_path": cert_path,
            "service": output.stdout.trim()
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `Add-CATemplate` for each named template (CN names, comma-separated) —
/// the lab publishes `OCSPResponseSigning` and `Workstation`. Idempotent: a
/// template already on the CA is skipped, so converging plans re-run clean.
pub struct CaPublishTemplate;

impl CommandHandler for CaPublishTemplate {
    fn name(&self) -> &'static str {
        "ca.publish_template"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let raw = required(ctx, "templates")?;
        let templates: Vec<&str> = raw
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect();
        let names_ok = !templates.is_empty()
            && templates.iter().all(|t| {
                (1..=64).contains(&t.len())
                    && t.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            });
        if !names_ok {
            return Err(invalid(
                "templates",
                "must be a comma-separated list of template CN names",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "publishing templates",
            30.0,
        ));

        let script = "param([string]$Templates) \
            $ErrorActionPreference = 'Stop'; \
            foreach ($t in ($Templates -split ',')) { \
                try { Add-CATemplate -Name $t.Trim() -Force } \
                catch { if ($_.Exception.Message -notmatch 'already') { throw } } \
            }; \
            (Get-CATemplate | Select-Object -ExpandProperty Name) -join ','";
        let output =
            require_success(ctx.shell.run(script, &[templates.join(",")])?)?;

        let result = json!({
            "templates": templates,
            "on_ca": output.stdout.trim()
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `Get-Service certsvc` + `certutil -ping` — the CA health probe every CA
/// write step verifies against (Phase L). Reports facts: `ping_ok: false` on
/// a stopped/pending CA is a successful read — the backend engine's per-step
/// predicate decides whether to retry.
pub struct CaVerify;

impl CommandHandler for CaVerify {
    fn name(&self) -> &'static str {
        "ca.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress
            .report(crate::report::OpRunState::running("pinging CA", 50.0));

        // certutil -ping exits non-zero while the service is stopped; the
        // script still exits 0 because the ConvertTo-Json at the end succeeds
        // — pingOk carries the certutil verdict instead.
        let script = "$svc = Get-Service certsvc -ErrorAction SilentlyContinue; \
            $service = if ($svc) { $svc.Status.ToString() } else { 'NotInstalled' }; \
            $ping = (certutil -ping 2>&1) -join \"`n\"; \
            $pingOk = ($LASTEXITCODE -eq 0); \
            @{ service = $service; pingOk = $pingOk; ping = $ping } | ConvertTo-Json";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let probe = parse_json(&output.stdout);
        let result = json!({
            "service": probe["service"],
            "ping_ok": probe["pingOk"] == true,
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
    fn install_requires_common_name() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn install_rejects_bad_common_name() {
        let params = ctx_params(&[("commonName", "bad;name`$injection")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_rejects_unknown_algorithm() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("keyAlgorithm", "Dilithium"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_rejects_bad_key_length_for_rsa() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("keyAlgorithm", "RSA"),
            ("keyLength", "1024"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_rejects_out_of_range_validity() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("validityYears", "99"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_succeeds_and_reports_rsa_defaults() {
        let params = ctx_params(&[
            ("commonName", "EC-Root-CA"),
            ("validityYears", "20"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["commonName"], "EC-Root-CA");
        assert_eq!(result["keyAlgorithm"], "RSA");
        assert_eq!(result["keyLength"], "4096");
        assert_eq!(result["hashAlgorithm"], "SHA256");
        assert_eq!(result["validityYears"], "20");
    }

    #[test]
    fn install_pqc_uses_fixed_key_length_and_nohash() {
        // ML-DSA-87: the cmdlet needs the fixed 20736-bit public-key size and
        // -HashAlgorithm NoHash; the CryptoProviderName must be colon-delimited.
        let params = ctx_params(&[
            ("commonName", "EC-PQC-Root"),
            ("keyAlgorithm", "ML-DSA-87"),
            // Stale RSA-shaped values the backend might still carry — ignored.
            ("keyLength", "2048"),
            ("hashAlgorithm", "SHA256"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["keyAlgorithm"], "ML-DSA-87");
        assert_eq!(result["keyLength"], "20736");
        assert_eq!(result["hashAlgorithm"], "NoHash");
    }

    #[test]
    fn mldsa_provider_string_is_colon_delimited() {
        // Regression: a hyphenated `ML-DSA-87#...` is an unknown CNG provider
        // and fails Install-AdcsCertificationAuthority with 0x80070057.
        assert_eq!(
            cng_provider("ML-DSA-87"),
            "ML-DSA:87#Microsoft Software Key Storage Provider"
        );
    }

    #[test]
    fn install_uses_ecdsa_provider_without_key_length() {
        let params = ctx_params(&[
            ("commonName", "EC-ECDSA-Root"),
            ("keyAlgorithm", "ECDSA"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["keyAlgorithm"], "ECDSA");
        // ECDSA: key length is curve-fixed, not reported.
        assert!(result["keyLength"].is_null());
    }

    fn issuing_params() -> HashMap<String, String> {
        ctx_params(&[
            ("caType", "Issuing"),
            ("commonName", "EncryptionConsulting Issuing CA"),
            ("cpsUrl", "http://pki.EncryptionConsulting.com/cps.txt"),
            ("csrPath", "C:\\Transfer\\IssuingCA.req"),
            ("username", "ENCRYPTIONCONSU\\Administrator"),
            ("password", "Sup3r-Secret-Pw!"),
        ])
    }

    #[test]
    fn install_issuing_requires_credentials() {
        let mut params = issuing_params();
        params.remove("password");
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn install_issuing_reports_csr_path() {
        let params = issuing_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("C:\\Transfer\\IssuingCA.req\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert_eq!(result["caType"], "EnterpriseSubordinateCA");
        assert_eq!(result["csr_path"], "C:\\Transfer\\IssuingCA.req");
    }

    #[test]
    fn install_issuing_never_leaks_the_password() {
        let params = issuing_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        let result = CaInstall.execute(&ctx).unwrap();
        assert!(!result.to_string().contains("Sup3r-Secret-Pw!"));
        for script in shell.calls.lock().unwrap().iter() {
            assert!(!script.contains("Sup3r-Secret-Pw!"));
        }
    }

    #[test]
    fn install_issuing_rejects_bad_cps_url() {
        let mut params = issuing_params();
        params.insert("cpsUrl".into(), "javascript:alert(1)".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn install_issuing_rejects_bad_cps_oid() {
        let mut params = issuing_params();
        params.insert("cpsOid".into(), "not-an-oid".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaInstall.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_settings_requires_at_least_one_setting() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaConfigureSettings.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn configure_settings_rejects_bad_period() {
        let params = ctx_params(&[
            ("crlPeriodUnits", "52"),
            ("crlPeriod", "Fortnights"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaConfigureSettings.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_settings_rejects_bad_ds_config_dn() {
        let params =
            ctx_params(&[("dsConfigDn", "CN=Configuration'; drop --")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaConfigureSettings.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_settings_echoes_applied_subset() {
        let params = ctx_params(&[
            (
                "dsConfigDn",
                "CN=Configuration,DC=EncryptionConsulting,DC=com",
            ),
            ("crlPeriodUnits", "52"),
            ("crlPeriod", "Weeks"),
            ("crlDeltaPeriodUnits", "0"),
            ("auditFilter", "127"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaConfigureSettings.execute(&ctx).unwrap();
        assert_eq!(result["applied"]["crlPeriodUnits"], "52");
        assert_eq!(result["applied"]["crlDeltaPeriodUnits"], "0");
        assert_eq!(result["applied"]["auditFilter"], "127");
        assert!(result["applied"]["validityPeriodUnits"].is_null());
    }

    #[test]
    fn configure_cdp_aia_requires_at_least_one_array() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaConfigureCdpAia.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn configure_cdp_aia_rejects_unprefixed_entry() {
        let params = ctx_params(&[("cdpUrls", "http://pki.example/root.crl")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaConfigureCdpAia.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_cdp_aia_rejects_injection_shaped_entry() {
        let params =
            ctx_params(&[("cdpUrls", "2:http://pki.example/x.crl'; rm")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaConfigureCdpAia.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn configure_cdp_aia_accepts_the_labs_full_issuing_arrays() {
        let params = ctx_params(&[
            (
                "aiaUrls",
                "1:C:\\Windows\\system32\\CertSrv\\CertEnroll\\%1_%3%4.crt\n\
                 2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n\
                 2:http://pki.EncryptionConsulting.com/CertEnroll/%1_%3%4.crt\n\
                 32:http://srv1.EncryptionConsulting.com/ocsp",
            ),
            (
                "cdpUrls",
                "65:C:\\Windows\\system32\\CertSrv\\CertEnroll\\%3%8%9.crl\n\
                 79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n\
                 6:http://pki.EncryptionConsulting.com/CertEnroll/%3%8%9.crl\n\
                 65:\\\\srv1.EncryptionConsulting.com\\CertEnroll\\%3%8%9.crl",
            ),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaConfigureCdpAia.execute(&ctx).unwrap();
        assert_eq!(result["aia_urls"].as_array().unwrap().len(), 4);
        assert_eq!(result["cdp_urls"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn publish_crl_reports_published() {
        let params = ctx_params(&[("certEnrollPath", "D:\\PKI\\Published")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"certificateFileName":"CA01_Example Root CA.crt","baseCrlFileName":"Example Root CA.crl","deltaCrlFileName":null,"certificateContentB64":"Y2VydA==","baseCrlContentB64":"Y3Js"}"#,
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::clone(&shell) as _,
        };
        let result = CaPublishCrl.execute(&ctx).unwrap();
        assert_eq!(result["published"], true);
        assert_eq!(result["certificateFileName"], "CA01_Example Root CA.crt");
        assert_eq!(result["baseCrlFileName"], "Example Root CA.crl");
        assert!(result["deltaCrlFileName"].is_null());
        assert_eq!(result["certificateContentB64"], "Y2VydA==");
        assert_eq!(result["baseCrlContentB64"], "Y3Js");
        let script = &shell.calls.lock().unwrap()[0];
        assert!(script.starts_with("param([string]$CertEnroll)"));
        assert!(!script.contains("Join-Path $env:SystemRoot 'System32"));
    }

    #[test]
    fn publish_crl_rejects_relative_publication_directory() {
        let params = ctx_params(&[("certEnrollPath", "Published")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };

        assert!(matches!(
            CaPublishCrl.execute(&ctx),
            Err(CommandError::InvalidParam { name, .. }) if name == "certEnrollPath"
        ));
    }

    #[test]
    fn publish_crl_propagates_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "CertUtil: The service has not been started.");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            CaPublishCrl.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn sign_request_parses_the_request_id() {
        let params = ctx_params(&[
            ("csrPath", "C:\\Transfer\\IssuingCA.req"),
            ("certPath", "C:\\Transfer\\IssuingCA.crt"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("2\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaSignRequest.execute(&ctx).unwrap();
        assert_eq!(result["request_id"], "2");
        assert_eq!(result["cert_path"], "C:\\Transfer\\IssuingCA.crt");
    }

    #[test]
    fn sign_request_rejects_non_numeric_request_id_output() {
        let params = ctx_params(&[
            ("csrPath", "C:\\Transfer\\IssuingCA.req"),
            ("certPath", "C:\\Transfer\\IssuingCA.crt"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("unexpected chatter");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            CaSignRequest.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn sign_request_propagates_submit_failure() {
        let params = ctx_params(&[
            ("csrPath", "C:\\Transfer\\IssuingCA.req"),
            ("certPath", "C:\\Transfer\\IssuingCA.crt"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(
            1,
            "certreq -submit did not return a RequestId: denied",
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            CaSignRequest.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn install_cert_reports_service_status() {
        let params = ctx_params(&[("certPath", "C:\\Transfer\\IssuingCA.crt")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("Running\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaInstallCert.execute(&ctx).unwrap();
        assert_eq!(result["service"], "Running");
    }

    #[test]
    fn publish_template_rejects_injection_shaped_names() {
        let params =
            ctx_params(&[("templates", "OCSPResponseSigning,$(evil)")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            CaPublishTemplate.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn publish_template_reports_the_ca_readback() {
        let params =
            ctx_params(&[("templates", "OCSPResponseSigning, Workstation")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("OCSPResponseSigning,Workstation");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaPublishTemplate.execute(&ctx).unwrap();
        assert_eq!(result["templates"][0], "OCSPResponseSigning");
        assert_eq!(result["templates"][1], "Workstation");
        assert_eq!(result["on_ca"], "OCSPResponseSigning,Workstation");
    }

    #[test]
    fn verify_reports_running_service_and_live_interface() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"service":"Running","pingOk":true,"ping":"Cert Server \"EC-Root-CA\" is alive"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaVerify.execute(&ctx).unwrap();
        assert_eq!(result["service"], "Running");
        assert_eq!(result["ping_ok"], true);
    }

    #[test]
    fn verify_reports_stopped_service_without_erroring() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"service":"Stopped","pingOk":false,"ping":"CertUtil: The service has not been started."}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = CaVerify.execute(&ctx).unwrap();
        assert_eq!(result["service"], "Stopped");
        assert_eq!(result["ping_ok"], false);
    }
}
