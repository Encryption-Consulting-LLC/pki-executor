//! Certificate-template ACL commands (Phase L).
//!
//! `template.grant_access` replaces the lab guide's one GUI-only ACL step
//! (`certtmpl.msc` → Security → add the computer → Read + Enroll): it edits
//! the template object's AD ACL directly, granting a computer account
//! GenericRead plus the Enroll extended right.
//!
//! Like `cert.dspublish` it runs **on the DC** — but unlike it, running there
//! is not enough. `cert.dspublish` writes the domain NC, where the DC's
//! LocalSystem (the `DC01$` machine account) is privileged; certificate
//! templates live in the *Configuration* NC, whose objects grant `WriteDacl`
//! to Enterprise/Domain Admins and not to Domain Controllers. Editing the
//! DACL as LocalSystem fails with `ADProvider:SetSecurityDescriptor:
//! AccessDenied`, so the write is bound under the operator's domain-admin
//! credential — the same reason `ca.install` and `ca.install_cert` take one.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, require_success, required, valid_secret, valid_username,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// The AD extended-right GUID for certificate Enroll — fixed across forests.
const ENROLL_RIGHT_GUID: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";

fn valid_template_cn(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

fn valid_computer_name(value: &str) -> bool {
    (1..=15).contains(&value.len())
        && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// Grant a computer account Read+Enroll on a certificate template's AD object.
pub struct TemplateGrantAccess;

/// The DACL write goes through an explicit credentialed LDAP bind rather than
/// the ambient `AD:` drive, which authenticates as whoever the agent runs as.
/// `Get-Acl`/`Set-Acl` take no `-Credential`, and running *on* the DC makes a
/// direct bind a single hop — no delegation, and no scheduled-task indirection
/// like `ca.install_cert` needs. The reads (`Get-ADRootDSE`, `Get-ADComputer`)
/// stay in the agent's own context: only the write is privileged.
///
/// `AddAccessRule` is idempotent-enough for converging plans: re-adding an
/// identical ACE merges rather than erroring. The readback re-fetches the
/// committed descriptor and filters it to the granted account so the caller
/// can assert both rights landed.
fn grant_access_script() -> &'static str {
    "param([string]$Template,[string]$Computer,[string]$EnrollGuid,[string]$Username,[string]$Password) \
     $ErrorActionPreference = 'Stop'; \
     Import-Module ActiveDirectory; \
     $rootDse = Get-ADRootDSE; \
     $dn = \"CN=$Template,CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDse.configurationNamingContext)\"; \
     $account = Get-ADComputer -Identity $Computer; \
     $sid = [System.Security.Principal.SecurityIdentifier]$account.SID; \
     $entry = New-Object System.DirectoryServices.DirectoryEntry(\"LDAP://$dn\", $Username, $Password); \
     $acl = $entry.ObjectSecurity; \
     $read = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, [System.DirectoryServices.ActiveDirectoryRights]::GenericRead, [System.Security.AccessControl.AccessControlType]::Allow); \
     $enroll = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, [System.Security.AccessControl.AccessControlType]::Allow, [Guid]$EnrollGuid); \
     $acl.AddAccessRule($read); \
     $acl.AddAccessRule($enroll); \
     $entry.ObjectSecurity = $acl; \
     $entry.CommitChanges(); \
     $entry.RefreshCache(); \
     ConvertTo-Json @($entry.ObjectSecurity.Access | Where-Object { $_.IdentityReference.Value -match ('\\\\' + [regex]::Escape($Computer) + '\\$$') } | Select-Object @{n='identity';e={$_.IdentityReference.Value}}, @{n='rights';e={$_.ActiveDirectoryRights.ToString()}}, @{n='objectType';e={$_.ObjectType.ToString()}})"
}

impl CommandHandler for TemplateGrantAccess {
    fn name(&self) -> &'static str {
        "template.grant_access"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let template = required(ctx, "template")?;
        if !valid_template_cn(template) {
            return Err(invalid(
                "template",
                "must be a template CN of [A-Za-z0-9._-], max 64 chars",
            ));
        }
        let computer = required(ctx, "computer")?;
        if !valid_computer_name(computer) {
            return Err(invalid(
                "computer",
                "must be a computer name of [A-Za-z0-9-], max 15 chars",
            ));
        }

        // Rewriting a Configuration-NC template's DACL is an Enterprise/Domain
        // Admin write; the agent's own LocalSystem is denied it even on the DC.
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
            "granting template access",
            30.0,
        ));

        let args = [
            template.to_string(),
            computer.to_string(),
            ENROLL_RIGHT_GUID.to_string(),
            username.to_string(),
            password.to_string(),
        ];
        let output =
            require_success(ctx.shell.run(grant_access_script(), &args)?)?;

        let access = crate::commands::util::parse_json(&output.stdout);
        let result = json!({
            "template": template,
            "computer": computer,
            "access": access,
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

    fn grant_params() -> HashMap<String, String> {
        ctx_params(&[
            ("template", "OCSPResponseSigning"),
            ("computer", "SRV1"),
            ("username", "ENCRYPTIONCONSU\\Administrator"),
            ("password", "Sup3r-Secret-Pw!"),
        ])
    }

    #[test]
    fn grant_requires_template_and_computer() {
        let mut params = grant_params();
        params.remove("computer");
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            TemplateGrantAccess.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn grant_rejects_injection_shaped_template() {
        let mut params = grant_params();
        params.insert("template".into(), "OCSP,CN=elsewhere".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            TemplateGrantAccess.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn grant_rejects_overlong_computer_name() {
        let mut params = grant_params();
        params
            .insert("computer".into(), "a-name-way-past-netbios-limits".into());
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            TemplateGrantAccess.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn grant_reports_the_acl_readback() {
        let params = grant_params();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"[{"identity":"ENCRYPTIONCONSU\\SRV1$","rights":"GenericRead","objectType":"00000000-0000-0000-0000-000000000000"},{"identity":"ENCRYPTIONCONSU\\SRV1$","rights":"ExtendedRight","objectType":"0e10c968-78fb-11d2-90d4-00c04f79dc55"}]"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = TemplateGrantAccess.execute(&ctx).unwrap();
        assert_eq!(result["access"][0]["identity"], "ENCRYPTIONCONSU\\SRV1$");
        assert_eq!(
            result["access"][1]["objectType"],
            "0e10c968-78fb-11d2-90d4-00c04f79dc55"
        );
    }
}
