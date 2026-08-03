//! DNS client commands (Phase L).
//!
//! `dns.set_client` points a NIC's DNS resolvers at caller-supplied servers —
//! the pre-join step on every domain-joining machine (aim at the DC's pool
//! IP), and the post-promotion step on the DC itself (aim at self, replacing
//! the loopback default). Same conservative interface handling as `ip.write`:
//! an empty alias means the first Up adapter.

use std::net::Ipv4Addr;

use serde::Deserialize;
use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required, valid_dns_name,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

const MAX_DNS_RESOURCES: usize = 32;

#[derive(Clone, Deserialize)]
enum PlannedDnsKind {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "PTR")]
    Ptr,
    #[serde(rename = "CNAME")]
    Cname,
}

#[derive(Clone, Deserialize)]
struct PlannedDnsRecord {
    id: String,
    kind: PlannedDnsKind,
    zone: String,
    name: String,
    value: String,
}

fn valid_single_label(value: &str) -> bool {
    valid_dns_name(value) && !value.contains('.')
}

fn valid_reverse_zone(value: &str) -> bool {
    let normalized = value.trim_end_matches('.').to_ascii_lowercase();
    let Some(prefix) = normalized.strip_suffix(".in-addr.arpa") else {
        return false;
    };
    let labels: Vec<_> = prefix.split('.').collect();
    (1..=3).contains(&labels.len())
        && labels.iter().all(|label| label.parse::<u8>().is_ok())
}

fn parse_planned_records(
    ctx: &CommandContext,
) -> Result<(String, Vec<PlannedDnsRecord>), CommandError> {
    let raw = required(ctx, "records")?;
    if raw.len() > 32 * 1024 {
        return Err(invalid("records", "JSON payload is too large"));
    }
    let records: Vec<PlannedDnsRecord> =
        serde_json::from_str(raw).map_err(|_| {
            invalid("records", "must be a JSON array of DNS resources")
        })?;
    if records.is_empty() || records.len() > MAX_DNS_RESOURCES {
        return Err(invalid(
            "records",
            "must contain between 1 and 32 resources",
        ));
    }
    for record in &records {
        if record.id.is_empty()
            || record.id.len() > 500
            || !record
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ":_-".contains(c))
        {
            return Err(invalid("records", "contains an invalid resource id"));
        }
        if !valid_dns_name(&record.zone) {
            return Err(invalid("records", "contains an invalid DNS zone"));
        }
        match record.kind {
            PlannedDnsKind::A => {
                if !valid_single_label(&record.name)
                    || record.value.parse::<Ipv4Addr>().is_err()
                {
                    return Err(invalid(
                        "records",
                        "contains an invalid A record",
                    ));
                }
            }
            PlannedDnsKind::Ptr => {
                if !valid_reverse_zone(&record.zone)
                    || record.name.parse::<Ipv4Addr>().is_err()
                    || !valid_dns_name(&record.value)
                {
                    return Err(invalid(
                        "records",
                        "contains an invalid PTR record",
                    ));
                }
            }
            PlannedDnsKind::Cname => {
                if !valid_single_label(&record.name)
                    || !valid_dns_name(&record.value)
                {
                    return Err(invalid(
                        "records",
                        "contains an invalid CNAME record",
                    ));
                }
            }
        }
    }
    Ok((raw.to_string(), records))
}

/// `Set-DnsClientServerAddress` — replace a NIC's DNS server list.
pub struct DnsSetClient;

impl CommandHandler for DnsSetClient {
    fn name(&self) -> &'static str {
        "dns.set_client"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let servers = required(ctx, "servers")?;
        let parsed: Vec<&str> = servers
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parsed.is_empty()
            || parsed.iter().any(|s| s.parse::<Ipv4Addr>().is_err())
        {
            return Err(invalid(
                "servers",
                "must be a comma-separated list of dotted-quad IPv4 addresses",
            ));
        }
        let servers = parsed.join(",");

        // Empty alias → the script picks the first Up adapter itself.
        let alias = param(ctx, "interface").unwrap_or_default().to_string();

        ctx.progress.report(crate::report::OpRunState::running(
            "configuring DNS client",
            30.0,
        ));

        // Echo the applied list back (readback) so the caller verifies the
        // change from the same run.
        let script = "param([string]$Servers,[string]$Alias) \
            $ErrorActionPreference = 'Stop'; \
            if (-not $Alias) { $Alias = Get-NetAdapter | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1 -ExpandProperty Name }; \
            Set-DnsClientServerAddress -InterfaceAlias $Alias -ServerAddresses ($Servers -split ','); \
            (Get-DnsClientServerAddress -InterfaceAlias $Alias -AddressFamily IPv4).ServerAddresses -join ','";
        let args = [servers.clone(), alias.clone()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "servers": parsed,
            "applied": output.stdout.trim(),
            "interface": if alias.is_empty() { serde_json::Value::Null } else { json!(alias) }
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// `Add-DnsServerResourceRecordCName` — the lab's `pki` alias on DC01
/// (`pki.<domain>` → the web host actually serving CertEnroll). Idempotent:
/// an existing CNAME of the same name is replaced, so re-running a plan
/// converges instead of erroring on the duplicate.
pub struct DnsCreateRecord;

impl CommandHandler for DnsCreateRecord {
    fn name(&self) -> &'static str {
        "dns.create_record"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let zone = required(ctx, "zone")?;
        if !valid_dns_name(zone) {
            return Err(invalid("zone", "must be a DNS zone name"));
        }
        let name = required(ctx, "name")?;
        if !valid_dns_name(name) || name.contains('.') {
            return Err(invalid("name", "must be a single DNS label"));
        }
        let target = required(ctx, "target")?;
        if !valid_dns_name(target) {
            return Err(invalid("target", "must be a DNS host name"));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "creating DNS record",
            30.0,
        ));

        let script = "param([string]$Zone,[string]$Name,[string]$Target) \
            $ErrorActionPreference = 'Stop'; \
            $existing = Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType CName -ErrorAction SilentlyContinue; \
            if ($existing) { $existing | Remove-DnsServerResourceRecord -ZoneName $Zone -Force }; \
            Add-DnsServerResourceRecordCName -ZoneName $Zone -Name $Name -HostNameAlias $Target; \
            (Get-DnsServerResourceRecord -ZoneName $Zone -Name $Name -RRType CName).RecordData.HostNameAlias";
        let args = [zone.to_string(), name.to_string(), target.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "zone": zone,
            "name": name,
            "target": target,
            "applied": output.stdout.trim()
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Apply explicit A/PTR/CNAME plan resources on the authoritative DC.
/// Existing identical values are retained; a different pre-existing value is
/// a hard conflict so a deploy never takes ownership by silently replacing it.
pub struct DnsApplyResources;

impl CommandHandler for DnsApplyResources {
    fn name(&self) -> &'static str {
        "dns.apply_resources"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let (records_json, records) = parse_planned_records(ctx)?;
        ctx.progress.report(crate::report::OpRunState::running(
            "applying DNS resources",
            30.0,
        ));

        let script = r#"param([string]$RecordsJson)
$ErrorActionPreference = 'Stop'
Import-Module DnsServer
# Windows PowerShell 5.1 writes a decoded JSON array to the pipeline as one
# object, so @(... | ConvertFrom-Json) nests it and the loop below would bind
# every record at once. Assign first, then normalise to an array.
$records = $RecordsJson | ConvertFrom-Json
$records = @($records)
$results = foreach ($record in $records) {
    $zone = [string]$record.zone
    $name = [string]$record.name
    $value = [string]$record.value
    if ($record.kind -eq 'PTR') {
        $existingZone = Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue
        if (-not $existingZone) {
            $prefixLabels = @($zone.ToLowerInvariant().Replace('.in-addr.arpa','').Split('.'))
            [array]::Reverse($prefixLabels)
            $networkOctets = @($prefixLabels)
            while ($networkOctets.Count -lt 4) { $networkOctets += '0' }
            $networkId = ($networkOctets -join '.') + '/' + ($prefixLabels.Count * 8)
            Add-DnsServerPrimaryZone -NetworkId $networkId -ReplicationScope Forest | Out-Null
        }
        $prefixCount = @($zone.ToLowerInvariant().Replace('.in-addr.arpa','').Split('.')).Count
        $remaining = @($name.Split('.')[$prefixCount..3])
        [array]::Reverse($remaining)
        $relativeName = $remaining -join '.'
        $existing = @(Get-DnsServerResourceRecord -ZoneName $zone -Name $relativeName -RRType PTR -ErrorAction SilentlyContinue)
        $actual = @($existing | ForEach-Object { $_.RecordData.PtrDomainName.TrimEnd('.') })
        $expected = $value.TrimEnd('.')
        if ($existing.Count -gt 0 -and -not ($actual.Count -eq 1 -and $actual[0] -ieq $expected)) {
            throw "DNS conflict for PTR ${name}: expected $value; found $($actual -join ',')"
        }
        if ($existing.Count -eq 0) {
            Add-DnsServerResourceRecordPtr -ZoneName $zone -Name $relativeName -PtrDomainName $value | Out-Null
            $status = 'created'
        } else { $status = 'retained' }
    } elseif ($record.kind -eq 'A') {
        $existing = @(Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType A -ErrorAction SilentlyContinue)
        $actual = @($existing | ForEach-Object { $_.RecordData.IPv4Address.IPAddressToString })
        if ($existing.Count -gt 0 -and -not ($actual.Count -eq 1 -and $actual[0] -eq $value)) {
            throw "DNS conflict for A $name.${zone}: expected $value; found $($actual -join ',')"
        }
        if ($existing.Count -eq 0) {
            Add-DnsServerResourceRecordA -ZoneName $zone -Name $name -IPv4Address $value | Out-Null
            $status = 'created'
        } else { $status = 'retained' }
    } elseif ($record.kind -eq 'CNAME') {
        $existing = @(Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType CNAME -ErrorAction SilentlyContinue)
        $actual = @($existing | ForEach-Object { $_.RecordData.HostNameAlias.TrimEnd('.') })
        $expected = $value.TrimEnd('.')
        if ($existing.Count -gt 0 -and -not ($actual.Count -eq 1 -and $actual[0] -ieq $expected)) {
            throw "DNS conflict for CNAME $name.${zone}: expected $value; found $($actual -join ',')"
        }
        if ($existing.Count -eq 0) {
            Add-DnsServerResourceRecordCName -ZoneName $zone -Name $name -HostNameAlias $value | Out-Null
            $status = 'created'
        } else { $status = 'retained' }
    } else { throw "Unsupported DNS resource kind '$($record.kind)'" }
    [pscustomobject]@{ id = [string]$record.id; kind = [string]$record.kind; status = $status }
}
[pscustomobject]@{ applied = @($results).Count; records = @($results) } | ConvertTo-Json -Depth 5 -Compress"#;
        let output = require_success(ctx.shell.run(script, &[records_json])?)?;
        let readback = parse_json(&output.stdout);
        let result = json!({
            "applied": records.len(),
            "readback": readback,
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Resolve every planned record through the requested DNS server, optionally
/// prove the forest's essential AD SRV registrations and an HTTP publication
/// URL. The PowerShell command exits non-zero on any mismatch, making this a
/// deployment gate rather than a best-effort observation.
pub struct DnsVerify;

impl CommandHandler for DnsVerify {
    fn name(&self) -> &'static str {
        "dns.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let (records_json, records) = parse_planned_records(ctx)?;
        let server = required(ctx, "server")?;
        if server.parse::<Ipv4Addr>().is_err() && !valid_dns_name(server) {
            return Err(invalid(
                "server",
                "must be an IPv4 address or DNS name",
            ));
        }
        let require_ad_srv = param(ctx, "requireAdSrv").unwrap_or("false");
        if require_ad_srv != "true" && require_ad_srv != "false" {
            return Err(invalid("requireAdSrv", "must be true or false"));
        }
        let domain = param(ctx, "domain").unwrap_or_default();
        if require_ad_srv == "true" && !valid_dns_name(domain) {
            return Err(invalid("domain", "must be a DNS domain name"));
        }
        let http_url = param(ctx, "httpUrl").unwrap_or_default();
        if !http_url.is_empty()
            && (!(http_url.starts_with("http://")
                || http_url.starts_with("https://"))
                || http_url.len() > 300
                || http_url.chars().any(|c| "\"'`;$ \r\n".contains(c)))
        {
            return Err(invalid("httpUrl", "must be a safe HTTP(S) URL"));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "verifying DNS resources",
            30.0,
        ));
        let script = r#"param([string]$RecordsJson,[string]$Server,[string]$RequireAdSrv,[string]$Domain,[string]$HttpUrl)
$ErrorActionPreference = 'Stop'
# See dns.apply_resources: @(... | ConvertFrom-Json) nests the decoded array on
# Windows PowerShell 5.1, which binds $record to every record at once.
$records = $RecordsJson | ConvertFrom-Json
$records = @($records)
$checks = foreach ($record in $records) {
    if ($record.kind -eq 'PTR') {
        $answer = @(Resolve-DnsName -Name ([string]$record.name) -Type PTR -Server $Server -DnsOnly -NoHostsFile)
        $actual = @($answer | Where-Object Type -eq PTR | ForEach-Object { $_.NameHost.TrimEnd('.') })
        $expected = ([string]$record.value).TrimEnd('.')
    } else {
        $fqdn = ([string]$record.name) + '.' + ([string]$record.zone)
        $answer = @(Resolve-DnsName -Name $fqdn -Type ([string]$record.kind) -Server $Server -DnsOnly -NoHostsFile)
        if ($record.kind -eq 'A') { $actual = @($answer | Where-Object Type -eq A | ForEach-Object IPAddress); $expected = [string]$record.value }
        else { $actual = @($answer | Where-Object Type -eq CNAME | ForEach-Object { $_.NameHost.TrimEnd('.') }); $expected = ([string]$record.value).TrimEnd('.') }
    }
    $ok = @($actual | Where-Object { $_ -ieq $expected }).Count -gt 0
    [pscustomobject]@{ id = [string]$record.id; kind = [string]$record.kind; ok = $ok; expected = $expected; actual = @($actual) }
}
$adSrvOk = $true
$srvChecks = @()
if ($RequireAdSrv -eq 'true') {
    $srvNames = @("_ldap._tcp.$Domain", "_kerberos._tcp.$Domain", "_ldap._tcp.dc._msdcs.$Domain")
    $srvChecks = @($srvNames | ForEach-Object {
        $answers = @(Resolve-DnsName -Name $_ -Type SRV -Server $Server -DnsOnly -NoHostsFile)
        [pscustomobject]@{ name = $_; ok = @($answers | Where-Object Type -eq SRV).Count -gt 0 }
    })
    $adSrvOk = @($srvChecks | Where-Object { -not $_.ok }).Count -eq 0
}
$httpOk = $true
if ($HttpUrl) {
    $response = Invoke-WebRequest -Uri $HttpUrl -UseBasicParsing -TimeoutSec 30
    $httpOk = [int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 400
}
$allVerified = @($checks | Where-Object { -not $_.ok }).Count -eq 0
if (-not $allVerified -or -not $adSrvOk -or -not $httpOk) { throw 'DNS verification failed' }
[pscustomobject]@{ all_verified = $allVerified; ad_srv_ok = $adSrvOk; http_ok = $httpOk; records = @($checks); srv = @($srvChecks) } | ConvertTo-Json -Depth 6 -Compress"#;
        let args = [
            records_json,
            server.to_string(),
            require_ad_srv.to_string(),
            domain.to_string(),
            http_url.to_string(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;
        let result = parse_json(&output.stdout);
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        let _ = records;
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
    fn set_client_requires_servers() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsSetClient.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn set_client_rejects_malformed_server() {
        let params = ctx_params(&[("servers", "192.168.1.90,not-an-ip")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsSetClient.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn set_client_rejects_empty_list() {
        let params = ctx_params(&[("servers", " , ")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsSetClient.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn set_client_applies_and_echoes_readback() {
        let params = ctx_params(&[("servers", "192.168.1.90, 192.168.1.91")]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("192.168.1.90,192.168.1.91");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DnsSetClient.execute(&ctx).unwrap();
        assert_eq!(result["servers"][0], "192.168.1.90");
        assert_eq!(result["servers"][1], "192.168.1.91");
        assert_eq!(result["applied"], "192.168.1.90,192.168.1.91");
        assert!(result["interface"].is_null());
    }

    #[test]
    fn create_record_requires_all_params() {
        let params = ctx_params(&[("zone", "EncryptionConsulting.com")]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsCreateRecord.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }

    #[test]
    fn create_record_rejects_dotted_name() {
        let params = ctx_params(&[
            ("zone", "EncryptionConsulting.com"),
            ("name", "pki.extra"),
            ("target", "srv1.EncryptionConsulting.com."),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsCreateRecord.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn create_record_rejects_injection_shaped_target() {
        let params = ctx_params(&[
            ("zone", "EncryptionConsulting.com"),
            ("name", "pki"),
            ("target", "srv1; Remove-Item -Recurse C:\\"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsCreateRecord.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn create_record_echoes_the_applied_alias() {
        let params = ctx_params(&[
            ("zone", "EncryptionConsulting.com"),
            ("name", "pki"),
            ("target", "srv1.EncryptionConsulting.com."),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("srv1.EncryptionConsulting.com.");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DnsCreateRecord.execute(&ctx).unwrap();
        assert_eq!(result["name"], "pki");
        assert_eq!(result["applied"], "srv1.EncryptionConsulting.com.");
    }

    fn planned_records_json() -> &'static str {
        r#"[{"id":"dns:a:dc:web","kind":"A","zone":"encon.pki","name":"srv1","value":"192.168.1.92"},{"id":"dns:ptr:dc:web","kind":"PTR","zone":"1.168.192.in-addr.arpa","name":"192.168.1.92","value":"srv1.encon.pki."},{"id":"dns:cname:dc:pki","kind":"CNAME","zone":"encon.pki","name":"pki","value":"srv1.encon.pki."}]"#
    }

    #[test]
    fn apply_resources_validates_and_reports_readback() {
        let params = ctx_params(&[("records", planned_records_json())]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"applied":3,"records":[{"id":"dns:a:dc:web","status":"created"}]}"#,
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: shell.clone(),
        };
        let result = DnsApplyResources.execute(&ctx).unwrap();
        assert_eq!(result["applied"], 3);
        assert_eq!(result["readback"]["applied"], 3);

        let calls = shell.calls.lock().unwrap();
        let script = &calls[0];
        assert!(script.contains("DNS conflict for PTR ${name}:"));
        assert!(script.contains("DNS conflict for A $name.${zone}:"));
        assert!(script.contains("DNS conflict for CNAME $name.${zone}:"));
    }

    #[test]
    fn apply_resources_rejects_invalid_ptr_zone() {
        let records = r#"[{"id":"dns:ptr:dc:web","kind":"PTR","zone":"encon.pki","name":"192.168.1.92","value":"srv1.encon.pki."}]"#;
        let params = ctx_params(&[("records", records)]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsApplyResources.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn verify_accepts_srv_and_http_checks() {
        let params = ctx_params(&[
            ("records", planned_records_json()),
            ("server", "192.168.1.90"),
            ("requireAdSrv", "true"),
            ("domain", "encon.pki"),
            ("httpUrl", "http://pki.encon.pki/CertEnroll/"),
        ]);
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"all_verified":true,"ad_srv_ok":true,"http_ok":true}"#,
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = DnsVerify.execute(&ctx).unwrap();
        assert_eq!(result["all_verified"], true);
        assert_eq!(result["ad_srv_ok"], true);
        assert_eq!(result["http_ok"], true);
    }

    #[test]
    fn verify_rejects_unsafe_http_url() {
        let params = ctx_params(&[
            ("records", planned_records_json()),
            ("server", "192.168.1.90"),
            ("httpUrl", "http://pki.encon.pki/;Remove-Item"),
        ]);
        let sink = NullProgressSink;
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell: Arc::new(MockPowerShell::new()),
        };
        assert!(matches!(
            DnsVerify.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }
}
