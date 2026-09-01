//! CertSecure Manager provisioning commands — the Linux product half of the
//! catalog.
//!
//! These are registered on **every** platform, unlike the `linux` module's
//! overrides: the command catalog is a cross-repo contract asserted against one
//! shared fixture, and a name that exists only on one OS would make that
//! fixture unassertable on the other. They are only ever dispatched to a Linux
//! product guest, which the backend decides by template.
//!
//! Division of labour with the vendor installer: `certsecure.install` runs
//! `install-linux.sh` verbatim and does **not** reimplement any of it. Only the
//! four things the installer cannot do for itself live here — the `apt` list
//! refresh it needs before its first package (`apt.refresh`), the `/etc/hosts`
//! entries the lab has no resolver for yet (`certsecure.write_hosts`), the TLS
//! certificate it prompts for but does not generate (`certsecure.make_cert`),
//! and the file modes it leaves world-readable (`certsecure.harden`).

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required, valid_dns_name,
        valid_posix_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

/// Where the firstboot payload staging step extracts the product tree. Fixed
/// rather than a parameter: it is also the `file.*` relay allowlist prefix and
/// the installer derives `conf.ini` / `installation-logs.log` from its own
/// working directory, so one side moving alone silently breaks the other.
const INSTALL_DIR: &str = "/opt/certsecure-manager";

/// A managed `/etc/hosts` block, rewritten whole on every run. Delimited so a
/// re-run replaces its own previous entries instead of appending duplicates —
/// which matters because a redelivered plan step re-dispatches verbatim.
const HOSTS_BEGIN: &str = "# BEGIN pki-executor managed entries";
const HOSTS_END: &str = "# END pki-executor managed entries";

fn valid_ipv4(value: &str) -> bool {
    let octets: Vec<&str> = value.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.chars().all(|c| c.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|n| n <= 255)
        })
}

/// Parse the `entries` param: one `<ipv4> <name> [<name> …]` per line.
///
/// Validated here rather than in the script because these values are the one
/// thing on this path that comes from another node's configuration: an
/// unchecked line could inject a whole extra host entry, and `/etc/hosts`
/// outranks DNS for every name it mentions.
fn parse_hosts_entries(raw: &str) -> Result<String, CommandError> {
    let mut lines: Vec<String> = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let ip = fields.next().unwrap_or_default();
        if !valid_ipv4(ip) {
            return Err(invalid(
                "entries",
                "each line must start with an IPv4 address",
            ));
        }
        let names: Vec<&str> = fields.collect();
        if names.is_empty() {
            return Err(invalid(
                "entries",
                "each line must name at least one host",
            ));
        }
        if !names.iter().all(|name| valid_dns_name(name)) {
            return Err(invalid(
                "entries",
                "host names must be valid DNS names",
            ));
        }
        lines.push(format!("{ip} {}", names.join(" ")));
    }
    if lines.is_empty() {
        return Err(invalid("entries", "must contain at least one entry"));
    }
    Ok(lines.join("\n"))
}

/// `apt-get update`.
///
/// A step of its own rather than a line inside the installer's own package
/// work: the golden image's package lists are stale enough that every build
/// dependency URL 404s, and the installer dies four seconds in with a package
/// error that reads like a broken mirror. Refreshing first turns that into a
/// step with its own name, its own retry schedule and its own error.
pub struct AptRefresh;

impl CommandHandler for AptRefresh {
    fn name(&self) -> &'static str {
        "apt.refresh"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "refreshing package lists",
            30.0,
        ));
        let script = r#"set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update
"#;
        let output = require_success(ctx.shell.run(script, &[])?)?;
        let result = json!({ "refreshed": true, "raw": output.stdout.trim() });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Rewrite this guest's managed `/etc/hosts` block.
///
/// The product's own three FQDNs resolve through the lab DC once the A records
/// land, but the installer contacts them (and Keycloak binds to one) during the
/// install itself, before anything has verified DNS end to end. Hosts entries
/// make that independent of the DC being reachable at that exact moment.
pub struct CertSecureWriteHosts;

impl CommandHandler for CertSecureWriteHosts {
    fn name(&self) -> &'static str {
        "certsecure.write_hosts"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let block = parse_hosts_entries(required(ctx, "entries")?)?;

        ctx.progress.report(crate::report::OpRunState::running(
            "writing hosts entries",
            50.0,
        ));

        let script = r#"set -eu
begin="$1"
end="$2"
block="$3"
tmp="$(mktemp)"
# Drop any previous managed block, then append the current one. sed's range
# form deletes an unterminated block to EOF too, so a half-written file from an
# interrupted run converges rather than accumulating.
sed "/^${begin}\$/,/^${end}\$/d" /etc/hosts > "$tmp"
{
  printf '%s\n' "$begin"
  printf '%s\n' "$block"
  printf '%s\n' "$end"
} >> "$tmp"
# Preserve /etc/hosts' own mode and ownership rather than mktemp's 0600, which
# would make the file unreadable to every non-root resolver on the box.
chmod 0644 "$tmp"
chown root:root "$tmp"
cat "$tmp" > /etc/hosts
rm -f "$tmp"
grep -c . /etc/hosts
"#;
        let args = [
            HOSTS_BEGIN.to_string(),
            HOSTS_END.to_string(),
            block.clone(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "entries": block.lines().count(),
            "totalLines": output.stdout.trim().parse::<u32>().unwrap_or(0),
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Generate the product's TLS certificate: self-signed RSA-2048/SHA-256, with
/// a SAN for every name the service answers to plus its address.
///
/// Deliberately **not** issued by the lab CA. The shipping lab's root and
/// issuing CAs are ML-DSA-87 for both signature and public key, and no shipping
/// browser validates ML-DSA in a TLS chain — a CA-issued certificate here
/// produces a service that cannot be opened at all. (The issuing CA also
/// publishes no WebServer template, so there is no enrolment path to it
/// either.) The trade is explicit: this certificate is trusted by pushing it
/// into each Windows lab node's machine root store, which is a step of its own
/// in the sequence.
///
/// Returns the DER in `contentB64` — the key the sequence engine's `produces`
/// lifts into the artifact relay, so the trust push consumes this exact bytes
/// rather than re-reading the file.
pub struct CertSecureMakeCert;

impl CommandHandler for CertSecureMakeCert {
    fn name(&self) -> &'static str {
        "certsecure.make_cert"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let names_raw = required(ctx, "names")?;
        let names: Vec<&str> = names_raw
            .split(',')
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .collect();
        if names.is_empty() || !names.iter().all(|name| valid_dns_name(name)) {
            return Err(invalid(
                "names",
                "must be a comma-separated list of DNS names",
            ));
        }
        if names.len() > 8 {
            return Err(invalid(
                "names",
                "at most 8 subject alternative names",
            ));
        }
        let ip = param(ctx, "ip").unwrap_or_default();
        if !ip.is_empty() && !valid_ipv4(ip) {
            return Err(invalid("ip", "must be an IPv4 address"));
        }
        let cert_path = required(ctx, "certPath")?;
        let key_path = required(ctx, "keyPath")?;
        for (name, path) in [("certPath", cert_path), ("keyPath", key_path)] {
            if !valid_posix_path(path) || !path.starts_with(INSTALL_DIR) {
                return Err(invalid(
                    name,
                    "must be an absolute path under the product install directory",
                ));
            }
        }
        let days = param(ctx, "days").unwrap_or("825");
        if !days.parse::<u32>().is_ok_and(|d| (1..=3650).contains(&d)) {
            return Err(invalid("days", "must be an integer in 1-3650"));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "generating TLS certificate",
            30.0,
        ));

        // `-addext` rather than a written-out openssl.cnf: the SAN list is the
        // only variable part, and a config file would have to be templated with
        // the same values anyway. The system openssl is used on purpose — the
        // installer's side-by-side OpenSSL 3.5 build does not exist yet at this
        // point in the sequence.
        let script = r#"set -eu
cert_path="$1"
key_path="$2"
subject_cn="$3"
san="$4"
days="$5"
mkdir -p "$(dirname "$cert_path")" "$(dirname "$key_path")"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -days "$days" \
  -keyout "$key_path" -out "$cert_path" \
  -subj "/CN=${subject_cn}" \
  -addext "subjectAltName=${san}" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
chmod 0600 "$key_path"
chmod 0644 "$cert_path"
printf '{"contentB64":"%s","sha256":"%s","notAfter":"%s"}' \
  "$(openssl x509 -in "$cert_path" -outform DER | base64 -w0)" \
  "$(openssl x509 -in "$cert_path" -outform DER | sha256sum | cut -d' ' -f1)" \
  "$(openssl x509 -in "$cert_path" -noout -enddate | cut -d= -f2)"
"#;
        let mut san: Vec<String> =
            names.iter().map(|name| format!("DNS:{name}")).collect();
        if !ip.is_empty() {
            san.push(format!("IP:{ip}"));
        }
        let args = [
            cert_path.to_string(),
            key_path.to_string(),
            names[0].to_string(),
            san.join(","),
            days.to_string(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let payload = parse_json(&output.stdout);
        if payload["contentB64"].as_str().is_none() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: 1,
                    stderr: "certsecure.make_cert produced no certificate"
                        .into(),
                },
            ));
        }
        let result = json!({
            "certPath": cert_path,
            "keyPath": key_path,
            "subject": names[0],
            "sans": san,
            "contentB64": payload["contentB64"],
            "sha256": payload["sha256"],
            "notAfter": payload["notAfter"],
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Run the vendor installer non-interactively.
///
/// `install-linux.sh`'s `read_inputs` prompts for six values on stdin in a
/// fixed order; they are piped in rather than passed as flags because the
/// installer accepts none. It derives `conf.ini` and its own log path from
/// `$(pwd)`, so it must run with the product tree as the working directory.
///
/// Every expensive phase is idempotent (the OpenSSL build skips on an exact
/// version match, `setup_venv` on an existing venv, nginx once installed), so a
/// re-run to change host names is cheap and a redelivered step is safe.
pub struct CertSecureInstall;

impl CommandHandler for CertSecureInstall {
    fn name(&self) -> &'static str {
        "certsecure.install"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let frontend = required(ctx, "frontendHost")?;
        let backend = required(ctx, "backendHost")?;
        let keycloak = required(ctx, "keycloakHost")?;
        for (name, value) in [
            ("frontendHost", frontend),
            ("backendHost", backend),
            ("keycloakHost", keycloak),
        ] {
            if !valid_dns_name(value) {
                return Err(invalid(name, "must be a DNS name"));
            }
        }
        let realm = required(ctx, "keycloakRealm")?;
        // The installer's own `validate_inputs` rule — enforced here so a bad
        // realm fails before 595 seconds of installation rather than after.
        let realm_ok = (1..=64).contains(&realm.len())
            && realm
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
        if !realm_ok {
            return Err(invalid(
                "keycloakRealm",
                "may only contain letters, digits, dot, dash, underscore",
            ));
        }
        let cert_path = required(ctx, "certPath")?;
        let key_path = required(ctx, "keyPath")?;
        for (name, path) in [("certPath", cert_path), ("keyPath", key_path)] {
            if !valid_posix_path(path) || !path.starts_with(INSTALL_DIR) {
                return Err(invalid(
                    name,
                    "must be an absolute path under the product install directory",
                ));
            }
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "installing CertSecure Manager",
            10.0,
        ));

        let script = r#"set -eu
install_dir="$1"
cd "$install_dir"
chmod +x ./install-linux.sh
# The six read_inputs prompts, in order: frontend host, backend host, SSL
# certificate path, SSL private key path, Keycloak host, Keycloak realm.
printf '%s\n%s\n%s\n%s\n%s\n%s\n' "$2" "$3" "$4" "$5" "$6" "$7" \
  | ./install-linux.sh
# The installer's own log is the record of what happened; echo its tail so a
# failed step carries something diagnosable in the op error.
tail -n 5 "${install_dir}/installation-logs.log" 2>/dev/null || true
"#;
        let args = [
            INSTALL_DIR.to_string(),
            frontend.to_string(),
            backend.to_string(),
            cert_path.to_string(),
            key_path.to_string(),
            keycloak.to_string(),
            realm.to_string(),
        ];
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let result = json!({
            "installDir": INSTALL_DIR,
            "frontendHost": frontend,
            "backendHost": backend,
            "keycloakHost": keycloak,
            "keycloakRealm": realm,
            "frontendUrl": format!("https://{frontend}/"),
            "raw": output.stdout.trim(),
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// Probe the product's own HTTPS endpoints from the guest.
///
/// Read tier, and safe to re-run — which is what lets the sequence use it two
/// ways: as the install step's hard `verify` gate (the dashboard must answer
/// 200) and as an advisory `settle` on Keycloak, which finishes coming up after
/// `kc.sh build` on its own schedule and must never be able to fail a
/// deployment on its own.
///
/// `curl -k`, deliberately: the certificate is the self-signed one this agent
/// generated minutes earlier, and the guest is the one machine in the lab that
/// was never given it to trust. The trust push targets the Windows nodes, where
/// it matters, and *that* is what the end-to-end check exercises. Verifying
/// here would only assert something about this box's own CA bundle.
pub struct CertSecureVerify;

impl CommandHandler for CertSecureVerify {
    fn name(&self) -> &'static str {
        "certsecure.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let frontend = required(ctx, "frontendUrl")?;
        let keycloak = param(ctx, "keycloakUrl").unwrap_or_default();
        for (name, value) in
            [("frontendUrl", frontend), ("keycloakUrl", keycloak)]
        {
            if !value.is_empty() && !valid_https_url(value) {
                return Err(invalid(name, "must be an https:// URL"));
            }
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "probing product endpoints",
            50.0,
        ));

        // `000` is curl's own "no response at all" code; reported as-is rather
        // than mapped to an error, because a settle predicate wants a *result*
        // it can keep waiting on, not a failed step.
        let script = r#"set -eu
probe() {
  [ -z "$1" ] && { printf '0'; return; }
  curl -sk -o /dev/null -m 10 -w '%{http_code}' "$1" 2>/dev/null || printf '000'
}
printf '{"frontendStatus":"%s","keycloakStatus":"%s"}'   "$(probe "$1")" "$(probe "${2:-}")"
"#;
        let args = [frontend.to_string(), keycloak.to_string()];
        let output = require_success(ctx.shell.run(script, &args)?)?;
        let payload = parse_json(&output.stdout);

        let frontend_status = payload["frontendStatus"].as_str().unwrap_or("0");
        let keycloak_status = payload["keycloakStatus"].as_str().unwrap_or("0");
        let result = json!({
            "frontendUrl": frontend,
            "frontendStatus": frontend_status,
            "frontendOk": http_ok(frontend_status),
            "keycloakUrl": keycloak,
            "keycloakStatus": keycloak_status,
            // An unconfigured Keycloak URL settles immediately rather than
            // holding the window open for five minutes on a probe nobody asked
            // for.
            "keycloakOk": keycloak.is_empty() || http_ok(keycloak_status),
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

fn valid_https_url(value: &str) -> bool {
    value.len() <= 200
        && value.starts_with("https://")
        && value[8..].chars().all(|c| {
            c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c)
        })
}

/// Any 2xx or 3xx. A dashboard behind an identity provider legitimately answers
/// 302 to an unauthenticated GET, so requiring 200 exactly would report a
/// healthy CertSecure as broken.
fn http_ok(status: &str) -> bool {
    status
        .parse::<u16>()
        .is_ok_and(|code| (200..400).contains(&code))
}

/// The four files the vendor installer leaves world-readable at 0755 — its own
/// log claims they are root-readable only. `key.pem` is the service's TLS
/// private key and `keycloak-credentials.txt` holds the generated client secret
/// and service-account password, so this is not cosmetic.
const HARDENED: &[(&str, &str)] = &[
    ("conf/key.pem", "600"),
    ("conf/keycloak-credentials.txt", "600"),
    ("conf/server.yaml", "640"),
    ("conf.ini", "640"),
];

pub struct CertSecureHarden;

impl CommandHandler for CertSecureHarden {
    fn name(&self) -> &'static str {
        "certsecure.harden"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "restricting credential file modes",
            50.0,
        ));

        // A file the installer did not produce on this run is skipped, not an
        // error: the set is a superset across product versions, and failing the
        // op over an absent file would undo a completed install.
        let script = r#"set -eu
install_dir="$1"
shift
changed=""
while [ "$#" -gt 0 ]; do
  rel="$1"
  mode="$2"
  shift 2
  path="${install_dir}/${rel}"
  if [ -f "$path" ]; then
    chown root:root "$path"
    chmod "$mode" "$path"
    changed="${changed}${rel} "
  fi
done
printf '%s' "$changed"
"#;
        let mut args = vec![INSTALL_DIR.to_string()];
        for (rel, mode) in HARDENED {
            args.push((*rel).to_string());
            args.push((*mode).to_string());
        }
        let output = require_success(ctx.shell.run(script, &args)?)?;

        let hardened: Vec<&str> = output.stdout.split_whitespace().collect();
        let result = json!({ "hardened": hardened });
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

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn run(
        handler: &dyn CommandHandler,
        pairs: &[(&str, &str)],
        stdout: &str,
    ) -> Result<serde_json::Value, CommandError> {
        let map = params(pairs);
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(stdout);
        let ctx = CommandContext {
            params: &map,
            progress: &NullProgressSink,
            shell,
        };
        handler.execute(&ctx)
    }

    #[test]
    fn hosts_entries_reject_anything_that_is_not_ip_plus_names() {
        for raw in [
            "not-an-ip certsecure.encon.pki",
            "10.0.181.5",
            "10.0.181.5 bad_name",
            "999.1.1.1 certsecure",
            "",
        ] {
            assert!(
                parse_hosts_entries(raw).is_err(),
                "{raw:?} should be rejected"
            );
        }
    }

    #[test]
    fn hosts_entries_normalize_whitespace() {
        let block = parse_hosts_entries(
            "  10.0.181.5   certsecure  certsecure-api \n\n",
        )
        .unwrap();
        assert_eq!(block, "10.0.181.5 certsecure certsecure-api");
    }

    #[test]
    fn make_cert_requires_paths_inside_the_product_tree() {
        let err = run(
            &CertSecureMakeCert,
            &[
                ("names", "certsecure.encon.pki"),
                ("certPath", "/etc/ssl/private/cert.pem"),
                ("keyPath", "/opt/certsecure-manager/conf/key.pem"),
            ],
            "",
        );
        assert!(matches!(err, Err(CommandError::InvalidParam { .. })));
    }

    /// `produces` lifts `result.contentB64`; without that exact key the trust
    /// push silently carries nothing.
    #[test]
    fn make_cert_returns_the_der_under_the_relay_key() {
        let result = run(
            &CertSecureMakeCert,
            &[
                ("names", "certsecure.encon.pki,certsecure-api.encon.pki"),
                ("ip", "10.0.181.5"),
                ("certPath", "/opt/certsecure-manager/conf/cert.pem"),
                ("keyPath", "/opt/certsecure-manager/conf/key.pem"),
            ],
            r#"{"contentB64":"MIIB","sha256":"ff","notAfter":"Dec  4 00:00:00 2028 GMT"}"#,
        )
        .unwrap();
        assert_eq!(result["contentB64"], "MIIB");
        assert_eq!(
            result["sans"],
            serde_json::json!([
                "DNS:certsecure.encon.pki",
                "DNS:certsecure-api.encon.pki",
                "IP:10.0.181.5"
            ])
        );
    }

    #[test]
    fn install_rejects_a_realm_keycloak_would_reject() {
        let err = run(
            &CertSecureInstall,
            &[
                ("frontendHost", "certsecure.encon.pki"),
                ("backendHost", "certsecure-api.encon.pki"),
                ("keycloakHost", "kc.encon.pki"),
                ("keycloakRealm", "encon pki"),
                ("certPath", "/opt/certsecure-manager/conf/cert.pem"),
                ("keyPath", "/opt/certsecure-manager/conf/key.pem"),
            ],
            "",
        );
        assert!(matches!(err, Err(CommandError::InvalidParam { .. })));
    }

    #[test]
    fn install_pipes_six_answers_in_read_inputs_order() {
        let map = params(&[
            ("frontendHost", "certsecure.encon.pki"),
            ("backendHost", "certsecure-api.encon.pki"),
            ("keycloakHost", "kc.encon.pki"),
            ("keycloakRealm", "encon.pki"),
            ("certPath", "/opt/certsecure-manager/conf/cert.pem"),
            ("keyPath", "/opt/certsecure-manager/conf/key.pem"),
        ]);
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("===== Installation Completed Successfully =====");
        let ctx = CommandContext {
            params: &map,
            progress: &NullProgressSink,
            shell: shell.clone(),
        };
        let result = CertSecureInstall.execute(&ctx).unwrap();
        assert_eq!(result["frontendUrl"], "https://certsecure.encon.pki/");
        let script = shell.calls.lock().unwrap()[0].clone();
        // $2..$7 map to frontend, backend, cert, key, keycloak host, realm —
        // the order `read_inputs` prompts in, which no flag makes explicit.
        assert!(script.contains(r#""$2" "$3" "$4" "$5" "$6" "$7""#));
    }

    #[test]
    fn verify_treats_a_redirect_as_healthy() {
        // The dashboard bounces an unauthenticated GET to Keycloak; a 200-only
        // gate would report a working install as a failure.
        let result = run(
            &CertSecureVerify,
            &[
                ("frontendUrl", "https://certsecure.encon.pki/"),
                ("keycloakUrl", "https://kc.encon.pki/"),
            ],
            r#"{"frontendStatus":"302","keycloakStatus":"200"}"#,
        )
        .unwrap();
        assert_eq!(result["frontendOk"], true);
        assert_eq!(result["keycloakOk"], true);
    }

    #[test]
    fn verify_reports_no_answer_without_failing_the_step() {
        let result = run(
            &CertSecureVerify,
            &[("frontendUrl", "https://certsecure.encon.pki/")],
            r#"{"frontendStatus":"000","keycloakStatus":"0"}"#,
        )
        .unwrap();
        assert_eq!(result["frontendOk"], false);
        // No Keycloak URL configured: settles immediately rather than holding
        // an advisory window open on a probe nobody asked for.
        assert_eq!(result["keycloakOk"], true);
    }

    #[test]
    fn harden_reports_only_the_files_that_existed() {
        let result =
            run(&CertSecureHarden, &[], "conf/key.pem conf.ini ").unwrap();
        assert_eq!(
            result["hardened"],
            serde_json::json!(["conf/key.pem", "conf.ini"])
        );
    }
}
