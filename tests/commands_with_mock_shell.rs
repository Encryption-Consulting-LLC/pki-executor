//! Integration tests exercising the full registry wiring (not just each
//! handler's `execute` in isolation) for every command. The load-bearing
//! one is `guest_cannot_exec_arbitrary_end_to_end`: `VM_EXEC_ARBITRARY` must
//! never be reachable by `Role::Guest`, end to end through `dispatch`.

use std::{collections::HashMap, sync::Arc};

use pki_executor::{
    authz::Role, commands::build_default_registry, powershell::MockPowerShell,
    registry::DispatchError, report::NullProgressSink,
};

fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn operator_can_rename_hostname() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success("");
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "hostname.rename",
        Role::Operator,
        params(&[("name", "CA02")]),
        &sink,
        shell,
    );
    assert!(result.is_ok());
}

#[test]
fn guest_cannot_rename_hostname() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "hostname.rename",
        Role::Guest,
        params(&[("name", "CA02")]),
        &sink,
        shell,
    );
    assert!(matches!(result, Err(DispatchError::Forbidden { .. })));
}

#[test]
fn guest_can_verify_cert() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success(r#"{"chain_ok":true,"healthy":true}"#);
    let sink = NullProgressSink;
    let result = registry
        .dispatch(
            "cert.verify",
            Role::Guest,
            params(&[("path", "C:\\win11.cer")]),
            &sink,
            shell,
        )
        .unwrap();
    assert_eq!(result["chain_ok"], true);
}

#[test]
fn guest_can_verify_enterprise_pki() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success(r#"{"healthy":true}"#);
    let sink = NullProgressSink;
    let result = registry
        .dispatch(
            "pki.verify",
            Role::Guest,
            params(&[
                ("rootCaCommonName", "EC-Root-CA"),
                ("issuingCaCommonName", "EC-Issuing-CA"),
                ("templates", "OCSPResponseSigning,Workstation"),
                (
                    "httpUrls",
                    r#"["http://pki.encon.test/CertEnroll/root.crt"]"#,
                ),
            ]),
            &sink,
            shell,
        )
        .unwrap();
    assert_eq!(result["healthy"], true);
}

#[test]
fn guest_can_read_system_identity() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success(
        r#"{"hostname":"DC01","operating_system":"Microsoft Windows Server 2025 Standard","server":true}"#,
    );
    let sink = NullProgressSink;
    let result = registry
        .dispatch("system.identity", Role::Guest, HashMap::new(), &sink, shell)
        .unwrap();
    assert_eq!(result["hostname"], "DC01");
    assert_eq!(result["server"], true);
}

#[test]
fn guest_can_read_hostname() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success("CA02\n");
    let sink = NullProgressSink;
    let result = registry
        .dispatch("hostname.read", Role::Guest, HashMap::new(), &sink, shell)
        .unwrap();
    assert_eq!(result["hostname"], "CA02");
}

#[test]
fn guest_can_read_boot_info() {
    // boot_info is computed natively (tick count + task-file existence), so
    // no shell responses are queued — the result reflects the host we run on.
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    let sink = NullProgressSink;
    let result = registry
        .dispatch(
            "system.boot_info",
            Role::Guest,
            HashMap::new(),
            &sink,
            shell.clone(),
        )
        .unwrap();
    assert!(result["uptimeS"].as_u64().unwrap() > 0);
    assert!(result["finalizePending"].is_boolean());
    assert_eq!(result["finalizeRunning"], false);
    assert!(shell.calls.lock().unwrap().is_empty());
}

#[test]
fn guest_can_read_ip() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success(
        r#"[{"InterfaceAlias":"Ethernet0","IPAddress":"10.0.0.5","PrefixLength":24}]"#
    );
    let sink = NullProgressSink;
    let result = registry
        .dispatch("ip.read", Role::Guest, HashMap::new(), &sink, shell)
        .unwrap();
    assert_eq!(result["addresses"][0]["IPAddress"], "10.0.0.5");
}

#[test]
fn guest_cannot_write_ip() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "ip.write",
        Role::Guest,
        params(&[("address", "10.0.0.5")]),
        &sink,
        shell,
    );
    assert!(matches!(result, Err(DispatchError::Forbidden { .. })));
}

#[test]
fn operator_can_write_ip() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success("");
    let sink = NullProgressSink;
    let result = registry
        .dispatch(
            "ip.write",
            Role::Operator,
            params(&[("address", "10.0.0.5"), ("prefixLength", "16")]),
            &sink,
            shell,
        )
        .unwrap();
    assert_eq!(result["prefix_length"], "16");
}

#[test]
fn guest_cannot_exec_arbitrary_end_to_end() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "powershell.exec_arbitrary",
        Role::Guest,
        params(&[("script", "Remove-Item -Recurse C:\\")]),
        &sink,
        shell,
    );
    assert!(matches!(result, Err(DispatchError::Forbidden { .. })));
}

#[test]
fn operator_can_exec_arbitrary() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    shell.push_success("hello");
    let sink = NullProgressSink;
    let result = registry
        .dispatch(
            "powershell.exec_arbitrary",
            Role::Operator,
            params(&[("script", "echo hello")]),
            &sink,
            shell,
        )
        .unwrap();
    assert_eq!(result["stdout"], "hello");
}

#[test]
fn unknown_command_is_rejected_regardless_of_role() {
    let registry = build_default_registry();
    let shell = Arc::new(MockPowerShell::new());
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "does.not.exist",
        Role::Operator,
        HashMap::new(),
        &sink,
        shell,
    );
    assert!(matches!(result, Err(DispatchError::UnknownCommand(_))));
}
