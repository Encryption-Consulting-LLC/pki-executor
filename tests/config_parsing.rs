use std::{io::Write, path::Path};

use pki_executor::{
    authz::Role,
    config::{ConfigError, ExecutorConfig},
};

#[test]
fn parses_minimal_config() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
        [identity]
        vm_id = "dev-local"
        role = "operator"
        "#
    )
    .unwrap();

    let config = ExecutorConfig::load_from_file(file.path()).unwrap();
    assert_eq!(config.identity.vm_id, "dev-local");
    assert_eq!(config.identity.role, Role::Operator);
    assert!(config.backend.url.is_none());
}

#[test]
fn execution_defaults_apply_when_section_omitted() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        file,
        r#"
        [identity]
        vm_id = "dev-local"
        role = "guest"
        "#
    )
    .unwrap();

    let config = ExecutorConfig::load_from_file(file.path()).unwrap();
    let expected_shell = if cfg!(windows) {
        "powershell.exe"
    } else {
        "pwsh"
    };
    assert_eq!(config.execution.shell_binary, expected_shell);
    assert_eq!(config.execution.script_timeout_secs, 900);
    assert_eq!(config.service.log_level, "info");
}

#[test]
fn missing_file_is_a_read_error() {
    let result = ExecutorConfig::load_from_file(Path::new(
        "/nonexistent/orchestrator.toml",
    ));
    assert!(matches!(result, Err(ConfigError::Read { .. })));
}

#[test]
fn malformed_toml_is_a_parse_error() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    writeln!(file, "not valid toml [[[").unwrap();
    let result = ExecutorConfig::load_from_file(file.path());
    assert!(matches!(result, Err(ConfigError::Parse { .. })));
}
