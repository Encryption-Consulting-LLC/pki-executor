//! Command-catalog parity: the backend hand-mirrors this registry in
//! `EC-PKI-Playground/backend/src/app/routers/executor.py`'s
//! `_COMMAND_CAPABILITIES`. Both sides assert against a byte-identical
//! fixture — this one and `backend/tests/fixtures/command_catalog.json` —
//! so drift fails a test on whichever side forgot, instead of surfacing as
//! a 422 on dispatch. Adding a command means updating BOTH fixture copies.

use pki_executor::commands::build_default_registry;

#[test]
fn registry_matches_the_shared_catalog_fixture() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/command_catalog.json"))
            .expect("fixture is valid JSON");

    let actual: serde_json::Value = build_default_registry()
        .commands()
        .into_iter()
        .map(|(name, cap)| (name.to_string(), cap.wire_value().into()))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    assert_eq!(
        actual, fixture,
        "registry and tests/fixtures/command_catalog.json disagree — update \
         the fixture here AND the backend's copy + _COMMAND_CAPABILITIES"
    );
}
