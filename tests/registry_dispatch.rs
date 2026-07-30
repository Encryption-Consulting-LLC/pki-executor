use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use pki_executor::{
    authz::{Capability, Role},
    powershell::MockPowerShell,
    registry::{
        CommandContext, CommandError, CommandHandler, CommandRegistry,
        DispatchError,
    },
    report::NullProgressSink,
};

struct SpyHandler {
    capability: Capability,
    calls: Arc<AtomicUsize>,
}

impl CommandHandler for SpyHandler {
    fn name(&self) -> &'static str {
        "spy.command"
    }

    fn required_capability(&self) -> Capability {
        self.capability
    }

    fn execute(
        &self,
        _ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({ "ok": true }))
    }
}

fn registry_with_spy(
    capability: Capability,
) -> (CommandRegistry, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut registry = CommandRegistry::new();
    registry.register(Box::new(SpyHandler {
        capability,
        calls: calls.clone(),
    }));
    (registry, calls)
}

fn mock_shell() -> Arc<dyn pki_executor::powershell::PowerShellExecutor> {
    Arc::new(MockPowerShell::new())
}

#[test]
fn forbidden_role_never_reaches_handler() {
    let (registry, calls) = registry_with_spy(Capability::VmExecArbitrary);
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "spy.command",
        Role::Guest,
        HashMap::new(),
        &sink,
        mock_shell(),
    );
    assert!(matches!(result, Err(DispatchError::Forbidden { .. })));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn allowed_role_reaches_handler() {
    let (registry, calls) = registry_with_spy(Capability::VmRead);
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "spy.command",
        Role::Guest,
        HashMap::new(),
        &sink,
        mock_shell(),
    );
    assert!(result.is_ok());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn unknown_command_is_reported() {
    let registry = CommandRegistry::new();
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "does.not.exist",
        Role::Operator,
        HashMap::new(),
        &sink,
        mock_shell(),
    );
    assert!(matches!(result, Err(DispatchError::UnknownCommand(_))));
}

#[test]
fn guest_specifically_cannot_reach_exec_arbitrary_gate() {
    let (registry, calls) = registry_with_spy(Capability::VmExecArbitrary);
    let sink = NullProgressSink;
    let result = registry.dispatch(
        "spy.command",
        Role::Guest,
        HashMap::new(),
        &sink,
        mock_shell(),
    );
    assert!(matches!(
        result,
        Err(DispatchError::Forbidden {
            required: Capability::VmExecArbitrary,
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
