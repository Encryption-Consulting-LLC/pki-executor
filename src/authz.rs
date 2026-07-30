//! Local mirror of `EC-PKI-Playground/backend/src/app/core/authz.py`.
//!
//! Capability wire values MUST match the backend's `Capability.value`
//! strings exactly — they are intended to cross the wire once the
//! executor talks to the backend. There is no automated sync between the
//! two languages: if you add or rename a capability here, update
//! `authz.py`'s `Capability` and `ROLE_CAPABILITIES` too.
//!
//! `VM_EXEC_ARBITRARY` must remain absent from `Role::Guest`'s capability
//! set — see `tests::guest_cannot_exec_arbitrary`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    #[serde(rename = "vm:list")]
    VmList,
    #[serde(rename = "vm:read")]
    VmRead,
    #[serde(rename = "vm:clone")]
    VmClone,
    #[serde(rename = "vm:update")]
    VmUpdate,
    #[serde(rename = "vm:power")]
    VmPower,
    #[serde(rename = "vm:delete")]
    VmDelete,
    #[serde(rename = "vm:provision")]
    VmProvision,
    #[serde(rename = "config:generate")]
    ConfigGenerate,
    #[serde(rename = "vm:exec-arbitrary")]
    VmExecArbitrary,
    #[serde(rename = "deploy")]
    Deploy,
}

impl Capability {
    pub const ALL: &'static [Capability] = &[
        Capability::VmList,
        Capability::VmRead,
        Capability::VmClone,
        Capability::VmUpdate,
        Capability::VmPower,
        Capability::VmDelete,
        Capability::VmProvision,
        Capability::ConfigGenerate,
        Capability::VmExecArbitrary,
        Capability::Deploy,
    ];

    /// The exact wire string used by the backend's `Capability.value`.
    pub fn wire_value(self) -> &'static str {
        match self {
            Capability::VmList => "vm:list",
            Capability::VmRead => "vm:read",
            Capability::VmClone => "vm:clone",
            Capability::VmUpdate => "vm:update",
            Capability::VmPower => "vm:power",
            Capability::VmDelete => "vm:delete",
            Capability::VmProvision => "vm:provision",
            Capability::ConfigGenerate => "config:generate",
            Capability::VmExecArbitrary => "vm:exec-arbitrary",
            Capability::Deploy => "deploy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    #[serde(rename = "operator")]
    Operator,
    #[serde(rename = "guest")]
    Guest,
}

impl Role {
    /// Mirrors the backend's `ROLE_CAPABILITIES` mapping.
    pub fn capabilities(self) -> &'static [Capability] {
        match self {
            Role::Operator => Capability::ALL,
            Role::Guest => &[
                Capability::VmList,
                Capability::VmRead,
                Capability::VmClone,
                Capability::VmDelete,
                Capability::VmProvision,
                Capability::Deploy,
            ],
        }
    }

    pub fn has(self, cap: Capability) -> bool {
        self.capabilities().contains(&cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_cannot_exec_arbitrary() {
        assert!(!Role::Guest.has(Capability::VmExecArbitrary));
    }

    #[test]
    fn operator_has_every_capability() {
        for cap in Capability::ALL {
            assert!(Role::Operator.has(*cap));
        }
    }

    #[test]
    fn guest_capability_set_matches_backend_allowlist() {
        let allowed = [
            Capability::VmList,
            Capability::VmRead,
            Capability::VmClone,
            Capability::VmDelete,
            Capability::VmProvision,
            Capability::Deploy,
        ];
        for cap in &allowed {
            assert!(Role::Guest.has(*cap));
        }

        let forbidden = [
            Capability::VmUpdate,
            Capability::VmPower,
            Capability::ConfigGenerate,
            Capability::VmExecArbitrary,
        ];
        for cap in &forbidden {
            assert!(!Role::Guest.has(*cap));
        }
    }

    #[test]
    fn wire_values_match_backend_verbatim() {
        assert_eq!(Capability::VmList.wire_value(), "vm:list");
        assert_eq!(Capability::VmRead.wire_value(), "vm:read");
        assert_eq!(Capability::VmClone.wire_value(), "vm:clone");
        assert_eq!(Capability::VmUpdate.wire_value(), "vm:update");
        assert_eq!(Capability::VmPower.wire_value(), "vm:power");
        assert_eq!(Capability::VmDelete.wire_value(), "vm:delete");
        assert_eq!(Capability::VmProvision.wire_value(), "vm:provision");
        assert_eq!(Capability::ConfigGenerate.wire_value(), "config:generate");
        assert_eq!(
            Capability::VmExecArbitrary.wire_value(),
            "vm:exec-arbitrary"
        );
        assert_eq!(Capability::Deploy.wire_value(), "deploy");
    }

    #[test]
    fn serde_round_trip_uses_wire_values() {
        assert_eq!(
            serde_json::to_string(&Capability::VmExecArbitrary).unwrap(),
            "\"vm:exec-arbitrary\""
        );
        assert_eq!(serde_json::to_string(&Role::Guest).unwrap(), "\"guest\"");
    }
}
