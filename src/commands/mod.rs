mod ca;
mod cert_enroll;
mod cert_store;
mod cert_verify;
mod certsecure;
mod dc;
mod dns;
mod domain;
mod exec_arbitrary;
mod file;
mod hostname_read;
mod hostname_rename;
mod iis;
mod ip;
#[cfg(unix)]
mod linux;
mod ocsp;
mod pki_verify;
mod system;
mod system_identity;
mod template;
pub(crate) mod util;

use crate::registry::CommandRegistry;

/// The command surface: the v0 role-spectrum handlers (guest-eligible read,
/// operator-only write, guest-forbidden escape hatch), the hostname/IP
/// read-write parity set, the Phase F CA provisioning commands, and (Phase L)
/// the growing ADCS lab catalog — verify probes first, so every later write
/// command lands with its readiness check already dispatchable. The catalog
/// is mirrored in the backend's `_COMMAND_CAPABILITIES`; both sides assert
/// against the shared fixture in `tests/fixtures/command_catalog.json`.
///
/// The list is unconditional, including the Linux product commands: the
/// catalog is a cross-repo contract asserted against one shared fixture, so a
/// command that existed on only one platform would make that fixture
/// unassertable on the other. Platform differences are expressed by *layering*
/// instead — the `cfg(unix)` block at the end re-registers the Linux
/// implementations of shared names, and `register` overwrites by name, so the
/// name and capability set this returns is identical on both.
pub fn build_default_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.register(Box::new(hostname_rename::HostnameRename));
    registry.register(Box::new(hostname_read::HostnameRead));
    registry.register(Box::new(cert_verify::CertVerify));
    registry.register(Box::new(exec_arbitrary::ExecArbitrary));
    registry.register(Box::new(ip::IpRead));
    registry.register(Box::new(ip::IpWrite));
    registry.register(Box::new(ca::CaInstall));
    registry.register(Box::new(ca::CaConfigureSettings));
    registry.register(Box::new(ca::CaConfigureCdpAia));
    registry.register(Box::new(ca::CaPublishCrl));
    registry.register(Box::new(ca::CaSignRequest));
    registry.register(Box::new(ca::CaInstallCert));
    registry.register(Box::new(ca::CaPublishTemplate));
    registry.register(Box::new(ca::CaVerify));
    registry.register(Box::new(file::FileRead));
    registry.register(Box::new(file::FileWrite));
    registry.register(Box::new(dc::DcVerify));
    registry.register(Box::new(dc::DcInstallForest));
    registry.register(Box::new(domain::DomainVerify));
    registry.register(Box::new(domain::DomainJoin));
    registry.register(Box::new(system::SystemReboot));
    registry.register(Box::new(system::SystemBootInfo::default()));
    registry.register(Box::new(dns::DnsSetClient));
    registry.register(Box::new(dns::DnsCreateRecord));
    registry.register(Box::new(dns::DnsApplyResources));
    registry.register(Box::new(dns::DnsVerify));
    registry.register(Box::new(cert_store::CertAddStore));
    registry.register(Box::new(cert_store::CertDsPublish));
    registry.register(Box::new(template::TemplateGrantAccess));
    registry.register(Box::new(iis::IisSetupCertEnroll));
    registry.register(Box::new(ocsp::OcspInstall));
    registry.register(Box::new(ocsp::OcspConfigureRevocation));
    registry.register(Box::new(ocsp::OcspVerify));
    registry.register(Box::new(cert_enroll::CertEnroll));
    registry.register(Box::new(pki_verify::PkiVerify));
    registry.register(Box::new(system_identity::SystemIdentity));
    registry.register(Box::new(certsecure::AptRefresh));
    registry.register(Box::new(certsecure::CertSecureWriteHosts));
    registry.register(Box::new(certsecure::CertSecureMakeCert));
    registry.register(Box::new(certsecure::CertSecureInstall));
    registry.register(Box::new(certsecure::CertSecureHarden));
    registry.register(Box::new(certsecure::CertSecureVerify));

    // Layered, not forked: every name below is already registered above, so
    // this replaces behaviour without touching the catalog.
    #[cfg(unix)]
    {
        registry.register(Box::new(linux::HostnameRead));
        registry.register(Box::new(linux::SystemIdentity));
        registry.register(Box::new(linux::SystemReboot));
        registry.register(Box::new(linux::SystemBootInfo::default()));
        registry.register(Box::new(linux::FileRead));
        registry.register(Box::new(linux::FileWrite));
    }

    registry
}
