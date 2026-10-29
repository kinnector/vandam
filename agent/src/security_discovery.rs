use crate::generic_discovery::discover_and_enforce_services;

pub fn enforce_security_policies() {
    let services = discover_and_enforce_services("linux_security_signatures.json", 0);
    tracing::info!("[Vandam Security] Discovered {} security services.", services.len());
}
