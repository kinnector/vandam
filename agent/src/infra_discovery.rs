use crate::generic_discovery::discover_and_enforce_services;

pub fn enforce_infra_policies() {
    let services = discover_and_enforce_services("linux_infrastructure_signatures.json", 0);
    tracing::info!("[Vandam Infra] Discovered {} infrastructure services.", services.len());
}
