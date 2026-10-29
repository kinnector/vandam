use crate::generic_discovery::discover_and_enforce_services;

pub fn enforce_monitoring_policies() {
    let services = discover_and_enforce_services("linux_monitoring_signatures.json", 0);
    tracing::info!("[Vandam Monitoring] Discovered {} monitoring services.", services.len());
}
