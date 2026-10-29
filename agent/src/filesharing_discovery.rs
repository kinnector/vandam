use crate::generic_discovery::discover_and_enforce_services;

pub fn enforce_filesharing_policies() {
    let services = discover_and_enforce_services("linux_filesharing_signatures.json", 0);
    tracing::info!("[Vandam FileSharing] Discovered {} file sharing services.", services.len());
}
