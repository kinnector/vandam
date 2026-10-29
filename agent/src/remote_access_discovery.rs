use crate::generic_discovery::discover_and_enforce_services;

pub fn enforce_remote_access_policies() {
    let services = discover_and_enforce_services("linux_remote_access_signatures.json", 0);
    tracing::info!("[Vandam RemoteAccess] Discovered {} remote access services.", services.len());
}
