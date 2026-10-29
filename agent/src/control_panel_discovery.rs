use crate::generic_discovery::{discover_and_enforce_services, ROLE_CONTROL_PANEL};

pub fn enforce_control_panel_policies() {
    let services = discover_and_enforce_services("linux_control_panel_signatures.json", ROLE_CONTROL_PANEL);
    tracing::info!("[Vandam ControlPanel] Discovered {} control panel services.", services.len());
}

pub fn is_control_panel_signature(sig: &str) -> bool {
    matches!(sig, "cpanel" | "plesk" | "webmin" | "aapanel" | "cyberpanel" | "hestiacp" | "vestacp")
}
