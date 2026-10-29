//! Typed calls to the agent's local API, one module per area. Shared by the CLI commands and
//! (later) `vandam mcp`, so both read the agent's real JSON the same way.

pub mod access;
pub mod alerts;
pub mod audit;
pub mod cloud;
pub mod containers;
pub mod firewall;
pub mod risks;
pub mod servers;
pub mod status;
pub mod storage;
