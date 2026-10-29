mod investigate;
mod firewall_sync;
mod rasp;
mod quota_guard;
mod cloud_api;
mod session_correlation;
mod summarize;
mod deep_audit;
mod supply_chain_cloud;

use clap::Parser;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "vandamd")]
#[command(about = "vandam: Server EDR Daemon", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/var/run/kinnector/telemetry.sock", help = "Path to core telemetry UDS socket")]
    telemetry_socket: String,

    #[arg(short, long, default_value = "/var/www/html", help = "Web application root directory for FIM and OSV scans")]
    web_root: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging with env-filter
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into()))
        .init();

    let args = Args::parse();

    // Warning signal consumer: receives raw JSON from heuristics ext_tx
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<String>(2048);
    tokio::spawn(async move {
        while let Some(raw_json) = event_rx.recv().await {
            tracing::debug!("Warning event received: {}", raw_json);
            // "SessionActivity" entries (Decision 3, Access design plan) get
            // routed into the session-correlation store; anything else is a
            // no-op here.
            session_correlation::handle_event(&raw_json);
        }
    });

    let config = vandam::VandamConfig {
        telemetry_socket: args.telemetry_socket,
        web_root: args.web_root,
        telemetry_enabled: true,
        event_tx: Some(event_tx),
        on_engine_ready: Some(Box::new(move |engine: Arc<vandam::heuristics::HeuristicsEngine>| {
            tokio::spawn(rasp::start_rasp_listener(Arc::clone(&engine)));
            tokio::spawn(deep_audit::cloud_transport::run(engine));
        })),
        extra_routes: Some(
            investigate::router()
                .merge(firewall_sync::router())
                .merge(cloud_api::router())
                .merge(summarize::router())
                .merge(deep_audit::api::router())
                .merge(supply_chain_cloud::router()),
        ),
        firewall_cloud_sync: Some(Arc::new(firewall_sync::ProFirewallSync)),
    };

    vandam::run_vandam(config).await
}
