//! sluss — Unified router management CLI
//!
//! A token-efficient CLI for both humans and AI agents to manage
//! DNS, DHCP, firewall, security, and VPN on a Linux router.

mod adapters;
mod cli;
mod commands;
mod location;
mod notify;
mod output;
mod web;

use anyhow::Result;
use clap::Parser;
use tracing::error;

use cli::{Cli, Commands, DdnsAction, DhcpAction, DnsAction, FwAction, SecAction, VpnAction};

fn main() {
    // Initialize logging (stderr only, preserve stdout for output)
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sluss=info".parse().unwrap()),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        error!("{:#}", e);
        std::process::exit(1);
    }
}

#[tokio::main]
async fn run_web(bind: String, port: u16) -> Result<()> {
    web::serve(&bind, port).await
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Status => commands::status::status(cli.json),
        Commands::Doctor => commands::status::doctor(cli.json),

        Commands::Dns { action } => match action {
            DnsAction::List => commands::dns::list(cli.json),
            DnsAction::Add { hostname, ip } => commands::dns::add(&hostname, ip, cli.json),
            DnsAction::Rm { hostname } => commands::dns::remove(&hostname, cli.json),
        },

        Commands::Dhcp { action } => match action {
            DhcpAction::Leases => commands::dhcp::leases(cli.json),
            DhcpAction::Reserve { mac, ip, hostname } => {
                commands::dhcp::reserve(&mac, ip, hostname.as_deref(), cli.yes, cli.json)
            }
            DhcpAction::Unreserve { target } => {
                commands::dhcp::unreserve(&target, cli.yes, cli.json)
            }
        },

        Commands::Fw { action } => match action {
            FwAction::List => commands::fw::list(cli.json),
            FwAction::Forward {
                external_port,
                internal,
                proto,
            } => commands::fw::forward(external_port, &internal, &proto, cli.yes, cli.json),
            FwAction::Unforward { external_port } => {
                commands::fw::unforward(external_port, cli.yes, cli.json)
            }
            FwAction::Block { target } => commands::fw::block(&target, cli.yes, cli.json),
            FwAction::Unblock { target } => commands::fw::unblock(&target, cli.yes, cli.json),
        },

        Commands::Sec { action } => match action {
            SecAction::Status => commands::sec::status(cli.json),
            SecAction::Blocks => commands::sec::blocks(cli.json),
            SecAction::Scan => commands::sec::scan(cli.json),
            SecAction::Report { hours } => commands::sec::report(hours, cli.json),
            SecAction::Findings { days } => commands::sec::findings(days, cli.json),
        },

        Commands::Vpn { action } => match action {
            VpnAction::Peers => commands::vpn::peers(cli.json),
            VpnAction::Status => commands::vpn::status(cli.json),
        },

        Commands::Ddns { action } => match action {
            DdnsAction::Status => commands::ddns::status(cli.json),
            DdnsAction::Update { force } => commands::ddns::update(force, cli.json),
        },

        Commands::Web { port, bind } => run_web(bind, port),
    }
}
