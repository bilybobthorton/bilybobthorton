/// SentinelCore Agent — lightweight endpoint security daemon.
/// Monitors file system, processes, and file integrity in real time.
mod alert;
mod config;
mod monitor;
mod quarantine;
mod reporter;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use crossbeam_channel::unbounded;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "sentinel-agent",
    version = "0.1.0",
    about = "SentinelCore endpoint security agent",
    long_about = "Real-time malware detection: filesystem monitoring, process analysis, LOLBAS detection, and file integrity verification."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// API endpoint to report alerts to
    #[arg(
        long,
        env = "SENTINEL_API_URL",
        default_value = "http://localhost:8000"
    )]
    api_url: String,

    /// API key for authentication
    #[arg(long, env = "SENTINEL_API_KEY", default_value = "")]
    api_key: String,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_level: String,

    /// Quarantine vault directory
    #[arg(long)]
    quarantine_dir: Option<PathBuf>,

    /// Auto-quarantine confirmed threats
    #[arg(long, default_value_t = false)]
    auto_quarantine: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the agent daemon (default)
    Run,
    /// List all quarantined files
    Quarantine {
        #[command(subcommand)]
        action: QuarantineCommands,
    },
    /// Show agent status and configuration
    Status,
}

#[derive(Subcommand)]
enum QuarantineCommands {
    /// List quarantined files
    List,
    /// Restore a quarantined file by alert ID
    Restore {
        /// Alert ID of the quarantined file
        alert_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .with_target(false)
        .compact()
        .init();

    // Build config
    let mut config = config::AgentConfig::default();
    if cli.auto_quarantine {
        config.auto_quarantine = true;
    }
    if let Some(dir) = cli.quarantine_dir {
        config.quarantine_dir = dir;
    }
    let config = Arc::new(config);

    match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => run_agent(config, cli.api_url, cli.api_key).await,
        Commands::Quarantine { action } => handle_quarantine(action, &config),
        Commands::Status => {
            print_status(&config);
            Ok(())
        }
    }
}

async fn run_agent(
    config: Arc<config::AgentConfig>,
    api_url: String,
    api_key: String,
) -> Result<()> {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let agent_id = uuid::Uuid::new_v4().to_string();

    info!("SentinelCore Agent v0.1.0 starting");
    info!("Hostname: {}", hostname);
    info!("Agent ID: {}", agent_id);
    info!("Auto-quarantine: {}", config.auto_quarantine);
    info!("Watching {} directories", config.watch_dirs.len());

    // Alert channel — all monitors write here, reporter reads
    let (alert_tx, alert_rx) = unbounded::<alert::Alert>();
    // Second receiver for local logging (clone sender, broadcast manually)
    let (log_tx, log_rx) = unbounded::<alert::Alert>();

    // Fan-out: forward alerts to both reporter and local logger
    let fan_tx = alert_tx.clone();
    let fan_log_tx = log_tx.clone();
    let (raw_tx, raw_rx) = unbounded::<alert::Alert>();

    // Fanout task — reads from raw channel, broadcasts to both reporter + log
    tokio::spawn(async move {
        loop {
            match raw_rx.recv() {
                Ok(alert) => {
                    let _ = fan_tx.send(alert.clone());
                    let _ = fan_log_tx.send(alert);
                }
                Err(_) => break,
            }
        }
    });

    let monitor_tx = raw_tx.clone();

    // Filesystem monitor
    let fs_config = Arc::clone(&config);
    let fs_tx = monitor_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = monitor::filesystem::start_monitor(fs_config, fs_tx).await {
            error!("Filesystem monitor crashed: {}", e);
        }
    });

    // Process monitor
    let proc_config = Arc::clone(&config);
    let proc_tx = monitor_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = monitor::process::start_monitor(proc_config, proc_tx).await {
            error!("Process monitor crashed: {}", e);
        }
    });

    // File integrity monitor
    let fim_tx = monitor_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = monitor::fim::start_monitor(fim_tx).await {
            error!("FIM monitor crashed: {}", e);
        }
    });

    // Network connection monitor
    let net_config = Arc::clone(&config);
    let net_tx = monitor_tx.clone();
    tokio::spawn(async move {
        if let Err(e) = monitor::network::start_monitor(net_config, net_tx).await {
            error!("Network monitor crashed: {}", e);
        }
    });

    // Local alert logger (always active)
    let log_rx_clone = log_rx;
    tokio::spawn(async move {
        reporter::log_alerts_locally(log_rx_clone).await;
    });

    // API reporter (only if API key provided)
    if !api_key.is_empty() {
        match reporter::Reporter::new(api_url.clone(), api_key, agent_id.clone(), hostname.clone())
        {
            Ok(rep) => {
                let rep = Arc::new(rep);
                tokio::spawn(async move {
                    rep.run(alert_rx).await;
                });
                info!("Alert reporter active — shipping to {}", api_url);
            }
            Err(e) => {
                error!(
                    "Failed to initialize reporter: {} — alerts will only log locally",
                    e
                );
            }
        }
    } else {
        info!("No API key set — alerts will only log locally (pass --api-key or SENTINEL_API_KEY)");
    }

    info!("All monitors running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received — stopping agent");

    Ok(())
}

fn handle_quarantine(action: QuarantineCommands, config: &config::AgentConfig) -> Result<()> {
    let vault = quarantine::QuarantineVault::new(config.quarantine_dir.clone())?;

    match action {
        QuarantineCommands::List => {
            let records = vault.list();
            if records.is_empty() {
                println!("Quarantine vault is empty.");
            } else {
                println!(
                    "{:<36} {:<30} {:<12} {}",
                    "Alert ID", "Filename", "Size", "Quarantined At"
                );
                println!("{}", "-".repeat(100));
                for r in &records {
                    let filename = PathBuf::from(&r.original_path)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    println!(
                        "{:<36} {:<30} {:<12} {}",
                        r.alert_id,
                        filename,
                        format_size(r.file_size),
                        r.quarantined_at
                    );
                }
                println!("\nTotal: {} file(s)", records.len());
            }
        }
        QuarantineCommands::Restore { alert_id } => {
            let records = vault.list();
            match records.iter().find(|r| r.alert_id == alert_id) {
                Some(record) => {
                    vault.restore(record)?;
                    println!("Restored: {}", record.original_path);
                }
                None => {
                    eprintln!("No quarantined file found with alert ID: {}", alert_id);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn print_status(config: &config::AgentConfig) {
    println!("SentinelCore Agent v0.1.0");
    println!();
    println!("Watch directories:");
    for dir in &config.watch_dirs {
        println!("  {}", dir.display());
    }
    println!();
    println!("Excluded directories:");
    for dir in &config.exclude_dirs {
        println!("  {}", dir.display());
    }
    println!();
    println!("Auto-quarantine: {}", config.auto_quarantine);
    println!("Quarantine vault: {}", config.quarantine_dir.display());
    println!("Max scan size: {} MB", config.max_scan_size_mb);
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
