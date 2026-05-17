use std::path::PathBuf;

use clap::Parser;
use tokio::sync::mpsc;
use tracing::{info, error};
use tracing_subscriber::EnvFilter;

use siem_rust::collectors::{
    FileCollector, StdinCollector, SyslogTcpCollector, SyslogUdpCollector,
};
use siem_rust::pipeline::Pipeline;
use siem_rust::storage::{FileStorage, InMemoryStorage};

#[derive(Parser, Debug)]
#[command(name = "siem-rust")]
#[command(about = "SIEM Log Ingestion and Collection Engine")]
struct Cli {
    /// Enable syslog UDP collector
    #[arg(long, default_value_t = false)]
    syslog_udp: bool,

    /// Syslog UDP bind address
    #[arg(long, default_value = "0.0.0.0:1514")]
    syslog_udp_addr: String,

    /// Enable syslog TCP collector
    #[arg(long, default_value_t = false)]
    syslog_tcp: bool,

    /// Syslog TCP bind address
    #[arg(long, default_value = "0.0.0.0:1514")]
    syslog_tcp_addr: String,

    /// Read logs from stdin
    #[arg(long, default_value_t = false)]
    stdin: bool,

    /// Log files to watch (can be specified multiple times)
    #[arg(long, short = 'f')]
    file: Vec<PathBuf>,

    /// Output file for storing events (JSONL format)
    #[arg(long, short = 'o')]
    output: Option<PathBuf>,

    /// Maximum events to keep in memory
    #[arg(long, default_value_t = 10000)]
    max_events: usize,

    /// Channel buffer size for the pipeline
    #[arg(long, default_value_t = 1000)]
    buffer_size: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    info!("SIEM Log Ingestion Engine starting...");

    let has_collectors = cli.syslog_udp || cli.syslog_tcp || cli.stdin || !cli.file.is_empty();
    if !has_collectors {
        error!("No collectors enabled. Use --syslog-udp, --syslog-tcp, --stdin, or --file <path>.");
        error!("Run with --help for usage information.");
        std::process::exit(1);
    }

    let (tx, rx) = mpsc::channel(cli.buffer_size.max(1));

    // Start the pipeline with appropriate storage
    let (stats, pipeline_handle) = if let Some(output_path) = &cli.output {
        let storage = FileStorage::new(output_path.clone(), cli.max_events);
        let pipeline = Pipeline::new(storage);
        let stats = pipeline.stats();
        let handle = tokio::spawn(async move {
            pipeline.run(rx).await;
        });
        (stats, handle)
    } else {
        let storage = InMemoryStorage::new(cli.max_events);
        let pipeline = Pipeline::new(storage);
        let stats = pipeline.stats();
        let handle = tokio::spawn(async move {
            pipeline.run(rx).await;
        });
        (stats, handle)
    };

    // Start collectors
    let mut handles = Vec::new();

    if cli.syslog_udp {
        let collector = SyslogUdpCollector::new(&cli.syslog_udp_addr);
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = collector.run(tx).await {
                error!("Syslog UDP collector failed: {}", e);
            }
        }));
        info!("Syslog UDP collector enabled on {}", cli.syslog_udp_addr);
    }

    if cli.syslog_tcp {
        let collector = SyslogTcpCollector::new(&cli.syslog_tcp_addr);
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = collector.run(tx).await {
                error!("Syslog TCP collector failed: {}", e);
            }
        }));
        info!("Syslog TCP collector enabled on {}", cli.syslog_tcp_addr);
    }

    if !cli.file.is_empty() {
        let collector = FileCollector::new(cli.file.clone());
        let tx = tx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = collector.run(tx).await {
                error!("File collector failed: {}", e);
            }
        }));
        info!("File collector watching: {:?}", cli.file);
    }

    if cli.stdin {
        let collector = StdinCollector::new();
        let tx_stdin = tx.clone();
        handles.push(tokio::spawn(async move {
            if let Err(e) = collector.run(tx_stdin).await {
                error!("Stdin collector failed: {}", e);
            }
        }));
        info!("Stdin collector enabled");
    }

    drop(tx);

    // Print stats on Ctrl+C
    let stats_clone = stats.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutting down... {}", stats_clone.summary());
        std::process::exit(0);
    });

    for handle in handles {
        let _ = handle.await;
    }

    // Wait for pipeline to finish processing all queued events
    let _ = pipeline_handle.await;

    info!("All collectors finished. {}", stats.summary());
}
