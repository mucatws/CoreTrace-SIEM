use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{error, info};

use crate::models::LogSource;
use super::RawLogSender;

pub struct StdinCollector;

impl StdinCollector {
    pub fn new() -> Self {
        Self
    }

    pub async fn run(&self, sender: RawLogSender) -> std::io::Result<()> {
        info!("Stdin collector started, reading from standard input...");

        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    let line = line.trim().to_string();
                    if line.is_empty() {
                        continue;
                    }

                    if let Err(e) = sender.send((line, LogSource::Stdin, None)).await {
                        error!("Failed to send stdin log to pipeline: {}", e);
                        break;
                    }
                }
                Ok(None) => {
                    info!("Stdin closed (EOF)");
                    break;
                }
                Err(e) => {
                    error!("Stdin read error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Default for StdinCollector {
    fn default() -> Self {
        Self::new()
    }
}
