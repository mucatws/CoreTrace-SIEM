use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::models::LogSource;
use super::RawLogSender;

pub struct SyslogTcpCollector {
    bind_addr: String,
}

impl SyslogTcpCollector {
    pub fn new(bind_addr: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
        }
    }

    pub async fn run(&self, sender: RawLogSender) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.bind_addr).await?;
        info!("Syslog TCP collector listening on {}", self.bind_addr);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let sender = sender.clone();
                    let addr_str = addr.to_string();
                    info!("New TCP connection from {}", addr_str);

                    tokio::spawn(async move {
                        let reader = BufReader::new(stream);
                        let mut lines = reader.lines();

                        loop {
                            match lines.next_line().await {
                                Ok(Some(line)) => {
                                    let line = line.trim().to_string();
                                    if line.is_empty() {
                                        continue;
                                    }

                                    if let Err(e) = sender
                                        .send((
                                            line,
                                            LogSource::SyslogTcp,
                                            Some(addr_str.clone()),
                                        ))
                                        .await
                                    {
                                        error!("Failed to send TCP log to pipeline: {}", e);
                                        break;
                                    }
                                }
                                Ok(None) => {
                                    info!("TCP connection closed from {}", addr_str);
                                    break;
                                }
                                Err(e) => {
                                    warn!("TCP read error from {}: {}", addr_str, e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                }
            }
        }
    }
}
