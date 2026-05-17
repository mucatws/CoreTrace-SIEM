use tokio::net::UdpSocket;
use tracing::{error, info};

use crate::models::LogSource;
use super::RawLogSender;

pub struct SyslogUdpCollector {
    bind_addr: String,
}

impl SyslogUdpCollector {
    pub fn new(bind_addr: &str) -> Self {
        Self {
            bind_addr: bind_addr.to_string(),
        }
    }

    pub async fn run(&self, sender: RawLogSender) -> std::io::Result<()> {
        let socket = UdpSocket::bind(&self.bind_addr).await?;
        info!("Syslog UDP collector listening on {}", self.bind_addr);

        let mut buf = vec![0u8; 65535];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let raw = String::from_utf8_lossy(&buf[..len]).to_string();
                    let raw = raw.trim().to_string();
                    if raw.is_empty() {
                        continue;
                    }

                    if let Err(e) = sender
                        .send((raw, LogSource::SyslogUdp, Some(addr.to_string())))
                        .await
                    {
                        error!("Failed to send UDP log to pipeline: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("UDP recv error: {}", e);
                }
            }
        }

        Ok(())
    }
}
