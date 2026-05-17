use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{error, info};

use crate::collectors::RawLogReceiver;
use crate::models::LogEvent;
use crate::parser::LogParser;
use crate::storage::Storage;

pub struct PipelineStats {
    pub events_received: AtomicU64,
    pub events_parsed: AtomicU64,
    pub events_stored: AtomicU64,
    pub events_failed: AtomicU64,
}

impl PipelineStats {
    pub fn new() -> Self {
        Self {
            events_received: AtomicU64::new(0),
            events_parsed: AtomicU64::new(0),
            events_stored: AtomicU64::new(0),
            events_failed: AtomicU64::new(0),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Pipeline Stats - Received: {}, Parsed: {}, Stored: {}, Failed: {}",
            self.events_received.load(Ordering::Relaxed),
            self.events_parsed.load(Ordering::Relaxed),
            self.events_stored.load(Ordering::Relaxed),
            self.events_failed.load(Ordering::Relaxed),
        )
    }
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Pipeline<S: Storage> {
    parser: LogParser,
    storage: S,
    stats: Arc<PipelineStats>,
}

impl<S: Storage> Pipeline<S> {
    pub fn new(storage: S) -> Self {
        Self {
            parser: LogParser::new(),
            storage,
            stats: Arc::new(PipelineStats::new()),
        }
    }

    pub fn stats(&self) -> Arc<PipelineStats> {
        self.stats.clone()
    }

    pub async fn run(&self, mut receiver: RawLogReceiver) {
        info!("Pipeline started, waiting for log events...");

        while let Some((raw, source, addr)) = receiver.recv().await {
            self.stats.events_received.fetch_add(1, Ordering::Relaxed);

            let mut event: LogEvent = self.parser.parse(&raw, source);

            if let Some(addr) = addr {
                event = event.with_source_addr(addr);
            }

            self.stats.events_parsed.fetch_add(1, Ordering::Relaxed);

            match self.storage.store(event).await {
                Ok(()) => {
                    self.stats.events_stored.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    self.stats.events_failed.fetch_add(1, Ordering::Relaxed);
                    error!("Failed to store event: {}", e);
                }
            }

            // Log stats periodically
            let total = self.stats.events_received.load(Ordering::Relaxed);
            if total > 0 && total.is_multiple_of(100) {
                info!("{}", self.stats.summary());
            }
        }

        info!("Pipeline shutting down. {}", self.stats.summary());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LogSource;
    use crate::storage::InMemoryStorage;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_pipeline_processes_syslog() {
        let storage = InMemoryStorage::new(1000);
        let pipeline = Pipeline::new(storage);

        let (tx, rx) = mpsc::channel(100);

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run(rx).await;
            pipeline
        });

        tx.send((
            "<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root".to_string(),
            LogSource::SyslogUdp,
            Some("192.168.1.1:514".to_string()),
        ))
        .await
        .unwrap();

        tx.send((
            r#"{"level":"error","message":"disk full","hostname":"db01"}"#.to_string(),
            LogSource::File,
            None,
        ))
        .await
        .unwrap();

        drop(tx);

        let pipeline = pipeline_handle.await.unwrap();
        let stats = pipeline.stats();

        assert_eq!(stats.events_received.load(Ordering::Relaxed), 2);
        assert_eq!(stats.events_parsed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.events_stored.load(Ordering::Relaxed), 2);
        assert_eq!(stats.events_failed.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_pipeline_processes_plain_text() {
        let storage = InMemoryStorage::new(100);
        let pipeline = Pipeline::new(storage);

        let (tx, rx) = mpsc::channel(100);

        let pipeline_handle = tokio::spawn(async move {
            pipeline.run(rx).await;
            pipeline
        });

        tx.send((
            "ERROR: something broke".to_string(),
            LogSource::Stdin,
            None,
        ))
        .await
        .unwrap();

        drop(tx);

        let pipeline = pipeline_handle.await.unwrap();
        assert_eq!(
            pipeline
                .stats()
                .events_stored
                .load(Ordering::Relaxed),
            1
        );
    }
}
