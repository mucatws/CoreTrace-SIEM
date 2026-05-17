use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::models::LogEvent;

pub trait Storage: Send + Sync {
    fn store(&self, event: LogEvent) -> impl std::future::Future<Output = Result<(), String>> + Send;
    fn query_recent(&self, count: usize) -> impl std::future::Future<Output = Vec<LogEvent>> + Send;
    fn count(&self) -> impl std::future::Future<Output = usize> + Send;
}

pub struct InMemoryStorage {
    events: Arc<Mutex<VecDeque<LogEvent>>>,
    max_size: usize,
}

impl InMemoryStorage {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            max_size,
        }
    }
}

impl Storage for InMemoryStorage {
    async fn store(&self, event: LogEvent) -> Result<(), String> {
        let mut events = self.events.lock().await;
        if events.len() >= self.max_size {
            events.pop_front();
        }
        events.push_back(event);
        Ok(())
    }

    async fn query_recent(&self, count: usize) -> Vec<LogEvent> {
        let events = self.events.lock().await;
        events.iter().rev().take(count).cloned().collect()
    }

    async fn count(&self) -> usize {
        let events = self.events.lock().await;
        events.len()
    }
}

pub struct FileStorage {
    path: PathBuf,
    in_memory: InMemoryStorage,
}

impl FileStorage {
    pub fn new(path: PathBuf, max_memory_events: usize) -> Self {
        Self {
            path,
            in_memory: InMemoryStorage::new(max_memory_events),
        }
    }
}

impl Storage for FileStorage {
    async fn store(&self, event: LogEvent) -> Result<(), String> {
        let json_line = serde_json::to_string(&event).map_err(|e| e.to_string())?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| format!("Failed to open storage file: {}", e))?;

        file.write_all(json_line.as_bytes())
            .await
            .map_err(|e| format!("Failed to write to storage file: {}", e))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| format!("Failed to write newline: {}", e))?;

        self.in_memory.store(event).await
    }

    async fn query_recent(&self, count: usize) -> Vec<LogEvent> {
        self.in_memory.query_recent(count).await
    }

    async fn count(&self) -> usize {
        self.in_memory.count().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{LogEvent, LogSource, Severity};

    #[tokio::test]
    async fn test_in_memory_storage() {
        let storage = InMemoryStorage::new(3);

        for i in 0..5 {
            let event = LogEvent::new(
                LogSource::Stdin,
                format!("message {}", i),
                format!("raw {}", i),
            );
            storage.store(event).await.unwrap();
        }

        assert_eq!(storage.count().await, 3);

        let recent = storage.query_recent(2).await;
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].message, "message 4");
        assert_eq!(recent[1].message, "message 3");
    }

    #[tokio::test]
    async fn test_file_storage() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test_events.jsonl");
        let storage = FileStorage::new(file_path.clone(), 100);

        let event = LogEvent::new(
            LogSource::SyslogUdp,
            "test file storage".to_string(),
            "<13>test file storage".to_string(),
        )
        .with_severity(Severity::Warning);

        storage.store(event).await.unwrap();

        assert_eq!(storage.count().await, 1);

        let contents = tokio::fs::read_to_string(&file_path).await.unwrap();
        assert!(contents.contains("test file storage"));
        assert!(contents.contains("Warning"));

        let recent = storage.query_recent(10).await;
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].message, "test file storage");
    }
}
