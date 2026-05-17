use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};
use tracing::{error, info, warn};

use crate::models::LogSource;
use super::RawLogSender;

pub struct FileCollector {
    paths: Vec<PathBuf>,
}

impl FileCollector {
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    pub async fn run(&self, sender: RawLogSender) -> std::io::Result<()> {
        let mut handles = Vec::new();

        for path in &self.paths {
            let path = path.clone();
            let sender = sender.clone();

            info!("File collector watching: {}", path.display());

            let handle = tokio::spawn(async move {
                if let Err(e) = tail_file(path.clone(), sender).await {
                    error!("File collector error for {}: {}", path.display(), e);
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}

async fn tail_file(path: PathBuf, sender: RawLogSender) -> std::io::Result<()> {
    let file = File::open(&path).await?;
    let mut reader = BufReader::new(file);

    // Seek to end to only read new lines (tail -f behavior)
    reader.seek(SeekFrom::End(0)).await?;

    let path_str = path.display().to_string();
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                // No new data, wait a bit before checking again
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

                // Check if file was rotated (size smaller than current position)
                if let Ok(metadata) = tokio::fs::metadata(&path).await {
                    let current_pos = reader.seek(SeekFrom::Current(0)).await?;
                    if metadata.len() < current_pos {
                        warn!("File rotation detected for {}, resetting position", path_str);
                        let new_file = File::open(&path).await?;
                        reader = BufReader::new(new_file);
                    }
                }
            }
            Ok(_) => {
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }

                let mut metadata_source = path_str.clone();
                metadata_source.push_str(" (file)");

                if let Err(e) = sender
                    .send((trimmed, LogSource::File, Some(path_str.clone())))
                    .await
                {
                    error!("Failed to send file log to pipeline: {}", e);
                    break;
                }
            }
            Err(e) => {
                error!("File read error for {}: {}", path_str, e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }

    Ok(())
}
