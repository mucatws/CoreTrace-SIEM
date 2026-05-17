mod syslog_udp;
mod syslog_tcp;
mod file_collector;
mod stdin_collector;

pub use syslog_udp::SyslogUdpCollector;
pub use syslog_tcp::SyslogTcpCollector;
pub use file_collector::FileCollector;
pub use stdin_collector::StdinCollector;

use tokio::sync::mpsc;

pub type RawLogSender = mpsc::Sender<(String, crate::models::LogSource, Option<String>)>;
pub type RawLogReceiver = mpsc::Receiver<(String, crate::models::LogSource, Option<String>)>;
