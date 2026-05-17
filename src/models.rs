use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Informational,
    Debug,
}

impl Severity {
    pub fn from_syslog_priority(priority: u8) -> Self {
        let severity = priority & 0x07;
        match severity {
            0 => Severity::Emergency,
            1 => Severity::Alert,
            2 => Severity::Critical,
            3 => Severity::Error,
            4 => Severity::Warning,
            5 => Severity::Notice,
            6 => Severity::Informational,
            7 => Severity::Debug,
            _ => Severity::Informational,
        }
    }

    pub fn from_str_level(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "emerg" | "emergency" | "panic" => Severity::Emergency,
            "alert" => Severity::Alert,
            "crit" | "critical" => Severity::Critical,
            "err" | "error" => Severity::Error,
            "warn" | "warning" => Severity::Warning,
            "notice" => Severity::Notice,
            "info" | "informational" => Severity::Informational,
            "debug" | "trace" => Severity::Debug,
            _ => Severity::Informational,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Emergency => write!(f, "EMERGENCY"),
            Severity::Alert => write!(f, "ALERT"),
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::Error => write!(f, "ERROR"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Notice => write!(f, "NOTICE"),
            Severity::Informational => write!(f, "INFO"),
            Severity::Debug => write!(f, "DEBUG"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LogSource {
    SyslogUdp,
    SyslogTcp,
    File,
    Stdin,
}

impl fmt::Display for LogSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogSource::SyslogUdp => write!(f, "syslog-udp"),
            LogSource::SyslogTcp => write!(f, "syslog-tcp"),
            LogSource::File => write!(f, "file"),
            LogSource::Stdin => write!(f, "stdin"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub source: LogSource,
    pub source_addr: Option<String>,
    pub severity: Severity,
    pub facility: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub process_id: Option<String>,
    pub message: String,
    pub raw: String,
    pub metadata: HashMap<String, String>,
}

impl LogEvent {
    pub fn new(source: LogSource, message: String, raw: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            received_at: Utc::now(),
            source,
            source_addr: None,
            severity: Severity::Informational,
            facility: None,
            hostname: None,
            app_name: None,
            process_id: None,
            message,
            raw,
            metadata: HashMap::new(),
        }
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    pub fn with_app_name(mut self, app_name: String) -> Self {
        self.app_name = Some(app_name);
        self
    }

    pub fn with_source_addr(mut self, addr: String) -> Self {
        self.source_addr = Some(addr);
        self
    }

    pub fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts;
        self
    }

    pub fn with_facility(mut self, facility: String) -> Self {
        self.facility = Some(facility);
        self
    }

    pub fn with_process_id(mut self, pid: String) -> Self {
        self.process_id = Some(pid);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_from_syslog_priority() {
        assert_eq!(Severity::from_syslog_priority(0), Severity::Emergency);
        assert_eq!(Severity::from_syslog_priority(3), Severity::Error);
        assert_eq!(Severity::from_syslog_priority(6), Severity::Informational);
        assert_eq!(Severity::from_syslog_priority(7), Severity::Debug);
        // Priority includes facility bits: facility=1 (user), severity=3 (error) => 8+3=11
        assert_eq!(Severity::from_syslog_priority(11), Severity::Error);
    }

    #[test]
    fn test_severity_from_str_level() {
        assert_eq!(Severity::from_str_level("error"), Severity::Error);
        assert_eq!(Severity::from_str_level("ERROR"), Severity::Error);
        assert_eq!(Severity::from_str_level("warn"), Severity::Warning);
        assert_eq!(Severity::from_str_level("info"), Severity::Informational);
        assert_eq!(Severity::from_str_level("unknown"), Severity::Informational);
    }

    #[test]
    fn test_log_event_builder() {
        let event = LogEvent::new(
            LogSource::SyslogUdp,
            "test message".to_string(),
            "<13>test message".to_string(),
        )
        .with_severity(Severity::Error)
        .with_hostname("server01".to_string())
        .with_app_name("sshd".to_string());

        assert_eq!(event.severity, Severity::Error);
        assert_eq!(event.hostname.unwrap(), "server01");
        assert_eq!(event.app_name.unwrap(), "sshd");
        assert_eq!(event.source, LogSource::SyslogUdp);
    }

    #[test]
    fn test_log_event_serialization() {
        let event = LogEvent::new(
            LogSource::File,
            "test".to_string(),
            "raw test".to_string(),
        );
        let json = serde_json::to_string(&event).unwrap();
        let deserialized: LogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.message, "test");
        assert_eq!(deserialized.source, LogSource::File);
    }
}
