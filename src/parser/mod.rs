use chrono::{NaiveDateTime, TimeZone, Utc};
use regex::Regex;

use crate::models::{LogEvent, LogSource, Severity};

pub struct LogParser {
    syslog_rfc3164: Regex,
    syslog_rfc5424: Regex,
    json_detector: Regex,
    severity_detector: Regex,
}

impl LogParser {
    pub fn new() -> Self {
        // RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
        let syslog_rfc3164 = Regex::new(
            r"^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)"
        ).expect("Invalid RFC3164 regex");

        // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        let syslog_rfc5424 = Regex::new(
        let syslog_rfc5424 = Regex::new(
            r"^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:\[.*?\]+-|-)\s*(.*)"
        ).expect("Invalid RFC5424 regex");
        ).expect("Invalid RFC5424 regex");

        let json_detector = Regex::new(r"^\s*\{").expect("Invalid JSON regex");

        let severity_detector = Regex::new(
            r"(?i)\b(EMERG(?:ENCY)?|ALERT|CRIT(?:ICAL)?|ERR(?:OR)?|WARN(?:ING)?|NOTICE|INFO(?:RMATIONAL)?|DEBUG)\b"
        ).expect("Invalid severity regex");

        Self {
            syslog_rfc3164,
            syslog_rfc5424,
            json_detector,
            severity_detector,
        }
    }

    pub fn parse(&self, raw: &str, source: LogSource) -> LogEvent {
        if let Some(event) = self.try_parse_syslog_rfc5424(raw, source.clone()) {
            return event;
        }

        if let Some(event) = self.try_parse_syslog_rfc3164(raw, source.clone()) {
            return event;
        }

        if let Some(event) = self.try_parse_json(raw, source.clone()) {
            return event;
        }

        self.parse_plain(raw, source)
    }

    fn try_parse_syslog_rfc3164(&self, raw: &str, source: LogSource) -> Option<LogEvent> {
        let caps = self.syslog_rfc3164.captures(raw)?;

        let priority: u8 = caps.get(1)?.as_str().parse().ok()?;
        let severity = Severity::from_syslog_priority(priority);
        let facility = syslog_facility_name(priority >> 3);

        let timestamp_str = caps.get(2)?.as_str();
        let current_year = Utc::now().format("%Y").to_string();
        let ts_with_year = format!("{} {}", current_year, timestamp_str);
        let timestamp = NaiveDateTime::parse_from_str(&ts_with_year, "%Y %b %d %H:%M:%S")
            .ok()
            .map(|naive| Utc.from_utc_datetime(&naive))
            .unwrap_or_else(Utc::now);

        let hostname = caps.get(3).map(|m| m.as_str().to_string());
        let app_name = caps.get(4).map(|m| m.as_str().to_string());
        let process_id = caps.get(5).map(|m| m.as_str().to_string());
        let message = caps.get(6).map(|m| m.as_str().to_string()).unwrap_or_default();

        let mut event = LogEvent::new(source, message, raw.to_string())
            .with_severity(severity)
            .with_facility(facility)
            .with_timestamp(timestamp);

        if let Some(h) = hostname {
            event = event.with_hostname(h);
        }
        if let Some(a) = app_name {
            event = event.with_app_name(a);
        }
        if let Some(p) = process_id {
            event = event.with_process_id(p);
        }

        Some(event)
    }

    fn try_parse_syslog_rfc5424(&self, raw: &str, source: LogSource) -> Option<LogEvent> {
        let caps = self.syslog_rfc5424.captures(raw)?;

        let priority: u8 = caps.get(1)?.as_str().parse().ok()?;
        let severity = Severity::from_syslog_priority(priority);
        let facility = syslog_facility_name(priority >> 3);

        let timestamp_str = caps.get(3)?.as_str();
        let timestamp = timestamp_str
            .parse::<DateTime<Utc>>()
            .ok()
            .unwrap_or_else(Utc::now);

        let hostname = non_nil(caps.get(4).map(|m| m.as_str()));
        let app_name = non_nil(caps.get(5).map(|m| m.as_str()));
        let process_id = non_nil(caps.get(6).map(|m| m.as_str()));
        let message = caps.get(8).map(|m| m.as_str().to_string()).unwrap_or_default();

        let mut event = LogEvent::new(source, message, raw.to_string())
            .with_severity(severity)
            .with_facility(facility)
            .with_timestamp(timestamp);

        if let Some(h) = hostname {
            event = event.with_hostname(h);
        }
        if let Some(a) = app_name {
            event = event.with_app_name(a);
        }
        if let Some(p) = process_id {
            event = event.with_process_id(p);
        }

        Some(event)
    }

    fn try_parse_json(&self, raw: &str, source: LogSource) -> Option<LogEvent> {
        if !self.json_detector.is_match(raw) {
            return None;
        }

        let value: serde_json::Value = serde_json::from_str(raw).ok()?;
        let obj = value.as_object()?;

        let message = obj
            .get("message")
            .or_else(|| obj.get("msg"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let severity = obj
            .get("level")
            .or_else(|| obj.get("severity"))
            .or_else(|| obj.get("log_level"))
            .and_then(|v| v.as_str())
            .map(Severity::from_str_level)
            .unwrap_or(Severity::Informational);

        let hostname = obj
            .get("hostname")
            .or_else(|| obj.get("host"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let app_name = obj
            .get("app")
            .or_else(|| obj.get("application"))
            .or_else(|| obj.get("service"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let timestamp = obj
            .get("timestamp")
            .or_else(|| obj.get("time"))
            .or_else(|| obj.get("@timestamp"))
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<DateTime<Utc>>().ok())
            .unwrap_or_else(Utc::now);

        let mut event = LogEvent::new(source, message, raw.to_string())
            .with_severity(severity)
            .with_timestamp(timestamp);

        if let Some(h) = hostname {
            event = event.with_hostname(h);
        }
        if let Some(a) = app_name {
            event = event.with_app_name(a);
        }

        // Store extra JSON fields as metadata
        for (key, val) in obj {
            if !matches!(
                key.as_str(),
                "message"
                    | "msg"
                    | "level"
                    | "severity"
                    | "log_level"
                    | "hostname"
                    | "host"
                    | "app"
                    | "application"
                    | "service"
                    | "timestamp"
                    | "time"
                    | "@timestamp"
            ) {
                if let Some(s) = val.as_str() {
                    event.metadata.insert(key.clone(), s.to_string());
                } else {
                    event.metadata.insert(key.clone(), val.to_string());
                }
            }
        }

        Some(event)
    }

    fn parse_plain(&self, raw: &str, source: LogSource) -> LogEvent {
        let severity = self
            .severity_detector
            .captures(raw)
            .and_then(|caps| caps.get(1))
            .map(|m| Severity::from_str_level(m.as_str()))
            .unwrap_or(Severity::Informational);

        LogEvent::new(source, raw.to_string(), raw.to_string()).with_severity(severity)
    }
}

impl Default for LogParser {
    fn default() -> Self {
        Self::new()
    }
}

use chrono::DateTime;

fn non_nil(opt: Option<&str>) -> Option<String> {
    opt.and_then(|s| {
        if s == "-" {
            None
        } else {
            Some(s.to_string())
        }
    })
}

fn syslog_facility_name(facility: u8) -> String {
    match facility {
        0 => "kern".to_string(),
        1 => "user".to_string(),
        2 => "mail".to_string(),
        3 => "daemon".to_string(),
        4 => "auth".to_string(),
        5 => "syslog".to_string(),
        6 => "lpr".to_string(),
        7 => "news".to_string(),
        8 => "uucp".to_string(),
        9 => "cron".to_string(),
        10 => "authpriv".to_string(),
        11 => "ftp".to_string(),
        16 => "local0".to_string(),
        17 => "local1".to_string(),
        18 => "local2".to_string(),
        19 => "local3".to_string(),
        20 => "local4".to_string(),
        21 => "local5".to_string(),
        22 => "local6".to_string(),
        23 => "local7".to_string(),
        _ => format!("unknown({})", facility),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_syslog_rfc3164() {
        let parser = LogParser::new();
        let raw = "<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root";
        let event = parser.parse(raw, LogSource::SyslogUdp);

        assert_eq!(event.severity, Severity::Critical);
        assert_eq!(event.hostname.as_deref(), Some("mymachine"));
        assert_eq!(event.app_name.as_deref(), Some("sshd"));
        assert_eq!(event.process_id.as_deref(), Some("1234"));
        assert_eq!(event.message, "Failed password for root");
        assert_eq!(event.facility.as_deref(), Some("auth"));
    }

    #[test]
    fn test_parse_syslog_rfc5424() {
        let parser = LogParser::new();
        let raw = "<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] An application event log entry";
        let event = parser.parse(raw, LogSource::SyslogTcp);

        assert_eq!(event.severity, Severity::Notice);
        assert_eq!(event.hostname.as_deref(), Some("mymachine.example.com"));
        assert_eq!(event.app_name.as_deref(), Some("evntslog"));
        assert_eq!(event.message, "An application event log entry");
    }

    #[test]
    fn test_parse_json_log() {
        let parser = LogParser::new();
        let raw = r#"{"timestamp":"2023-10-11T22:14:15Z","level":"error","message":"Connection refused","hostname":"web01","app":"nginx","request_id":"abc123"}"#;
        let event = parser.parse(raw, LogSource::File);

        assert_eq!(event.severity, Severity::Error);
        assert_eq!(event.message, "Connection refused");
        assert_eq!(event.hostname.as_deref(), Some("web01"));
        assert_eq!(event.app_name.as_deref(), Some("nginx"));
        assert_eq!(event.metadata.get("request_id").map(|s| s.as_str()), Some("abc123"));
    }

    #[test]
    fn test_parse_plain_text_with_severity() {
        let parser = LogParser::new();
        let raw = "2023-10-11 ERROR: Something went wrong";
        let event = parser.parse(raw, LogSource::Stdin);

        assert_eq!(event.severity, Severity::Error);
        assert_eq!(event.message, raw);
    }

    #[test]
    fn test_parse_plain_text_no_severity() {
        let parser = LogParser::new();
        let raw = "Just a plain log line with no level indicator";
        let event = parser.parse(raw, LogSource::Stdin);

        assert_eq!(event.severity, Severity::Informational);
    }

    #[test]
    fn test_syslog_facility_name() {
        assert_eq!(syslog_facility_name(0), "kern");
        assert_eq!(syslog_facility_name(4), "auth");
        assert_eq!(syslog_facility_name(23), "local7");
        assert_eq!(syslog_facility_name(99), "unknown(99)");
    }
}
