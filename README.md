# CoreTrace-SIEM
Coded by me and Devin ai helped on some errors i made

If something right here shoots an error, send me a message on discord;
@mucatws

SIEM Log Ingestion and Collection Engine written in Rust.

## Features

- **Multiple collectors**: Syslog UDP/TCP (RFC 3164 & 5424), file tailing, stdin
- **Auto-detection parser**: Automatically detects and parses syslog, JSON, and plain text log formats
- **Normalized schema**: All logs are normalized into a unified `LogEvent` structure with severity, hostname, app name, timestamps, and metadata
- **Dual storage**: In-memory ring buffer for fast queries + optional JSONL file output for persistence
- **Async pipeline**: Built on Tokio for high-throughput, non-blocking log processing
- **File rotation detection**: Automatically handles log file rotation
- **Pipeline statistics**: Real-time ingestion metrics

## Build

```bash
cargo build --release
```

## Usage

```bash
# Read logs from stdin
echo '<34>Oct 11 22:14:15 myhost sshd[1234]: Failed password' | cargo run -- --stdin

# Listen for syslog over UDP
cargo run -- --syslog-udp --syslog-udp-addr 0.0.0.0:1514

# Listen for syslog over TCP
cargo run -- --syslog-tcp --syslog-tcp-addr 0.0.0.0:1514

# Watch log files
cargo run -- -f /var/log/syslog -f /var/log/auth.log

# Combine collectors with file output
cargo run -- --syslog-udp --stdin -f /var/log/syslog -o events.jsonl

# Multiple collectors at once
cargo run -- --syslog-udp --syslog-tcp --stdin -f /var/log/syslog -o /tmp/siem_events.jsonl
```

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--syslog-udp` | Enable syslog UDP collector | `false` |
| `--syslog-udp-addr` | UDP bind address | `0.0.0.0:1514` |
| `--syslog-tcp` | Enable syslog TCP collector | `false` |
| `--syslog-tcp-addr` | TCP bind address | `0.0.0.0:1514` |
| `--stdin` | Read logs from stdin | `false` |
| `-f, --file` | Log files to tail (repeatable) | — |
| `-o, --output` | JSONL output file path | — |
| `--max-events` | Max events in memory ring buffer | `10000` |
| `--buffer-size` | Internal channel buffer size | `1000` |

## Supported Log Formats

### Syslog RFC 3164
```
<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for root
```

### Syslog RFC 5424
```
<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473] An application event
```

### JSON
```json
{"timestamp":"2023-10-11T22:14:15Z","level":"error","message":"Connection refused","hostname":"web01","app":"nginx"}
```

### Plain text (auto severity detection)
```
2023-10-11 ERROR: Something went wrong
```

## Architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Syslog UDP  │  │ Syslog TCP  │  │  File Tail  │  │    Stdin    │
│  Collector  │  │  Collector  │  │  Collector  │  │  Collector  │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       │                │                │                │
       └────────────────┴────────┬───────┴────────────────┘
                                 │
                          ┌──────▼──────┐
                          │   Channel   │
                          │   (mpsc)    │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │   Parser    │
                          │ (auto-detect│
                          │  format)    │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │  Pipeline   │
                          │  (normalize │
                          │   + stats)  │
                          └──────┬──────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
             ┌──────▼──────┐          ┌──────▼──────┐
             │  In-Memory  │          │    File     │
             │   Storage   │          │   Storage   │
             │ (ring buf)  │          │  (JSONL)    │
             └─────────────┘          └─────────────┘
```

## Tests

```bash
cargo test
```

## License

MIT
