# Mailoney

![GitHub release (latest by date)](https://img.shields.io/github/v/release/phin3has/mailoney)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/phin3has/mailoney/Docker%20Image%20CI/CD)
![GitHub](https://img.shields.io/github/license/phin3has/mailoney)

A modern SMTP honeypot designed to capture and log email-based attacks with database integration.

## About

Mailoney is a low-interaction SMTP honeypot that simulates a vulnerable mail server to detect and log unauthorized access attempts, credential harvesting, and other SMTP-based attacks. This version (2.1.0) is a complete rewrite with modern Python packaging practices and database logging.

### Features

- 📧 Simulates an SMTP server accepting connections on port 25
- 🔐 Captures authentication attempts and credentials
- 💾 Stores all session data in a database (PostgreSQL recommended)
- 🐳 Containerized for easy deployment via Docker
- 🛠️ Modern, maintainable Python code base
- 📊 Structured data for easy analysis and integration

## Quick Start with Docker

Pull and run the container with a single command:

```bash
docker run -p 25:25 ghcr.io/phin3has/mailoney:latest
```

## Installation Options

### Option 1: Docker Compose (Recommended)

The most convenient way to run Mailoney with proper database persistence:

1. Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  mailoney:
    image: ghcr.io/phin3has/mailoney:latest
    restart: unless-stopped
    ports:
      - "25:25"
    environment:
      - MAILONEY_BIND_IP=0.0.0.0
      - MAILONEY_BIND_PORT=25
      - MAILONEY_SERVER_NAME=mail.example.com
      - MAILONEY_LOG_LEVEL=INFO
      - MAILONEY_DB_URL=postgresql://postgres:postgres@db:5432/mailoney
    depends_on:
      - db
    
  db:
    image: postgres:15
    restart: unless-stopped
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=mailoney
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

2. Start the services:

```bash
docker-compose up -d
```

3. View logs:

```bash
docker-compose logs -f mailoney
```

### Option 2: Local Installation

For development or customization:

```bash
# Clone the repository
git clone https://github.com/phin3has/mailoney.git
cd mailoney

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install the package in development mode
pip install -e .

# Run Mailoney
python main.py
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAILONEY_BIND_IP` | IP address to bind to | 0.0.0.0 |
| `MAILONEY_BIND_PORT` | Port to listen on | 25 |
| `MAILONEY_SERVER_NAME` | SMTP server name | mail.example.com |
| `MAILONEY_DB_URL` | Database connection URL. Set to an empty string (`MAILONEY_DB_URL=`) to disable the database and run in event-logging-only mode. | sqlite:///mailoney.db |
| `MAILONEY_MAIL_DIR` | When set, captured SMTP message bodies are written under this directory as `<YYYY-MM-DD>/<src-ip>/<session>.eml`. Unset = bodies stay inline in the session log. | (unset) |
| `MAILONEY_LOG_LEVEL` | Logging level | INFO |
| `MAILONEY_LOG_JSON` | When `true`, emit honeypot events (session start/end, captured credentials) as JSON Lines on the `mailoney.events` logger. Default emits human-readable text. | false |
| `MAILONEY_METRICS_PORT` | Port for the Prometheus `/metrics` endpoint. Unset disables the endpoint. | (unset) |
| `MAILONEY_METRICS_BIND` | Bind address for the metrics endpoint. Default is dual-stack IPv4+IPv6. | `::` |

### Running without a database

Mailoney can run as a pure event emitter — useful when you ship logs to a
SIEM, ELK stack, Loki, etc. and don't want to operate a SQL database just
for honeypot capture.

```bash
# DB-less mode, JSON log output suitable for log shippers
docker run -p 25:25 \
  -e MAILONEY_DB_URL= \
  -e MAILONEY_LOG_JSON=true \
  ghcr.io/phin3has/mailoney:latest
```

When the database is disabled:
- No tables are created, no migrations are run, no DB driver is required at
  runtime.
- Per-session events (`session_started`, `credential_captured`,
  `session_ended`) are emitted to the `mailoney.events` logger.
- In JSON mode, `session_ended` events include the full SMTP transcript.

### Command-line Arguments

When running directly:

```bash
python main.py --help
```

Available arguments:
- `-i`, `--ip`: IP address to bind to
- `-p`, `--port`: Port to listen on
- `-s`, `--server-name`: Server name to display in SMTP responses
- `-d`, `--db-url`: Database URL. Pass an empty string to disable the database.
- `--mail-dir`: Directory under which captured message bodies are written
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--log-json`: Emit honeypot events as JSON Lines instead of human-readable text.
- `--metrics-port`: Port for the Prometheus `/metrics` endpoint (unset = disabled)
- `--metrics-bind`: Bind address for the metrics endpoint (default: `::`)

### Captured mail bodies

Mailoney implements the SMTP `DATA` phase: when a client sends `DATA`, the
server responds with `354 End data with <CR><LF>.<CR><LF>`, reads the
message body until the standard terminator (or 1 MiB, whichever comes
first), and replies `250 Ok`.

Storage:

- **Default** (`MAILONEY_MAIL_DIR` unset): the body is recorded inline in
  the session log entry as `data` (UTF-8, with replacement on decode
  errors).
- **`MAILONEY_MAIL_DIR=/path`**: the body is written to
  `<path>/<YYYY-MM-DD>/<src-ip>/<session-uuid>.eml` (mode `0640`,
  directories `0750`) and the session log records the relative path
  rather than the body contents. Recommended for production — keeps the
  DB blob / event log small and lets bodies be handled directly by mail
  / forensics tooling.

Source IPs land in directory names with their colons intact (e.g.
`2001:db8::1`). This is fine on Linux filesystems but breaks on Windows
/ FAT bind mounts.

### Database Configuration

Mailoney can use various SQL databases:

**SQLite** (simplest, for testing):
```
sqlite:///mailoney.db
```

**PostgreSQL** (recommended for production):
```
postgresql://username:password@hostname:port/database
```

**MySQL/MariaDB**:
```
mysql+pymysql://username:password@hostname:port/database
```

## Prometheus Metrics

Mailoney can expose a `/metrics` endpoint for Prometheus scraping when
`MAILONEY_METRICS_PORT` is set (or `--metrics-port` is passed). A typical
deployment:

```bash
docker run -p 25:25 -p 9025:9025 \
  -e MAILONEY_METRICS_PORT=9025 \
  ghcr.io/phin3has/mailoney:latest
```

Exposed metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `mailoney_smtp_connections_total` | Counter | — | SMTP connections accepted. |
| `mailoney_smtp_sessions_total` | Counter | `result` (`ok`/`error`) | SMTP sessions that ran to completion. |
| `mailoney_smtp_credentials_captured_total` | Counter | — | AUTH PLAIN credentials captured. |
| `mailoney_smtp_commands_total` | Counter | `command` | SMTP commands by verb (`ehlo`, `helo`, `auth`, `mail`, `rcpt`, `data`, `quit`, `unknown`). |
| `mailoney_smtp_active_sessions` | Gauge | — | Sessions currently in flight. |
| `mailoney_smtp_session_duration_seconds` | Histogram | — | Time from accept to close, per session. |
| `mailoney_smtp_banner_only_sessions_total` | Counter | — | Sessions where the client connected but never sent a command (port-scanner signal). |
| `mailoney_start_time_seconds` | Gauge | — | Unix timestamp at process start. Compute uptime in PromQL with `time() - mailoney_start_time_seconds`. |
| `mailoney_build_info` | Info | `version` | Mailoney build/version info. |

The endpoint binds dual-stack (`::`) by default. Override with
`MAILONEY_METRICS_BIND=127.0.0.1` if you want loopback-only.

## Database Schema

Mailoney creates two main tables:

1. `smtp_sessions`: Stores information about each SMTP session
   - Session ID, timestamp, IP address, port, server name
   - Full JSON log of the entire session

2. `credentials`: Stores captured authentication credentials
   - Credential ID, timestamp, session ID, auth string

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest

# Run tests with coverage
pytest --cov=mailoney
```

### Database Migrations

```bash
# Create a new migration
alembic revision --autogenerate -m "Description of changes"

# Apply migrations
alembic upgrade head
```

### Building the Package

```bash
# Install build tools
pip install build

# Build the package
python -m build
```

## Project Structure

```
mailoney/
├── mailoney/            # Main package
│   ├── __init__.py      # Package initialization  
│   ├── core.py          # Core server functionality
│   ├── db.py            # Database handling
│   ├── config.py        # Configuration management
│   └── migrations/      # Database migrations
├── tests/               # Test suite
├── main.py              # Clean entry point
├── docker-compose.yml   # Docker Compose configuration
├── Dockerfile           # Docker configuration
├── pyproject.toml       # Package configuration
└── ... other files
```

## Security Considerations

- Mailoney is a honeypot and should be deployed in a controlled environment
- Consider running with limited privileges
- Firewall appropriately to prevent misuse
- Regularly backup and analyze collected data

## Integrating with Other Tools

### Forwarding Logs to Security Systems

Mailoney stores all interaction data in the database. To integrate with SIEM or other security tools:

1. **Direct Database Integration**: Connect your security tools to the PostgreSQL database
2. **Log Forwarding**: Use a separate service to monitor the database and forward events
3. **API Development**: Extend Mailoney to provide a REST API for data access

## License

MIT License - See LICENSE file for details.

## Acknowledgments

This project is a modernized rewrite of the original Mailoney by @phin3has.

 
