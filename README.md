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
| `MAILONEY_CONN_TIMEOUT` | Per-connection inactivity timeout (seconds). A client that sends nothing for this long is dropped, so slow-loris connections cannot pin handler threads. `0` disables it. | 30 |
| `MAILONEY_DB_URL` | Database connection URL | sqlite:///mailoney.db |
| `MAILONEY_MAIL_DIR` | When set, captured SMTP message bodies are written under this directory as `<YYYY-MM-DD>/<src-ip>/<session>.eml` and the session log records the relative path. Unset = bodies are discarded after their metadata (size, truncated flag) is recorded. Operators opt *in* to body retention. | (unset) |
| `MAILONEY_TLS_CERT` | Path to a PEM cert/chain. Both `MAILONEY_TLS_CERT` and `MAILONEY_TLS_KEY` must be set to enable STARTTLS. | (unset) |
| `MAILONEY_TLS_KEY` | Path to the PEM private key matching `MAILONEY_TLS_CERT`. | (unset) |
| `MAILONEY_LOG_LEVEL` | Logging level | INFO |
| `MAILONEY_METRICS_PORT` | Port for the Prometheus `/metrics` endpoint. Unset disables the endpoint. | (unset) |
| `MAILONEY_METRICS_BIND` | Bind address for the metrics endpoint. Loopback by default; set `0.0.0.0` or `::` only to scrape from another host/container, and keep that port off public interfaces (see [Prometheus Metrics](#prometheus-metrics)). | `127.0.0.1` |

### Command-line Arguments

When running directly:

```bash
python main.py --help
```

Available arguments:
- `-i`, `--ip`: IP address to bind to
- `-p`, `--port`: Port to listen on
- `-s`, `--server-name`: Server name to display in SMTP responses
- `--conn-timeout`: Per-connection inactivity timeout in seconds (0 disables it)
- `-d`, `--db-url`: Database URL
- `--mail-dir`: Directory under which captured message bodies are written
- `--tls-cert`: Path to a PEM cert/chain (enables STARTTLS together with --tls-key)
- `--tls-key`: Path to the PEM private key matching --tls-cert
- `--log-level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--metrics-port`: Port for the Prometheus `/metrics` endpoint (unset = disabled)
- `--metrics-bind`: Bind address for the metrics endpoint (default: `127.0.0.1`, loopback only)

### Captured mail bodies

Mailoney implements the SMTP `DATA` phase: when a client sends `DATA`, the
server responds with `354 End data with <CR><LF>.<CR><LF>`, reads the
message body until the standard terminator (or 1 MiB, whichever comes
first), and replies `250 Ok`.

Storage is opt-in:

- **Default** (`MAILONEY_MAIL_DIR` unset): the body is discarded after
  the session log records its metadata (`size`, `truncated`). The
  operator gets a record that a body was received but no body content
  is retained.
- **`MAILONEY_MAIL_DIR=/path`**: the body is written to
  `<path>/<YYYY-MM-DD>/<src-ip>/<session-uuid>.eml` (mode `0640`,
  directories `0750`) and the session log records the relative path.
  This is the only way to retain body content; the JSON log stream
  never carries body bytes inline regardless of `MAILONEY_LOG_JSON`.

Source IPs land in directory names with their colons intact (e.g.
`2001:db8::1`).

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

## STARTTLS

Mailoney supports the SMTP `STARTTLS` extension when both
`MAILONEY_TLS_CERT` and `MAILONEY_TLS_KEY` are set. Any cert/key pair
works — the server presents the cert and never verifies anything, so a
self-signed cert is perfectly adequate for a honeypot.

When unconfigured, `EHLO` does not advertise `STARTTLS`, and an explicit
`STARTTLS` command from a client gets `454 4.7.0 TLS not available`.

### A note on file permissions

The container image runs as the unprivileged `mailoney` user, and
private keys are root-owned and mode `0600`/`0640` almost everywhere
they are generated. Bind-mounting `/etc/letsencrypt` or `/etc/ssl`
straight into the container therefore does **not** work on its own —
the process cannot read the key.

Mailoney checks this at startup and exits with status 2 and an explicit
message rather than failing later at handshake time:

```
[!] STARTTLS: TLS key is not readable: /etc/letsencrypt/live/mx.example.com/privkey.pem
```

Two ways to resolve it, in order of preference:

1. **Copy the pair to a location the container user can read** (below).
2. **Pin the container to a known UID** with `user:` in compose, and
   `chown` the copied files to it.

Running the container as root also works but gives up the image's
privilege separation, which is a poor trade for a service that
deliberately accepts hostile input on port 25.

### Self-signed certificate

Generate a throwaway pair:

```bash
mkdir -p ./tls
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout ./tls/privkey.pem -out ./tls/fullchain.pem \
  -subj "/CN=mx.example.com"
chmod 640 ./tls/privkey.pem
```

On Debian/Ubuntu the `ssl-cert` package's *snakeoil* pair works too, but
it lives in `/etc/ssl/private` (mode `0710`, group `ssl-cert`) and the
key is `0640 root:ssl-cert`, so copy it out rather than mounting it:

```bash
mkdir -p ./tls
sudo install -m 0644 /etc/ssl/certs/ssl-cert-snakeoil.pem ./tls/fullchain.pem
sudo install -m 0640 /etc/ssl/private/ssl-cert-snakeoil.key ./tls/privkey.pem
sudo chown -R 1000:1000 ./tls
```

Either way, mount the directory and pin the user:

```yaml
services:
  mailoney:
    image: ghcr.io/phin3has/mailoney:latest
    user: "1000:1000"
    ports:
      - "25:25"
    environment:
      - MAILONEY_TLS_CERT=/tls/fullchain.pem
      - MAILONEY_TLS_KEY=/tls/privkey.pem
    volumes:
      - ./tls:/tls:ro
```

### Let's Encrypt / certbot

Certbot writes `privkey.pem` as `0600 root:root`, so the honeypot
container cannot read it from a bind mount. Use a **deploy hook** to
publish a readable copy on every renewal, then restart the container so
the new cert is picked up:

```bash
# /etc/letsencrypt/renewal-hooks/deploy/mailoney.sh   (chmod +x)
#!/bin/sh
set -eu
DEST=/srv/mailoney/tls
install -d -m 0750 -o 1000 -g 1000 "$DEST"
install -m 0644 -o 1000 -g 1000 "$RENEWED_LINEAGE/fullchain.pem" "$DEST/fullchain.pem"
install -m 0640 -o 1000 -g 1000 "$RENEWED_LINEAGE/privkey.pem"   "$DEST/privkey.pem"
docker compose -f /srv/mailoney/docker-compose.yml restart mailoney
```

`$RENEWED_LINEAGE` is set by certbot to the `live/<domain>` directory
being renewed, so the hook needs no per-domain editing. It runs on
issuance and on every successful renewal.

```yaml
services:
  mailoney:
    image: ghcr.io/phin3has/mailoney:latest
    user: "1000:1000"
    ports:
      - "25:25"
    environment:
      - MAILONEY_TLS_CERT=/tls/fullchain.pem
      - MAILONEY_TLS_KEY=/tls/privkey.pem
    volumes:
      - /srv/mailoney/tls:/tls:ro
```

Using a real cert for a honeypot is a deliberate choice: it makes the
listener look like production infrastructure, at the cost of tying a
domain you control to it (and publishing the hostname in the
Certificate Transparency logs). A self-signed cert leaks nothing but is
a fingerprintable signal in itself. Neither is wrong — pick per
deployment.

### Behaviour

- The `EHLO` response advertises `STARTTLS`. After a successful upgrade,
  the post-TLS `EHLO` drops the line per RFC 3207 §4.2.
- The handshake is pinned to TLS 1.2 minimum.
- A 10-second handshake timeout protects against half-open clients; the
  per-connection inactivity timeout is restored afterwards, so an
  upgraded connection is bounded exactly like a plaintext one.
- The upgrade is recorded in the session log as a `tls-upgrade` entry
  carrying the negotiated version.
- A repeat `STARTTLS` on an encrypted connection gets
  `503 5.5.1 STARTTLS already active`.
- Cert and key are loaded **once at process start**. Restart the
  container after a renewal — hence the `restart` in the deploy hook
  above.

### Startup validation

TLS configuration is checked before the database is touched, so a cert
problem never surfaces as a database error:

| Condition | Behaviour |
|---|---|
| Neither cert nor key set | STARTTLS disabled, no message (the default) |
| Only one of the two set | Warning on stderr; server starts, plaintext only |
| Path missing | `exit 2`, names the missing file |
| Path unreadable | `exit 2`, names the file and the likely cause |
| Cert/key mismatch, malformed PEM | `exit 2`, reports the OpenSSL error |

## Prometheus Metrics

Mailoney can expose a `/metrics` endpoint for Prometheus scraping when
`MAILONEY_METRICS_PORT` is set (or `--metrics-port` is passed).

> **Keep this endpoint off the internet.** The exposition is unauthenticated,
> is served on every path, and includes `mailoney_build_info` — the software
> name and version. Anyone who can reach it learns in one request that the
> "mail server" is a honeypot. The endpoint therefore binds to loopback
> (`127.0.0.1`) by default, and Mailoney logs a warning at startup whenever
> it is bound anywhere else.

Running directly on the host, the default just works and Prometheus on the
same machine scrapes `127.0.0.1:9025`:

```bash
MAILONEY_METRICS_PORT=9025 python main.py
```

In Docker, port publishing forwards to the container's network interface,
not its loopback, so the container-side bind must be widened to `0.0.0.0`
(or `::`) and the exposure controlled on the Docker side instead. Two safe
patterns:

**Scrape over an internal network, publish nothing.** Prometheus and
Mailoney share a compose network; only port 25 reaches the outside:

```yaml
services:
  mailoney:
    image: ghcr.io/phin3has/mailoney:latest
    ports:
      - "25:25"                     # only the honeypot port is published
    environment:
      - MAILONEY_METRICS_PORT=9025
      - MAILONEY_METRICS_BIND=0.0.0.0
    networks: [monitoring]

  prometheus:
    image: prom/prometheus
    networks: [monitoring]          # scrapes http://mailoney:9025/metrics

networks:
  monitoring:
```

**Publish to the host's loopback only.** For a Prometheus that runs on the
Docker host itself:

```bash
docker run -p 25:25 -p 127.0.0.1:9025:9025 \
  -e MAILONEY_METRICS_PORT=9025 \
  -e MAILONEY_METRICS_BIND=0.0.0.0 \
  ghcr.io/phin3has/mailoney:latest
```

Never use a bare `-p 9025:9025` on an internet-facing host: that publishes
the fingerprint on every interface.

Exposed metrics:

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `mailoney_smtp_connections_total` | Counter | — | SMTP connections accepted. |
| `mailoney_smtp_sessions_total` | Counter | `result` (`ok`/`error`/`timeout`) | SMTP sessions that ran to completion. `timeout` is an inactivity drop, reported separately so slow-loris pressure is visible. |
| `mailoney_smtp_credentials_captured_total` | Counter | — | AUTH PLAIN credentials captured. |
| `mailoney_smtp_commands_total` | Counter | `command` | SMTP commands by verb (`ehlo`, `helo`, `auth`, `starttls`, `mail`, `rcpt`, `data`, `quit`, `unknown`). |
| `mailoney_smtp_active_sessions` | Gauge | — | Sessions currently in flight. |
| `mailoney_smtp_session_duration_seconds` | Histogram | — | Time from accept to close, per session. |
| `mailoney_smtp_banner_only_sessions_total` | Counter | — | Sessions where the client connected but never sent a command (port-scanner signal). |
| `mailoney_start_time_seconds` | Gauge | — | Unix timestamp at process start. Compute uptime in PromQL with `time() - mailoney_start_time_seconds`. |
| `mailoney_build_info` | Info | `version` | Mailoney build/version info. |

`MAILONEY_METRICS_BIND` (or `--metrics-bind`) overrides the bind address.

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

 
