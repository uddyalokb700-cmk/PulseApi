# PulseAPI — API Performance Monitor & Observability Dashboard

> **Tagline:** Every endpoint. Every millisecond. One clear picture.  
> **Dashboard Title:** PulseAPI Observability  
> **Project Directory:** `api-performance-monitor/`

---

## 1. Overview & Architecture

**PulseAPI** is a standalone, developer-focused API observability and performance monitoring platform designed to monitor HTTP/HTTPS endpoints, measure round-trip response latencies with monotonic clocks, classify failure modes, enforce strict Server-Side Request Forgery (SSRF) protections, and visualize uptime and SLA trends in real time.

PulseAPI is built as a modular Django monolith with clear boundaries:

```
api-performance-monitor/
├── backend/
│   ├── pulseapi/               # Django root configuration & Celery setup
│   ├── accounts/               # Authentication, user profiles & registration
│   ├── monitors/               # Monitored endpoint models, headers, validation
│   ├── checks/                 # Health check engine, monotonic timing, SSRF guard, Celery tasks
│   ├── analytics/              # DB-side aggregations, percentiles (p50, p95), timeseries
│   ├── alerts/                 # Threshold alert engine, state transitions & notifications
│   ├── templates/              # Rich dark observability UI (HTML5 / Bootstrap 5 / Chart.js)
│   └── static/                 # CSS theme, charts engine, dynamic JS, SVG brand logo
├── tests/                      # Automated pytest & pytest-django test suite
├── loadtests/                  # Locust load test scripts and benchmark suite
├── docker-compose.yml          # Multi-container orchestration (PostgreSQL, Redis, Web, Celery)
├── Dockerfile                  # Production container image definition
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable configuration template
└── README.md                   # Full operating and deployment manual
```

---

## 2. Key Database Models

### `monitors.Monitor`
- `owner`: Reference to User account (with object-level isolation)
- `name`: Friendly endpoint label
- `target_url`: Fully-qualified destination URL
- `http_method`: HTTP method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`)
- `request_body`: Optional payload for POST/PUT/PATCH
- `enabled`: Active/paused monitoring toggle
- `check_interval`: Probe recurrence in seconds (e.g., 30s, 60s, 300s)
- `request_timeout`: Request timeout ceiling (1s to 60s)
- `expected_status_codes`: Expected status pattern (e.g., `200`, `200-299`, `200,201,204`)
- `latency_warning_threshold`: Response duration in ms triggering `degraded` state
- `latency_failure_threshold`: Response duration in ms triggering `failing` SLA alert
- Denormalized tracking: `last_checked_at`, `last_status`, `last_response_time_ms`, `last_status_code`, `consecutive_failures`
- Composite DB indexes: `['owner', 'enabled']`, `['owner', 'last_status']`, `['enabled', 'last_checked_at']`

### `monitors.MonitorHeader`
- `monitor`: ForeignKey to Monitor
- `name`: Header key (e.g. `Authorization`, `X-API-Key`)
- `value`: Header content
- `is_secret`: Boolean indicating sensitive credentials. **Secret values are masked as `********` in all REST API responses and logs.**

### `checks.CheckResult`
- `monitor`: ForeignKey to Monitor
- `created_at`: Monotonic execution timestamp
- `http_status_code`: Received HTTP status code (nullable on timeout/error)
- `response_time_ms`: Round-trip duration in milliseconds measured via `time.perf_counter()`
- `outcome`: `success`, `failure`, `timeout`, or `error`
- `error_category`: Standardized category (`status_mismatch`, `connection_failed`, `connect_timeout`, `read_timeout`, `ssrf_blocked`, etc.)
- `error_detail`: Sanitized diagnostic message
- `response_size_bytes`: Bounded payload response size
- `resolved_ip`: Destination IP address resolved during pre-flight check
- Composite DB indexes: `['monitor', '-created_at']`, `['monitor', 'outcome', '-created_at']`

### `alerts.AlertEvent`
- `monitor`: ForeignKey to Monitor
- `alert_type`: `endpoint_down`, `repeated_failure`, `latency_warning`, `latency_failure`, `recovery`
- `severity`: `info`, `warning`, `critical`
- `state`: `active`, `resolved`
- `triggered_at`: Incident trigger timestamp
- `resolved_at`: Incident resolution timestamp
- `description`: Human-readable incident summary
- `consecutive_count`: Counter for deduplication without spamming alerts

### `alerts.NotificationConfig`
- `owner`: ForeignKey to User
- `channel`: `email` or `webhook`
- `target`: Recipient address or webhook URL
- `secret_token`: Masked authorization token
- `notify_on_failure`, `notify_on_latency`, `notify_on_recovery`: Granular event subscriptions

---

## 3. Security & SSRF Protection Architecture

PulseAPI enforces multi-layered Server-Side Request Forgery protections in `checks/ssrf.py`:

1. **Protocol Restriction**: Only `http` and `https` schemes permitted.
2. **Credential Stripping**: Embedded user credentials (`http://user:pass@host`) strictly rejected.
3. **Port Filtering**: Access to internal database & infrastructure ports (22, 5432, 6379, 27017, etc.) is blocked.
4. **IP Space Defense**:
   - Loopback (`127.0.0.0/8`, `::1`) blocked.
   - RFC 1918 Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`) blocked.
   - Link-Local (`169.254.0.0/16`, `fe80::/10`) blocked.
   - Cloud Metadata IPs (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) strictly blocked.
5. **DNS Pre-Validation & Rebinding Defense**: Every hostname is resolved to all associated IPv4 and IPv6 addresses via `socket.getaddrinfo`. If *any* address belongs to a prohibited range, the request is aborted prior to connecting.
6. **Redirect Verification**: Bounded manual redirect loop (max 3 redirects). Every redirect destination `Location` header is intercepted and re-validated against the SSRF filter before connecting.
7. **Resource Bounds**: Outbound responses are capped at `SSRF_MAX_RESPONSE_BYTES` (2MB) via streaming to eliminate memory exhaustion attacks.

---

## 4. API Endpoints

### Authentication (`/api/v1/auth/`)
- `POST /api/v1/auth/register/` — Register new user
- `POST /api/v1/auth/login/` — Authenticate and establish session
- `POST /api/v1/auth/logout/` — Destroy session
- `GET /api/v1/auth/me/` — Current user profile

### Monitors Fleet (`/api/v1/monitors/`)
- `GET /api/v1/monitors/` — List user's monitors (with search `?q=` and status `?status=`)
- `POST /api/v1/monitors/` — Register new monitored endpoint
- `GET /api/v1/monitors/{id}/` — Retrieve monitor configuration & latest status
- `PATCH /api/v1/monitors/{id}/` — Update monitor settings
- `DELETE /api/v1/monitors/{id}/` — Delete monitor
- `POST /api/v1/monitors/{id}/toggle/` — Toggle active/paused state
- `POST /api/v1/monitors/{id}/check-now/` — Trigger immediate manual health check probe

### Check Logs (`/api/v1/checks/`)
- `GET /api/v1/checks/` — Paginated check records (`?monitor={id}&outcome={status}`)
- `GET /api/v1/checks/{id}/` — Single check measurement details

### Performance Analytics (`/api/v1/analytics/`)
- `GET /api/v1/analytics/summary/?range={1h|24h|7d|30d}` — Overall or per-monitor KPI summary
- `GET /api/v1/analytics/timeseries/?range={1h|24h|7d|30d}` — Sampled latency trend data points
- `GET /api/v1/analytics/status-distribution/?range={1h|24h|7d|30d}` — HTTP status distribution
- `GET /api/v1/analytics/comparison/?range={1h|24h|7d|30d}` — Cross-endpoint performance ranking
- `GET /api/v1/health/` — System health check (service & database connectivity)

### Alerts & Notifications (`/api/v1/alerts/`)
- `GET /api/v1/alerts/?state={active|resolved}` — Incident list
- `POST /api/v1/alerts/{id}/resolve/` — Mark incident as resolved
- `GET /api/v1/notifications/` — List notification channels
- `POST /api/v1/notifications/` — Register email or webhook destination

### OpenAPI Documentation
- Interactive Swagger UI: `http://localhost:8000/api/docs/`
- Redoc UI: `http://localhost:8000/api/redoc/`
- Schema JSON/YAML: `http://localhost:8000/api/schema/`

---

## 5. Local Setup & Execution Guide

### Prerequisites
- Python 3.12+ (or compatible installed Python version)
- PostgreSQL (or SQLite fallback for zero-dependency local testing)
- Redis (for Celery background tasks)

### Step 1: Environment Setup
```bash
cd api-performance-monitor
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(By default, if `DB_NAME` is omitted or PostgreSQL is unreachable, the system automatically uses SQLite for instant local execution).*

### Step 3: Run Database Migrations
```bash
python backend/manage.py migrate
```

### Step 4: Seed Demo Superuser and Sample Endpoints
```bash
python backend/manage.py seed_demo_data
```
*Credentials: `admin` / `adminpass123`*

### Step 5: Start Components

#### A. Web Server
```bash
python backend/manage.py runserver 8000
```
Open `http://localhost:8000/` in your browser.

#### B. Celery Worker (In a separate terminal)
```bash
celery -A pulseapi worker --workdir backend --loglevel=info --concurrency=4
```

#### C. Celery Beat Scheduler (In a separate terminal)
```bash
celery -A pulseapi beat --workdir backend --loglevel=info
```

---

## 6. Docker Deployment

To launch the full containerized production stack (PostgreSQL 16, Redis 7, Gunicorn Web, Celery Worker, and Celery Beat):

```bash
docker compose up -d --build
```
The application will be accessible at `http://localhost:8000`.

---

## 7. Testing & Verification

### Running Automated Test Suite
```bash
pytest -v
```
**Results:** 34 tests covering Monitoring, SSRF Security, Analytics, Alerts, Celery Tasks, and Web Pages.

### Running Lint Checks (Ruff)
```bash
ruff check .
```

### Running Locust Load Benchmarks
```bash
locust -f loadtests/locustfile.py --host http://localhost:8000 --headless -u 20 -r 4 --run-time 30s
```

---

## 8. Data Retention & Maintenance

PulseAPI implements an automated daily retention maintenance job (`checks.tasks.cleanup_old_records`) driven by Celery Beat. By default, records older than 30 days (`CHECK_RETENTION_DAYS=30`) are pruned to keep database queries fast.
