# PulseAPI Load Testing & Benchmarking Suite

This directory contains automated load tests written with **Locust** to evaluate the latency, throughput, and query performance of PulseAPI under concurrent engineer workloads.

## Tested Workflows

1. **User Authentication & Seeding**: Registers session and seeds synthetic endpoints.
2. **Dashboard Overview**: Fetches HTML dashboard (`/`).
3. **Monitors Fleet API**: High-frequency endpoint listing (`/api/v1/monitors/`).
4. **Analytics Aggregations**:
   - Aggregate latency & reliability summaries (`/api/v1/analytics/summary/`)
   - Timeseries downsampled response charts (`/api/v1/analytics/timeseries/`)
   - HTTP status distribution calculations (`/api/v1/analytics/status-distribution/`)
   - Cross-endpoint comparison matrix (`/api/v1/analytics/comparison/`)
5. **Check History Pagination**: Evaluates indexed paging on historical probe records (`/api/v1/checks/?page=1`).
6. **System Health Probes**: Sub-millisecond database check ping (`/api/v1/health/`).

---

## Running Locust Benchmarks

### 1. Start the PulseAPI server
```bash
cd backend
python manage.py runserver 8000
```

### 2. Run Headless Load Test (Example: 20 concurrent users, spawn rate 4/s, for 30s)
```bash
locust -f loadtests/locustfile.py --host http://localhost:8000 --headless -u 20 -r 4 --run-time 30s --csv loadtests/benchmark_results
```

### 3. Run Interactive Web UI Mode
```bash
locust -f loadtests/locustfile.py --host http://localhost:8000
```
Open `http://localhost:8089` in your browser to adjust virtual users, ramp-up rates, and view live latency percentiles.
