import uuid
from locust import HttpUser, task, between


class PulseAPIUser(HttpUser):
    wait_time = between(1, 2.5)

    def on_start(self):
        """
        Creates a synthetic authenticated user session for load testing.
        """
        self.username = f"loadtest_user_{uuid.uuid4().hex[:8]}"
        self.password = "BenchmarkPass123!"

        # Register user
        reg_resp = self.client.post("/api/v1/auth/register/", json={
            "username": self.username,
            "password": self.password,
            "password_confirm": self.password,
            "email": f"{self.username}@benchmark.local"
        })

        if reg_resp.status_code == 201:
            # Login session
            self.client.post("/api/v1/auth/login/", json={
                "username": self.username,
                "password": self.password
            })
            # Extract CSRF token from cookies
            csrftoken = self.client.cookies.get("csrftoken", "")
            headers = {"X-CSRFToken": csrftoken} if csrftoken else {}

            # Seed 2 synthetic test monitors for this user using HTTP Basic Auth
            self.client.post("/api/v1/monitors/", json={
                "name": "Synthetic Benchmark Target A",
                "target_url": "https://httpbin.org/status/200",
                "check_interval": 30,
                "request_timeout": 5,
                "expected_status_codes": "200"
            }, auth=(self.username, self.password), headers=headers)
            self.client.post("/api/v1/monitors/", json={
                "name": "Synthetic Benchmark Target B",
                "target_url": "https://httpbin.org/status/200",
                "check_interval": 60,
                "request_timeout": 5,
                "expected_status_codes": "200"
            }, auth=(self.username, self.password), headers=headers)

    @task(3)
    def view_dashboard_overview(self):
        self.client.get("/", name="Web: Overview Dashboard")

    @task(4)
    def get_monitors_list(self):
        self.client.get("/api/v1/monitors/", name="API: List Monitors")

    @task(5)
    def get_analytics_summary(self):
        self.client.get("/api/v1/analytics/summary/?range=24h", name="API: Analytics Summary (24h)")

    @task(4)
    def get_timeseries_latency(self):
        self.client.get("/api/v1/analytics/timeseries/?range=24h", name="API: Latency Timeseries")

    @task(3)
    def get_status_distribution(self):
        self.client.get("/api/v1/analytics/status-distribution/?range=24h", name="API: Status Distribution")

    @task(3)
    def get_endpoint_comparison(self):
        self.client.get("/api/v1/analytics/comparison/?range=24h", name="API: Endpoint Comparison")

    @task(4)
    def get_check_history_paginated(self):
        self.client.get("/api/v1/checks/?page=1", name="API: Check History Page 1")

    @task(2)
    def check_system_health(self):
        self.client.get("/api/v1/health/", name="API: System Health Probe")
