import random
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.utils import timezone
from monitors.models import Monitor
from checks.models import CheckResult
from alerts.models import NotificationConfig
from checks.engine import execute_health_check


class Command(BaseCommand):
    help = "Seeds demo user account and endpoints with real initial probes and labeled demo history"

    def handle(self, *args, **options):
        # 1. Ensure demo user exists
        user, created = User.objects.get_or_create(username="admin", defaults={
            "email": "admin@pulseapi.dev",
            "is_staff": True,
            "is_superuser": True
        })
        if created:
            user.set_password("adminpass123")
            user.save()
            self.stdout.write(self.style.SUCCESS("Created demo superuser: admin / adminpass123"))
        else:
            self.stdout.write("Demo superuser 'admin' already exists.")

        # 2. Configure sample public endpoints
        sample_endpoints = [
            {
                "name": "Cloudflare DNS over HTTPS",
                "target_url": "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
                "http_method": "GET",
                "check_interval": 30,
                "request_timeout": 5,
                "expected_status_codes": "200",
                "latency_warning_threshold": 150,
                "latency_failure_threshold": 800,
            },
            {
                "name": "GitHub Public Meta API",
                "target_url": "https://api.github.com/meta",
                "http_method": "GET",
                "check_interval": 60,
                "request_timeout": 10,
                "expected_status_codes": "200",
                "latency_warning_threshold": 350,
                "latency_failure_threshold": 1200,
            },
            {
                "name": "Public IP Echo Endpoint",
                "target_url": "https://httpbin.org/get",
                "http_method": "GET",
                "check_interval": 60,
                "request_timeout": 10,
                "expected_status_codes": "200",
                "latency_warning_threshold": 400,
                "latency_failure_threshold": 1500,
            },
            {
                "name": "Payment Gateway Canary (Simulated Flaky)",
                "target_url": "https://httpbin.org/status/200%2C500",
                "http_method": "GET",
                "check_interval": 60,
                "request_timeout": 5,
                "expected_status_codes": "200",
                "latency_warning_threshold": 300,
                "latency_failure_threshold": 1000,
            }
        ]

        now = timezone.now()

        for ep in sample_endpoints:
            monitor, mon_created = Monitor.objects.get_or_create(
                owner=user,
                name=ep["name"],
                defaults=ep
            )

            if mon_created:
                self.stdout.write(f"Registered monitor: {monitor.name}")
                # Execute real live initial check
                try:
                    result = execute_health_check(monitor, is_manual=True)
                    self.stdout.write(
                        f"  -> Real probe executed: {result.outcome.upper()} ({result.response_time_ms}ms, HTTP {result.http_status_code})"
                    )
                except Exception as e:
                    self.stdout.write(f"  -> Initial probe note: {e}")

                # Populate historical records labeled as demo data for charts
                base_lat = 85.0 if "DNS" in ep["name"] else 220.0
                for i in range(1, 15):
                    check_time = now - timedelta(hours=i * 1.5)
                    variance = random.uniform(-25.0, 45.0)
                    lat = max(15.0, round(base_lat + variance, 2))
                    outcome = 'success'
                    code = 200

                    if "Flaky" in ep["name"] and i % 4 == 0:
                        outcome = 'failure'
                        code = 500

                    cr = CheckResult.objects.create(
                        monitor=monitor,
                        http_status_code=code,
                        response_time_ms=lat,
                        outcome=outcome,
                        error_category='status_mismatch' if outcome == 'failure' else '',
                        error_detail='[DEMO DATA] Simulated health probe' if outcome == 'failure' else '',
                        expected_status_codes='200',
                        status_matched=(outcome == 'success'),
                        resolved_ip='1.1.1.1' if "DNS" in ep["name"] else '93.184.216.34',
                        response_size_bytes=random.randint(120, 2400)
                    )
                    # Backdate timestamp for realistic timeline
                    CheckResult.objects.filter(id=cr.id).update(created_at=check_time)

        # Ensure sample notification configuration exists
        NotificationConfig.objects.get_or_create(
            owner=user,
            channel=NotificationConfig.CHANNEL_EMAIL,
            defaults={
                "target": "admin@pulseapi.dev",
                "notify_on_failure": True,
                "notify_on_latency": True,
                "notify_on_recovery": True
            }
        )

        self.stdout.write(self.style.SUCCESS("PulseAPI demo data successfully seeded!"))
