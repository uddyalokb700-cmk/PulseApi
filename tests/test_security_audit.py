import pytest
from unittest.mock import patch, MagicMock
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from monitors.models import Monitor, MonitorHeader
from checks.models import CheckResult
from alerts.models import AlertEvent, NotificationConfig
from checks.ssrf import (
    validate_url_syntax,
    resolve_and_verify_destination,
    sanitize_headers,
    SSRFSecurityError,
    SSRFSafeNetworkBackend,
    is_port_allowed,
)
from checks.engine import execute_health_check


@pytest.fixture
def auth_user():
    return User.objects.create_user(username="alice", password="alice-password-123", email="alice@pulseapi.dev")


@pytest.fixture
def other_user():
    return User.objects.create_user(username="mallory", password="mallory-password-123", email="mallory@pulseapi.dev")


@pytest.fixture
def client_alice(auth_user):
    client = APIClient()
    client.force_authenticate(user=auth_user)
    return client


@pytest.fixture
def client_mallory(other_user):
    client = APIClient()
    client.force_authenticate(user=other_user)
    return client


@pytest.fixture
def alice_monitor(auth_user):
    return Monitor.objects.create(
        owner=auth_user,
        name="Alice Production API",
        target_url="https://api.example.com/v1/health",
        http_method="GET",
        check_interval=60,
        request_timeout=10,
        expected_status_codes="200",
        latency_warning_threshold=500,
        latency_failure_threshold=1500,
        enabled=True
    )


# ==============================================================================
# 1. AUTHENTICATION & AUTHORIZATION REGRESSION TESTS
# ==============================================================================

@pytest.mark.django_db
def test_user_cannot_access_other_users_monitor_detail(client_mallory, alice_monitor):
    res = client_mallory.get(f"/api/v1/monitors/{alice_monitor.id}/")
    assert res.status_code == 404


@pytest.mark.django_db
def test_user_cannot_update_other_users_monitor(client_mallory, alice_monitor):
    res = client_mallory.patch(f"/api/v1/monitors/{alice_monitor.id}/", {"name": "Hacked Name"})
    assert res.status_code == 404
    alice_monitor.refresh_from_db()
    assert alice_monitor.name == "Alice Production API"


@pytest.mark.django_db
def test_user_cannot_delete_other_users_monitor(client_mallory, alice_monitor):
    res = client_mallory.delete(f"/api/v1/monitors/{alice_monitor.id}/")
    assert res.status_code == 404
    assert Monitor.objects.filter(id=alice_monitor.id).exists()


@pytest.mark.django_db
def test_user_cannot_toggle_other_users_monitor(client_mallory, alice_monitor):
    res = client_mallory.post(f"/api/v1/monitors/{alice_monitor.id}/toggle/")
    assert res.status_code == 404


@pytest.mark.django_db
def test_user_cannot_override_owner_field_on_create(client_alice, other_user):
    payload = {
        "name": "Ownership Spoofing Test",
        "target_url": "https://api.example.com/status",
        "http_method": "GET",
        "owner": other_user.id,
    }
    res = client_alice.post("/api/v1/monitors/", payload, format="json")
    assert res.status_code == 201
    created_id = res.data["id"]
    mon = Monitor.objects.get(id=created_id)
    # Owner must be authenticated user, ignoring client-supplied owner
    assert mon.owner.username == "alice"
    assert mon.owner != other_user


@pytest.mark.django_db
def test_user_cannot_view_other_users_check_results(client_mallory, alice_monitor):
    CheckResult.objects.create(
        monitor=alice_monitor,
        http_status_code=200,
        response_time_ms=45.2,
        outcome=CheckResult.OUTCOME_SUCCESS,
        status_matched=True
    )
    res = client_mallory.get("/api/v1/checks/")
    assert res.status_code == 200
    assert len(res.data.get("results", [])) == 0


@pytest.mark.django_db
def test_user_cannot_resolve_other_users_alerts(client_mallory, alice_monitor):
    alert = AlertEvent.objects.create(
        monitor=alice_monitor,
        alert_type=AlertEvent.TYPE_ENDPOINT_DOWN,
        severity=AlertEvent.SEVERITY_CRITICAL,
        state=AlertEvent.STATE_ACTIVE,
        description="Outage"
    )
    res = client_mallory.post(f"/api/v1/alerts/{alert.id}/resolve/")
    assert res.status_code == 404
    alert.refresh_from_db()
    assert alert.state == AlertEvent.STATE_ACTIVE


@pytest.mark.django_db
def test_user_cannot_view_or_modify_other_users_notifications(client_alice, client_mallory, auth_user):
    cfg = NotificationConfig.objects.create(
        owner=auth_user,
        channel=NotificationConfig.CHANNEL_EMAIL,
        target="alice@pulseapi.dev",
        secret_token="super-secret-token"
    )
    # Mallory tries to view
    res = client_mallory.get(f"/api/v1/alerts/notifications/{cfg.id}/")
    assert res.status_code == 404
    # Mallory tries to delete
    res = client_mallory.delete(f"/api/v1/alerts/notifications/{cfg.id}/")
    assert res.status_code == 404
    assert NotificationConfig.objects.filter(id=cfg.id).exists()


@pytest.mark.django_db
def test_login_open_redirect_mitigation(client):
    User.objects.create_user(username="bob", password="password123")
    # Attempt login with external phishing next parameter
    res = client.post(
        "/accounts/login/?next=https://attacker-phishing.com/steal",
        {"username": "bob", "password": "password123"}
    )
    assert res.status_code == 302
    # Must redirect to safe internal overview, NOT attacker URL
    assert res.url == "overview" or res.url == "/"


# ==============================================================================
# 2. SSRF AND OUTBOUND-REQUEST SECURITY REGRESSION TESTS
# ==============================================================================

@pytest.mark.parametrize("malicious_url", [
    # IPv4 loopback & numeric representations
    "http://127.0.0.1/",
    "http://127.0.0.2/",
    "http://2130706433/",        # Decimal notation for 127.0.0.1
    "http://0x7f000001/",        # Hex notation for 127.0.0.1
    "http://017700000001/",      # Octal notation for 127.0.0.1
    "http://0.0.0.0/",
    # IPv6 loopback & mapped representations
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    # Cloud metadata endpoints
    "http://169.254.169.254/",
    "http://[::ffff:169.254.169.254]/",
    "http://100.100.100.200/",   # Alibaba Cloud IMDS
    "http://[::ffff:100.100.100.200]/",
    "http://[fd00:ec2::254]/",   # AWS IMDSv6
    "http://169.254.170.2/",     # AWS ECS Task Credentials
    # Private RFC 1918 networks
    "http://10.0.0.1/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://[::ffff:10.0.0.1]/",
    # Link local & carrier-grade NAT
    "http://169.254.1.1/",
    # Embedded credentials
    "http://admin:secret@api.example.com/",
    # Prohibited protocols
    "ftp://api.example.com/",
    "gopher://api.example.com/",
    "file:///etc/passwd",
    # Restricted dangerous ports
    "http://api.example.com:22/",
    "http://api.example.com:3306/",
    "http://api.example.com:5432/",
    "http://api.example.com:6379/",
    "http://api.example.com:27017/",
])
def test_prohibited_ssrf_destinations_blocked(malicious_url):
    with pytest.raises(SSRFSecurityError):
        validate_url_syntax(malicious_url, allow_private=False)
        resolve_and_verify_destination(malicious_url, allow_private=False)


def test_allowed_ports_policy():
    assert is_port_allowed(None) is True
    assert is_port_allowed(80) is True
    assert is_port_allowed(443) is True
    assert is_port_allowed(8080) is True
    assert is_port_allowed(22) is False   # SSH
    assert is_port_allowed(25) is False   # SMTP
    assert is_port_allowed(53) is False   # DNS
    assert is_port_allowed(6379) is False # Redis
    assert is_port_allowed(5432) is False # Postgres


def test_anti_dns_rebinding_socket_verification():
    """
    Verifies that SSRFSafeNetworkBackend intercepts DNS rebinding at socket
    connection time (after TCP handshake) if the connected peer IP is a restricted address.
    """
    backend = SSRFSafeNetworkBackend(allow_private=False)
    mock_stream = MagicMock()
    # Emulate socket getpeername() returning loopback IP 127.0.0.1
    mock_stream.get_extra_info.return_value = ("127.0.0.1", 80)

    with patch("checks.ssrf.resolve_and_verify_destination", return_value=["93.184.216.34"]), \
         patch("httpcore._backends.sync.SyncBackend.connect_tcp", return_value=mock_stream):
        with pytest.raises(SSRFSecurityError) as exc_info:
            backend.connect_tcp("rebound.attacker.com", 80)

        assert "DNS rebinding detected" in str(exc_info.value)
        mock_stream.close.assert_called_once()


@pytest.mark.django_db
def test_redirect_ssrf_destination_is_blocked(alice_monitor):
    """
    Verifies that redirects hopping from a public URL to a private/metadata URL
    are stopped before following.
    """
    mock_redirect_resp = MagicMock()
    mock_redirect_resp.is_redirect = True
    mock_redirect_resp.headers = {"location": "http://169.254.169.254/latest/meta-data/"}

    def mock_resolve(hostname, allow_private=False):
        if hostname == "api.example.com":
            return ["93.184.216.34"]
        return resolve_and_verify_destination(hostname, allow_private=allow_private)

    with patch("checks.engine.resolve_and_verify_destination", side_effect=mock_resolve), \
         patch("httpx.Client.stream") as mock_stream_fn:
        mock_ctx = MagicMock()
        mock_ctx.__enter__.return_value = mock_redirect_resp
        mock_stream_fn.return_value = mock_ctx

        check = execute_health_check(alice_monitor)
        assert check.outcome == CheckResult.OUTCOME_ERROR
        assert check.error_category == "ssrf_blocked"
        assert "restricted or private IP address" in check.error_detail


@pytest.mark.django_db
def test_webhook_notification_ssrf_blocked(client_alice):
    """
    Verifies that users cannot configure internal/cloud metadata URLs as webhook endpoints.
    """
    res = client_alice.post("/api/v1/notifications/", {
        "channel": "webhook",
        "target": "http://169.254.169.254/webhook",
        "secret_token": "token123"
    }, format="json")
    assert res.status_code == 400
    assert "target" in res.data


# ==============================================================================
# 3. SECRETS AND SENSITIVE DATA REGRESSION TESTS
# ==============================================================================

@pytest.mark.django_db
def test_secret_header_masking_in_api_response(client_alice, alice_monitor):
    MonitorHeader.objects.create(
        monitor=alice_monitor,
        name="X-Api-Key",
        value="super-secret-prod-api-key-9988",
        is_secret=True
    )
    res = client_alice.get(f"/api/v1/monitors/{alice_monitor.id}/")
    assert res.status_code == 200
    headers = res.data["headers"]
    assert len(headers) == 1
    assert headers[0]["name"] == "X-Api-Key"
    # Secret must be masked in API response
    assert headers[0]["value"] == "********"


@pytest.mark.django_db
def test_secret_header_preserved_on_update(client_alice, alice_monitor):
    hdr = MonitorHeader.objects.create(
        monitor=alice_monitor,
        name="Authorization",
        value="Bearer token_abcdef_123456",
        is_secret=True
    )
    # Client submits masked placeholder back via PATCH
    update_data = {
        "name": "Updated Monitor Name",
        "headers": [
            {"name": "Authorization", "value": "********", "is_secret": True}
        ]
    }
    res = client_alice.patch(f"/api/v1/monitors/{alice_monitor.id}/", update_data, format="json")
    assert res.status_code == 200
    hdr.refresh_from_db()
    # Real token must be preserved in DB, not replaced with '********'
    assert hdr.value == "Bearer token_abcdef_123456"


def test_custom_header_crlf_and_hop_by_hop_sanitization():
    raw_headers = {
        "Authorization": "Bearer token123",
        "Host": "evil.com",                           # Hop-by-hop / transport override
        "X-Forwarded-For": "127.0.0.1",               # Hop-by-hop
        "Transfer-Encoding": "chunked",               # Smuggling vector
        "X-Injection": "value\r\nInjected-Header: 1",  # CRLF injection
        "X-Normal": "safe-value"
    }
    cleaned = sanitize_headers(raw_headers)
    assert "Authorization" in cleaned
    assert "X-Normal" in cleaned
    assert "Host" not in cleaned
    assert "X-Forwarded-For" not in cleaned
    assert "Transfer-Encoding" not in cleaned
    assert "X-Injection" not in cleaned


# ==============================================================================
# 4. RESOURCE EXHAUSTION AND BOUNDS TESTS
# ==============================================================================

@pytest.mark.django_db
def test_manual_check_rate_limiting_cooldown(client_alice, alice_monitor):
    """
    Verifies that manual health checks have rate limiting and return 429
    if triggered in rapid succession.
    """
    from django.core.cache import cache
    cache.delete(f"manual_probe_lock_{alice_monitor.id}")

    with patch("checks.engine.execute_health_check") as mock_exec:
        mock_result = MagicMock()
        mock_result.outcome = "success"
        mock_result.http_status_code = 200
        mock_result.response_time_ms = 50.0
        mock_result.status_matched = True
        mock_result.error_category = ""
        mock_result.error_detail = ""
        mock_result.created_at.isoformat.return_value = "2026-10-13T12:00:00"
        mock_exec.return_value = mock_result

        # First call succeeds
        res1 = client_alice.post(f"/api/v1/monitors/{alice_monitor.id}/check-now/")
        assert res1.status_code == 200

        # Immediate second call is throttled with 429
        res2 = client_alice.post(f"/api/v1/monitors/{alice_monitor.id}/check-now/")
        assert res2.status_code == 429
        assert "Please wait 5 seconds" in res2.data["detail"]


@pytest.mark.django_db
def test_monitor_interval_and_timeout_bounds_enforced(client_alice):
    # check_interval below 10 rejected
    res = client_alice.post("/api/v1/monitors/", {
        "name": "Rapid Interval Test",
        "target_url": "https://api.example.com/health",
        "check_interval": 2,
    }, format="json")
    assert res.status_code == 400
    assert "check_interval" in res.data

    # request_timeout over 60 rejected
    res2 = client_alice.post("/api/v1/monitors/", {
        "name": "Excessive Timeout Test",
        "target_url": "https://api.example.com/health",
        "request_timeout": 120,
    }, format="json")
    assert res2.status_code == 400
    assert "request_timeout" in res2.data
