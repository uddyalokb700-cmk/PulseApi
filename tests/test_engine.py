import pytest
from unittest.mock import patch, MagicMock
import httpx
from checks.engine import execute_health_check
from checks.models import CheckResult
from checks.ssrf import SSRFSecurityError


@pytest.mark.django_db
def test_successful_health_check(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="https://api.example.com/status")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.iter_bytes.return_value = [b'{"status": "ok"}']

    # Mock DNS resolution and client stream
    with patch('checks.engine.resolve_and_verify_destination', return_value=['93.184.216.34']), \
         patch('httpx.Client.stream') as mock_stream:
        mock_stream.return_value.__enter__.return_value = mock_resp

        result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_SUCCESS
    assert result.http_status_code == 200
    assert result.status_matched is True
    assert result.error_category == ''
    assert result.response_size_bytes == 16
    assert result.response_time_ms >= 0

    monitor.refresh_from_db()
    assert monitor.last_status == monitor.STATUS_HEALTHY
    assert monitor.last_status_code == 200
    assert monitor.consecutive_failures == 0


@pytest.mark.django_db
def test_unexpected_status_code_marks_failure(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="https://api.example.com/status", expected_status_codes="200")

    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_resp.is_redirect = False
    mock_resp.iter_bytes.return_value = [b'Internal Server Error']

    with patch('checks.engine.resolve_and_verify_destination', return_value=['93.184.216.34']), \
         patch('httpx.Client.stream') as mock_stream:
        mock_stream.return_value.__enter__.return_value = mock_resp

        result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_FAILURE
    assert result.http_status_code == 500
    assert result.status_matched is False
    assert result.error_category == 'status_mismatch'

    monitor.refresh_from_db()
    assert monitor.last_status == monitor.STATUS_FAILING
    assert monitor.consecutive_failures == 1


@pytest.mark.django_db
def test_timeout_health_check(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="https://api.example.com/status")

    with patch('checks.engine.resolve_and_verify_destination', return_value=['93.184.216.34']), \
         patch('httpx.Client.stream', side_effect=httpx.ReadTimeout("Socket timed out")):

        result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_TIMEOUT
    assert result.http_status_code is None
    assert result.error_category == 'read_timeout'

    monitor.refresh_from_db()
    assert monitor.last_status == monitor.STATUS_FAILING
    assert monitor.consecutive_failures == 1


@pytest.mark.django_db
def test_connection_error_health_check(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="https://api.example.com/status")

    with patch('checks.engine.resolve_and_verify_destination', return_value=['93.184.216.34']), \
         patch('httpx.Client.stream', side_effect=httpx.ConnectError("Connection refused")):

        result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_FAILURE
    assert result.http_status_code is None
    assert result.error_category == 'connection_failed'

    monitor.refresh_from_db()
    assert monitor.last_status == monitor.STATUS_FAILING


@pytest.mark.django_db
def test_ssrf_blocked_execution(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="http://169.254.169.254/latest/meta-data/")

    result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_ERROR
    assert result.error_category == 'ssrf_blocked'
    assert 'restricted or private' in result.error_detail

    monitor.refresh_from_db()
    assert monitor.last_status == monitor.STATUS_FAILING


@pytest.mark.django_db
def test_redirect_ssrf_intercepted(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="https://api.example.com/redirect-to-metadata")

    redirect_resp = MagicMock()
    redirect_resp.is_redirect = True
    redirect_resp.headers = {'location': 'http://169.254.169.254/latest/meta-data/'}

    # Initial URL resolves safely, but redirect target triggers SSRF error
    with patch('checks.engine.resolve_and_verify_destination') as mock_resolve, \
         patch('httpx.Client.stream') as mock_stream:
        # First call for api.example.com succeeds, second call for redirect target fails
        mock_resolve.side_effect = [
            ['93.184.216.34'],
            SSRFSecurityError("Destination '169.254.169.254' points to a restricted or private IP address.")
        ]
        mock_stream.return_value.__enter__.return_value = redirect_resp

        result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_ERROR
    assert result.error_category == 'ssrf_blocked'
    assert 'restricted or private' in result.error_detail


@pytest.mark.django_db
def test_response_size_limit_ceiling(monitor_factory, user1):
    monitor = monitor_factory(owner=user1, url="https://api.example.com/huge-file")

    huge_chunk = b"A" * (1024 * 1024)  # 1MB chunk
    mock_resp = MagicMock()
    mock_resp.is_redirect = False
    # Yield 3MB of chunks, exceeding the 2MB ceiling
    mock_resp.iter_bytes.return_value = [huge_chunk, huge_chunk, huge_chunk]

    with patch('checks.engine.resolve_and_verify_destination', return_value=['93.184.216.34']), \
         patch('httpx.Client.stream') as mock_stream:
        mock_stream.return_value.__enter__.return_value = mock_resp

        result = execute_health_check(monitor)

    assert result.outcome == CheckResult.OUTCOME_ERROR
    assert 'exceeded' in result.error_detail

