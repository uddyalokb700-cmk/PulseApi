import time
import httpx
import urllib.parse
from django.utils import timezone
from django.conf import settings
from checks.models import CheckResult
from checks.ssrf import (
    validate_url_syntax,
    resolve_and_verify_destination,
    sanitize_headers,
    SSRFSecurityError
)
from alerts.engine import evaluate_monitor_alerts


def execute_health_check(monitor, is_manual: bool = False) -> CheckResult:
    """
    Executes a real, secure HTTP health check for the given monitor.
    Uses monotonic time measurement, strict SSRF pre-check & redirect validation,
    and updates monitor state & alerts.
    """
    url = monitor.target_url
    method = monitor.http_method.upper()
    timeout = float(monitor.request_timeout)
    max_response_bytes = getattr(settings, 'SSRF_MAX_RESPONSE_BYTES', 2 * 1024 * 1024)

    # Prepare custom headers
    raw_headers = {h.name: h.value for h in monitor.headers.all()}
    headers = sanitize_headers(raw_headers)
    if 'User-Agent' not in headers:
        headers['User-Agent'] = 'PulseAPI-Observability-Engine/1.0'

    resolved_ip = ''
    start_time = time.perf_counter()

    try:
        # Step 1: Pre-flight SSRF and DNS verification
        parsed_url = validate_url_syntax(url)
        resolved_ips = resolve_and_verify_destination(parsed_url.hostname)
        resolved_ip = resolved_ips[0] if resolved_ips else ''

        # Step 2: Bounded HTTP Request execution with manual redirect security loop
        current_url = url
        redirect_limit = 3
        response = None
        total_bytes = 0

        # Build httpx client with connection limits and strict timeouts
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        timeout_config = httpx.Timeout(timeout, connect=min(5.0, timeout))

        with httpx.Client(limits=limits, timeout=timeout_config, verify=True, follow_redirects=False) as client:
            for _ in range(redirect_limit + 1):
                req_kwargs = {
                    'headers': headers,
                }
                if method in ('POST', 'PUT', 'PATCH') and monitor.request_body:
                    req_kwargs['content'] = monitor.request_body.encode('utf-8')

                with client.stream(method, current_url, **req_kwargs) as stream_resp:
                    # Check for redirects
                    if stream_resp.is_redirect and 'location' in stream_resp.headers:
                        location = stream_resp.headers['location']
                        current_url = urllib.parse.urljoin(current_url, location)

                        # Revalidate redirect destination against SSRF protections
                        redirect_parsed = validate_url_syntax(current_url)
                        redirect_ips = resolve_and_verify_destination(redirect_parsed.hostname)
                        resolved_ip = redirect_ips[0] if redirect_ips else resolved_ip
                        continue

                    # Read bounded content
                    content_chunks = []
                    for chunk in stream_resp.iter_bytes(chunk_size=8192):
                        content_chunks.append(chunk)
                        total_bytes += len(chunk)
                        if total_bytes > max_response_bytes:
                            raise ValueError(f"Response size exceeded {max_response_bytes} bytes ceiling.")

                    response = stream_resp
                    break

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        if response is None:
            raise ValueError("Too many redirects encountered without response.")

        status_code = response.status_code
        status_matched = monitor.matches_expected_status(status_code)

        if status_matched:
            outcome = CheckResult.OUTCOME_SUCCESS
            error_category = ''
            error_detail = ''
        else:
            outcome = CheckResult.OUTCOME_FAILURE
            error_category = 'status_mismatch'
            error_detail = f"Received HTTP {status_code}, expected {monitor.expected_status_codes}."

        result = CheckResult.objects.create(
            monitor=monitor,
            http_status_code=status_code,
            response_time_ms=round(duration_ms, 2),
            outcome=outcome,
            error_category=error_category,
            error_detail=error_detail,
            response_size_bytes=total_bytes,
            expected_status_codes=monitor.expected_status_codes,
            status_matched=status_matched,
            resolved_ip=resolved_ip
        )

    except SSRFSecurityError as e:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        result = CheckResult.objects.create(
            monitor=monitor,
            http_status_code=None,
            response_time_ms=round(duration_ms, 2),
            outcome=CheckResult.OUTCOME_ERROR,
            error_category='ssrf_blocked',
            error_detail=str(e),
            response_size_bytes=0,
            expected_status_codes=monitor.expected_status_codes,
            status_matched=False,
            resolved_ip=resolved_ip
        )

    except httpx.TimeoutException as e:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        category = 'connect_timeout' if isinstance(e, httpx.ConnectTimeout) else 'read_timeout'
        result = CheckResult.objects.create(
            monitor=monitor,
            http_status_code=None,
            response_time_ms=round(duration_ms, 2),
            outcome=CheckResult.OUTCOME_TIMEOUT,
            error_category=category,
            error_detail=f"Request timed out after {timeout}s: {e.__class__.__name__}",
            response_size_bytes=0,
            expected_status_codes=monitor.expected_status_codes,
            status_matched=False,
            resolved_ip=resolved_ip
        )

    except httpx.ConnectError as e:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        result = CheckResult.objects.create(
            monitor=monitor,
            http_status_code=None,
            response_time_ms=round(duration_ms, 2),
            outcome=CheckResult.OUTCOME_FAILURE,
            error_category='connection_failed',
            error_detail=f"Connection refused or unreachable: {str(e)[:200]}",
            response_size_bytes=0,
            expected_status_codes=monitor.expected_status_codes,
            status_matched=False,
            resolved_ip=resolved_ip
        )

    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        result = CheckResult.objects.create(
            monitor=monitor,
            http_status_code=None,
            response_time_ms=round(duration_ms, 2),
            outcome=CheckResult.OUTCOME_ERROR,
            error_category=e.__class__.__name__.lower(),
            error_detail=str(e)[:250],
            response_size_bytes=0,
            expected_status_codes=monitor.expected_status_codes,
            status_matched=False,
            resolved_ip=resolved_ip
        )

    # Step 3: Update monitor state
    now = timezone.now()
    monitor.last_checked_at = now
    monitor.last_response_time_ms = result.response_time_ms
    monitor.last_status_code = result.http_status_code

    if result.outcome == CheckResult.OUTCOME_SUCCESS:
        monitor.consecutive_failures = 0
        if result.response_time_ms >= monitor.latency_warning_threshold:
            monitor.last_status = monitor.STATUS_DEGRADED
        else:
            monitor.last_status = monitor.STATUS_HEALTHY
    else:
        monitor.consecutive_failures += 1
        monitor.last_status = monitor.STATUS_FAILING

    monitor.save(update_fields=[
        'last_checked_at', 'last_response_time_ms', 'last_status_code',
        'consecutive_failures', 'last_status', 'updated_at'
    ])

    # Step 4: Evaluate alert threshold policies
    try:
        evaluate_monitor_alerts(monitor, result)
    except Exception:
        pass

    return result
