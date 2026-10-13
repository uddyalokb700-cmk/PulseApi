from datetime import timedelta
from django.utils import timezone
from django.db.models import Avg, Min, Max, Count, Q
from checks.models import CheckResult
from monitors.models import Monitor


def get_time_cutoff(time_range: str):
    now = timezone.now()
    range_map = {
        '1h': timedelta(hours=1),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7),
        '30d': timedelta(days=30),
    }
    delta = range_map.get(time_range.lower(), timedelta(hours=24))
    return now - delta


def calculate_performance_summary(user, monitor_id=None, time_range='24h') -> dict:
    """
    Computes system-level or monitor-specific performance metrics with DB-side aggregation.
    """
    cutoff = get_time_cutoff(time_range)
    qs = CheckResult.objects.filter(monitor__owner=user, created_at__gte=cutoff)

    if monitor_id:
        qs = qs.filter(monitor_id=monitor_id)

    total_checks = qs.count()
    if total_checks == 0:
        return {
            'total_checks': 0,
            'success_checks': 0,
            'failed_checks': 0,
            'success_rate': 0.0,
            'error_rate': 0.0,
            'avg_latency_ms': 0.0,
            'min_latency_ms': 0.0,
            'max_latency_ms': 0.0,
            'p50_latency_ms': 0.0,
            'p95_latency_ms': 0.0,
            'time_range': time_range,
        }

    # DB-side aggregate for average, min, and max latency
    aggs = qs.aggregate(
        avg_latency=Avg('response_time_ms'),
        min_latency=Min('response_time_ms'),
        max_latency=Max('response_time_ms'),
        success_count=Count('id', filter=Q(outcome='success')),
        failure_count=Count('id', filter=~Q(outcome='success')),
    )

    avg_latency = round(aggs['avg_latency'] or 0.0, 2)
    min_latency = round(aggs['min_latency'] or 0.0, 2)
    max_latency = round(aggs['max_latency'] or 0.0, 2)
    success_count = aggs['success_count'] or 0
    failure_count = aggs['failure_count'] or 0

    success_rate = round((success_count / total_checks) * 100.0, 2)
    error_rate = round((failure_count / total_checks) * 100.0, 2)

    # Compute p50 and p95 percentiles efficiently
    sorted_durations = list(qs.order_by('response_time_ms').values_list('response_time_ms', flat=True))
    p50_idx = max(0, int(total_checks * 0.50) - 1)
    p95_idx = max(0, int(total_checks * 0.95) - 1)

    p50_latency = round(sorted_durations[p50_idx], 2) if sorted_durations else 0.0
    p95_latency = round(sorted_durations[p95_idx], 2) if sorted_durations else 0.0

    return {
        'total_checks': total_checks,
        'success_checks': success_count,
        'failed_checks': failure_count,
        'success_rate': success_rate,
        'error_rate': error_rate,
        'avg_latency_ms': avg_latency,
        'min_latency_ms': min_latency,
        'max_latency_ms': max_latency,
        'p50_latency_ms': p50_latency,
        'p95_latency_ms': p95_latency,
        'time_range': time_range,
    }


def calculate_timeseries_latency(user, monitor_id=None, time_range='24h', max_points=40) -> list[dict]:
    """
    Returns sampled time-series latency data points for line chart rendering.
    """
    cutoff = get_time_cutoff(time_range)
    qs = CheckResult.objects.filter(
        monitor__owner=user,
        created_at__gte=cutoff
    ).select_related('monitor').order_by('created_at')

    if monitor_id:
        qs = qs.filter(monitor_id=monitor_id)

    total = qs.count()
    if total == 0:
        return []

    # Downsample if we have more points than max_points to keep payload fast and light
    step = max(1, total // max_points)
    points = []
    for i, check in enumerate(qs):
        if i % step == 0:
            points.append({
                'timestamp': check.created_at.strftime('%H:%M:%S' if time_range in ('1h', '24h') else '%m-%d %H:%M'),
                'response_time_ms': check.response_time_ms,
                'outcome': check.outcome,
                'status_code': check.http_status_code,
                'monitor_name': check.monitor.name,
            })

    return points


def calculate_status_distribution(user, monitor_id=None, time_range='24h') -> dict:
    """
    Categorizes status codes into 2xx, 3xx, 4xx, 5xx, and Connection/Timeout errors.
    """
    cutoff = get_time_cutoff(time_range)
    qs = CheckResult.objects.filter(monitor__owner=user, created_at__gte=cutoff)

    if monitor_id:
        qs = qs.filter(monitor_id=monitor_id)

    distribution = {
        '2xx': 0,
        '3xx': 0,
        '4xx': 0,
        '5xx': 0,
        'errors': 0,
    }

    for item in qs.values('http_status_code', 'outcome'):
        code = item['http_status_code']
        outcome = item['outcome']
        if outcome in ('timeout', 'error') or code is None:
            distribution['errors'] += 1
        elif 200 <= code < 300:
            distribution['2xx'] += 1
        elif 300 <= code < 400:
            distribution['3xx'] += 1
        elif 400 <= code < 500:
            distribution['4xx'] += 1
        elif 500 <= code < 600:
            distribution['5xx'] += 1
        else:
            distribution['errors'] += 1

    return distribution


def calculate_endpoint_comparison(user, time_range='24h') -> list[dict]:
    """
    Aggregates latency and reliability per monitor for comparative endpoint performance tables/charts.
    """
    cutoff = get_time_cutoff(time_range)
    monitors = Monitor.objects.filter(owner=user)
    comparison = []

    for mon in monitors:
        checks_qs = mon.check_results.filter(created_at__gte=cutoff)
        total = checks_qs.count()
        if total > 0:
            avg_lat = checks_qs.aggregate(avg=Avg('response_time_ms'))['avg'] or 0.0
            p95_lat = checks_qs.order_by('response_time_ms').values_list('response_time_ms', flat=True)
            p95_val = p95_lat[max(0, int(total * 0.95) - 1)] if p95_lat else 0.0
            success_count = checks_qs.filter(outcome='success').count()
            success_rate = round((success_count / total) * 100.0, 1)
        else:
            avg_lat = mon.last_response_time_ms or 0.0
            p95_val = mon.last_response_time_ms or 0.0
            success_rate = 100.0 if mon.last_status == 'healthy' else 0.0

        comparison.append({
            'id': mon.id,
            'name': mon.name,
            'target_url': mon.target_url,
            'status': mon.last_status,
            'avg_latency_ms': round(avg_lat, 2),
            'p95_latency_ms': round(p95_val, 2),
            'success_rate': success_rate,
            'total_checks': total,
        })

    # Sort slowest first
    comparison.sort(key=lambda x: x['avg_latency_ms'], reverse=True)
    return comparison
