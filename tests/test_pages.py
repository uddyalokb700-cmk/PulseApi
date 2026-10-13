import pytest
from django.test import Client


@pytest.mark.django_db
def test_all_web_pages_render_successfully(user1, monitor_factory):
    mon = monitor_factory(owner=user1, name="Canary Monitor")

    client = Client()

    # Unauthenticated redirects to login
    overview_resp = client.get('/')
    assert overview_resp.status_code == 302
    assert '/accounts/login/' in overview_resp.url

    # Authenticate user
    client.force_login(user1)

    # 1. Overview Page
    res = client.get('/')
    assert res.status_code == 200
    assert b"PulseAPI Observability" in res.content

    # 2. Monitors Fleet
    res = client.get('/monitors/')
    assert res.status_code == 200
    assert b"Monitored Endpoints" in res.content
    assert b"Canary Monitor" in res.content

    # 3. Create Monitor Form
    res = client.get('/monitors/create/')
    assert res.status_code == 200
    assert b"New Endpoint Configuration" in res.content

    # 4. Monitor Detail
    res = client.get(f'/monitors/{mon.id}/')
    assert res.status_code == 200
    assert b"Monitor Telemetry: Canary Monitor" in res.content

    # 5. Check History
    res = client.get('/checks/')
    assert res.status_code == 200
    assert b"Health Check Execution Logs" in res.content

    # 6. Alerts & Incidents
    res = client.get('/alerts/')
    assert res.status_code == 200
    assert b"Incidents & Alert Events" in res.content

    # 7. Settings
    res = client.get('/settings/')
    assert res.status_code == 200
    assert b"Notification Channels" in res.content

    # 8. OpenAPI Swagger UI
    res = client.get('/api/docs/')
    assert res.status_code == 200
    assert b"swagger-ui" in res.content.lower()

    # 9. OpenAPI Redoc
    res = client.get('/api/redoc/')
    assert res.status_code == 200
    assert b"redoc" in res.content.lower()

    # 10. System Health API
    res = client.get('/api/v1/health/')
    assert res.status_code == 200
    data = res.json()
    assert data['status'] == 'healthy'
    assert data['database'] == 'connected'
