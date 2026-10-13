import pytest
from rest_framework import status
from unittest.mock import patch, MagicMock


@pytest.mark.django_db
def test_create_monitor_via_api(auth_client):
    payload = {
        "name": "Auth API Endpoint",
        "target_url": "https://auth.example.com/health",
        "http_method": "GET",
        "check_interval": 60,
        "request_timeout": 5,
        "expected_status_codes": "200,204",
        "latency_warning_threshold": 300,
        "latency_failure_threshold": 1500,
        "headers": [
            {"name": "X-API-Key", "value": "super-secret-key-123", "is_secret": True},
            {"name": "Accept", "value": "application/json", "is_secret": False}
        ]
    }
    response = auth_client.post('/api/v1/monitors/', payload, format='json')
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data['name'] == "Auth API Endpoint"
    assert data['target_url'] == "https://auth.example.com/health"
    assert data['hostname'] == "auth.example.com"

    # Secret header must be masked as '********' in response!
    headers = data['headers']
    secret_header = next(h for h in headers if h['name'] == 'X-API-Key')
    assert secret_header['value'] == '********'
    assert secret_header['is_secret'] is True

    plain_header = next(h for h in headers if h['name'] == 'Accept')
    assert plain_header['value'] == 'application/json'


@pytest.mark.django_db
def test_ownership_isolation_prevents_unauthorized_access(auth_client, auth_client_bob, monitor_factory, user1):
    # Monitor belongs to Alice (user1)
    mon = monitor_factory(owner=user1, name="Alice Private Monitor")

    # Bob tries to access Alice's monitor
    bob_resp = auth_client_bob.get(f'/api/v1/monitors/{mon.id}/')
    assert bob_resp.status_code == status.HTTP_404_NOT_FOUND

    # Bob tries to update Alice's monitor
    bob_patch = auth_client_bob.patch(f'/api/v1/monitors/{mon.id}/', {'name': 'Hacked'}, format='json')
    assert bob_patch.status_code == status.HTTP_404_NOT_FOUND

    # Bob tries to delete Alice's monitor
    bob_del = auth_client_bob.delete(f'/api/v1/monitors/{mon.id}/')
    assert bob_del.status_code == status.HTTP_404_NOT_FOUND

    # Alice can access her own monitor
    alice_resp = auth_client.get(f'/api/v1/monitors/{mon.id}/')
    assert alice_resp.status_code == status.HTTP_200_OK
    assert alice_resp.json()['name'] == "Alice Private Monitor"


@pytest.mark.django_db
def test_toggle_monitor_status(auth_client, monitor_factory, user1):
    mon = monitor_factory(owner=user1, enabled=True)
    assert mon.enabled is True

    # Toggle to paused
    resp = auth_client.post(f'/api/v1/monitors/{mon.id}/toggle/')
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()['enabled'] is False

    mon.refresh_from_db()
    assert mon.enabled is False

    # Toggle back to enabled
    resp2 = auth_client.post(f'/api/v1/monitors/{mon.id}/toggle/')
    assert resp2.status_code == status.HTTP_200_OK
    assert resp2.json()['enabled'] is True


@pytest.mark.django_db
def test_manual_check_api_endpoint(auth_client, monitor_factory, user1):
    mon = monitor_factory(owner=user1)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_redirect = False
    mock_resp.iter_bytes.return_value = [b'{"ok": true}']

    with patch('checks.engine.resolve_and_verify_destination', return_value=['93.184.216.34']), \
         patch('httpx.Client.stream') as mock_stream:
        mock_stream.return_value.__enter__.return_value = mock_resp

        response = auth_client.post(f'/api/v1/monitors/{mon.id}/check-now/')

    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data['outcome'] == 'success'
    assert data['http_status_code'] == 200
    assert data['status_matched'] is True
