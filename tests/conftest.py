import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from monitors.models import Monitor


@pytest.fixture
def user_factory(db):
    def create_user(username="testuser", email="test@example.com", password="StrongPassword123!"):
        return User.objects.create_user(username=username, email=email, password=password)
    return create_user


@pytest.fixture
def user1(user_factory):
    return user_factory(username="alice", email="alice@pulseapi.dev")


@pytest.fixture
def user2(user_factory):
    return user_factory(username="bob", email="bob@pulseapi.dev")


@pytest.fixture
def auth_client(user1):
    client = APIClient()
    client.force_authenticate(user=user1)
    return client


@pytest.fixture
def auth_client_bob(user2):
    client = APIClient()
    client.force_authenticate(user=user2)
    return client


@pytest.fixture
def monitor_factory(db):
    def create_monitor(owner, name="Primary API", url="https://api.example.com/health", **kwargs):
        defaults = {
            'http_method': 'GET',
            'check_interval': 60,
            'request_timeout': 10,
            'expected_status_codes': '200-299',
            'latency_warning_threshold': 500,
            'latency_failure_threshold': 2000,
            'enabled': True,
        }
        defaults.update(kwargs)
        return Monitor.objects.create(owner=owner, name=name, target_url=url, **defaults)
    return create_monitor
