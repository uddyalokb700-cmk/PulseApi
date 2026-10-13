import pytest
from rest_framework import status
from django.contrib.auth.models import User
from rest_framework.test import APIClient


@pytest.mark.django_db
def test_user_registration_api():
    client = APIClient()
    payload = {
        "username": "newdev",
        "email": "dev@pulseapi.dev",
        "password": "SecurePassword123!",
        "password_confirm": "SecurePassword123!"
    }
    response = client.post('/api/v1/auth/register/', payload, format='json')
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data['username'] == "newdev"
    assert data['email'] == "dev@pulseapi.dev"
    assert User.objects.filter(username="newdev").exists()


@pytest.mark.django_db
def test_user_registration_password_mismatch():
    client = APIClient()
    payload = {
        "username": "newdev",
        "password": "SecurePassword123!",
        "password_confirm": "DifferentPassword123!"
    }
    response = client.post('/api/v1/auth/register/', payload, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
def test_user_login_and_me_api(user1):
    client = APIClient()
    # Login
    login_resp = client.post('/api/v1/auth/login/', {
        "username": "alice",
        "password": "StrongPassword123!"
    }, format='json')
    assert login_resp.status_code == status.HTTP_200_OK

    # Me
    me_resp = client.get('/api/v1/auth/me/')
    assert me_resp.status_code == status.HTTP_200_OK
    assert me_resp.json()['username'] == "alice"

    # Logout
    logout_resp = client.post('/api/v1/auth/logout/')
    assert logout_resp.status_code == status.HTTP_200_OK
