import pytest
import ipaddress
from checks.ssrf import (
    validate_url_syntax,
    is_ip_forbidden,
    resolve_and_verify_destination,
    sanitize_headers,
    SSRFSecurityError
)


def test_url_syntax_allowed_schemes():
    assert validate_url_syntax("http://example.com/api").scheme == "http"
    assert validate_url_syntax("https://example.com/api").scheme == "https"


def test_url_syntax_rejects_prohibited_schemes():
    with pytest.raises(SSRFSecurityError, match="Prohibited scheme"):
        validate_url_syntax("ftp://example.com/file")
    with pytest.raises(SSRFSecurityError, match="Prohibited scheme"):
        validate_url_syntax("gopher://example.com")
    with pytest.raises(SSRFSecurityError, match="Prohibited scheme"):
        validate_url_syntax("file:///etc/passwd")


def test_url_syntax_rejects_embedded_credentials():
    with pytest.raises(SSRFSecurityError, match="Embedded credentials"):
        validate_url_syntax("https://user:password@example.com/api")
    with pytest.raises(SSRFSecurityError, match="Embedded credentials"):
        validate_url_syntax("https://admin@example.com/api")


def test_url_syntax_rejects_dangerous_ports():
    with pytest.raises(SSRFSecurityError, match="restricted infrastructure port"):
        validate_url_syntax("http://example.com:22/ssh")
    with pytest.raises(SSRFSecurityError, match="restricted infrastructure port"):
        validate_url_syntax("http://example.com:5432/postgres")
    with pytest.raises(SSRFSecurityError, match="restricted infrastructure port"):
        validate_url_syntax("http://example.com:6379/redis")


def test_ip_forbidden_checks():
    # Loopback
    assert is_ip_forbidden(ipaddress.ip_address("127.0.0.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("127.0.0.2")) is True
    assert is_ip_forbidden(ipaddress.ip_address("::1")) is True

    # Private RFC1918
    assert is_ip_forbidden(ipaddress.ip_address("10.0.0.5")) is True
    assert is_ip_forbidden(ipaddress.ip_address("172.16.50.1")) is True
    assert is_ip_forbidden(ipaddress.ip_address("192.168.1.1")) is True

    # Link local & Cloud Metadata
    assert is_ip_forbidden(ipaddress.ip_address("169.254.169.254")) is True
    assert is_ip_forbidden(ipaddress.ip_address("100.100.100.200")) is True

    # Public valid IP
    assert is_ip_forbidden(ipaddress.ip_address("93.184.216.34")) is False
    assert is_ip_forbidden(ipaddress.ip_address("8.8.8.8")) is False


def test_resolve_and_verify_destination_catches_private_ip():
    with pytest.raises(SSRFSecurityError, match="restricted or private"):
        resolve_and_verify_destination("127.0.0.1", allow_private=False)

    with pytest.raises(SSRFSecurityError, match="restricted or private"):
        resolve_and_verify_destination("169.254.169.254", allow_private=False)

    with pytest.raises(SSRFSecurityError, match="restricted or private"):
        resolve_and_verify_destination("192.168.1.100", allow_private=False)


def test_sanitize_headers():
    headers = {
        'Authorization': 'Bearer 12345',
        'Host': 'internal.admin',
        'X-Forwarded-For': '127.0.0.1',
        'Content-Type': 'application/json',
    }
    clean = sanitize_headers(headers)
    assert 'Authorization' in clean
    assert 'Content-Type' in clean
    assert 'Host' not in clean
    assert 'X-Forwarded-For' not in clean
