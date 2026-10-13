import socket
import ipaddress
import urllib.parse
from django.conf import settings


class SSRFSecurityError(ValueError):
    """Raised when a URL violates Server-Side Request Forgery protections."""
    pass


# Disallowed ports typically associated with internal infrastructure & databases
DANGEROUS_PORTS = {
    21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 389, 445,
    1433, 1521, 2049, 2375, 2376, 3306, 3389, 5000, 5432, 5984,
    6379, 6443, 7001, 8086, 8500, 9042, 9200, 9300, 11211, 27017, 28017
}

# Known Cloud Metadata IP addresses / CIDRs
CLOUD_METADATA_IPS = {
    '169.254.169.254',       # AWS, Azure, GCP, OpenStack
    'fd00:ec2::254',         # AWS IMDSv6
    '100.100.100.200',       # Alibaba Cloud
    '169.254.170.2',         # AWS ECS task credentials
}


def is_ip_forbidden(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool = False) -> bool:
    """
    Checks if an IP address belongs to loopback, private, link-local, multicast,
    reserved, or known cloud metadata ranges.
    """
    ip_str = str(ip_obj)

    # Cloud metadata is ALWAYS forbidden under any mode
    if ip_str in CLOUD_METADATA_IPS:
        return True

    # Link-local (169.254.0.0/16, fe80::/10) is ALWAYS forbidden
    if ip_obj.is_link_local:
        return True

    # Multicast, reserved, unspecified (0.0.0.0, ::)
    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return True

    # Loopback (127.0.0.0/8, ::1)
    if ip_obj.is_loopback and not allow_private:
        return True

    # Private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    if ip_obj.is_private and not allow_private:
        return True

    # Carrier-grade NAT (100.64.0.0/10)
    try:
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in ipaddress.IPv4Network('100.64.0.0/10'):
            if not allow_private:
                return True
    except Exception:
        pass

    return False


def validate_url_syntax(url: str) -> urllib.parse.ParseResult:
    """
    Validates URL scheme, credentials, and hostname syntax.
    """
    if not url:
        raise SSRFSecurityError("Target URL cannot be empty.")

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise SSRFSecurityError(f"Malformed URL: {e}")

    # Scheme validation: ONLY http and https
    if parsed.scheme.lower() not in ('http', 'https'):
        raise SSRFSecurityError(f"Prohibited scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    # Reject embedded userinfo / credentials (e.g. http://admin:pass@host)
    if parsed.username or parsed.password:
        raise SSRFSecurityError("Embedded credentials in target URLs are strictly prohibited.")

    # Hostname must be present
    if not parsed.hostname:
        raise SSRFSecurityError("URL is missing a valid hostname.")

    # Port validation
    if parsed.port and parsed.port in DANGEROUS_PORTS:
        raise SSRFSecurityError(f"Connection to restricted infrastructure port {parsed.port} is blocked.")

    return parsed


def resolve_and_verify_destination(hostname: str, allow_private: bool = None) -> list[str]:
    """
    Resolves DNS for the given hostname and verifies that all resolved IP addresses
    (both IPv4 and IPv6) are safe for outbound HTTP requests.
    Returns list of verified IP string representations.
    """
    if allow_private is None:
        allow_private = getattr(settings, 'SSRF_ALLOW_PRIVATE_IPS', False)

    # Check if the hostname itself is a literal IP address (including hex/octal/decimal representations)
    try:
        ip_obj = ipaddress.ip_address(hostname)
        if is_ip_forbidden(ip_obj, allow_private=allow_private):
            raise SSRFSecurityError(f"Destination '{hostname}' points to a restricted or private IP address.")
        return [str(ip_obj)]
    except ValueError:
        # Not a raw IP literal; proceed with DNS resolution
        pass

    # Resolve via socket.getaddrinfo to capture all IPv4 and IPv6 addresses
    try:
        addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFSecurityError(f"DNS resolution failed for hostname '{hostname}': {e}")
    except Exception as e:
        raise SSRFSecurityError(f"Could not resolve destination '{hostname}': {e}")

    if not addr_info:
        raise SSRFSecurityError(f"No IP addresses resolved for hostname '{hostname}'.")

    resolved_ips: list[str] = []
    for info in addr_info:
        sockaddr = info[4]
        ip_str = sockaddr[0]

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFSecurityError(f"Resolved address '{ip_str}' is an invalid IP representation.")

        if is_ip_forbidden(ip_obj, allow_private=allow_private):
            raise SSRFSecurityError(
                f"Resolved destination '{hostname}' ({ip_str}) points to a restricted or private IP address."
            )

        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    return resolved_ips


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Sanitizes user-supplied HTTP request headers to prevent Host header poisoning
    or internal hop-by-hop header overriding.
    """
    prohibited_headers = {
        'host', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
        'x-real-ip', 'connection', 'upgrade', 'keep-alive', 'proxy-connection'
    }
    clean = {}
    for k, v in headers.items():
        if k.lower() not in prohibited_headers:
            clean[k] = v
    return clean
