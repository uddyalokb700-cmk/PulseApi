import socket
import ipaddress
import urllib.parse
import typing
import httpcore
from httpcore._backends.sync import SyncBackend
import httpx
from django.conf import settings


class SSRFSecurityError(ValueError):
    """Raised when a URL or outbound connection violates SSRF security policies."""
    pass


# Privileged system ports (< 1024) except standard web ports 80 and 443
PRIVILEGED_PORTS_ALLOWED = {80, 443}

# Known sensitive infrastructure, internal service, and database ports >= 1024
DANGEROUS_PORTS_HIGH = {
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


def normalize_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """
    Normalizes IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) to standard IPv4.
    """
    if getattr(ip_obj, 'ipv4_mapped', None) is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


def is_ip_forbidden(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_private: bool = False) -> bool:
    """
    Checks if an IP address belongs to loopback, private, link-local, multicast,
    reserved, carrier-grade NAT, or known cloud metadata ranges.
    """
    ip_obj = normalize_ip(ip_obj)
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


def is_port_allowed(port: int | None) -> bool:
    """
    Validates destination port against security policy:
    - If no port specified, defaults to 80/443 (allowed)
    - If port < 1024: only 80 and 443 are permitted (blocks privileged ports: 21, 22, 23, 25, 53, etc.)
    - If port >= 1024: blocks known internal infrastructure/database ports
    """
    if port is None:
        return True
    if port < 1024:
        return port in PRIVILEGED_PORTS_ALLOWED
    if port in DANGEROUS_PORTS_HIGH:
        return False
    return True


def parse_numeric_ip(hostname: str) -> ipaddress.IPv4Address | None:
    """
    Detects and parses alternate numeric IP representations:
    - Decimal integer strings: e.g. '2130706433' -> 127.0.0.1
    - Hex representations: e.g. '0x7f000001' -> 127.0.0.1
    - Octal numeric strings: e.g. '017700000001' -> 127.0.0.1
    """
    if not hostname:
        return None
    # Hex representation
    if hostname.lower().startswith('0x'):
        try:
            val = int(hostname, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass
    # Pure numeric (decimal or octal if leading 0)
    if hostname.isdigit():
        try:
            # Handle octal with leading zero if strictly octal digits
            if hostname.startswith('0') and len(hostname) > 1 and all(c in '01234567' for c in hostname):
                try:
                    val = int(hostname, 8)
                    if 0 <= val <= 0xFFFFFFFF:
                        return ipaddress.IPv4Address(val)
                except ValueError:
                    pass
            val = int(hostname, 10)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass
    return None


def validate_url_syntax(url: str, allow_private: bool = None) -> urllib.parse.ParseResult:
    """
    Validates URL scheme, credentials, ports, and hostname syntax.
    """
    if allow_private is None:
        allow_private = getattr(settings, 'SSRF_ALLOW_PRIVATE_IPS', False)

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
    if not is_port_allowed(parsed.port):
        raise SSRFSecurityError(f"Connection to restricted infrastructure port {parsed.port} is blocked.")

    # Check for direct numeric IP representation
    numeric_ip = parse_numeric_ip(parsed.hostname)
    if numeric_ip and is_ip_forbidden(numeric_ip, allow_private=allow_private):
        raise SSRFSecurityError(f"Destination '{parsed.hostname}' points to a restricted or private IP address.")

    # Check for literal IPv4 or IPv6 address
    clean_host = parsed.hostname.split('%')[0] if '%' in parsed.hostname else parsed.hostname
    try:
        ip_obj = ipaddress.ip_address(clean_host)
    except ValueError:
        ip_obj = None

    if ip_obj and is_ip_forbidden(ip_obj, allow_private=allow_private):
        raise SSRFSecurityError(f"Destination '{parsed.hostname}' points to a restricted or private IP address.")

    return parsed


def resolve_and_verify_destination(hostname: str, allow_private: bool = None) -> list[str]:
    """
    Resolves DNS for the given hostname and verifies that all resolved IP addresses
    (both IPv4 and IPv6) are safe for outbound HTTP requests.
    Returns list of verified IP string representations.
    """
    if allow_private is None:
        allow_private = getattr(settings, 'SSRF_ALLOW_PRIVATE_IPS', False)

    # Check if the hostname itself is a literal IP address (or numeric representation)
    numeric_ip = parse_numeric_ip(hostname)
    if numeric_ip:
        if is_ip_forbidden(numeric_ip, allow_private=allow_private):
            raise SSRFSecurityError(f"Destination '{hostname}' points to a restricted or private IP address.")
        return [str(numeric_ip)]

    clean_host = hostname.split('%')[0] if '%' in hostname else hostname
    try:
        ip_obj = ipaddress.ip_address(clean_host)
    except ValueError:
        ip_obj = None

    if ip_obj:
        if is_ip_forbidden(ip_obj, allow_private=allow_private):
            raise SSRFSecurityError(f"Destination '{hostname}' points to a restricted or private IP address.")
        return [str(normalize_ip(ip_obj))]

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

        clean_ip = str(normalize_ip(ip_obj))
        if clean_ip not in resolved_ips:
            resolved_ips.append(clean_ip)

    return resolved_ips


def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
    """
    Sanitizes user-supplied HTTP request headers to prevent Host header poisoning,
    internal hop-by-hop header overriding, or CRLF header injection.
    """
    prohibited_headers = {
        'host', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
        'x-real-ip', 'connection', 'upgrade', 'keep-alive', 'proxy-connection',
        'transfer-encoding', 'content-length', 'te', 'trailer',
        'proxy-authenticate', 'proxy-authorization'
    }
    clean = {}
    for k, v in headers.items():
        # Prevent CRLF header injection
        if any(c in k for c in ('\r', '\n', '\0')) or any(c in v for c in ('\r', '\n', '\0')):
            continue
        if k.lower() not in prohibited_headers:
            clean[k] = v
    return clean


class SSRFSafeNetworkBackend(SyncBackend):
    """
    Custom NetworkBackend that intercepts TCP socket connections right before
    and right after creation, guaranteeing:
    1. Pre-connection resolution verification
    2. Post-connection peer address verification (Zero TOCTOU / DNS Rebinding gap)
    """
    def __init__(self, allow_private: bool = False):
        super().__init__()
        self.allow_private = allow_private

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: typing.Iterable[typing.Any] | None = None,
    ):
        if isinstance(host, bytes):
            host = host.decode('ascii', errors='ignore')

        # 1. Port policy verification
        if not is_port_allowed(port):
            raise SSRFSecurityError(f"Connection to port {port} is prohibited by SSRF security policy.")

        # 2. Pre-connection DNS validation
        resolve_and_verify_destination(host, allow_private=self.allow_private)

        # 3. Establish TCP connection
        stream = super().connect_tcp(host, port, timeout=timeout, local_address=local_address, socket_options=socket_options)

        # 4. Immediate post-connection connected peer address verification (anti-DNS rebinding)
        server_addr = stream.get_extra_info("server_addr")
        if server_addr:
            peer_ip = server_addr[0]
            if isinstance(peer_ip, bytes):
                peer_ip = peer_ip.decode('ascii', errors='ignore')

            # Parse IP safely without masking SSRFSecurityError
            try:
                peer_obj = ipaddress.ip_address(peer_ip)
            except ValueError:
                stream.close()
                raise SSRFSecurityError(f"Invalid peer address '{peer_ip}' received from socket.")

            if is_ip_forbidden(peer_obj, allow_private=self.allow_private):
                stream.close()
                raise SSRFSecurityError(
                    f"Connected peer IP '{peer_ip}' violates SSRF policy (DNS rebinding detected)."
                )

        return stream


class SSRFSafeTransport(httpx.HTTPTransport):
    """
    Custom HTTPTransport wrapping httpcore.ConnectionPool with SSRFSafeNetworkBackend.
    """
    def __init__(self, allow_private: bool = False, **kwargs):
        super().__init__(**kwargs)
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._pool._ssl_context,
            max_connections=self._pool._max_connections,
            max_keepalive_connections=self._pool._max_keepalive_connections,
            keepalive_expiry=self._pool._keepalive_expiry,
            http1=self._pool._http1,
            http2=self._pool._http2,
            retries=self._pool._retries,
            local_address=self._pool._local_address,
            uds=self._pool._uds,
            network_backend=SSRFSafeNetworkBackend(allow_private=allow_private),
            socket_options=self._pool._socket_options,
        )
