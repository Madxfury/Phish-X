"""Bounded HTTP client for untrusted websites. Never uses proxies or re-resolves at connect."""
from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

import dns.exception
import dns.resolver


class ScanError(Exception):
    def __init__(self, message: str, code: str = "unreachable"):
        super().__init__(message)
        self.code = code


@dataclass
class Target:
    url: str
    hostname: str
    port: int
    scheme: str
    addresses: list[str] = field(default_factory=list)


def public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if value == "168.63.129.16":  # Azure platform / WireServer endpoint.
        return False
    # Reject transition ranges, mapped IPv4, shared, multicast and reserved networks.
    if not address.is_global or address.is_multicast or address.is_reserved:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if address in ipaddress.ip_network("64:ff9b::/96") or address in ipaddress.ip_network("64:ff9b:1::/48"):
            return False
    return True


def normalize_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScanError("Enter a website URL.", "invalid_url")
    value = value.strip()
    if len(value) > 4096 or re.search(r"[\s\x00-\x1f\x7f\\]", value):
        raise ScanError("URL is too long or contains whitespace, control characters or backslashes.", "invalid_url")
    if "://" not in value:
        if re.match(r"^[a-zA-Z][\w+.-]*:", value) and not re.match(r"^[^/:]+:(80|443)(/|$)", value):
            raise ScanError("Only HTTP and HTTPS URLs are supported.", "invalid_url")
        value = "https:" + value if value.startswith("//") else "https://" + value
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing embedded credentials are not allowed.")
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        if not host or "%" in host:
            raise ValueError("Invalid hostname.")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or "." not in host or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in host.split(".")):
                raise ValueError("Use a valid public hostname.")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port != (443 if parsed.scheme.lower() == "https" else 80):
            raise ValueError("Only standard website ports (HTTP 80 / HTTPS 443) are allowed.")
        netloc = f"[{host}]" if ":" in host else host
        # Preserve existing percent escapes; encode Unicode paths consistently.
        return urlunsplit((parsed.scheme.lower(), netloc, quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~"), quote(parsed.query, safe="%/?@!$&'()*+,;=:-._~"), ""))
    except (ValueError, UnicodeError) as exc:
        raise ScanError(str(exc), "invalid_url") from None


def resolve_target(value: str, deadline: float | None = None) -> Target:
    url = normalize_url(value)
    p = urlsplit(url)
    host = p.hostname
    target = Target(url, host, 443 if p.scheme == "https" else 80, p.scheme)
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home", ".test", ".invalid")) or host in {"metadata.google.internal", "metadata.goog", "instance-data.ec2.internal"}:
        raise ScanError("Internal, local and metadata destinations are blocked.", "blocked_destination")
    try:
        ipaddress.ip_address(host)
        target.addresses = [host]
    except ValueError:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1.0
        for kind in ("A", "AAAA"):
            remaining = min(1.5, deadline - time.monotonic()) if deadline else 1.5
            if remaining <= 0:
                raise ScanError("Scan time budget exhausted during DNS resolution.", "timeout")
            try:
                answer = resolver.resolve(host, kind, lifetime=remaining, search=False)
                target.addresses.extend(str(record) for record in answer)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except dns.exception.DNSException:
                # Do not continue with a partial resolution that may hide private records.
                raise ScanError("DNS lookup failed or timed out.", "dns_error") from None
    if not target.addresses or len(target.addresses) > 64:
        raise ScanError("No usable DNS address found.", "dns_error")
    if any(not public_ip(ip) for ip in target.addresses):
        raise ScanError("Destination resolves to a non-public address; request blocked.", "blocked_destination")
    return target


def _pinned_socket(address: str, port: int, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
        if ipaddress.ip_address(sock.getpeername()[0]) != ipaddress.ip_address(address):
            raise ScanError("Connection address mismatch.", "blocked_destination")
        return sock
    except BaseException:
        sock.close()
        raise



def _connect_vetted(target: Target, deadline: float):
    """Try a bounded set of already-vetted addresses without resolving again."""
    connect_deadline = min(deadline, time.monotonic() + 4)
    last_error = None
    for address in target.addresses[:4]:
        remaining = connect_deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("Connection budget exhausted")
        try:
            sock = _pinned_socket(address, target.port, min(1.5, remaining))
            sock.settimeout(min(4.0, max(0.001, deadline - time.monotonic())))
            return sock, address
        except (OSError, TimeoutError) as exc:
            last_error = exc
    raise last_error or OSError("No connection addresses")


def _certificate(sock) -> dict:
    cert = sock.getpeercert()
    issuer = dict(item for group in cert.get("issuer", ()) for item in group)
    not_before = ssl.cert_time_to_seconds(cert["notBefore"])
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    return {"status": "completed", "verified": True, "cert_issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
            "cert_validity_days": int((not_after - not_before) / 86400), "days_to_expiry": int((not_after - time.time()) / 86400),
            "not_before": cert["notBefore"], "not_after": cert["notAfter"], "tls_version": sock.version(), "cipher": sock.cipher()[0]}


def request_once(target: Target, deadline: float, max_bytes: int) -> dict:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ScanError("Scan time budget exhausted.", "timeout")
    timeout = min(4.0, remaining)
    if target.scheme == "https":
        connection = http.client.HTTPSConnection(target.hostname, target.port, timeout=timeout, context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(target.hostname, target.port, timeout=timeout)
    # Host header / TLS SNI stay the original hostname, TCP uses only the validated IP.
    connected = {}
    def create_connection(address, timeout, source_address=None):
        sock, ip = _connect_vetted(target, deadline)
        connected["ip"] = ip
        return sock
    connection._create_connection = create_connection
    try:
        connection.connect()
        tls = _certificate(connection.sock) if target.scheme == "https" else {"status": "not_applicable", "verified": False, "reason": "HTTP connection has no TLS."}
        p = urlsplit(target.url)
        connection.request("GET", p.path + ("?" + p.query if p.query else ""), headers={"User-Agent": "Phish-X-AI/3.0 (bounded security inspection)", "Accept": "text/html,application/xhtml+xml,text/javascript,*/*;q=0.3", "Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        header_items = response.getheaders()
        if sum(len(k) + len(v) for k, v in header_items) > 65536:
            raise ScanError("Response headers exceed size limit.", "response_too_large")
        headers = {k.lower(): v for k, v in header_items if k.lower() not in {"set-cookie", "authorization", "proxy-authorization"}}
        result = {"url": target.url, "status_code": response.status, "headers": headers, "addresses": target.addresses, "connected_ip": connected["ip"], "tls": tls, "body": b"", "truncated": False}
        if response.status in {301, 302, 303, 307, 308}:
            return result  # Never download redirect bodies.
        encoding = headers.get("content-encoding", "identity").lower()
        if encoding not in {"identity", "", "gzip", "deflate"}:
            raise ScanError("Unsupported response compression.", "unsupported_content")
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS) if encoding in {"gzip", "deflate"} else None
        chunks, count, wire_count = [], 0, 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScanError("Response exceeded the scan time budget.", "timeout")
            if connection.sock:
                connection.sock.settimeout(min(3.0, remaining))
            elif response.fp:
                response.fp.raw._sock.settimeout(min(3.0, remaining))
            raw = response.read1(min(32768, max_bytes - wire_count + 1))
            if not raw:
                break
            wire_count += len(raw)
            if wire_count > max_bytes:
                result["truncated"] = True
                break
            chunk = decompressor.decompress(raw, max_bytes - count + 1) if decompressor else raw
            count += len(chunk)
            if count > max_bytes or (decompressor and decompressor.unconsumed_tail):
                chunks.append(chunk[:max_bytes - (count - len(chunk))])
                result["truncated"] = True
                break
            chunks.append(chunk)
        if decompressor and not result["truncated"] and not decompressor.eof:
            raise ScanError("Compressed response was incomplete.", "unreachable")
        result["body"] = b"".join(chunks)
        result["bytes_received"] = len(result["body"])
        return result
    except ssl.SSLCertVerificationError:
        raise ScanError("TLS certificate verification failed; unverified content was not fetched.", "tls_error") from None
    except (socket.timeout, TimeoutError):
        raise ScanError("Target connection or response timed out.", "timeout") from None
    except ScanError:
        raise
    except (OSError, http.client.HTTPException, zlib.error):
        raise ScanError("Website connection failed or returned an invalid HTTP response.", "unreachable") from None
    finally:
        connection.close()


def fetch_website(url: str, deadline: float | None = None, max_bytes: int = 1024 * 1024, max_redirects: int = 5, on_event=None, initial: Target | None = None) -> dict:
    deadline = deadline or time.monotonic() + 15
    current, chain, seen = normalize_url(url), [], set()
    try:
        for index in range(max_redirects + 1):
            if current in seen:
                raise ScanError("Redirect loop detected.", "redirect_error")
            seen.add(current)
            target = initial if index == 0 and initial and initial.url == current else resolve_target(current, deadline)
            response = request_once(target, deadline, max_bytes)
            if response["status_code"] not in {301, 302, 303, 307, 308}:
                response["redirect_chain"] = chain
                response["final_url"] = current
                return response
            location = response["headers"].get("location")
            if not location:
                raise ScanError("Redirect response is missing its Location header.", "redirect_error")
            destination = normalize_url(urljoin(current, location))
            chain.append({"from": current, "to": destination, "status_code": response["status_code"], "connected_ip": response["connected_ip"], "tls": response["tls"]})
            if on_event:
                on_event("Redirect observed", "completed", f"HTTP {response['status_code']}: {current} -> {destination}")
            if index == max_redirects:
                raise ScanError("Redirect limit exceeded.", "redirect_error")
            current = destination
    except ScanError as exc:
        # Keep observed redirects even when a later destination is blocked or fails.
        exc.redirect_chain = chain
        raise
