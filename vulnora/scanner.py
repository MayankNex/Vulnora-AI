"""Low-volume passive website checks with basic SSRF protections."""
from __future__ import annotations

import ipaddress
import socket
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlparse

import requests

USER_AGENT = "VulnoraAI/0.1 (+https://github.com/MayankNex/Vulnora-AI)"
TIMEOUT = 8
MAX_REDIRECTS = 4


class ScanError(ValueError):
    """Raised when a target is invalid or unsafe to scan."""


def _validate_public_host(hostname: str) -> None:
    if not hostname or hostname.lower() == "localhost" or hostname.lower().endswith(".localhost"):
        raise ScanError("Localhost and local network targets are not allowed.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, None)}
    except socket.gaierror as exc:
        raise ScanError("The hostname could not be resolved.") from exc
    if not addresses:
        raise ScanError("The hostname did not resolve.")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])
        if not ip.is_global:
            raise ScanError("Private, local, or reserved IP addresses are not allowed.")


def _normalize_url(raw_url: str) -> str:
    value = raw_url.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScanError("Enter a valid http:// or https:// website URL.")
    if parsed.username or parsed.password:
        raise ScanError("URLs containing embedded credentials are not allowed.")
    try:
        parsed.port
    except ValueError as exc:
        raise ScanError("Invalid port.") from exc
    _validate_public_host(parsed.hostname)
    return value


def _safe_get(url: str) -> requests.Response:
    current = _normalize_url(url)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8"})
    for _ in range(MAX_REDIRECTS + 1):
        response = session.get(current, timeout=TIMEOUT, allow_redirects=False, verify=True, stream=True)
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                raise ScanError("Redirect destination was missing.")
            current = _normalize_url(urljoin(current, location))
            continue
        response.raw.read(1024, decode_content=True)
        return response
    raise ScanError("Too many redirects. Scan stopped for safety.")


def _finding(severity: str, title: str, description: str, evidence: str, remediation: str) -> dict:
    return {"severity": severity, "title": title, "description": description,
            "evidence": evidence, "remediation": remediation}


def scan_website(raw_url: str) -> dict:
    requested_url = _normalize_url(raw_url)
    response = _safe_get(requested_url)
    try:
        headers = {key.lower(): value for key, value in response.headers.items()}
        final_url = response.url
        findings = []

        if urlparse(final_url).scheme != "https":
            findings.append(_finding("High", "HTTPS is not enabled",
                "The final page uses plain HTTP, so traffic may be exposed in transit.",
                final_url, "Enable HTTPS with a valid certificate and redirect HTTP to HTTPS."))

        checks = [
            ("content-security-policy", "Content Security Policy", "Medium",
             "Add a carefully tested Content-Security-Policy that limits allowed content sources."),
            ("x-content-type-options", "X-Content-Type-Options", "Low",
             "Set X-Content-Type-Options: nosniff."),
            ("referrer-policy", "Referrer Policy", "Low",
             "Set Referrer-Policy: strict-origin-when-cross-origin or a stricter suitable policy."),
            ("permissions-policy", "Permissions Policy", "Low",
             "Set a Permissions-Policy that disables browser features your site does not need."),
        ]
        for header, label, severity, fix in checks:
            if header not in headers:
                findings.append(_finding(severity, f"Missing {label}",
                    f"The response does not include the {label} header.",
                    f"{label} response header not present", fix))

        if urlparse(final_url).scheme == "https" and "strict-transport-security" not in headers:
            findings.append(_finding("Medium", "Missing HTTP Strict Transport Security",
                "The HTTPS response does not advertise HSTS to browsers.",
                "Strict-Transport-Security response header not present",
                "After confirming all relevant subdomains support HTTPS, consider Strict-Transport-Security: max-age=31536000; includeSubDomains. Review before enabling preload."))

        csp = headers.get("content-security-policy", "").lower()
        if "x-frame-options" not in headers and "frame-ancestors" not in csp:
            findings.append(_finding("Medium", "Clickjacking protection not detected",
                "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected.",
                "No recognized frame protection header found",
                "Set an appropriate CSP frame-ancestors directive, or X-Frame-Options for legacy support."))

        cookie_header = response.headers.get("Set-Cookie", "")
        if cookie_header:
            cookie = SimpleCookie()
            try:
                cookie.load(cookie_header)
                for name, morsel in cookie.items():
                    missing = [flag for flag in ("secure", "httponly", "samesite") if not morsel[flag]]
                    if missing:
                        labels = {"secure": "Secure", "httponly": "HttpOnly", "samesite": "SameSite"}
                        findings.append(_finding("Medium", f"Cookie flags need review: {name}",
                            "A cookie in the landing-page response is missing recommended attributes.",
                            "Missing: " + ", ".join(labels[x] for x in missing),
                            "Set Secure for HTTPS cookies, HttpOnly when JavaScript does not need access, and an appropriate SameSite value. Test session behaviour before changing cookies."))
            except Exception:
                findings.append(_finding("Low", "Cookie attributes could not be parsed",
                    "The Set-Cookie header could not be fully interpreted.",
                    "Cookie parsing was inconclusive",
                    "Review Set-Cookie headers manually in your browser or server configuration."))

        return {
            "tool": "Vulnora AI", "version": "0.1.0",
            "requested_url": requested_url, "final_url": final_url,
            "status_code": response.status_code,
            "https": urlparse(final_url).scheme == "https",
            "findings": findings,
            "limitations": [
                "Passive landing-page response checks only.",
                "No exploitation, crawling, brute-force, or authenticated testing.",
                "Header presence does not prove a configuration is secure.",
                "Cookie review covers only cookies visible on this response.",
            ],
        }
    finally:
        response.close()
