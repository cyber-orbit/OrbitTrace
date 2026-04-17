#!/usr/bin/env python3
"""
OrbitTrace - Helper Utilities
Common HTTP, DNS, and data-processing helpers used across modules
"""

import socket
import time
import random
import re
import requests
from typing import Optional, Dict, Any


# Default request timeout (seconds)
DEFAULT_TIMEOUT = 10

# Rotate through several user agents to reduce blocking
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
]


def get_headers(extra: Optional[Dict] = None) -> Dict:
    """Return randomised request headers to avoid basic bot detection"""
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }
    if extra:
        headers.update(extra)
    return headers


def safe_get(url: str, timeout: int = DEFAULT_TIMEOUT,
             allow_redirects: bool = True, headers: Optional[Dict] = None,
             verify: bool = True) -> Optional[requests.Response]:
    """
    Safe HTTP GET wrapper with error handling.
    
    Returns:
        requests.Response on success, None on failure
    """
    try:
        h = get_headers(headers)
        resp = requests.get(
            url, timeout=timeout, headers=h,
            allow_redirects=allow_redirects,
            verify=verify
        )
        return resp
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.SSLError:
        # Retry without SSL verification
        try:
            resp = requests.get(url, timeout=timeout, headers=get_headers(),
                                allow_redirects=allow_redirects, verify=False)
            return resp
        except Exception:
            return None
    except Exception:
        return None


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve a hostname to an IP address"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup on an IP address"""
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except (socket.herror, socket.gaierror):
        return None


def clean_domain(raw: str) -> str:
    """Strip protocol, www, and trailing slashes from a domain"""
    domain = re.sub(r'^https?://', '', raw.strip())
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0]   # Remove path
    domain = domain.split('?')[0]   # Remove query string
    return domain.lower().strip()


def format_bytes(size: int) -> str:
    """Format byte size into human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def truncate(s: str, max_len: int = 80) -> str:
    """Truncate a string to max_len characters"""
    if len(s) <= max_len:
        return s
    return s[:max_len - 3] + "..."


def sleep_random(min_s: float = 0.3, max_s: float = 1.2):
    """Sleep for a random interval to be polite to servers"""
    time.sleep(random.uniform(min_s, max_s))


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is in a private/reserved range"""
    private_ranges = [
        re.compile(r'^10\.'),
        re.compile(r'^172\.(1[6-9]|2\d|3[01])\.'),
        re.compile(r'^192\.168\.'),
        re.compile(r'^127\.'),
        re.compile(r'^::1$'),
        re.compile(r'^fc[0-9a-f]{2}:'),
    ]
    return any(p.match(ip) for p in private_ranges)


def md5_hash(data: bytes) -> str:
    """Return MD5 hash of bytes"""
    import hashlib
    return hashlib.md5(data).hexdigest()


def sha256_hash(data: bytes) -> str:
    """Return SHA-256 hash of bytes"""
    import hashlib
    return hashlib.sha256(data).hexdigest()
