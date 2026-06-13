"""Worker version targeting and SSRF-safe release URL construction.

The hub is the source of truth for the target worker version. Update tasks carry
the release download URL and the checksums URL; the worker verifies the binary's
SHA-256 against the published checksums before swapping. Every URL host is checked
against the configured allowlist on *both* sides (defense in depth).
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.models.enums import WorkerArch

# "owner/repo" and a tag like "v1.2.3" — no path traversal, no userinfo, no
# metacharacters that could reshape the release URL.
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")


class SSRFError(Exception):
    """Raised when a release URL host is not in the allowlist."""


def _asset_name(arch: WorkerArch) -> str:
    return f"huginn-worker-linux-{arch.value}"


def validate_release_domain(domain: str) -> None:
    """Reject allowlist entries that are IP literals or otherwise unsafe.

    Keeps an admin (or a leaked agent token) from pointing the update channel at
    internal infrastructure (e.g. 169.254.169.254, localhost, private ranges).
    """
    host = domain.strip().lower()
    if not host or "/" in host or ":" in host:
        raise SSRFError(f"invalid release domain: {domain!r}")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        raise SSRFError(f"release domain must be a hostname, not an IP: {domain!r}")
    if host in {"localhost"} or host.endswith(".local") or host.endswith(".internal"):
        raise SSRFError(f"release domain not allowed: {domain!r}")


def validate_url_host(url: str, allowed_domains: list[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SSRFError(f"release URL must be https: {url!r}")
    host = (parsed.hostname or "").lower()
    if host not in {d.lower() for d in allowed_domains}:
        raise SSRFError(f"release host {host!r} not in allowlist")


def build_release_urls(
    *, repo: str, version: str, arch: WorkerArch, allowed_domains: list[str]
) -> dict[str, str]:
    """Construct and validate the binary + checksums URLs for a GitHub release."""
    if not _REPO_RE.match(repo):
        raise SSRFError(f"invalid repo: {repo!r}")
    if not _VERSION_RE.match(version):
        raise SSRFError(f"invalid version: {version!r}")
    base = f"https://github.com/{repo}/releases/download/{version}"
    urls = {
        "binary_url": f"{base}/{_asset_name(arch)}",
        "checksums_url": f"{base}/checksums.txt",
        "asset_name": _asset_name(arch),
        "version": version,
    }
    validate_url_host(urls["binary_url"], allowed_domains)
    validate_url_host(urls["checksums_url"], allowed_domains)
    return urls
