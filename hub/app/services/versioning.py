"""Worker version targeting and SSRF-safe release URL construction.

The hub is the source of truth for the target worker version. Update tasks carry
the release download URL and the checksums URL; the worker verifies the binary's
SHA-256 against the published checksums before swapping. Every URL host is checked
against the configured allowlist on *both* sides (defense in depth).
"""

from __future__ import annotations

from urllib.parse import urlparse

from app.models.enums import WorkerArch


class SSRFError(Exception):
    """Raised when a release URL host is not in the allowlist."""


def _asset_name(arch: WorkerArch) -> str:
    return f"huginn-worker-linux-{arch.value}"


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
