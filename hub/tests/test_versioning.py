"""SSRF-safe release URL construction."""

from __future__ import annotations

import pytest

from app.models.enums import WorkerArch
from app.services import versioning


def test_build_release_urls_for_allowed_host() -> None:
    urls = versioning.build_release_urls(
        repo="Internal-website/Huginn",
        version="v0.1.0",
        arch=WorkerArch.amd64,
        allowed_domains=["github.com"],
    )
    assert urls["binary_url"].startswith("https://github.com/Internal-website/Huginn/releases/")
    assert urls["binary_url"].endswith("huginn-worker-linux-amd64")
    assert urls["checksums_url"].endswith("checksums.txt")


def test_rejects_disallowed_repo_host_injection() -> None:
    # A repo crafted to point the host elsewhere must be blocked by the allowlist.
    with pytest.raises(versioning.SSRFError):
        versioning.build_release_urls(
            repo="Internal-website/Huginn",
            version="v0.1.0",
            arch=WorkerArch.amd64,
            allowed_domains=["objects.githubusercontent.com"],  # github.com not allowed
        )


def test_validate_url_host_rejects_http() -> None:
    with pytest.raises(versioning.SSRFError):
        versioning.validate_url_host("http://github.com/x", ["github.com"])


def test_validate_url_host_rejects_evil_host() -> None:
    with pytest.raises(versioning.SSRFError):
        versioning.validate_url_host("https://evil.example.com/x", ["github.com"])
