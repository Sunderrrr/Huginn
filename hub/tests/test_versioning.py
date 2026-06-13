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


def test_rejects_repo_with_metacharacters() -> None:
    with pytest.raises(versioning.SSRFError):
        versioning.build_release_urls(
            repo="owner/repo@evil.com", version="v1", arch=WorkerArch.amd64,
            allowed_domains=["github.com"],
        )


def test_rejects_version_path_traversal() -> None:
    with pytest.raises(versioning.SSRFError):
        versioning.build_release_urls(
            repo="owner/repo", version="../../etc/passwd", arch=WorkerArch.amd64,
            allowed_domains=["github.com"],
        )


def test_validate_release_domain_rejects_ip_and_internal() -> None:
    for bad in ["169.254.169.254", "127.0.0.1", "localhost", "db.internal", "x.local", "10.0.0.5"]:
        with pytest.raises(versioning.SSRFError):
            versioning.validate_release_domain(bad)


def test_validate_release_domain_accepts_public_hostname() -> None:
    versioning.validate_release_domain("github.com")
    versioning.validate_release_domain("objects.githubusercontent.com")
