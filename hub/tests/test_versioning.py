"""SSRF-safe release URL construction."""

from __future__ import annotations

import pytest

from app.models.enums import WorkerArch
from app.services import versioning


def test_build_release_urls_for_allowed_host() -> None:
    urls = versioning.build_release_urls(
        repo="Sunderrrr/Huginn",
        version="v0.1.0",
        arch=WorkerArch.amd64,
        allowed_domains=["github.com"],
    )
    assert urls["binary_url"].startswith("https://github.com/Sunderrrr/Huginn/releases/")
    assert urls["binary_url"].endswith("huginn-worker-linux-amd64")
    assert urls["checksums_url"].endswith("checksums.txt")


def test_build_release_urls_self_hosted() -> None:
    urls = versioning.build_release_urls(
        repo="https://hub.example.com/dist",
        version="v0.1.0",
        arch=WorkerArch.amd64,
        allowed_domains=["hub.example.com"],
    )
    assert urls["binary_url"] == "https://hub.example.com/dist/huginn-worker-linux-amd64"
    assert urls["checksums_url"] == "https://hub.example.com/dist/checksums.txt"


def test_build_release_urls_self_hosted_ip() -> None:
    urls = versioning.build_release_urls(
        repo="https://192.0.2.13/dist",
        version="v0.1.0",
        arch=WorkerArch.amd64,
        allowed_domains=["192.0.2.13"],
    )
    assert urls["binary_url"] == "https://192.0.2.13/dist/huginn-worker-linux-amd64"


def test_rejects_disallowed_repo_host_injection() -> None:
    # A repo crafted to point the host elsewhere must be blocked by the allowlist.
    with pytest.raises(versioning.SSRFError):
        versioning.build_release_urls(
            repo="Sunderrrr/Huginn",
            version="v0.1.0",
            arch=WorkerArch.amd64,
            allowed_domains=["objects.githubusercontent.com"],  # github.com not allowed
        )


def test_validate_url_host_allows_http() -> None:
    # HTTP is allowed for self-hosted artifacts (e.g. LAN hub)
    versioning.validate_url_host("http://192.0.2.13/dist/checksums.txt", ["192.0.2.13"])


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


def test_validate_release_domain_rejects_localhost_and_internal() -> None:
    for bad in ["localhost", "db.internal", "x.local"]:
        with pytest.raises(versioning.SSRFError):
            versioning.validate_release_domain(bad)


def test_validate_release_domain_allows_ip() -> None:
    # IPs are allowed for self-hosted deployments (LAN hub)
    versioning.validate_release_domain("192.0.2.13")
    versioning.validate_release_domain("10.0.0.5")


def test_validate_release_domain_accepts_public_hostname() -> None:
    versioning.validate_release_domain("github.com")
    versioning.validate_release_domain("objects.githubusercontent.com")
