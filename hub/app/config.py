"""Hub configuration, loaded from environment (prefix ``HUGINN_``)."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HUGINN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core
    env: Literal["dev", "prod"] = "dev"
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://huginn:huginn@localhost:5432/huginn"
    # Connection pool — long-poll holds a connection briefly per active worker.
    db_pool_size: int = 20
    db_max_overflow: int = 30

    # Security
    jwt_secret: str = "change-me-please-generate-a-real-secret"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 60
    secret_hash_key: str = "change-me-another-32-byte-secret"
    mcp_service_token: str = "change-me-mcp-service-token"
    # Dedicated key for reversible encryption of TOTP secrets at rest. MUST be
    # distinct from jwt_secret/secret_hash_key so a single key leak can't both
    # forge tokens AND decrypt MFA seeds. A Fernet key is derived from this.
    mfa_encryption_key: str = "change-me-mfa-encryption-key-32b"
    # Short-lived intermediate token (post-password, pre-second-factor) TTL.
    mfa_challenge_ttl_minutes: int = 5
    # Require local admin accounts to enrol a second factor before they can use
    # the dashboard.
    require_admin_mfa: bool = True
    # When OIDC is enabled, password login is disabled by default (SSO-first);
    # set this true to also permit the local password form ("unsafe" opt-in).
    # When OIDC is off, password login is always available (no lockout).
    allow_password_login: bool = False

    # WebAuthn / passkeys. RP ID must be a registrable domain (NOT a bare IP),
    # so passkeys only work over the configured domain. Empty => passkeys off.
    webauthn_rp_id: str = ""
    webauthn_rp_name: str = "Huginn"
    webauthn_origin: str = ""
    # "preferred" works with the widest range of authenticators (incl. a YubiKey
    # with no PIN); "required" enforces a PIN/biometric for true passwordless MFA.
    webauthn_user_verification: str = "preferred"

    # TLS policy for hub<->worker
    require_tls: bool = True

    # Trust X-Forwarded-For for the client IP (enable only when behind a trusted
    # reverse proxy such as the bundled Caddy; otherwise clients could spoof it).
    trust_forwarded_for: bool = True

    # CORS: allowed dashboard origins (comma-separated). Empty disables CORS.
    # Stored as a raw string: pydantic-settings JSON-decodes list-typed env vars
    # before validators run, which would reject a plain CSV value.
    cors_origins_csv: str = Field(default="", validation_alias="HUGINN_CORS_ORIGINS")

    # Bootstrap admin
    bootstrap_admin_username: str = "admin"
    bootstrap_admin_password: str | None = None

    # MCP client token (for agent → MCP HTTP auth). Seeded into DB on first boot.
    mcp_client_token: str = ""

    # OIDC / Authentik
    oidc_enabled: bool = False
    # Label shown on the login button ("Continue with <name>").
    oidc_provider_name: str = "SSO"
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_url: str = "http://localhost:8000/api/auth/oidc/callback"
    # If set, the OIDC callback redirects the browser here with the access token
    # in the URL fragment (so a SPA dashboard can complete login). If empty, the
    # callback returns the token as JSON.
    oidc_post_login_redirect: str = ""

    # Execution limits
    max_body_bytes: int = 65_536
    max_output_bytes: int = 1_048_576
    default_task_timeout_seconds: int = 60
    task_dead_letter_retries: int = 3
    rate_limit_exec_per_minute: int = 30
    heartbeat_offline_seconds: int = 120

    # Worker update / release source. CSV string for the same reason as CORS.
    target_worker_version: str = "v1.0.0"
    target_release_repo: str = "Sunderrrr/Huginn"
    allowed_release_domains_csv: str = Field(
        default="github.com,objects.githubusercontent.com",
        validation_alias="HUGINN_ALLOWED_RELEASE_DOMAINS",
    )

    @staticmethod
    def _csv(value: str) -> list[str]:
        return [item.strip() for item in value.split(",") if item.strip()]

    @property
    def allowed_release_domains(self) -> list[str]:
        return self._csv(self.allowed_release_domains_csv)

    @property
    def cors_origins(self) -> list[str]:
        return self._csv(self.cors_origins_csv)

    @property
    def is_prod(self) -> bool:
        return self.env == "prod"

    def password_login_enabled(self, *, oidc_enabled: bool) -> bool:
        """Password login is on unless OIDC is active and it isn't re-enabled.

        Never locks out: with OIDC off the password form is always available.
        """
        return (not oidc_enabled) or self.allow_password_login

    def validate_for_prod(self) -> None:
        """Fail closed if deployed to prod with placeholder/weak secrets.

        Prevents the catastrophic-but-silent case where an operator ships with the
        default HS256 JWT key / HMAC key / MCP token, which would let anyone forge
        admin tokens, worker secrets, or the agent identity.
        """
        if not self.is_prod:
            return
        weak: list[str] = []
        checks = {
            "HUGINN_JWT_SECRET": self.jwt_secret,
            "HUGINN_SECRET_HASH_KEY": self.secret_hash_key,
            "HUGINN_MCP_SERVICE_TOKEN": self.mcp_service_token,
            "HUGINN_MFA_ENCRYPTION_KEY": self.mfa_encryption_key,
        }
        for name, value in checks.items():
            if value.startswith("change-me") or len(value) < 32:
                weak.append(name)
        if weak:
            raise RuntimeError(
                "refusing to start in prod with placeholder/weak secrets: "
                + ", ".join(sorted(weak))
                + " (generate with: openssl rand -hex 32)"
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
