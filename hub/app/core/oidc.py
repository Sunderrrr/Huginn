"""Minimal OIDC authorization-code flow for Authentik (or any compliant IdP).

Discovery document and JWKS are fetched lazily and cached. The ID token is
verified against the provider's JWKS before any claim is trusted.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlencode

import httpx
import jwt

from app.config import Settings


class OIDCError(Exception):
    """Raised on any OIDC configuration or verification failure."""


@dataclass
class OIDCClaims:
    subject: str
    username: str
    email: str | None


class OIDCClient:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._discovery: dict | None = None

    @property
    def enabled(self) -> bool:
        s = self._settings
        return bool(s.oidc_enabled and s.oidc_issuer and s.oidc_client_id)

    def _require_enabled(self) -> None:
        if not self.enabled:
            raise OIDCError("OIDC is not enabled or fully configured")

    async def _get_discovery(self) -> dict:
        if self._discovery is None:
            url = self._settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                self._discovery = resp.json()
        return self._discovery

    @staticmethod
    def new_state() -> str:
        return secrets.token_urlsafe(24)

    async def authorization_url(self, state: str) -> str:
        self._require_enabled()
        discovery = await self._get_discovery()
        params = {
            "response_type": "code",
            "client_id": self._settings.oidc_client_id,
            "redirect_uri": self._settings.oidc_redirect_url,
            "scope": "openid profile email",
            "state": state,
        }
        return f"{discovery['authorization_endpoint']}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> OIDCClaims:
        self._require_enabled()
        discovery = await self._get_discovery()
        token_endpoint = discovery["token_endpoint"]
        jwks_uri = discovery["jwks_uri"]
        issuer = discovery.get("issuer", self._settings.oidc_issuer)

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self._settings.oidc_redirect_url,
                    "client_id": self._settings.oidc_client_id,
                    "client_secret": self._settings.oidc_client_secret,
                },
            )
        if resp.status_code != httpx.codes.OK:
            raise OIDCError(f"token endpoint returned {resp.status_code}")
        id_token = resp.json().get("id_token")
        if not id_token:
            raise OIDCError("no id_token in token response")

        return self._verify_id_token(id_token, jwks_uri, issuer)

    def _verify_id_token(self, id_token: str, jwks_uri: str, issuer: str) -> OIDCClaims:
        try:
            jwk_client = jwt.PyJWKClient(jwks_uri)
            signing_key = jwk_client.get_signing_key_from_jwt(id_token)
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                audience=self._settings.oidc_client_id,
                issuer=issuer,
            )
        except jwt.PyJWTError as exc:
            raise OIDCError(f"id_token verification failed: {exc}") from exc

        subject = claims.get("sub")
        if not subject:
            raise OIDCError("id_token missing 'sub'")
        username = claims.get("preferred_username") or claims.get("email") or subject
        return OIDCClaims(subject=subject, username=username, email=claims.get("email"))
