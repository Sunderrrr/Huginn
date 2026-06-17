"""Auth request/response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import UserRole


class LoginRequest(BaseModel):
    username: str = Field(max_length=255)
    # Cap length to bound Argon2 work (anti-DoS).
    password: str = Field(max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str | None
    role: UserRole
    is_active: bool
    vm_ids: list[uuid.UUID] = []
    totp_enabled: bool = False
    passkey_count: int = 0


class OIDCStartResponse(BaseModel):
    authorization_url: str
    state: str


class UpdateProfileRequest(BaseModel):
    email: str | None = Field(default=None, max_length=320)


# --- MFA two-step login ---


class LoginChallengeResponse(BaseModel):
    """Returned by /login when a second factor (or first-time setup) is needed."""

    mfa_required: bool = False
    mfa_setup_required: bool = False
    challenge_token: str
    methods: list[str] = []


class MfaVerifyRequest(BaseModel):
    code: str | None = Field(default=None, max_length=10)
    backup_code: str | None = Field(default=None, max_length=16)


class TotpEnrollBeginResponse(BaseModel):
    secret: str
    otpauth_uri: str


class TotpEnrollFinishRequest(BaseModel):
    code: str = Field(max_length=10)


class BackupCodesResponse(BaseModel):
    backup_codes: list[str]


class TotpDisableRequest(BaseModel):
    code: str | None = Field(default=None, max_length=10)
    backup_code: str | None = Field(default=None, max_length=16)


# --- WebAuthn / passkeys ---


class WebAuthnRegisterFinishRequest(BaseModel):
    name: str = Field(default="", max_length=255)
    credential: dict


class WebAuthnLoginBeginRequest(BaseModel):
    username: str | None = Field(default=None, max_length=255)


class WebAuthnLoginFinishRequest(BaseModel):
    credential: dict


class WebAuthnCredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    created_at: datetime
    last_used_at: datetime | None
    transports: list[str] | None = None
