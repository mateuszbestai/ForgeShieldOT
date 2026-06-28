"""Authentication & authorization.

Auth is Supabase Cloud: the frontend logs in via @supabase/supabase-js and sends
the Supabase-issued access token as a Bearer JWT. The backend *verifies* that JWT
(HS256 using the project's SUPABASE_JWT_SECRET) — it never issues tokens or stores
passwords. RBAC role is read from the token's ``app_metadata.role`` claim and
mirrored to a local ``User`` row (JIT-provisioned) for ownership FKs and audit.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass

import httpx
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from sqlmodel import Session, select

from app.core.config import settings
from app.core.db import get_session
from app.core.enums import RoleName
from app.core.exceptions import AuthenticationError, PermissionDeniedError

_bearer = HTTPBearer(auto_error=False)

# --- JWKS cache for asymmetric (ES256/RS256) Supabase access tokens ----------
# Modern Supabase projects sign user access tokens with rotating asymmetric keys
# ("JWT signing keys"), not the legacy HS256 shared secret. We fetch the project
# JWKS lazily, cache it by ``kid``, and refresh (rate-limited) on a cache miss so
# key rotation is handled transparently.
_JWKS_LOCK = threading.Lock()
_JWKS_KEYS: dict[str, dict] = {}
_JWKS_LAST_FETCH: float = 0.0
_JWKS_MIN_REFETCH_SECONDS = 10.0
_JWKS_TIMEOUT_SECONDS = 5.0


def _refresh_jwks() -> None:
    """Fetch the project's JWKS and replace the cached keys."""
    global _JWKS_LAST_FETCH
    url = settings.supabase_jwks_url
    if not url:
        return
    _JWKS_LAST_FETCH = time.monotonic()
    resp = httpx.get(url, timeout=_JWKS_TIMEOUT_SECONDS)
    resp.raise_for_status()
    keys = resp.json().get("keys", [])
    _JWKS_KEYS.clear()
    for jwk in keys:
        kid = jwk.get("kid")
        if kid:
            _JWKS_KEYS[kid] = jwk


def _jwks_key_for(kid: str | None) -> dict:
    """Return the JWK matching ``kid``, refreshing the cache on a miss (rotation)."""
    if not kid:
        raise AuthenticationError("Token header missing 'kid' for asymmetric verification.")
    with _JWKS_LOCK:
        key = _JWKS_KEYS.get(kid)
        if key is None and (time.monotonic() - _JWKS_LAST_FETCH) > _JWKS_MIN_REFETCH_SECONDS:
            try:
                _refresh_jwks()
            except httpx.HTTPError as exc:
                raise AuthenticationError(
                    f"Could not fetch Supabase signing keys: {exc}"
                ) from exc
            key = _JWKS_KEYS.get(kid)
        if key is None:
            raise AuthenticationError("No matching Supabase signing key for token (unknown kid).")
        return key


@dataclass(frozen=True)
class AuthenticatedUser:
    id: uuid.UUID  # local User.id
    supabase_id: str
    email: str
    role: RoleName
    full_name: str

    def has_role(self, *roles: RoleName) -> bool:
        return self.role == RoleName.ADMIN or self.role in roles


def _decode_token(token: str) -> dict:
    """Verify a Supabase access token signature and standard claims.

    Handles both signing schemes a Supabase project may use:
      * **HS256** — the legacy shared-secret tokens (and the locally-minted
        dev-bypass test tokens), verified with ``SUPABASE_JWT_SECRET``.
      * **ES256 / RS256 / EdDSA** — the asymmetric tokens that modern projects
        issue, verified against the project's published JWKS public key.
    """
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise AuthenticationError(f"Malformed token header: {exc}") from exc

    alg = str(header.get("alg", "")).upper()
    issuer = settings.supabase_issuer
    # Only enforce issuer when we actually have a Supabase project configured and we
    # are not in dev-bypass mode (locally-minted test tokens omit the real issuer).
    verify_issuer = bool(issuer) and not (settings.auth_dev_bypass and not settings.is_production)

    if alg.startswith("HS"):
        key: object = settings.supabase_jwt_secret
        algorithms = ["HS256"]
    elif alg.startswith(("ES", "RS", "PS", "ED")):
        if not settings.supabase_jwks_url:
            raise AuthenticationError(
                "Received an asymmetric token but SUPABASE_URL is not configured."
            )
        key = _jwks_key_for(header.get("kid"))
        algorithms = [alg]
    else:
        raise AuthenticationError(f"Unsupported token algorithm: {alg or 'none'}")

    try:
        return jwt.decode(
            token,
            key,
            algorithms=algorithms,
            audience=settings.supabase_jwt_aud,
            issuer=issuer if verify_issuer else None,
            options={"verify_aud": True, "verify_iss": verify_issuer},
        )
    except JWTError as exc:
        raise AuthenticationError(f"Invalid or expired token: {exc}") from exc


def _role_from_claims(claims: dict) -> RoleName:
    app_meta = claims.get("app_metadata") or {}
    raw = app_meta.get("role") or claims.get("role")
    if isinstance(raw, str):
        try:
            return RoleName(raw.upper())
        except ValueError:
            pass
    return RoleName.VIEWER


def _provision_local_user(session: Session, claims: dict, role: RoleName) -> AuthenticatedUser:
    from app.models.user import User  # local import avoids import cycle

    supabase_id = str(claims.get("sub") or "")
    if not supabase_id:
        raise AuthenticationError("Token missing subject (sub) claim.")
    email = str(claims.get("email") or "").lower()
    user_meta = claims.get("user_metadata") or {}
    full_name = str(user_meta.get("full_name") or user_meta.get("name") or email or "Unknown")

    user = session.exec(select(User).where(User.supabase_id == supabase_id)).first()
    if user is None:
        user = User(
            supabase_id=supabase_id,
            email=email or f"{supabase_id}@unknown.local",
            full_name=full_name,
            role=role,
            is_active=True,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
    elif user.role != role or (email and user.email != email):
        user.role = role
        if email:
            user.email = email
        session.add(user)
        session.commit()
        session.refresh(user)

    assert user.id is not None
    return AuthenticatedUser(
        id=user.id,
        supabase_id=supabase_id,
        email=user.email,
        role=role,
        full_name=user.full_name,
    )


def get_current_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> AuthenticatedUser:
    if creds is None or not creds.credentials:
        raise AuthenticationError("Missing bearer token.")
    claims = _decode_token(creds.credentials)
    role = _role_from_claims(claims)
    auth_user = _provision_local_user(session, claims, role)
    # Expose for rate-limiter keying and audit middleware.
    request.state.user_id = str(auth_user.id)
    request.state.user_email = auth_user.email
    return auth_user


def get_optional_user(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    session: Session = Depends(get_session),
) -> AuthenticatedUser | None:
    if creds is None or not creds.credentials:
        return None
    try:
        return get_current_user(request, creds, session)
    except AuthenticationError:
        return None


def require_role(*allowed: RoleName):
    """Dependency factory enforcing that the caller holds one of ``allowed`` roles.

    ADMIN is always permitted.
    """

    def _dep(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not user.has_role(*allowed):
            raise PermissionDeniedError(
                f"Requires one of roles: {', '.join(r.value for r in allowed)}"
            )
        return user

    return _dep


# Convenience role groups used across routers.
WRITE_OPERATIONS = (RoleName.ADMIN, RoleName.OT_SECURITY_ENGINEER)
SOC_OPERATIONS = (RoleName.ADMIN, RoleName.OT_SECURITY_ENGINEER, RoleName.SOC_ANALYST)
COMPLIANCE_OPERATIONS = (RoleName.ADMIN, RoleName.COMPLIANCE_OFFICER)
