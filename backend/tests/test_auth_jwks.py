"""Auth verifier: both HS256 (legacy/dev-bypass) and asymmetric ES256 (JWKS).

Modern Supabase projects sign user access tokens with rotating asymmetric keys
(ES256) verified against the project JWKS, rather than the legacy HS256 shared
secret. These tests pin both paths so a regression can't reintroduce the silent
"The specified alg value is not allowed" 401 that breaks browser sign-in.
"""
from __future__ import annotations

# NOTE: conftest.py imports tests._env before any test module is collected, so the
# deterministic test settings (SUPABASE_JWT_SECRET=testsecret, SUPABASE_URL="" …)
# are already applied by the time this module — and app.core.security — load.
import time

import pytest
from app.core import security
from app.core.exceptions import AuthenticationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jose import jwk, jwt


def _es256_keypair() -> tuple[str, str]:
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def test_es256_token_is_verified_via_jwks(monkeypatch) -> None:
    priv_pem, pub_pem = _es256_keypair()
    kid = "test-kid-1"
    public_jwk = jwk.construct(pub_pem, "ES256").to_dict()
    public_jwk["kid"] = kid

    # Point the verifier at a project and preload the JWKS cache (so no network).
    monkeypatch.setattr(security.settings, "supabase_url", "https://test.supabase.co")
    monkeypatch.setitem(security._JWKS_KEYS, kid, public_jwk)

    token = jwt.encode(
        {
            "sub": "abc-123",
            "email": "es256@forgeshield.local",
            "aud": "authenticated",
            "app_metadata": {"role": "ADMIN"},
            "exp": int(time.time()) + 600,
        },
        priv_pem,
        algorithm="ES256",
        headers={"kid": kid},
    )

    claims = security._decode_token(token)
    assert claims["email"] == "es256@forgeshield.local"
    assert claims["app_metadata"]["role"] == "ADMIN"


def test_asymmetric_token_without_supabase_url_is_rejected(monkeypatch) -> None:
    priv_pem, _ = _es256_keypair()
    monkeypatch.setattr(security.settings, "supabase_url", "")
    token = jwt.encode(
        {"sub": "x", "aud": "authenticated", "exp": int(time.time()) + 600},
        priv_pem,
        algorithm="ES256",
        headers={"kid": "k"},
    )
    with pytest.raises(AuthenticationError):
        security._decode_token(token)


def test_hs256_token_still_verifies() -> None:
    token = jwt.encode(
        {
            "sub": "y-456",
            "email": "hs@forgeshield.local",
            "aud": "authenticated",
            "app_metadata": {"role": "VIEWER"},
            "exp": int(time.time()) + 600,
        },
        security.settings.supabase_jwt_secret,
        algorithm="HS256",
    )
    claims = security._decode_token(token)
    assert claims["email"] == "hs@forgeshield.local"
    assert claims["app_metadata"]["role"] == "VIEWER"
