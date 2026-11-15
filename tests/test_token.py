import base64
import hashlib
import hmac
import itertools
import json
import time

import jwt
import pytest

from health_tech.lib import tokenmaker
from health_tech.lib.config import get_settings
from health_tech.lib.tokenmaker import (
    TOKEN_LIFETIME_SECONDS,
    TokenError,
    TokenPurpose,
    TokenRequirements,
    generate_token,
    validate_token,
)

IDENTITY = TokenRequirements(email="user1@example.com", user_id="account-1", role="doctor")
HMAC_HASHES = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def signed(payload: dict, purpose: TokenPurpose) -> str:
    """Sign payload directly with the key for purpose."""
    return jwt.encode(payload, tokenmaker._signing_key(purpose), algorithm="HS256")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def signed_with_algorithm(payload: dict, purpose: TokenPurpose, algorithm: str) -> str:
    """Build an HMAC JWT by hand, so PyJWT's key-length warning for HS384/HS512 never fires."""
    header = b64url(json.dumps({"alg": algorithm, "typ": "JWT"}).encode())
    body = b64url(json.dumps(payload).encode())
    key = tokenmaker._signing_key(purpose)
    signature = hmac.new(key, f"{header}.{body}".encode(), HMAC_HASHES[algorithm]).digest()
    return f"{header}.{body}.{b64url(signature)}"


def valid_payload(purpose: TokenPurpose) -> dict:
    now = int(time.time())
    return {
        "Email": IDENTITY.email,
        "UserID": IDENTITY.user_id,
        "Role": IDENTITY.role,
        "Purpose": purpose.value,
        "iat": now,
        "exp": now + 60,
    }


@pytest.mark.parametrize("purpose", list(TokenPurpose))
def test_token_round_trips_for_its_own_purpose(purpose):
    claims = validate_token(generate_token(IDENTITY, purpose), purpose)

    assert (claims.email, claims.user_id, claims.role) == (
        "user1@example.com",
        "account-1",
        "doctor",
    )
    assert claims.purpose == purpose
    assert claims.expires_at - claims.issued_at == TOKEN_LIFETIME_SECONDS[purpose]


@pytest.mark.parametrize(
    ("minted_for", "presented_as"),
    [pytest.param(a, b, id=f"{a}-as-{b}") for a, b in itertools.permutations(TokenPurpose, 2)],
)
def test_token_is_rejected_for_every_other_purpose(minted_for, presented_as):
    with pytest.raises(TokenError):
        validate_token(generate_token(IDENTITY, minted_for), presented_as)


def test_every_purpose_has_a_lifetime():
    assert set(TOKEN_LIFETIME_SECONDS) == set(TokenPurpose)


def test_access_tokens_are_shorter_lived_than_refresh_tokens():
    assert (
        TOKEN_LIFETIME_SECONDS[TokenPurpose.ACCESS] < TOKEN_LIFETIME_SECONDS[TokenPurpose.REFRESH]
    )


def test_email_confirmation_lifetime_matches_email_text():
    assert TOKEN_LIFETIME_SECONDS[TokenPurpose.EMAIL_CONFIRMATION] == 2 * 60 * 60


def test_purpose_claim_is_checked_independently_of_the_key():
    token = signed(valid_payload(TokenPurpose.REFRESH), TokenPurpose.ACCESS)

    with pytest.raises(TokenError, match="not issued for this purpose"):
        validate_token(token, TokenPurpose.ACCESS)


def test_key_is_checked_independently_of_the_purpose_claim():
    token = signed(valid_payload(TokenPurpose.ACCESS), TokenPurpose.REFRESH)

    with pytest.raises(TokenError, match="Signature verification failed"):
        validate_token(token, TokenPurpose.ACCESS)


def test_legacy_token_signed_with_raw_secret_is_rejected():
    now = int(time.time())
    legacy = jwt.encode(
        {
            "Email": "a@example.com",
            "UserID": "",
            "Role": "super_admin",
            "exp": now + 60,
            "iat": now,
            "sub": "email_verification",
        },
        get_settings().jwt_secret,
        algorithm="HS256",
    )

    for purpose in TokenPurpose:
        with pytest.raises(TokenError):
            validate_token(legacy, purpose)


@pytest.mark.parametrize("missing", ["Purpose", "exp", "iat"])
def test_required_claims_must_be_present(missing):
    payload = valid_payload(TokenPurpose.ACCESS)
    del payload[missing]

    with pytest.raises(TokenError):
        validate_token(signed(payload, TokenPurpose.ACCESS), TokenPurpose.ACCESS)


def test_expired_token_is_rejected():
    payload = valid_payload(TokenPurpose.ACCESS) | {"exp": int(time.time()) - 1}

    with pytest.raises(TokenError, match="expired"):
        validate_token(signed(payload, TokenPurpose.ACCESS), TokenPurpose.ACCESS)


def test_hand_built_hs256_token_is_accepted():
    token = signed_with_algorithm(valid_payload(TokenPurpose.ACCESS), TokenPurpose.ACCESS, "HS256")

    assert validate_token(token, TokenPurpose.ACCESS).user_id == IDENTITY.user_id


@pytest.mark.parametrize("algorithm", ["HS384", "HS512"])
def test_only_hs256_is_accepted(algorithm):
    token = signed_with_algorithm(
        valid_payload(TokenPurpose.ACCESS), TokenPurpose.ACCESS, algorithm
    )

    with pytest.raises(TokenError, match="alg value is not allowed"):
        validate_token(token, TokenPurpose.ACCESS)


def test_unsigned_token_is_rejected():
    token = jwt.encode(valid_payload(TokenPurpose.ACCESS), None, algorithm="none")

    with pytest.raises(TokenError):
        validate_token(token, TokenPurpose.ACCESS)


def test_purposes_use_distinct_signing_keys():
    keys = {tokenmaker._signing_key(purpose) for purpose in TokenPurpose}

    assert len(keys) == len(TokenPurpose)
    assert get_settings().jwt_secret.encode() not in keys


@pytest.fixture
def empty_jwt_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "")
    get_settings.cache_clear()
    yield
    monkeypatch.undo()
    get_settings.cache_clear()


def test_empty_secret_fails_closed(empty_jwt_secret):
    with pytest.raises(TokenError, match="JWT_SECRET is not set"):
        generate_token(IDENTITY, TokenPurpose.ACCESS)

    forged = jwt.encode(
        valid_payload(TokenPurpose.ACCESS),
        tokenmaker.hmac.new(b"", b"health-tech/jwt/access", "sha256").digest(),
        algorithm="HS256",
    )
    with pytest.raises(TokenError, match="JWT_SECRET is not set"):
        validate_token(forged, TokenPurpose.ACCESS)
