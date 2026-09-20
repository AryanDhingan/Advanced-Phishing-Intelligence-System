"""
Security utilities for authentication.

Handles:
- Password hashing
- Password verification
- JWT access-token creation
- JWT access-token decoding
"""

from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import (
    SECRET_KEY,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)


ALGORITHM = "HS256"


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
)


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""

    return pwd_context.hash(password)


def verify_password(
    plain_password: str,
    password_hash: str,
) -> bool:
    """Verify a plaintext password against its bcrypt hash."""

    return pwd_context.verify(
        plain_password,
        password_hash,
    )


def create_access_token(
    username: str,
) -> str:
    """Create a JWT access token for a user."""

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": username,
        "exp": expire,
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def decode_access_token(
    token: str,
) -> str | None:
    """Decode and validate a JWT token.

    Returns the username stored in the token,
    or None if the token is invalid or expired.
    """

    try:

        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        username = payload.get("sub")

        if not username:
            return None

        return username

    except JWTError:

        return None