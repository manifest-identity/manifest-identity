"""Password and token primitives.

Passwords: bcrypt. The policy is length-based, no composition rules: at
least twelve characters, and at most seventy-two bytes because bcrypt
silently truncates beyond that; the cap turns silent truncation into a
stated rule enforced where passwords are set.

Tokens: 256-bit random values. The database stores only the SHA-256 of
a token, so a database leak yields nothing a client can present. Plain
SHA-256 is correct here where it would be wrong for passwords: these
values are random and high-entropy, so offline guessing is infeasible
and the hash only needs to be one-way and deterministic for lookup.
"""

import hashlib
import secrets

import bcrypt

PASSWORD_MIN_CHARS = 12
PASSWORD_MAX_BYTES = 72

# Verified against when the username does not exist, so both login paths
# cost one bcrypt comparison. Computed once at import from a value that
# is immediately discarded; nothing can ever match it.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(32), bcrypt.gensalt())


class PasswordPolicyError(ValueError):
    """The password does not meet the stated policy."""


def validate_new_password(password: str) -> None:
    if len(password) < PASSWORD_MIN_CHARS:
        raise PasswordPolicyError(
            f"password must be at least {PASSWORD_MIN_CHARS} characters"
        )
    if len(password.encode()) > PASSWORD_MAX_BYTES:
        raise PasswordPolicyError(
            f"password must be at most {PASSWORD_MAX_BYTES} bytes"
        )


def hash_password(password: str) -> str:
    validate_new_password(password)
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def verify_against_dummy(password: str) -> bool:
    """The unknown-username path: same cost, never true."""
    return bcrypt.checkpw(password.encode(), _DUMMY_HASH)


def new_session_token() -> tuple[str, str]:
    """Return (token for the client, hash for the database)."""
    token = secrets.token_urlsafe(32)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
