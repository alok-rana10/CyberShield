"""Argon2id password hashing and validation services."""

import re
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

# Initialize Argon2id password hasher with secure defaults
# Memory cost: 64 MB, Time cost: 3 iterations, Parallelism: 4 threads
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]).{8,128}$"
)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerificationError, VerifyMismatchError):
        return False
    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validate password complexity against defensive cybersecurity policies.

    Requirements:
    - Minimum length 8 characters, maximum 128
    - At least one lowercase letter
    - At least one uppercase letter
    - At least one decimal digit
    - At least one special symbol
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        return False, "Password must contain at least one special symbol."

    return True, "Password meets complexity requirements."
