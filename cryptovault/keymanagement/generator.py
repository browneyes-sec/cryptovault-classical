"""Key generation for classical ciphers.

Provides secure random key generation for various cipher types,
following NIST SP 800-57 recommendations where applicable.
"""

from __future__ import annotations

import hashlib
import math
import os
import secrets
import string


def generate_caesar_key() -> int:
    """Generate a random Caesar cipher shift key (0-25).

    Returns:
        Random integer between 0 and 25.
    """
    return secrets.randbelow(26)


def generate_vigenere_key(length: int) -> str:
    """Generate a random Vigenère cipher key.

    Args:
        length: Key length (must be >= 1).

    Returns:
        Random alphabetic key string.

    Raises:
        ValueError: If length < 1.
    """
    if length < 1:
        msg = f"Key length must be >= 1, got {length}"
        raise ValueError(msg)
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(length))


def generate_affine_key() -> tuple[int, int]:
    """Generate a random Affine cipher key pair (a, b).

    a is coprime with 26, b is in range [0, 25].

    Returns:
        Tuple of (a, b) where gcd(a, 26) = 1.
    """
    valid_a = [x for x in range(26) if math.gcd(x, 26) == 1]
    a = secrets.choice(valid_a)
    b = secrets.randbelow(26)
    return a, b


def generate_playfair_key(length: int = 10) -> str:
    """Generate a random Playfair cipher keyword.

    Args:
        length: Key length (must be >= 1).

    Returns:
        Random alphabetic keyword.

    Raises:
        ValueError: If length < 1.
    """
    if length < 1:
        msg = f"Key length must be >= 1, got {length}"
        raise ValueError(msg)
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(length))


def generate_hill_key(dim: int = 3) -> list[list[int]]:
    """Generate a random invertible Hill cipher matrix.

    Args:
        dim: Matrix dimension (2 or 3).

    Returns:
        Invertible matrix of size dim×dim over Z_26.

    Raises:
        ValueError: If dim not in {2, 3}.
    """
    if dim not in (2, 3):
        msg = f"Dimension must be 2 or 3, got {dim}"
        raise ValueError(msg)

    while True:
        matrix = [[secrets.randbelow(26) for _ in range(dim)] for _ in range(dim)]
        det = round(_determinant(matrix)) % 26
        if math.gcd(det, 26) == 1:
            return matrix


def _determinant(matrix: list[list[int]]) -> float:
    """Compute determinant of a square matrix."""
    n = len(matrix)
    if n == 1:
        return float(matrix[0][0])
    if n == 2:
        return float(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0])
    det = 0.0
    for c in range(n):
        minor = [row[:c] + row[c + 1 :] for row in matrix[1:]]
        det += ((-1) ** c) * matrix[0][c] * _determinant(minor)
    return det


def generate_columnar_key(length: int = 6) -> str:
    """Generate a random columnar transposition keyword.

    Args:
        length: Key length (must be >= 2).

    Returns:
        Random alphabetic keyword.

    Raises:
        ValueError: If length < 2.
    """
    if length < 2:
        msg = f"Key length must be >= 2, got {length}"
        raise ValueError(msg)
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(length))


def generate_monoalphabetic_key() -> str:
    """Generate a random monoalphabetic substitution alphabet.

    Returns:
        A random permutation of A-Z.
    """
    alphabet = list(string.ascii_uppercase)
    secrets.SystemRandom().shuffle(alphabet)
    return "".join(alphabet)


def generate_vernam_key(length: int) -> bytes:
    """Generate a truly random Vernam (OTP) key.

    Uses Python's cryptographically secure random generator.

    Args:
        length: Key length in bytes.

    Returns:
        Random bytes.

    Raises:
        ValueError: If length < 1.
    """
    if length < 1:
        msg = f"Key length must be >= 1, got {length}"
        raise ValueError(msg)
    return secrets.token_bytes(length)


def derive_key_from_password(password: str, salt: bytes | None = None, key_length: int = 32) -> tuple[bytes, bytes]:
    """Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.

    Args:
        password: Password string.
        salt: Optional salt (generated if None).
        key_length: Desired key length in bytes.

    Returns:
        Tuple of (derived_key, salt).
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100_000, dklen=key_length)
    return key, salt
