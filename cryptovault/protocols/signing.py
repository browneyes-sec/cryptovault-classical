"""Digital signature utilities for message authentication.

Implements RSA-like digital signatures using classical cryptographic
primitives for educational purposes. In production, use established
libraries (e.g., cryptography).
"""

from __future__ import annotations

import hashlib
import secrets


def _mod_inverse(a: int, m: int) -> int:
    """Compute modular inverse using extended Euclidean algorithm.

    Args:
        a: The integer.
        m: The modulus.

    Returns:
        Modular inverse of a mod m.

    Raises:
        ValueError: If inverse doesn't exist.
    """
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        msg = f"No modular inverse for {a} mod {m}"
        raise ValueError(msg)
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _is_prime(n: int) -> bool:
    """Primality test (Miller-Rabin for educational purposes)."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False
    for _ in range(5):
        a = secrets.randbelow(n - 3) + 2
        if pow(a, n - 1, n) != 1:
            return False
    return True


def _generate_prime(bits: int) -> int:
    """Generate a random prime number.

    Args:
        bits: Bit length.

    Returns:
        Random prime.
    """
    while True:
        n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(n):
            return n


class SignatureKeyPair:
    """RSA-like key pair for digital signatures.

    Args:
        key_size: Bit size of the key (default 1024 for education).
    """

    def __init__(self, key_size: int = 1024) -> None:
        half = key_size // 2
        p = _generate_prime(half)
        q = _generate_prime(half)
        while q == p:
            q = _generate_prime(half)

        self._n = p * q
        phi = (p - 1) * (q - 1)
        self._e = 65537
        self._d = _mod_inverse(self._e, phi)

    @property
    def public_key(self) -> tuple[int, int]:
        """Get public key (n, e)."""
        return self._n, self._e

    @property
    def private_key(self) -> tuple[int, int]:
        """Get private key (n, d)."""
        return self._n, self._d

    def sign(self, message: bytes) -> int:
        """Sign a message.

        The message is first hashed, then signed with the private key.

        Args:
            message: Message to sign.

        Returns:
            Signature as integer.
        """
        digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
        return pow(digest, self._d, self._n)

    def verify(self, message: bytes, signature: int) -> bool:
        """Verify a signature.

        Args:
            message: Original message.
            signature: Signature to verify.

        Returns:
            True if signature is valid.
        """
        digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
        recovered = pow(signature, self._e, self._n)
        return recovered == digest


def sign_message(message: bytes, private_key: tuple[int, int]) -> int:
    """Sign a message using an RSA private key.

    Args:
        message: Message to sign.
        private_key: (n, d) tuple.

    Returns:
        Signature integer.
    """
    n, d = private_key
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    return pow(digest, d, n)


def verify_signature(message: bytes, public_key: tuple[int, int], signature: int) -> bool:
    """Verify a signature using an RSA public key.

    Args:
        message: Original message.
        public_key: (n, e) tuple.
        signature: Signature to verify.

    Returns:
        True if signature is valid.
    """
    n, e = public_key
    digest = int.from_bytes(hashlib.sha256(message).digest(), "big")
    recovered = pow(signature, e, n)
    return recovered == digest
