"""Message Authentication Code (MAC) using HMAC.

Implements HMAC-based message authentication following RFC 2104.
Provides integrity verification for messages.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets


class HMAC:
    """HMAC (Hash-based Message Authentication Code) implementation.

    Provides message authentication using a cryptographic hash function
    and a secret key.

    Args:
        key: Secret key for HMAC computation.
        algorithm: Hash algorithm name (default: sha256).
    """

    def __init__(self, key: bytes | None = None, algorithm: str = "sha256") -> None:
        self._key = key or secrets.token_bytes(32)
        self._algorithm = algorithm

    @property
    def key(self) -> bytes:
        """Get the HMAC key."""
        return self._key

    def compute(self, message: bytes) -> bytes:
        """Compute HMAC for a message.

        Args:
            message: Message to authenticate.

        Returns:
            HMAC digest bytes.
        """
        return hmac.new(self._key, message, self._algorithm).digest()

    def verify(self, message: bytes, tag: bytes) -> bool:
        """Verify an HMAC tag.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            message: The original message.
            tag: The HMAC tag to verify.

        Returns:
            True if the tag is valid.
        """
        expected = self.compute(message)
        return hmac.compare_digest(expected, tag)

    @staticmethod
    def generate_key(length: int = 32) -> bytes:
        """Generate a cryptographically secure random key.

        Args:
            length: Key length in bytes (default 32 for SHA-256).

        Returns:
            Random bytes.
        """
        return secrets.token_bytes(length)


def create_mac(message: bytes, key: bytes) -> bytes:
    """Create an HMAC-SHA256 MAC for a message.

    Args:
        message: Message to authenticate.
        key: Secret key.

    Returns:
        32-byte HMAC tag.
    """
    return hmac.new(key, message, "sha256").digest()


def verify_mac(message: bytes, key: bytes, tag: bytes) -> bool:
    """Verify an HMAC-SHA256 MAC.

    Args:
        message: The original message.
        key: The secret key.
        tag: The MAC tag to verify.

    Returns:
        True if the MAC is valid.
    """
    return hmac.compare_digest(create_mac(message, key), tag)


def mac_to_hex(tag: bytes) -> str:
    """Convert MAC bytes to hex string.

    Args:
        tag: MAC bytes.

    Returns:
        Hex string representation.
    """
    return tag.hex()


def mac_from_hex(hex_str: str) -> bytes:
    """Convert hex string to MAC bytes.

    Args:
        hex_str: Hex string.

    Returns:
        MAC bytes.

    Raises:
        ValueError: If hex string is invalid.
    """
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        msg = f"Invalid hex string: {hex_str!r}"
        raise ValueError(msg)
