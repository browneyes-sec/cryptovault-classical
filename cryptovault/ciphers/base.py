"""Abstract base class for all classical ciphers.

Defines the contract that every cipher implementation must satisfy:
encrypt(), decrypt(), and an optional crack() method.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CipherBase(ABC):
    """Base class for classical cipher implementations.

    All subclasses must implement encrypt() and decrypt().
    Subclasses that support key recovery should implement crack().
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the human-readable name of this cipher."""

    @abstractmethod
    def encrypt(self, plaintext: str, key: Any) -> str:
        """Encrypt plaintext using the given key.

        Args:
            plaintext: The text to encrypt.
            key: The encryption key (type varies by cipher).

        Returns:
            The ciphertext string.
        """

    @abstractmethod
    def decrypt(self, ciphertext: str, key: Any) -> str:
        """Decrypt ciphertext using the given key.

        Args:
            ciphertext: The text to decrypt.
            key: The decryption key (type varies by cipher).

        Returns:
            The plaintext string.
        """

    def crack(self, ciphertext: str, **kwargs: Any) -> list[tuple[Any, str, float]]:
        """Attempt to recover the plaintext without the key.

        Args:
            ciphertext: The text to crack.
            **kwargs: Additional parameters (cipher-specific).

        Returns:
            List of (key, plaintext, confidence) tuples, ranked by fitness.

        Raises:
            NotImplementedError: If this cipher does not support cracking.
        """
        msg = f"{self.name} does not support key recovery"
        raise NotImplementedError(msg)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"
