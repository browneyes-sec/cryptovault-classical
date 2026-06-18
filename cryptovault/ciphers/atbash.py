"""Atbash cipher — monoalphabetic substitution via alphabet reversal.

Vulnerability: Fixed mapping (only 1 key), frequency analysis.

The Atbash cipher maps each letter to its counterpart from the
reversed alphabet: A↔Z, B↔Y, C↔X, etc. It is an involution
(applying it twice returns the original text).
"""

from __future__ import annotations

import string

from cryptovault.ciphers.base import CipherBase

_ATBASH_MAP = str.maketrans(
    string.ascii_lowercase + string.ascii_uppercase,
    string.ascii_lowercase[::-1] + string.ascii_uppercase[::-1],
)


class AtbashCipher(CipherBase):
    """Atbash cipher — fixed alphabet reversal substitution.

    No key required; the mapping is always the same.
    """

    @property
    def name(self) -> str:
        return "Atbash Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt (and decrypt) using Atbash mapping.

        Since Atbash is an involution, encrypt and decrypt are identical.

        Args:
            plaintext: Text to transform.
            key: Ignored (no key needed).

        Returns:
            Atbash-transformed text.
        """
        return plaintext.translate(_ATBASH_MAP)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Atbash ciphertext (same as encrypt).

        Args:
            ciphertext: Text to transform.
            key: Ignored.

        Returns:
            Recovered plaintext.
        """
        return self.encrypt(ciphertext)
